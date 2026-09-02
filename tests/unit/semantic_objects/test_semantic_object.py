from __future__ import annotations

import json
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

from tests.pe_fixtures import (
    pe32_data_export_image,
    pe32_image,
    pe32_image_with_writable_data,
    pe32_import_image,
    pe32_load_config_image,
    pe32_resource_image,
    pe32_tls_image,
)

from spaghetti_extractor.artifacts.artifact_set import canonical_sha256_v3
from spaghetti_extractor.qualified_platform.requirements import (
    build_machine_ir_isa_extraction_request_v2,
    build_machine_ir_isa_requirements_v2,
)
from spaghetti_extractor.candidate.project import write_pe32_module_interface
from spaghetti_extractor.external.resolved import bind_launch_policy_v1
from spaghetti_extractor.semantic_objects.object_authority import (
    MachineObjectAuthorityV2,
    derive_pe32_machine_object_authority_v2,
)
from spaghetti_extractor.candidate.behavioral_c_package import (
    write_spx_behavioral_c_package,
    write_spx_behavioral_c_package_from_semantic_object,
)
from spaghetti_extractor.roundtrip_fuzz.image_io import (
    write_spx_load_image_contract,
)
from spaghetti_extractor.semantic_objects.semantic_object import (
    SemanticObjectError,
    SemanticObjectV1,
    write_semantic_object_v1,
)
from spaghetti_extractor.semantic_objects.replay import replay_semantic_object_v1
from spaghetti_extractor.semantic_objects.exception_projection import (
    project_exception_transitions,
)
from spaghetti_extractor.transfer.exception_semantics import (
    CheckedExceptionTransitionV1,
)
from spaghetti_extractor.testkit.transfer_fixture import (
    as_machine_ir_unit,
    transfer_row,
    write_fixture_transfer_plan,
)
from spaghetti_extractor.util import json_dumps, sha256_file, write_json
from spaghetti_extractor.isa.semantic_forms import (
    lean_semantic_form_classifier_sha256,
)
from tests.unit.qualified_platform.test_release import (
    QualifiedPlatformV1Tests,
)


class SemanticObjectV1Tests(unittest.TestCase):
    def test_object_authority_has_one_generation_policy_and_typed_view_catalog(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _, _, output = self._fixture(
                root, image=pe32_data_export_image(b"\x11\x22\x33\x44")
            )
            authority_path = output.parent / "machine-object-authority.json"
            authority = MachineObjectAuthorityV2.parse(json.loads(
                authority_path.read_text(encoding="utf-8")
            ))
            self.assertTrue(all(
                rule.generation_policy == {
                    "mode": "image_epoch",
                    "seed": rule.generation,
                    "expires_with": "image",
                }
                for rule in authority.rules
            ))
            self.assertEqual(len(authority.data_export_anchors), 1)
            anchor = replace(
                authority.data_export_anchors[0],
                typed_view={
                    "boundary_type_id": "fixture-u32",
                    "target_layout_sha256": "d" * 64,
                },
            )
            typed = MachineObjectAuthorityV2(
                machine_backend=authority.machine_backend,
                bindings=authority.bindings,
                rules=authority.rules,
                data_export_anchors=[anchor],
            )
            parsed = MachineObjectAuthorityV2.parse(typed.to_payload())
            self.assertEqual(
                parsed.data_export_anchors[0].typed_view,
                {
                    "boundary_type_id": "fixture-u32",
                    "target_layout_sha256": "d" * 64,
                },
            )

    def test_checked_exception_authority_becomes_typed_code_relocations(
        self,
    ) -> None:
        handled = CheckedExceptionTransitionV1(
            unit_id="source", source_rva=0x1000, effect_index=3,
            fault_index=0, fault_sha256="a" * 64,
            transition_id="exceptional-transition-v3:fixture",
            transition_sha256="b" * 64, authorizing=True,
            disposition="handled", handler_unit_id="handler",
            handler_rva=0x1100, resumption_unit_id="resume",
            resumption_rva=0x1200, guard={"op": "fault"},
            blocker_code=None, unwind_unit_ids=("cleanup",),
            state_projection={"registers": ["eax"]},
            native_exception_code=0xC0000094, native_exception_flags=0,
            native_exception_parameter_count=0,
            native_exception_continuable=True,
            operation="divide_if",
        )
        incomplete = CheckedExceptionTransitionV1(
            unit_id="source", source_rva=0x1000, effect_index=4,
            fault_index=1, fault_sha256="c" * 64,
            transition_id=None, transition_sha256=None, authorizing=False,
            disposition=None, handler_unit_id=None, handler_rva=None,
            guard=None, blocker_code="exception_transition_missing",
            operation="memory_read_if",
        )
        transfers = {
            unit_id: {
                "identity": unit_id,
                "source": {"rva_start": rva},
            }
            for unit_id, rva in (
                ("source", 0x1000), ("handler", 0x1100),
                ("resume", 0x1200), ("cleanup", 0x1300),
            )
        }
        symbols, definitions, relocations, holes = (
            project_exception_transitions((handled, incomplete), transfers)
        )
        self.assertEqual(len(symbols), 2)
        self.assertEqual(len(definitions), 1)
        self.assertEqual(
            {row["kind"] for row in relocations},
            {
                "exception_transition_activation",
                "exception_handler_target",
                "exception_resumption_target",
                "exception_unwind_target",
            },
        )
        self.assertTrue(all(
            row["status"] == "resolved_local"
            for row in relocations
            if row["kind"] != "exception_transition_activation"
        ))
        activations = [
            row for row in relocations
            if row["kind"] == "exception_transition_activation"
        ]
        self.assertEqual(len(activations), 2)
        self.assertEqual(
            {row["status"] for row in activations},
            {"resolved_local", "unresolved"},
        )
        handled_symbol = next(
            row["symbol_id"] for row in symbols
            if row["declaration"]["authorizing"] is True
        )
        self.assertTrue(all(
            row["source_symbol"] == handled_symbol
            for row in relocations
            if row["kind"] in {
                "exception_handler_target",
                "exception_resumption_target",
                "exception_unwind_target",
            }
        ))
        self.assertEqual(
            [row["kind"] for row in holes],
            ["exception_transition_not_authoritative"],
        )

    def _fixture(
        self, root: Path, *, image: bytes | None = None,
        transfer: dict[str, object] | list[dict[str, object]] | None = None,
    ) -> tuple[Path, Path, Path]:
        original = root / "fixture.exe"
        original.write_bytes(image or pe32_image(b"\x40\x40\xc3"))
        contract = root / "load-image-contract.json"
        write_spx_load_image_contract(original_pe=original, out=contract)
        interface_root = root / "interface"
        write_pe32_module_interface(
            image_id="fixture.exe",
            original_pe=original,
            load_image_contract=contract,
            out=interface_root,
        )
        machine_ir = root / "machine-ir.jsonl"
        transfers = (
            transfer if isinstance(transfer, list)
            else [transfer or transfer_row()]
        )
        machine_ir.write_text(
            "\n".join(
                json_dumps(as_machine_ir_unit(row)) for row in transfers
            ) + "\n",
            encoding="utf-8",
        )
        transfer_plan = write_fixture_transfer_plan(
            machine_ir, pe_sha256=sha256_file(original)
        )
        interface_path = interface_root / "module-interface.json"
        authority = derive_pe32_machine_object_authority_v2(
            module_interface=json.loads(interface_path.read_text(encoding="utf-8")),
            module_interface_sha256=sha256_file(interface_path),
        )
        authority_path = root / "machine-object-authority.json"
        write_json(authority_path, authority.to_payload())
        output = root / "semantic-object.json"
        write_semantic_object_v1(
            transfer_plan=transfer_plan,
            module_interface=interface_path,
            machine_object_authority=authority_path,
            out=output,
        )
        return transfer_plan, interface_path, output

    def test_exact_platform_selection_is_owned_by_the_semantic_object(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            row = transfer_row()
            row["original"] = {
                "rva_start": 0x1000, "rva_end": 0x1001, "size": 1,
            }
            row["outcome"] = {"kind": "fallthrough", "target_rva": 0x1001}
            row["instructions"] = [{
                "rva_start": 0x1000,
                "rva_end": 0x1001,
                "mnemonic": "nop",
                "operands": [],
            }]
            transfer_path, interface_path, output = self._fixture(
                root, image=pe32_image(b"\x90"), transfer=row
            )
            machine_ir = root / "machine-ir.jsonl"
            unit = json.loads(machine_ir.read_text(encoding="utf-8"))
            request = build_machine_ir_isa_extraction_request_v2(
                units=[unit],
                binary_sha256=json.loads(
                    interface_path.read_text(encoding="utf-8")
                )["identity"]["pe_sha256"],
                include_structural_universe=True,
            )
            semantic_form = (
                "SpaghettiExtractor.ISA.Formal.InstructionSemanticForm.nop"
            )
            classifier = lean_semantic_form_classifier_sha256()
            requirements = build_machine_ir_isa_requirements_v2(
                request=request,
                machine_ir_sha256=sha256_file(machine_ir),
                lean_rows={("original", 0): ({
                    "rva": 0x1000,
                    "size": 1,
                    "bytes": "90",
                    "form": semantic_form,
                },)},
                lean_evidence={
                    "status": "lean_extracted_untrusted",
                    "classifier_sha256": classifier,
                    "extractor_sha256": "3" * 64,
                    "source_sha256": "4" * 64,
                },
            )
            requirements_path = root / "requirements.json"
            write_json(requirements_path, requirements)
            platform = QualifiedPlatformV1Tests()._platform(root / "platform-fixture")
            write_semantic_object_v1(
                transfer_plan=transfer_path,
                module_interface=interface_path,
                machine_object_authority=(
                    output.parent / "machine-object-authority.json"
                ),
                isa_requirements=requirements_path,
                qualified_platform=platform,
                out=output,
            )

            semantic = SemanticObjectV1.load(output)
            replay = replay_semantic_object_v1(output)
            selection = semantic.platform_selection
            assert selection is not None
            self.assertEqual(selection["status"], "qualified")
            self.assertEqual(selection["counts"]["occurrences"], 1)
            self.assertEqual(selection["counts"]["occurrences_qualified"], 1)
            self.assertEqual(semantic.payload["counts"]["isa_occurrences"], 1)
            self.assertEqual(
                replay["platform_selection_sha256"],
                selection["selection_sha256"],
            )
            self.assertNotIn(
                "qualified_platform_selection_missing",
                {row["kind"] for row in semantic.payload["holes"]},
            )
            self.assertEqual(
                semantic.payload["members"]["qualified_platform"]["identity"],
                json.loads(platform.read_text(encoding="utf-8"))[
                    "platform_sha256"
                ],
            )

    def test_faithful_shadow_embeds_transfer_v2_as_its_only_body(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            transfer_path, interface_path, output = self._fixture(root)
            semantic = SemanticObjectV1.load(output)
            replay = replay_semantic_object_v1(output)
            plan = json.loads(transfer_path.read_text(encoding="utf-8"))
            interface = json.loads(interface_path.read_text(encoding="utf-8"))
            payload = semantic.payload

            self.assertNotIn("transfer_plan", payload)
            self.assertNotIn("module_interface", payload)
            member_plan = json.loads(
                (output.parent / "executable-transfer-plan.json").read_text(
                    encoding="utf-8"
                )
            )
            self.assertEqual(member_plan, plan)
            self.assertEqual(
                json_dumps(member_plan["transfers"]).encode(),
                json_dumps(plan["transfers"]).encode(),
            )
            self.assertEqual(
                json.loads(
                    (output.parent / "module-interface.json").read_text(
                        encoding="utf-8"
                    )
                ),
                interface,
            )
            self.assertEqual(
                payload["members"]["transfer_plan"]["identity"],
                plan["plan_sha256"],
            )
            self.assertEqual(
                payload["members"]["machine_object_authority"]["identity"],
                semantic.machine_object_authority.authority_sha256,
            )
            self.assertEqual(semantic.machine_object_authority.rules, ())
            self.assertEqual(payload["status"], "complete")
            self.assertEqual(replay["semantic_object_sha256"], semantic.identity)
            self.assertFalse(replay["authority"])
            self.assertFalse(payload["authority"])
            self.assertEqual(payload["role"], "checked_relocatable")
            self.assertEqual(
                payload["definitions"][0]["body"]["language"],
                "executable-transfer-plan-v2",
            )
            self.assertEqual(
                payload["definitions"][0]["evidence_dependencies"], [1]
            )
            self.assertEqual(payload["counts"]["transfers"], 1)
            self.assertEqual(
                payload["effect_index"]["direct_control_edges"]["field"],
                "direct_control_edges",
            )
            self.assertEqual(
                {
                    row["declaration"]["provider_id"]
                    for row in payload["symbols"]
                    if row["kind"] == "runtime_primitive"
                },
                set(plan["runtime_provider_requirements"]),
            )
            runtime_dependencies = payload["effect_index"][
                "runtime_primitive_dependencies"
            ]
            self.assertEqual(
                {
                    row["provider_id"] for row in runtime_dependencies
                },
                set(plan["runtime_provider_requirements"]),
            )
            self.assertTrue(all(
                row["source_symbols"]
                == [payload["definitions"][0]["symbol_id"]]
                and row["target_symbol"].startswith(
                    "platform:runtime-primitive:"
                )
                for row in runtime_dependencies
            ))
            self.assertEqual(
                payload["effect_index"]["object_symbol_bindings"], []
            )
            complete = SemanticObjectV1.load(output, require_complete=True)
            self.assertEqual(complete.identity, semantic.identity)
            self.assertFalse(complete.payload["authority"])

    def test_content_bound_link_view_matches_strict_object_identity(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _, _, output = self._fixture(root)
            strict = SemanticObjectV1.load(output)
            link_view = SemanticObjectV1.load_link_view(output)

            self.assertEqual(link_view.identity, strict.identity)
            self.assertEqual(link_view.payload, strict.payload)
            self.assertEqual(
                [(row.identity, row.rva_start) for row in link_view.transfers],
                [(row.identity, row.rva_start) for row in strict.transfers],
            )

            member = output.parent / "executable-transfer-plan.json"
            stale = json.loads(member.read_text(encoding="utf-8"))
            stale["plan_sha256"] = "0" * 64
            write_json(member, stale)
            with self.assertRaisesRegex(
                SemanticObjectError,
                "transfer-plan self hash is stale",
            ):
                SemanticObjectV1.load_link_view(output)

    def test_machine_object_authority_member_drift_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _, _, output = self._fixture(root)
            authority_path = output.parent / "machine-object-authority.json"
            authority = json.loads(authority_path.read_text(encoding="utf-8"))
            authority["bindings"]["original_pe_sha256"] = "0" * 64
            authority["authority_sha256"] = canonical_sha256_v3({
                key: value for key, value in authority.items()
                if key != "authority_sha256"
            })
            write_json(authority_path, authority)

            with self.assertRaisesRegex(
                SemanticObjectError, "package members are stale"
            ):
                SemanticObjectV1.load(output)

    def test_direct_edges_are_exact_typed_code_relocations(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            first = transfer_row()
            first["id"] = "semantic-transfer:first"
            first["original"] = {
                "rva_start": 0x1000, "rva_end": 0x1001, "size": 1,
            }
            first["outcome"] = {"kind": "fallthrough", "target_rva": 0x1001}
            second = transfer_row()
            second["id"] = "semantic-transfer:second"
            second["original"] = {
                "rva_start": 0x1001, "rva_end": 0x1002, "size": 1,
            }
            second["outcome"] = {
                "kind": "return",
                "value": {"op": "reg", "name": "eax", "width": 32},
            }
            _, _, output = self._fixture(
                root,
                image=pe32_image(b"\x40\xc3"),
                transfer=[first, second],
            )

            payload = SemanticObjectV1.load(output).payload
            code = [
                row for row in payload["relocations"]
                if row["kind"] == "direct_control"
            ]
            self.assertEqual(len(code), 1)
            self.assertEqual(code[0]["source_rva"], 0x1000)
            self.assertEqual(code[0]["target_rva"], 0x1001)
            self.assertEqual(code[0]["status"], "resolved_local")
            self.assertEqual(
                code[0]["required_view"], {"kind": "code_capability"}
            )
            self.assertTrue(code[0]["source_symbol"].endswith(":first"))
            self.assertTrue(code[0]["target_symbol"].endswith(":second"))
            self.assertEqual(
                replay_semantic_object_v1(output)["counts"]["relocations"],
                len(payload["relocations"]),
            )

    def test_import_slots_are_relocatable_and_remain_unclassified(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _, _, output = self._fixture(
                root,
                image=pe32_import_image(
                    b"\x40\x40\xc3", symbol="Sleep", dll="KERNEL32.dll"
                ),
            )
            payload = SemanticObjectV1.load(output).payload
            imports = [
                row for row in payload["symbols"]
                if row["kind"] == "unclassified_import"
            ]
            data = [
                row for row in payload["symbols"]
                if row["kind"] == "data"
                and row["storage_class"] == "image_section"
            ]
            self.assertEqual(len(imports), 1)
            self.assertEqual(len(data), 1)
            loader_relocations = [
                row for row in payload["relocations"]
                if row["kind"] == "iat_slot"
            ]
            self.assertEqual(len(loader_relocations), 1)
            relocation = loader_relocations[0]
            self.assertEqual(relocation["kind"], "iat_slot")
            self.assertEqual(relocation["source_symbol"], data[0]["symbol_id"])
            self.assertEqual(relocation["target_symbol"], imports[0]["symbol_id"])
            self.assertEqual(relocation["status"], "unresolved")
            self.assertEqual(
                imports[0]["declaration"]["namespace"],
                "original_loader_import_slot",
            )
            self.assertIn(
                "loader_relocations_unlinked",
                {row["kind"] for row in payload["holes"]},
            )

    def test_semantic_calls_do_not_conflate_loader_slots_with_support(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            row = transfer_row()
            call = {
                "family": "external",
                "kind": "external_call",
                "instruction_rva": 0x1000,
                "target_rva": 0,
                "return_rva": 0x1003,
                "dll": "kernel32.dll",
                "symbol": "GetProcAddress",
                "ordinal": None,
                "register_inputs": {
                    name: {"op": "reg", "name": name, "width": 32}
                    for name in (
                        "eax", "ebx", "ecx", "edx",
                        "esi", "edi", "ebp", "esp",
                    )
                },
                "flag_inputs": {
                    name: {"op": "flag", "name": name}
                    for name in ("cf", "zf", "sf", "of", "pf", "df")
                },
                "arguments": [],
                "stack_inputs": [],
            }
            row["external_events"] = [call]
            row["ordered_events"] = [call]
            transfer_path, interface_path, output = self._fixture(
                root,
                image=pe32_import_image(
                    b"\x40\x40\xc3",
                    symbol="GetProcAddress",
                    dll="KERNEL32.dll",
                ),
                transfer=row,
            )
            interface = json.loads(interface_path.read_text(encoding="utf-8"))
            identity = {
                "dll": "kernel32.dll",
                "symbol": "GetProcAddress",
                "ordinal": None,
            }
            contract = {
                "identity": identity,
                "iat_rva": interface["imports"][0]["iat_rva"],
                "boundary": {
                    "schema": {"schema_sha256": "1" * 64},
                    "physical_call_frame_v3": {"id": "fixture-frame"},
                },
                "contract": {"payload": {"loader_service": {
                    "kind": "dynamic_export_resolution",
                }}},
            }
            dynamic_identity = {
                "dll": "msvcrt.dll",
                "symbol": "___lc_codepage_func",
                "ordinal": None,
            }
            dynamic_contract = {
                "identity": dynamic_identity,
                "boundary": {
                    "schema": {"schema_sha256": "2" * 64},
                    "physical_call_frame_v3": {"id": "dynamic-frame"},
                },
                "contract": {"payload": {
                    "dynamic_export": {"kind": "code"},
                }},
                "dynamic_export_kind": "code",
                "import_kind": "dynamic_export",
            }
            loader_service = {
                **contract, "resolution_catalog": [dynamic_contract],
            }
            environment_core = {
                "format": (
                    "spaghetti-extractor-resolved-external-environment-v1"
                ),
                "status": "complete",
                "bindings": {
                    "module_interface_sha256": interface["interface_sha256"],
                    "module_pe_sha256": interface["identity"]["pe_sha256"],
                    "environment_intent_sha256": "2" * 64,
                    "runtime_profile_pack_sha256s": ["3" * 64],
                    "interface_profile_pack_sha256s": [],
                },
                "target": {
                    "abi": "pe32-i686-mingw32",
                    "data_layout": "pe32-ilp32-v1",
                },
                "launch_policy": bind_launch_policy_v1(
                    {
                        "format": "spaghetti-extractor-pe32-launch-assumption-template-v1",
                        "schema_version": 1,
                    },
                    source_sha256="0" * 64,
                    filename="fixture-launch.json",
                ),
                "canonical_boundaries": [],
                "interface_method_catalogs": [],
                "machine_import_contracts": [contract],
                "original_semantic_imports": [contract],
                "generated_runtime_support_imports": [],
                "loader_service_contracts": [loader_service],
                "static_authority_bindings": [],
                "checked_exception_protocols": [],
                "blockers": [],
                "authority": "checked_static_environment",
            }
            environment = {
                **environment_core,
                "resolved_environment_sha256": canonical_sha256_v3(
                    environment_core
                ),
            }
            environment_path = root / "resolved-external-environment.json"
            write_json(environment_path, environment)
            write_semantic_object_v1(
                transfer_plan=transfer_path,
                module_interface=interface_path,
                machine_object_authority=(
                    output.parent / "machine-object-authority.json"
                ),
                resolved_external_environment=environment_path,
                out=output,
            )
            payload = SemanticObjectV1.load(output).payload
            loader = next(
                item for item in payload["symbols"]
                if item["kind"] == "unclassified_import"
            )
            semantic = next(
                item for item in payload["symbols"]
                if item["kind"] == "external_function"
                and item["declaration"]["symbol"] == "GetProcAddress"
            )
            dynamic_semantic = next(
                item for item in payload["symbols"]
                if item["kind"] == "external_function"
                and item["declaration"]["symbol"] == "___lc_codepage_func"
            )
            support = [
                item for item in payload["symbols"]
                if item["kind"] == "runtime_primitive"
            ]
            self.assertNotEqual(loader["symbol_id"], semantic["symbol_id"])
            self.assertEqual(
                loader["declaration"]["namespace"],
                "original_loader_import_slot",
            )
            contract_sha256 = canonical_sha256_v3(contract)
            loader_service_sha256 = canonical_sha256_v3(loader_service)
            self.assertEqual(
                loader["declaration"]["environment_contract_sha256"],
                contract_sha256,
            )
            self.assertEqual(
                loader["declaration"]["loader_service_contract_sha256"],
                loader_service_sha256,
            )
            self.assertEqual(
                semantic["declaration"], {
                    "namespace": "original_semantic_import",
                    "dll": "kernel32.dll",
                    "symbol": "GetProcAddress",
                    "ordinal": None,
                    "environment_contract_sha256": contract_sha256,
                    "loader_service_contract_sha256": (
                        loader_service_sha256
                    ),
                    "declaration_role": "loader_service",
                },
            )
            self.assertEqual(
                dynamic_semantic["declaration"], {
                    "namespace": "original_semantic_import",
                    **dynamic_identity,
                    "environment_contract_sha256": canonical_sha256_v3(
                        dynamic_contract
                    ),
                    "loader_service_contract_sha256": (
                        loader_service_sha256
                    ),
                    "declaration_role": "loader_service",
                },
            )
            self.assertTrue(all(
                item["declaration"]["namespace"]
                == "generated_runtime_support"
                for item in support
            ))
            relocation = next(
                item for item in payload["relocations"]
                if item["kind"] == "external_call"
            )
            self.assertEqual(relocation["target_symbol"], semantic["symbol_id"])
            self.assertEqual(relocation["status"], "unresolved_external")
            self.assertEqual(relocation["site"]["instruction_rva"], 0x1000)
            replay_semantic_object_v1(output)

    def test_data_exports_resolve_to_shared_typed_address_anchors(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _, _, output = self._fixture(
                root, image=pe32_data_export_image(b"\x11\x22\x33\x44")
            )
            payload = SemanticObjectV1.load(output).payload
            anchors = [
                row for row in payload["symbols"]
                if row["kind"] == "data_anchor"
                and row["anchor_kind"] == "data_export"
            ]
            self.assertEqual(len(anchors), 1)
            self.assertEqual(anchors[0]["original_rva"], 0x2000)
            self.assertTrue(anchors[0]["permissions"]["write"])
            definition = next(
                row for row in payload["definitions"]
                if row["symbol_id"] == anchors[0]["symbol_id"]
            )
            self.assertEqual(definition["definition_kind"], "object_anchor")
            self.assertEqual(definition["anchor"]["offset"], 0)
            self.assertIsNone(definition["anchor"]["extent"])
            export = next(
                row for row in payload["roots"]
                if row["kind"] == "data_export"
            )
            self.assertEqual(export["target_symbol"], anchors[0]["symbol_id"])
            self.assertEqual(export["object_offset"], 0)
            replay_semantic_object_v1(output)

    def test_tls_geometry_is_projected_as_typed_storage_anchors(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _, _, output = self._fixture(
                root, image=pe32_tls_image((0x1100, 0x1108))
            )
            payload = SemanticObjectV1.load(output).payload
            anchors = {
                row["anchor_kind"]: row
                for row in payload["symbols"]
                if row["kind"] == "data_anchor"
            }
            self.assertEqual(set(anchors), {
                "tls_template", "tls_index_cell", "tls_callback_array",
            })
            self.assertEqual(anchors["tls_template"]["lifetime"], "thread")
            definitions = {
                row["symbol_id"]: row
                for row in payload["definitions"]
                if row["definition_kind"] == "object_anchor"
            }
            template = definitions[anchors["tls_template"]["symbol_id"]]
            callbacks = definitions[
                anchors["tls_callback_array"]["symbol_id"]
            ]
            self.assertEqual(template["anchor"]["extent"], 4)
            self.assertEqual(
                template["anchor"]["initialization"]["template_size"], 4
            )
            self.assertEqual(callbacks["anchor"]["extent"], 12)
            self.assertEqual(
                callbacks["anchor"]["initialization"]["callback_count"], 2
            )
            self.assertEqual(
                [
                    row["order"] for row in payload["roots"]
                    if row["kind"] == "tls_callback"
                ],
                [0, 1],
            )
            replay_semantic_object_v1(output)

    def test_load_config_targets_are_exact_typed_loader_relocations(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            transfers = []
            for index, rva in enumerate((0x1000, 0x1010, 0x1020)):
                row = transfer_row()
                row["id"] = f"semantic-transfer:load-config:{index}"
                row["original"] = {
                    "rva_start": rva, "rva_end": rva + 1, "size": 1,
                }
                row["outcome"] = {
                    "kind": "return",
                    "value": {"op": "reg", "name": "eax", "width": 32},
                }
                transfers.append(row)
            _, interface_path, output = self._fixture(
                root, image=pe32_load_config_image(), transfer=transfers
            )
            interface = json.loads(interface_path.read_text(encoding="utf-8"))
            payload = SemanticObjectV1.load(output).payload

            self.assertEqual(interface["status"], "complete")
            self.assertEqual(interface["load_config"]["structure_size"], 196)
            anchors = [
                row for row in payload["symbols"]
                if row.get("anchor_kind") in {
                    "load_config_directory", "load_config_table",
                }
            ]
            self.assertEqual(len(anchors), 5)
            relocations = [
                row for row in payload["relocations"]
                if row["relocation_id"].startswith("loader:load-config:")
            ]
            self.assertEqual(len(relocations), 27)
            by_kind: dict[str, list[dict[str, object]]] = {}
            for row in relocations:
                by_kind.setdefault(str(row["kind"]), []).append(row)
            self.assertEqual(len(by_kind["load_config_pointer"]), 18)
            self.assertEqual(len(by_kind["load_config_table_pointer"]), 5)
            self.assertEqual(
                by_kind["safe_seh_handler"][0]["required_view"],
                {
                    "kind": "code_capability",
                    "capability_role": "exception_handler",
                },
            )
            self.assertEqual(
                by_kind["guard_eh_continuation_target"][0]["required_view"],
                {
                    "kind": "code_capability",
                    "capability_role": "exception_continuation",
                },
            )
            self.assertTrue(all(
                row["status"] in {"resolved_local", "resolved_null"}
                for row in relocations
            ))
            self.assertFalse(any(
                row["kind"].startswith("load_config")
                for row in payload["holes"]
            ))
            replay_semantic_object_v1(output)

            corrupted = json.loads(output.read_text(encoding="utf-8"))
            target = next(
                row for row in corrupted["relocations"]
                if row["kind"] == "safe_seh_handler"
            )
            target["required_view"]["capability_role"] = "ordinary_callback"
            corrupted["semantic_object_sha256"] = canonical_sha256_v3({
                key: value for key, value in corrupted.items()
                if key != "semantic_object_sha256"
            })
            write_json(output, corrupted)
            with self.assertRaisesRegex(
                ValueError, "typed relocation inventory"
            ):
                replay_semantic_object_v1(output)

    def test_base_relocations_bind_exact_source_slots_to_semantic_targets(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _, interface_path, output = self._fixture(
                root,
                image=pe32_image_with_writable_data(
                    b"\x40\x40\xc3",
                    relocation_offsets=[0, 4],
                    relocation_page_rva=0x2000,
                    data=(
                        (0x401000).to_bytes(4, "little")
                        + (0x40003C).to_bytes(4, "little")
                    ),
                    data_size=8,
                ),
            )
            interface = json.loads(interface_path.read_text(encoding="utf-8"))
            payload = SemanticObjectV1.load(output).payload
            object_bindings = payload["effect_index"][
                "object_symbol_bindings"
            ]
            self.assertEqual(len(object_bindings), 2)
            self.assertTrue(all(
                row["target_symbol"] == f"original:object:{row['object_id']}"
                for row in object_bindings
            ))
            self.assertEqual(interface["counts"]["base_relocations"], 2)
            relocations = {
                row["target_rva"]: row for row in payload["relocations"]
                if row["kind"] == "image_base_relocation"
            }
            relocation = relocations[0x1000]
            self.assertEqual(relocation["source_rva"], 0x2000)
            self.assertEqual(relocation["offset"], 0)
            self.assertEqual(relocation["target_rva"], 0x1000)
            self.assertEqual(relocation["status"], "resolved_local")
            self.assertEqual(
                relocation["required_view"], {"kind": "code_capability"}
            )
            self.assertTrue(relocation["source_symbol"].startswith(
                "original:object:image:fixture.exe:section:1"
            ))
            self.assertTrue(relocation["target_symbol"].startswith(
                "original:function:semantic-transfer:fixture"
            ))
            header = relocations[0x3C]
            self.assertEqual(header["status"], "resolved_local")
            self.assertEqual(header["addend"], 0x3C)
            self.assertEqual(
                header["required_view"], {"kind": "object_reference"}
            )
            header_symbol = next(
                row for row in payload["symbols"]
                if row["symbol_id"] == header["target_symbol"]
            )
            self.assertEqual(header_symbol["storage_class"], "image_headers")
            self.assertFalse(any(
                row["kind"].startswith("base_relocation")
                or row["kind"] == "fragmented_base_relocation_unlinked"
                for row in payload["holes"]
            ))
            replay_semantic_object_v1(output)

    def test_unlifted_executable_relocation_source_is_loader_storage(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _, _, output = self._fixture(
                root,
                image=pe32_image_with_writable_data(
                    b"\x40\x40\xc3\x00" + (0x402000).to_bytes(4, "little"),
                    relocation_offsets=[4],
                    relocation_page_rva=0x1000,
                    data_size=4,
                ),
            )
            payload = SemanticObjectV1.load(output).payload
            relocation = next(
                row for row in payload["relocations"]
                if row["kind"] == "image_base_relocation"
            )
            self.assertEqual(relocation["source_rva"], 0x1004)
            self.assertEqual(relocation["offset"], 4)
            source = next(
                row for row in payload["symbols"]
                if row["symbol_id"] == relocation["source_symbol"]
            )
            self.assertEqual(source["kind"], "loader_storage")
            self.assertEqual(
                source["storage_class"],
                "executable_section_relocation_storage",
            )
            definition = next(
                row for row in payload["definitions"]
                if row["symbol_id"] == source["symbol_id"]
            )
            self.assertEqual(
                definition["definition_kind"], "loader_section_storage"
            )
            self.assertTrue(definition["storage"]["relocation_only"])
            self.assertFalse(any(
                row["kind"] == "base_relocation_source_unresolved"
                for row in payload["holes"]
            ))
            replay_semantic_object_v1(output)

    def test_resource_tree_and_content_are_typed_semantic_storage(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _, interface_path, output = self._fixture(
                root, image=pe32_resource_image(b"semantic-leaf\0")
            )
            interface = json.loads(interface_path.read_text(encoding="utf-8"))
            payload = SemanticObjectV1.load(output).payload
            self.assertEqual(interface["counts"]["resource_directories"], 3)
            anchors = {
                row["anchor_kind"]: []
                for row in payload["symbols"]
                if row.get("anchor_kind", "").startswith("resource_")
            }
            for row in payload["symbols"]:
                if row.get("anchor_kind", "").startswith("resource_"):
                    anchors[row["anchor_kind"]].append(row)
            self.assertEqual(len(anchors["resource_directory"]), 3)
            self.assertEqual(len(anchors["resource_name"]), 1)
            self.assertEqual(len(anchors["resource_data_entry"]), 1)
            self.assertEqual(len(anchors["resource_content"]), 1)
            resource_relocations = [
                row for row in payload["relocations"]
                if row["kind"].startswith("resource_")
            ]
            self.assertEqual(len(resource_relocations), 5)
            self.assertEqual(
                {row["kind"] for row in resource_relocations},
                {
                    "resource_name_reference",
                    "resource_directory_reference",
                    "resource_data_entry_reference",
                    "resource_content_reference",
                },
            )
            self.assertTrue(all(
                row["status"] == "resolved_local"
                for row in resource_relocations
            ))
            content = anchors["resource_content"][0]
            definition = next(
                row for row in payload["definitions"]
                if row["symbol_id"] == content["symbol_id"]
            )
            self.assertEqual(
                definition["anchor"]["initialization"]["content_sha256"],
                interface["resources"]["data_entries"][0]["content_sha256"],
            )
            replay_semantic_object_v1(output)



if __name__ == "__main__":
    unittest.main()
