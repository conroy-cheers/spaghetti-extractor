from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest
from types import SimpleNamespace

from spaghetti_extractor.artifacts.artifact_set import canonical_sha256_v3
from spaghetti_extractor.boundary import BoundarySchemaV1, TargetDataLayoutV1
from spaghetti_extractor.calls.frame import PhysicalCallFrameV3
from spaghetti_extractor.calls.dialects.ia32 import IA32DialectCheckerV1
from spaghetti_extractor.external.environment import (
    ExternalEnvironmentError,
    ResolvedExternalEnvironmentV1,
    _canonical_runtime_support_requirements,
    lower_machine_import_boundary_v1,
    write_external_environment_intent,
    write_resolved_external_environment,
)
from spaghetti_extractor.external.formats import (
    EXTERNAL_ENVIRONMENT_ANALYSIS_PROJECTION_FORMAT,
    EXTERNAL_ENVIRONMENT_INTENT_FORMAT,
    RESOLVED_EXTERNAL_ENVIRONMENT_FORMAT,
)
from spaghetti_extractor.external.machine_import_profiles import (
    load_machine_import_profile_set,
)
from spaghetti_extractor.external.machine_callback_boundary import (
    MachineCallbackBoundaryError,
    machine_callback_boundary_catalog_v1,
)
from spaghetti_extractor.semantic_link.capabilities import (
    semantic_export_capabilities_v1,
)
from spaghetti_extractor.util import write_json
from spaghetti_extractor.testkit.transfer_fixture import (
    as_machine_ir_unit,
    transfer_row,
    write_fixture_transfer_plan,
)


TESTKIT = {
    "resources": (
        "profiles/pe32-msvcrt-lockstep-v1.json",
        "profiles/pe32-msvcrt-machine-runtime-v1.json",
        "profiles/pe32-win32-console-launch-assumptions-v1.json",
        "profiles/pe32-win32-windowing-runtime-v1.json",
        "targets/dxball/intent/boundaries.json",
    )
}


def _write_checked_schema_package(spec_path: Path, out: Path) -> None:
    spec = json.loads(spec_path.read_text(encoding="utf-8"))
    schema = BoundarySchemaV1.create(
        schema_id=spec["schema_id"],
        types=spec["types"],
        signatures=spec["signatures"],
    )
    layout_row = spec["layout"]
    layout = TargetDataLayoutV1.create(
        target=layout_row["target"],
        abi_dialect=layout_row["abi_dialect"],
        byte_order=layout_row["byte_order"],
        pointer_width_bits=layout_row["pointer_width_bits"],
        packing=layout_row["packing"],
        schema=schema,
        layouts=layout_row["layouts"],
    )
    checker = IA32DialectCheckerV1(layout.abi_dialect)
    out.mkdir(parents=True)
    write_json(out / "boundary-schema.json", schema.to_payload())
    write_json(out / "target-data-layout.json", layout.to_payload())
    frame_ids = []
    for row in spec["frames"]:
        frame = checker.lower_boundary(
            subject=row["subject"],
            schema=schema,
            layout=layout,
            signature_id=row["signature_id"],
            transfer_kind=row["transfer_kind"],
        )
        write_json(
            out / f"physical-call-frame-{row['id']}.json",
            frame.to_payload(),
        )
        frame_ids.append(frame.frame_id)
    write_json(out / "boundary-status.json", {
        "format": "spaghetti-extractor-boundary-check-result-v1",
        "status": "complete",
        "schema_id": schema.schema_id,
        "schema_sha256": schema.schema_sha256,
        "layout_sha256": layout.layout_sha256,
        "frames": frame_ids,
    })


class ExternalEnvironmentTests(unittest.TestCase):
    def test_text_api_frames_remain_abi_only_until_effects_are_qualified(self) -> None:
        from spaghetti_extractor.candidate.runtime_canonical_common import _checked_contract
        from spaghetti_extractor.candidate.runtime_canonical_errors import CanonicalRuntimeError

        root = Path(__file__).parents[3]
        profiles = load_machine_import_profile_set([
            root / "profiles/pe32-kernel32-runtime-v1.json",
            root / "profiles/pe32-win32-windowing-runtime-v1.json",
        ])
        expected = {"lstrlenA": 1, "lstrlenW": 1, "SetWindowTextA": 2, "SetWindowTextW": 2}
        selected = {str(item.identity.value): item for item in profiles.contracts if item.identity.value in expected}
        self.assertEqual(set(selected), set(expected))
        for symbol, words in expected.items():
            with self.subTest(symbol=symbol):
                contract = selected[symbol]
                boundary = lower_machine_import_boundary_v1(contract, abi_dialect="pe32-i386-ms-v1")
                frame = boundary["physical_call_frame_v3"]["transport"]
                self.assertEqual(frame["calling_convention"], "stdcall")
                self.assertEqual([row["fragments"][0]["location"]["stack_offset_bytes"] for row in frame["arguments"]],
                                 list(range(4, 4 + words * 4, 4)))
                self.assertEqual(frame["stack"]["cleanup_bytes"], words * 4)
                for key in ("memory_effect", "world_effect", "callback_effect", "result_register_relations"):
                    self.assertNotIn(key, contract.contract)
                with self.assertRaisesRegex(CanonicalRuntimeError, "ABI-only declaration"):
                    _checked_contract(
                        row={"identity": contract.contract["import"], "boundary": boundary, "contract": {
                            "profile_id": contract.profile_id, "profile_sha256": contract.profile_sha256,
                            "entry_key": contract.entry_key, "entry_index": contract.entry_index,
                            "payload": contract.contract,
                        }},
                        call=SimpleNamespace(argument_nodes=(), instruction_rva=0x1000),
                        escape_index={},
                    )

    def test_external_service_profiles_lower_to_exact_outcomes_and_views(
        self,
    ) -> None:
        contracts = load_machine_import_profile_set([
            Path(__file__).parents[3]
            / "profiles/pe32-kernel32-runtime-v1.json"
        ]).by_identity()
        by_symbol = {
            str(identity.value): contract
            for identity, contract in contracts.items()
            if identity.dll == "kernel32.dll" and identity.kind == "symbol"
        }
        unwind = lower_machine_import_boundary_v1(
            by_symbol["RtlUnwind"], abi_dialect="pe32-i386-ms-v1"
        )
        self.assertEqual(
            unwind["physical_call_frame_v3"]["transport"]["outcomes"],
            ["nonlocal"],
        )
        self.assertEqual(
            unwind["external_service_protocol"]["kind"],
            "nonlocal_unwind",
        )
        exception_filter = lower_machine_import_boundary_v1(
            by_symbol["UnhandledExceptionFilter"],
            abi_dialect="pe32-i386-ms-v1",
        )
        self.assertEqual(
            exception_filter["physical_call_frame_v3"]["transport"][
                "outcomes"
            ],
            ["normal"],
        )
        self.assertEqual(
            exception_filter["memory_views"][0]["size"],
            {"kind": "fixed", "bytes": 8},
        )
        self.assertEqual(
            exception_filter["external_service_protocol"]["object_view"][
                "referent_access"
            ],
            "read_write",
        )

    def test_runtime_support_can_be_derived_from_incomplete_transfer_plan(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            row = transfer_row()
            row["status"] = "incomplete"
            machine_ir = root / "machine-ir.jsonl"
            machine_ir.write_text(
                json.dumps(as_machine_ir_unit(row), sort_keys=True) + "\n",
                encoding="utf-8",
            )
            transfer_plan = write_fixture_transfer_plan(machine_ir)
            payload = json.loads(transfer_plan.read_text(encoding="utf-8"))
            self.assertEqual(payload["status"], "incomplete")
            self.assertEqual(
                _canonical_runtime_support_requirements({
                    "executable_transfer_plan": transfer_plan,
                }),
                (),
            )

    def test_machine_callback_catalog_ignores_unmatched_imports(self) -> None:
        self.assertIsNone(machine_callback_boundary_catalog_v1(
            {
                "identity": {
                    "dll": "kernel32.dll",
                    "symbol": "UnhandledImport",
                    "ordinal": None,
                },
            },
            abi_dialect="pe32-i686-mingw32",
        ))
        with self.assertRaisesRegex(
            MachineCallbackBoundaryError, "contract must be an object"
        ):
            machine_callback_boundary_catalog_v1(
                {"contract": [], "identity": {}},
                abi_dialect="pe32-i686-mingw32",
            )

    @classmethod
    def setUpClass(cls) -> None:
        cls.root = Path(__file__).parents[3]
        cls.runtime_profile = (
            cls.root / "profiles/pe32-msvcrt-machine-runtime-v1.json"
        )
        cls.launch_profile = (
            cls.root
            / "profiles/pe32-win32-console-launch-assumptions-v1.json"
        )

    def test_multiframe_schema_binds_existing_import_and_callback_authority(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            profile = (
                self.root / "profiles/pe32-win32-windowing-runtime-v1.json"
            )
            boundary_spec = self.root / "targets/dxball/intent/boundaries.json"
            subject = "service:window-class-boundary"
            write_external_environment_intent(
                environment_id="fixture",
                runtime_profile_packs=[profile],
                interface_profile_packs=[],
                launch_profile=self.launch_profile,
                boundary_intents={subject: boundary_spec},
                process_termination=None,
                target_abi="pe32-i686-msvc",
                target_data_layout="pe32-ilp32-v1",
                out=root / "intent",
            )
            module = {
                "format": "spaghetti-extractor-pe32-module-interface-v2",
                "status": "complete",
                "identity": {"pe_sha256": "0" * 64},
                "imports": [{
                    "dll": "user32.dll",
                    "symbol": "RegisterClassA",
                    "ordinal": None,
                    "descriptor_index": 0,
                    "cell_index": 0,
                    "iat_rva": 4096,
                }],
                "delay_imports": [],
                "blockers": [],
            }
            module["interface_sha256"] = canonical_sha256_v3(module)
            module_path = root / "module-interface.json"
            write_json(module_path, module)
            machine_ir = root / "machine-ir.jsonl"
            machine_ir.write_text(
                json.dumps(as_machine_ir_unit(transfer_row()), sort_keys=True)
                + "\n",
                encoding="utf-8",
            )
            transfer_plan = write_fixture_transfer_plan(machine_ir)
            package = root / "boundary-package"
            _write_checked_schema_package(boundary_spec, package)
            resolved = write_resolved_external_environment(
                intent_path=root / "intent/external-environment-intent.json",
                module_interface_path=module_path,
                runtime_profile_packs=[profile],
                interface_profile_packs=[],
                boundary_intent_paths={subject: boundary_spec},
                boundary_packages={subject: package},
                static_authority_paths={
                    "executable_transfer_plan": transfer_plan,
                },
                out=root / "resolved",
            )

        self.assertEqual(resolved["status"], "complete")
        self.assertEqual(resolved["blockers"], [])
        catalog = next(
            row for row in resolved["canonical_boundaries"]
            if row["subject"] == subject
        )
        frames = {
            row["frame_name"]: row for row in catalog["physical_frames"]
        }
        self.assertEqual(set(frames), {"register-class", "wndproc"})
        self.assertEqual(
            frames["register-class"]["machine_bindings"][0]["kind"],
            "machine_import_contract",
        )
        self.assertEqual(
            frames["wndproc"]["machine_bindings"][0]["protocol_id"],
            "win32-window-procedure-ansi",
        )
        self.assertEqual(catalog["callback_links"], [{
            "protocol_id": "win32-window-procedure-ansi",
            "protocol_sha256": (
                frames["wndproc"]["machine_bindings"][0][
                    "protocol_sha256"
                ]
            ),
            "registering_frame_name": "register-class",
            "callback_frame_name": "wndproc",
            "source": {
                "kind": "argument_pointee", "argument": 0,
                "offset": 4, "sentinels": [],
            },
            "instance": {
                "kind": "provider_resource", "argument": 0,
                "callback_argument": 0,
            },
            "lifetime": {
                "kind": "until_resource_event_or_process_exit",
                "end_event": "user32.dll!UnregisterClassA",
            },
            "delivery": {
                "timing": "nested_or_deferred",
                "thread": "external_concurrent",
            },
        }])
        stale = json.loads(json.dumps(resolved))
        stale_catalog = next(
            row for row in stale["canonical_boundaries"]
            if row["subject"] == subject
        )
        stale_catalog["physical_frames"][0]["machine_bindings"][0][
            "profile_id"
        ] = "fabricated-profile"
        stale["resolved_environment_sha256"] = canonical_sha256_v3({
            key: value for key, value in stale.items()
            if key != "resolved_environment_sha256"
        })
        with self.assertRaisesRegex(
            ExternalEnvironmentError, "machine binding differs"
        ):
            ResolvedExternalEnvironmentV1.parse(
                stale, module_interface=module
            )
        stale_link = json.loads(json.dumps(resolved))
        stale_catalog = next(
            row for row in stale_link["canonical_boundaries"]
            if row["subject"] == subject
        )
        stale_catalog["callback_links"][0][
            "registering_frame_name"
        ] = "fabricated-registering-frame"
        stale_link["resolved_environment_sha256"] = canonical_sha256_v3({
            key: value for key, value in stale_link.items()
            if key != "resolved_environment_sha256"
        })
        with self.assertRaisesRegex(
            ExternalEnvironmentError, "callback links differ"
        ):
            ResolvedExternalEnvironmentV1.parse(
                stale_link, module_interface=module
            )

    def test_incomplete_callback_relationship_is_a_stable_blocker(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            profile = (
                self.root / "profiles/pe32-win32-windowing-runtime-v1.json"
            )
            spec = json.loads((
                self.root / "targets/dxball/intent/boundaries.json"
            ).read_text(encoding="utf-8"))
            registering_frame = next(
                row for row in spec["frames"]
                if row["id"] == "register-class"
            )
            registering_frame["subject"]["id"] = (
                "user32.dll.RegisterClassW"
            )
            boundary_spec = root / "boundaries.json"
            write_json(boundary_spec, spec)
            subject = "service:window-class-boundary"
            write_external_environment_intent(
                environment_id="fixture",
                runtime_profile_packs=[profile],
                interface_profile_packs=[],
                launch_profile=self.launch_profile,
                boundary_intents={subject: boundary_spec},
                process_termination=None,
                target_abi="pe32-i686-msvc",
                target_data_layout="pe32-ilp32-v1",
                out=root / "intent",
            )
            module = {
                "format": "spaghetti-extractor-pe32-module-interface-v2",
                "status": "complete",
                "identity": {"pe_sha256": "0" * 64},
                "imports": [{
                    "dll": "user32.dll",
                    "symbol": "RegisterClassA",
                    "ordinal": None,
                    "descriptor_index": 0,
                    "cell_index": 0,
                    "iat_rva": 4096,
                }],
                "delay_imports": [],
                "blockers": [],
            }
            module["interface_sha256"] = canonical_sha256_v3(module)
            module_path = root / "module-interface.json"
            write_json(module_path, module)
            machine_ir = root / "machine-ir.jsonl"
            machine_ir.write_text(
                json.dumps(as_machine_ir_unit(transfer_row()), sort_keys=True)
                + "\n",
                encoding="utf-8",
            )
            transfer_plan = write_fixture_transfer_plan(machine_ir)
            package = root / "boundary-package"
            _write_checked_schema_package(boundary_spec, package)
            resolved = write_resolved_external_environment(
                intent_path=root / "intent/external-environment-intent.json",
                module_interface_path=module_path,
                runtime_profile_packs=[profile],
                interface_profile_packs=[],
                boundary_intent_paths={subject: boundary_spec},
                boundary_packages={subject: package},
                static_authority_paths={
                    "executable_transfer_plan": transfer_plan,
                },
                out=root / "resolved",
            )

        self.assertEqual(resolved["status"], "incomplete")
        self.assertIn(
            "boundary_callback_relationship_unresolved",
            {row["category"] for row in resolved["blockers"]},
        )
        catalog = next(
            row for row in resolved["canonical_boundaries"]
            if row["subject"] == subject
        )
        self.assertEqual(catalog["callback_links"], [])
        self.assertEqual(
            ResolvedExternalEnvironmentV1.parse(
                resolved, module_interface=module
            ).identity,
            resolved["resolved_environment_sha256"],
        )

    def test_intent_projection_and_resolution_bind_exact_inputs(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            intent, projection = write_external_environment_intent(
                environment_id="fixture",
                runtime_profile_packs=[self.runtime_profile],
                interface_profile_packs=[],
                launch_profile=self.launch_profile,
                boundary_intents={},
                process_termination=None,
                target_abi="pe32-i686-mingw32",
                target_data_layout="pe32-ilp32-v1",
                out=root / "intent",
            )
            selected = next(
                contract for contract in load_machine_import_profile_set(
                    [self.runtime_profile]
                ).contracts
                if contract.identity.value == "__getmainargs"
            )
            identity = {
                "dll": selected.identity.dll,
                "symbol": (
                    selected.identity.value
                    if selected.identity.kind == "symbol"
                    else None
                ),
                "ordinal": (
                    selected.identity.value
                    if selected.identity.kind == "ordinal"
                    else None
                ),
            }
            module = {
                "format": "spaghetti-extractor-pe32-module-interface-v2",
                "status": "complete",
                "identity": {"pe_sha256": "0" * 64},
                "imports": [
                    {
                        **identity,
                        "descriptor_index": 0,
                        "cell_index": 0,
                        "iat_rva": 4096,
                    }
                ],
                "blockers": [],
            }
            module["interface_sha256"] = canonical_sha256_v3(module)
            module_path = root / "module-interface.json"
            write_json(module_path, module)
            machine_ir = root / "machine-ir.jsonl"
            machine_ir.write_text(
                json.dumps(as_machine_ir_unit(transfer_row()), sort_keys=True)
                + "\n",
                encoding="utf-8",
            )
            transfer_plan = write_fixture_transfer_plan(machine_ir)
            resolved = write_resolved_external_environment(
                intent_path=root / "intent/external-environment-intent.json",
                module_interface_path=module_path,
                runtime_profile_packs=[self.runtime_profile],
                interface_profile_packs=[],
                boundary_intent_paths={},
                boundary_packages={},
                static_authority_paths={
                    "executable_transfer_plan": transfer_plan,
                },
                out=root / "resolved",
            )
        self.assertEqual(intent["format"], EXTERNAL_ENVIRONMENT_INTENT_FORMAT)
        self.assertEqual(
            projection["format"],
            EXTERNAL_ENVIRONMENT_ANALYSIS_PROJECTION_FORMAT,
        )
        self.assertEqual(projection["authority"], "none")
        self.assertEqual(resolved["format"], RESOLVED_EXTERNAL_ENVIRONMENT_FORMAT)
        self.assertEqual(resolved["status"], "complete")
        self.assertEqual(
            resolved["launch_policy"]["payload"],
            json.loads(self.launch_profile.read_text(encoding="utf-8")),
        )
        self.assertEqual(
            resolved["launch_policy"]["payload_sha256"],
            canonical_sha256_v3(resolved["launch_policy"]["payload"]),
        )
        self.assertEqual(
            ResolvedExternalEnvironmentV1.parse(
                resolved, module_interface=module
            ).identity,
            resolved["resolved_environment_sha256"],
        )
        stale = dict(resolved)
        stale["resolved_environment_sha256"] = "0" * 64
        with self.assertRaisesRegex(ExternalEnvironmentError, "self hash"):
            ResolvedExternalEnvironmentV1.parse(stale)
        stale_launch = json.loads(json.dumps(resolved))
        stale_launch["launch_policy"]["payload_sha256"] = "0" * 64
        stale_launch["resolved_environment_sha256"] = canonical_sha256_v3({
            key: value
            for key, value in stale_launch.items()
            if key != "resolved_environment_sha256"
        })
        with self.assertRaisesRegex(
            ExternalEnvironmentError, "launch-policy payload hash"
        ):
            ResolvedExternalEnvironmentV1.parse(stale_launch)
        self.assertEqual(len(resolved["original_semantic_imports"]), 1)
        self.assertEqual(resolved["generated_runtime_support_imports"], [])
        boundary = resolved["machine_import_contracts"][0]["boundary"]
        schema = BoundarySchemaV1.parse(boundary["schema"])
        layout = TargetDataLayoutV1.parse(
            boundary["target_data_layout"], schema=schema
        )
        frame = PhysicalCallFrameV3.parse(
            boundary["physical_call_frame_v3"], schema=schema, layout=layout
        )
        self.assertEqual(frame.transport.transfer_kind, "import")
        self.assertEqual(len(boundary["out_pointer_relations"]), 2)
        self.assertEqual(
            len(frame.transport.arguments),
            selected.argument_words
            if selected.argument_words is not None
            else selected.contract["minimum_argument_words"],
        )
        self.assertEqual(len(resolved["canonical_boundaries"]), 2)
        ordinary_catalog = next(
            row for row in resolved["canonical_boundaries"]
            if "ordinary" in row["roles"]
        )
        self.assertEqual(
            ordinary_catalog["kind"],
            "checked_machine_import",
        )
        self.assertEqual(
            ordinary_catalog["artifacts"]
            ["boundary_schema"]["sha256"],
            schema.schema_sha256,
        )
        dynamic_catalog = next(
            row for row in resolved["canonical_boundaries"]
            if "dynamic_export" in row["roles"]
        )
        self.assertEqual(dynamic_catalog["kind"], "checked_machine_import")
        dynamic_boundary = next(
            row for row in load_machine_import_profile_set(
                [self.runtime_profile]
            ).contracts
            if "dynamic_export" in row.contract
        )
        self.assertEqual(
            dynamic_catalog["identity"]["symbol"],
            dynamic_boundary.identity.value,
        )

    def test_runtime_profile_callback_becomes_checked_boundary(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            write_external_environment_intent(
                environment_id="callback-fixture",
                runtime_profile_packs=[self.runtime_profile],
                interface_profile_packs=[],
                launch_profile=self.launch_profile,
                boundary_intents={},
                process_termination=None,
                target_abi="pe32-i686-mingw32",
                target_data_layout="pe32-ilp32-v1",
                out=root / "intent",
            )
            module = {
                "format": "spaghetti-extractor-pe32-module-interface-v2",
                "status": "complete",
                "identity": {"pe_sha256": "0" * 64},
                "imports": [{
                    "dll": "msvcrt.dll", "symbol": "atexit", "ordinal": None,
                    "descriptor_index": 0, "cell_index": 0, "iat_rva": 4096,
                }],
                "delay_imports": [],
                "blockers": [],
            }
            module["interface_sha256"] = canonical_sha256_v3(module)
            module_path = root / "module-interface.json"
            write_json(module_path, module)
            machine_ir = root / "machine-ir.jsonl"
            machine_ir.write_text(
                json.dumps(as_machine_ir_unit(transfer_row()), sort_keys=True)
                + "\n",
                encoding="utf-8",
            )
            transfer_plan = write_fixture_transfer_plan(machine_ir)
            resolved = write_resolved_external_environment(
                intent_path=root / "intent/external-environment-intent.json",
                module_interface_path=module_path,
                runtime_profile_packs=[self.runtime_profile],
                interface_profile_packs=[],
                boundary_intent_paths={},
                boundary_packages={},
                static_authority_paths={
                    "executable_transfer_plan": transfer_plan,
                },
                out=root / "resolved",
            )

        callback = next(
            row for row in resolved["canonical_boundaries"]
            if row["kind"] == "checked_machine_callback"
        )
        self.assertEqual(callback["subject"], "callback:msvcrt-atexit-handler")
        self.assertEqual(
            callback["callback_protocol"]["lifetime"]["kind"],
            "one_shot_or_process_exit",
        )
        artifacts = callback["artifacts"]
        schema = BoundarySchemaV1.parse(
            artifacts["boundary_schema"]["payload"]
        )
        layout = TargetDataLayoutV1.parse(
            artifacts["target_data_layout"]["payload"], schema=schema
        )
        frame = PhysicalCallFrameV3.parse(
            artifacts["physical_call_frame_v3"]["payload"],
            schema=schema,
            layout=layout,
        )
        self.assertEqual(frame.transport.subject.kind, "callback")
        self.assertEqual(frame.transport.calling_convention, "cdecl")
        self.assertEqual(frame.transport.arguments, ())
        self.assertEqual(frame.transport.stack.cleanup_bytes, 0)

        stale = json.loads(json.dumps(resolved))
        stale_callback = next(
            row for row in stale["canonical_boundaries"]
            if row["kind"] == "checked_machine_callback"
        )
        stale_callback["callback_protocol"]["delivery"]["thread"] = (
            "same_thread"
        )
        stale["resolved_environment_sha256"] = canonical_sha256_v3({
            key: value for key, value in stale.items()
            if key != "resolved_environment_sha256"
        })
        with self.assertRaisesRegex(
            ExternalEnvironmentError, "callback catalog differs"
        ):
            ResolvedExternalEnvironmentV1.parse(
                stale, module_interface=module
            )

    def test_module_exports_reuse_profile_contracts_by_eat_target(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            write_external_environment_intent(
                environment_id="module-export-fixture",
                runtime_profile_packs=[self.runtime_profile],
                interface_profile_packs=[],
                launch_profile=self.launch_profile,
                boundary_intents={},
                process_termination=None,
                target_abi="pe32-i686-mingw32",
                target_data_layout="pe32-ilp32-v1",
                out=root / "intent",
            )
            module = {
                "format": "spaghetti-extractor-pe32-module-interface-v2",
                "status": "complete",
                "image_id": "msvcrt-provider",
                "identity": {"pe_sha256": "0" * 64},
                "imports": [],
                "delay_imports": [],
                "export_directory": {
                    "dll_name": "MSVCRT.dll",
                    "slots": [{
                        "kind": "code",
                        "rva": 8192,
                        "ordinal": 1,
                        "names": ["atexit", "atexit_alias"],
                    }],
                },
                "blockers": [],
            }
            module["interface_sha256"] = canonical_sha256_v3(module)
            module_path = root / "module-interface.json"
            write_json(module_path, module)
            machine_ir = root / "machine-ir.jsonl"
            machine_ir.write_text(
                json.dumps(as_machine_ir_unit(transfer_row()), sort_keys=True)
                + "\n",
                encoding="utf-8",
            )
            transfer_plan = write_fixture_transfer_plan(machine_ir)
            resolved = write_resolved_external_environment(
                intent_path=root / "intent/external-environment-intent.json",
                module_interface_path=module_path,
                runtime_profile_packs=[self.runtime_profile],
                interface_profile_packs=[],
                boundary_intent_paths={},
                boundary_packages={},
                static_authority_paths={
                    "executable_transfer_plan": transfer_plan,
                },
                out=root / "resolved",
            )

        self.assertEqual(resolved["status"], "complete")
        catalog = next(
            row for row in resolved["canonical_boundaries"]
            if row["kind"] == "checked_module_export"
        )
        self.assertEqual(catalog["target_rva"], 8192)
        self.assertEqual(catalog["subject"], "export:atexit")
        self.assertEqual(
            catalog["aliases"],
            [
                {"name": "atexit", "ordinal": 1},
                {"name": "atexit_alias", "ordinal": 1},
            ],
        )
        frame = catalog["artifacts"]["physical_call_frame_v3"]["payload"]
        self.assertEqual(frame["transport"]["transfer_kind"], "export")
        self.assertEqual(
            frame["transport"]["subject"],
            {
                "kind": "export",
                "id": "atexit",
                "image_selector": "msvcrt-provider",
            },
        )
        capabilities, blockers = semantic_export_capabilities_v1(
            module_interface=module,
            resolved_environment=resolved,
            symbols=[{
                "kind": "function",
                "reachable": True,
                "original_rva": 8192,
                "symbol_id": "semantic-symbol:atexit",
                "root_ids": ["export:name:atexit"],
            }],
        )
        self.assertEqual(blockers, [])
        self.assertEqual(len(capabilities), 1)
        self.assertEqual(capabilities[0]["exports"], catalog["aliases"])

        stale = json.loads(json.dumps(resolved))
        stale_catalog = next(
            row for row in stale["canonical_boundaries"]
            if row["kind"] == "checked_module_export"
        )
        stale_catalog["physical_abi_sha256"] = "0" * 64
        stale["resolved_environment_sha256"] = canonical_sha256_v3({
            key: value for key, value in stale.items()
            if key != "resolved_environment_sha256"
        })
        with self.assertRaisesRegex(
            ExternalEnvironmentError, "protocol identity is stale"
        ):
            ResolvedExternalEnvironmentV1.parse(
                stale, module_interface=module
            )

    def test_canonical_empty_module_export_directory_is_absent(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            write_external_environment_intent(
                environment_id="empty-module-export-fixture",
                runtime_profile_packs=[self.runtime_profile],
                interface_profile_packs=[],
                launch_profile=self.launch_profile,
                boundary_intents={},
                process_termination=None,
                target_abi="pe32-i686-mingw32",
                target_data_layout="pe32-ilp32-v1",
                out=root / "intent",
            )
            module = {
                "format": "spaghetti-extractor-pe32-module-interface-v2",
                "status": "complete",
                "image_id": "empty-export-executable",
                "identity": {"pe_sha256": "0" * 64},
                "imports": [],
                "delay_imports": [],
                "export_directory": {
                    "dll_name": None,
                    "metadata": None,
                    "ordinal_base": 0,
                    "slot_count": 0,
                    "holes": [],
                    "slots": [],
                    "name_table": [],
                },
                "blockers": [],
            }
            module["interface_sha256"] = canonical_sha256_v3(module)
            module_path = root / "module-interface.json"
            write_json(module_path, module)
            machine_ir = root / "machine-ir.jsonl"
            machine_ir.write_text(
                json.dumps(as_machine_ir_unit(transfer_row()), sort_keys=True)
                + "\n",
                encoding="utf-8",
            )
            resolved = write_resolved_external_environment(
                intent_path=root / "intent/external-environment-intent.json",
                module_interface_path=module_path,
                runtime_profile_packs=[self.runtime_profile],
                interface_profile_packs=[],
                boundary_intent_paths={},
                boundary_packages={},
                static_authority_paths={
                    "executable_transfer_plan": write_fixture_transfer_plan(
                        machine_ir
                    ),
                },
                out=root / "resolved",
            )

        self.assertEqual(resolved["status"], "complete")
        self.assertFalse(any(
            row["kind"] == "checked_module_export"
            for row in resolved["canonical_boundaries"]
        ))

    def test_module_export_alias_contract_abi_conflict_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            profile = root / "provider-profile.json"
            write_json(profile, {
                "format": "spaghetti-extractor-static-machine-import-profile-v2",
                "id": "provider-profile",
                "includes": [],
                "machine_import_signatures": [
                    {
                        "import": {
                            "dll": "provider.dll", "symbol": "entry",
                        },
                        "abi_template": "pe32-cdecl-v1",
                        "arity": {"kind": "fixed", "words": 1},
                        "result_register_relations": [],
                        "memory_effect": "none",
                        "memory_footprints": [],
                        "world_effect": "none",
                    },
                    {
                        "import": {"dll": "provider.dll", "ordinal": 7},
                        "abi_template": "pe32-stdcall-v1",
                        "arity": {"kind": "fixed", "words": 2},
                        "result_register_relations": [],
                        "memory_effect": "none",
                        "memory_footprints": [],
                        "world_effect": "none",
                    },
                ],
            })
            write_external_environment_intent(
                environment_id="module-export-conflict",
                runtime_profile_packs=[profile],
                interface_profile_packs=[],
                launch_profile=self.launch_profile,
                boundary_intents={},
                process_termination=None,
                target_abi="pe32-i686-mingw32",
                target_data_layout="pe32-ilp32-v1",
                out=root / "intent",
            )
            module = {
                "format": "spaghetti-extractor-pe32-module-interface-v2",
                "status": "complete",
                "image_id": "provider",
                "identity": {"pe_sha256": "0" * 64},
                "imports": [],
                "delay_imports": [],
                "export_directory": {
                    "dll_name": "provider.dll",
                    "slots": [{
                        "kind": "code", "rva": 8192, "ordinal": 7,
                        "names": ["entry"],
                    }],
                },
                "blockers": [],
            }
            module["interface_sha256"] = canonical_sha256_v3(module)
            module_path = root / "module-interface.json"
            write_json(module_path, module)
            machine_ir = root / "machine-ir.jsonl"
            machine_ir.write_text(
                json.dumps(as_machine_ir_unit(transfer_row()), sort_keys=True)
                + "\n",
                encoding="utf-8",
            )
            resolved = write_resolved_external_environment(
                intent_path=root / "intent/external-environment-intent.json",
                module_interface_path=module_path,
                runtime_profile_packs=[profile],
                interface_profile_packs=[],
                boundary_intent_paths={},
                boundary_packages={},
                static_authority_paths={
                    "executable_transfer_plan": write_fixture_transfer_plan(
                        machine_ir
                    ),
                },
                out=root / "resolved",
            )

        self.assertEqual(resolved["status"], "incomplete")
        self.assertIn(
            "module_export_alias_abi_conflict",
            {row["category"] for row in resolved["blockers"]},
        )
        self.assertFalse(any(
            row["kind"] == "checked_module_export"
            for row in resolved["canonical_boundaries"]
        ))






if __name__ == "__main__":
    unittest.main()
