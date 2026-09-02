from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from tests.pe_fixtures import pe32_data_export_image, pe32_export_image
from tests.unit.candidate.native_ingress_support import (
    machine_ir_transfer as _machine_ir_transfer,
    native_ingress_plan as _native_ingress_plan,
)

from spaghetti_extractor.artifacts.artifact_set import canonical_sha256_v3
from spaghetti_extractor.candidate.native_ingress_plan import (
    _write_native_ingress_plan_v2 as write_native_ingress_plan,
    write_native_ingress_plan_from_linked_module,
    write_pe32_machine_object_authority_v2,
)
from spaghetti_extractor.candidate.native_ingress_derivation import (
    _derive_ingress_authorities,
    _reviewed_loader_call,
)
from spaghetti_extractor.candidate.native_ingress_errors import NativeIngressError
from spaghetti_extractor.candidate.native_ingress_runtime import (
    _capability_lifetime,
    _exception_record_projection_masks_v1,
    _seh_projection_masks,
    boundary_lifecycle_transducer_v1,
    compact_callback_runtime_v1,
    physical_frame_transducer_v1,
    render_native_ingress_assembly,
    render_native_ingress_header,
    render_native_ingress_source,
)
from spaghetti_extractor.candidate.outcomes import (
    CheckedSEHProtocolV1,
)
from spaghetti_extractor.candidate.project import write_pe32_module_interface
from spaghetti_extractor.calls.frame import PhysicalCallFrameV2
from spaghetti_extractor.errors import ToolkitInputError
from spaghetti_extractor.external.resolved import bind_launch_policy_v1
from spaghetti_extractor.pe32.behavioral_roots import generate_behavioral_roots
from spaghetti_extractor.roundtrip_fuzz.image_io import write_spx_load_image_contract
from spaghetti_extractor.testkit.transfer_fixture import write_fixture_transfer_plan
from spaghetti_extractor.transfer.formats import MODULE_EXECUTION_CLOSURE_FORMAT
from spaghetti_extractor.util import sha256_file, write_json


def _checked_export_package(root: Path) -> Path:
    checked = _reviewed_loader_call("dll_entry", "fixture")
    original = checked["physical_frame"]["transport"]
    transport = PhysicalCallFrameV2.create(
        subject={"kind": "export", "id": "Ping", "image_selector": "fixture"},
        transfer_kind="export",
        target=original["target"],
        abi_dialect=original["abi_dialect"],
        calling_convention=original["calling_convention"],
        arguments=original["arguments"],
        results=original["results"],
        stack=original["stack"],
        preserved_state=original["preserved_state"],
        clobbered_state=original["clobbered_state"],
        outcomes=original["outcomes"],
    )
    frame = {**checked["physical_frame"], "transport": transport.to_payload()}
    frame.pop("id")
    frame["id"] = f"physical-call-frame-v3:{canonical_sha256_v3(frame)}"
    protocol = {**checked["call_protocol"], "physical_frame_id": frame["id"]}
    protocol.pop("id")
    protocol["id"] = f"checked-call-protocol-v2:{canonical_sha256_v3(protocol)}"
    package = root / "checked-export"
    package.mkdir()
    write_json(package / "call-status.json", {
        "status": "complete",
        "subject": {"kind": "export", "id": "Ping", "image_selector": "fixture"},
    })
    write_json(package / "checked-call-protocol.json", protocol)
    write_json(package / "physical-call-frame-v3.json", frame)
    write_json(
        package / "boundary-lifecycle.json",
        checked["lifecycle_protocol"],
    )
    write_json(
        package / "boundary-lifecycle-receipt.json",
        checked["lifecycle_receipt"],
    )
    return package


def _checked_callback_package(root: Path, protocol_id: str) -> Path:
    checked = _reviewed_loader_call("dll_entry", "fixture")
    original = checked["physical_frame"]["transport"]
    transport = PhysicalCallFrameV2.create(
        subject={"kind": "callback", "id": protocol_id, "image_selector": "fixture"},
        transfer_kind="callback",
        target=original["target"],
        abi_dialect=original["abi_dialect"],
        calling_convention=original["calling_convention"],
        arguments=original["arguments"],
        results=original["results"],
        stack=original["stack"],
        preserved_state=original["preserved_state"],
        clobbered_state=original["clobbered_state"],
        outcomes=original["outcomes"],
    )
    frame = {**checked["physical_frame"], "transport": transport.to_payload()}
    frame.pop("id")
    frame["id"] = f"physical-call-frame-v3:{canonical_sha256_v3(frame)}"
    protocol = {**checked["call_protocol"], "physical_frame_id": frame["id"]}
    protocol.pop("id")
    protocol["id"] = f"checked-call-protocol-v2:{canonical_sha256_v3(protocol)}"
    package = root / f"checked-callback-{protocol_id}"
    package.mkdir()
    write_json(package / "call-status.json", {
        "status": "complete",
        "subject": {"kind": "callback", "id": protocol_id, "image_selector": "fixture"},
    })
    write_json(package / "checked-call-protocol.json", protocol)
    write_json(package / "physical-call-frame-v3.json", frame)
    write_json(
        package / "boundary-lifecycle.json",
        checked["lifecycle_protocol"],
    )
    write_json(
        package / "boundary-lifecycle-receipt.json",
        checked["lifecycle_receipt"],
    )
    return package


def _write_execution_inputs(
    root: Path,
    units: list[dict[str, object]],
    *,
    blockers: list[dict[str, object]] | None = None,
    exception_continuations: list[dict[str, object]] | None = None,
    callback_escapes: list[dict[str, object]] | None = None,
    boundary_packages: dict[str, Path] | None = None,
    runtime_support_imports: list[dict[str, object]] | None = None,
) -> tuple[Path, Path, Path]:
    machine_ir = root / "machine-ir.jsonl"
    machine_ir.write_text(
        "".join(json.dumps(unit, sort_keys=True) + "\n" for unit in units),
        encoding="utf-8",
    )
    transfer_plan = write_fixture_transfer_plan(machine_ir)
    transfer = json.loads(transfer_plan.read_text(encoding="utf-8"))
    boundary_catalogs = []
    for subject, package in sorted((boundary_packages or {}).items()):
        artifacts = {}
        for filename, key in (
            ("checked-call-protocol.json", "checked_call_protocol"),
            ("physical-call-frame-v3.json", "physical_call_frame_v3"),
            ("boundary-lifecycle.json", "boundary_lifecycle"),
            ("boundary-lifecycle-receipt.json", "boundary_lifecycle_receipt"),
        ):
            path = package / filename
            artifacts[key] = {
                "sha256": sha256_file(path),
                "payload": json.loads(path.read_text(encoding="utf-8")),
            }
        boundary_catalogs.append({
            "subject": subject,
            "kind": "checked_protocol",
            "status_sha256": sha256_file(package / "call-status.json"),
            "artifacts": artifacts,
        })
    environment_core = {
        "format": "spaghetti-extractor-resolved-external-environment-v1",
        "status": "complete",
        "bindings": {},
        "target": {},
        "launch_policy": bind_launch_policy_v1(
            {
                "format": "spaghetti-extractor-pe32-launch-assumption-template-v1",
                "schema_version": 1,
            },
            source_sha256="0" * 64,
            filename="fixture-launch.json",
        ),
        "canonical_boundaries": boundary_catalogs,
        "interface_method_catalogs": [],
        "machine_import_contracts": [],
        "original_semantic_imports": [],
        "generated_runtime_support_imports": (
            []
            if runtime_support_imports is None
            else runtime_support_imports
        ),
        "loader_service_contracts": [],
        "static_authority_bindings": [],
        "checked_exception_protocols": [],
        "blockers": [],
        "authority": "fixture checked static environment",
    }
    environment = root / "resolved-external-environment.json"
    write_json(environment, {
        **environment_core,
        "resolved_environment_sha256": canonical_sha256_v3(environment_core),
    })
    reachable = [
        {
            "unit_id": row["identity"],
            "rva": row["source"]["rva_start"],
        }
        for row in transfer["transfers"]
    ]
    closure_blockers = [] if blockers is None else blockers
    core = {
        "format": MODULE_EXECUTION_CLOSURE_FORMAT,
        "status": "complete" if not closure_blockers else "incomplete",
        "authorizes_execution": not closure_blockers,
        "bindings": {
            "executable_transfer_plan_sha256": sha256_file(transfer_plan),
            "resolved_external_environment_sha256": sha256_file(environment),
        },
        "roots": [row["rva"] for row in reachable],
        "reachable_units": reachable,
        "reachable_edges": [],
        "indirect_targets": [],
        "external_contracts": [],
        "runtime_providers": [],
        "callback_escapes": [] if callback_escapes is None else callback_escapes,
        "exception_continuations": (
            []
            if exception_continuations is None
            else exception_continuations
        ),
        "nonlocal_transitions": [],
        "lifecycle_effects": [],
        "witnesses": [],
        "blockers": closure_blockers,
        "metrics": {
            "reachable_units": len(reachable),
            "reachable_edges": 0,
            "indirect_sites": 0,
            "function_contexts": 0,
        },
        "analysis_policy": {
            "reference_alternative_limit": 64,
            "call_string_limit": 1,
            "maximum_worklist_steps": 1_000_000,
            "boundary_exit_rvas": [],
        },
        "authority": "fixture exact execution closure",
    }
    closure = root / "module-execution-closure.json"
    write_json(closure, {
        **core,
        "closure_sha256": canonical_sha256_v3(core),
    })
    return transfer_plan, closure, environment



class NativeIngressProtocolTests(unittest.TestCase):
    def test_v2_linked_package_is_the_direct_ingress_authority(self) -> None:
        from tests.unit.semantic_link.test_module_v2 import (
            LinkedSemanticModuleV2Tests,
        )

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            payload = LinkedSemanticModuleV2Tests()._module(root)
            write_json(root / "linked-semantic-module.json", payload)
            output = root / "native-ingress"

            plan = write_native_ingress_plan_from_linked_module(
                linked_semantic_module=root,
                out=output,
            )

        self.assertEqual(
            plan["module"]["linked_semantic_module_sha256"],
            payload["linked_semantic_module_sha256"],
        )
        self.assertNotIn(
            "module_execution_closure_sha256", plan["module"]
        )
        self.assertNotEqual(
            plan["module"].get("module_execution_closure_sha256"), "None"
        )

    def test_physical_transducer_rejects_an_uncaptured_register_bank(self) -> None:
        transport = PhysicalCallFrameV2.create(
            subject={"kind": "export", "id": "fixture-xmm", "image_selector": "fixture"},
            transfer_kind="export",
            target="i686-pc-windows-gnu",
            abi_dialect="pe32-i386-gnu-v1",
            calling_convention="cdecl",
            arguments=[{
                "id": "arg0", "role": "parameter", "storage_bits": 32,
                "value_bits": 32, "pass_mode": "direct", "logical_path": [],
                "fragments": [{
                    "logical_offset_bits": 0, "width_bits": 32,
                    "location_offset_bits": 0, "representation": "identity",
                    "specified": True,
                    "location": {
                        "kind": "register", "phase": "callee_entry",
                        "width_bits": 32, "bank": "xmm", "name": "xmm0",
                        "stack_base": None, "stack_offset_bytes": None,
                        "memory_slot": None,
                    },
                }],
            }],
            results=[],
            stack={
                "coordinate": "callee-entry-esp", "alignment_bytes": 4,
                "cleanup": "caller", "cleanup_bytes": 0, "reserved_bytes": 0,
            },
            preserved_state=["ebx", "ebp", "esi", "edi"],
            clobbered_state=["eax", "ecx", "edx", "eflags"],
        )
        _transducer, issues = physical_frame_transducer_v1({
            "id": "fixture-frame", "transport": transport.to_payload(),
        })
        self.assertEqual(issues, ({
            "slot_id": "arg0", "fragment_index": 0,
            "direction": "input", "reason": "register_bank_not_captured",
        },))

    def test_lifecycle_resource_borrow_uses_physical_frame_transducer(self) -> None:
        transport = PhysicalCallFrameV2.create(
            subject={
                "kind": "callback", "id": "fixture-resource",
                "image_selector": "fixture",
            },
            transfer_kind="callback",
            target="i686-pc-windows-gnu",
            abi_dialect="pe32-i386-gnu-v1",
            calling_convention="stdcall",
            arguments=[{
                "id": "arg0", "role": "parameter", "storage_bits": 32,
                "value_bits": 32, "pass_mode": "direct", "logical_path": [],
                "fragments": [{
                    "logical_offset_bits": 0, "width_bits": 32,
                    "location_offset_bits": 0, "representation": "identity",
                    "specified": True,
                    "location": {
                        "kind": "stack", "phase": "callee_entry",
                        "width_bits": 32, "bank": None, "name": None,
                        "stack_base": "callee-entry-esp",
                        "stack_offset_bytes": 4, "memory_slot": None,
                    },
                }],
            }],
            results=[],
            stack={
                "coordinate": "callee-entry-esp", "alignment_bytes": 4,
                "cleanup": "callee", "cleanup_bytes": 4,
                "reserved_bytes": 0,
            },
            preserved_state=["ebx", "ebp", "esi", "edi", "esp"],
            clobbered_state=["eax", "ecx", "edx", "eflags"],
        )
        path = {"root": "parameter", "value_id": "resource0", "fields": []}
        frame = {
            "id": "fixture-frame",
            "transport": transport.to_payload(),
            "bindings": [{
                "path": path, "slot_id": "arg0", "transport": "semantic",
            }],
        }
        lifecycle = {
            "lifecycle_sha256": "a" * 64,
            "roots": [{
                "root": "parameter",
                "values": [{
                    "id": "resource0", "interpretation": "resource",
                    "nullable": False, "resource_kind": "exception_context",
                    "provider_domain": "win32_exception_dispatch",
                }],
            }],
            "bindings": [{
                "id": "borrow.exception-info", "path": path,
                "transition": "borrow_shared",
                "resource_kind": "exception_context",
                "provider_domain": "win32_exception_dispatch",
            }],
        }

        transducer, issues = boundary_lifecycle_transducer_v1(frame, lifecycle)

        self.assertEqual(issues, ())
        self.assertEqual(transducer["bindings"], [{
            "binding_id": "borrow.exception-info",
            "transition": "borrow_shared",
            "resource_kind": "exception_context",
            "provider_domain": "win32_exception_dispatch",
            "nullable": False,
            "slot_id": "arg0",
            "location": transport.arguments[0].fragments[0].location.to_payload(),
        }])
        plan = _native_ingress_plan(0x1000)
        checked = {
            **transducer,
            "transducer_sha256": canonical_sha256_v3(transducer),
        }
        plan["ingresses"][0]["physical_frame_id"] = frame["id"]
        plan["ingresses"][0]["physical_frame"] = frame
        plan["ingresses"][0].pop("physical_transducer", None)
        plan["ingresses"][0]["lifecycle_transducer"] = checked
        source = render_native_ingress_source(plan)
        self.assertIn("spx_native_lifecycle_borrows[]", source)
        self.assertIn("spx_native_preflight_boundary_lifecycle", source)
        self.assertIn("/* borrow.exception-info */", source)

        malformed = {**checked, "physical_frame_id": "different-frame"}
        malformed_core = {
            key: value for key, value in malformed.items()
            if key != "transducer_sha256"
        }
        malformed["transducer_sha256"] = canonical_sha256_v3(malformed_core)
        plan["ingresses"][0]["lifecycle_transducer"] = malformed
        with self.assertRaisesRegex(
            ToolkitInputError, "does not bind its physical frame"
        ):
            render_native_ingress_source(plan)

    def test_lifecycle_plain_value_remains_a_stable_blocker(self) -> None:
        transport = PhysicalCallFrameV2.create(
            subject={"kind": "callback", "id": "plain", "image_selector": None},
            transfer_kind="callback", target="i686-pc-windows-gnu",
            abi_dialect="pe32-i386-gnu-v1", calling_convention="cdecl",
            arguments=[], results=[],
            stack={
                "coordinate": "callee-entry-esp", "alignment_bytes": 4,
                "cleanup": "caller", "cleanup_bytes": 0, "reserved_bytes": 0,
            },
            preserved_state=["ebx", "ebp", "esi", "edi"],
            clobbered_state=["eax", "ecx", "edx", "eflags"],
        )
        lifecycle = {
            "lifecycle_sha256": "b" * 64,
            "roots": [{"root": "parameter", "values": [{
                "id": "arg0", "interpretation": "value", "nullable": False,
                "resource_kind": None, "provider_domain": None,
            }]}],
            "bindings": [{
                "id": "borrow.exception-info",
                "path": {"root": "parameter", "value_id": "arg0", "fields": []},
                "transition": "borrow_shared", "resource_kind": "exception_context",
                "provider_domain": "win32_exception_dispatch",
            }],
        }

        _transducer, issues = boundary_lifecycle_transducer_v1(
            {"id": "plain-frame", "transport": transport.to_payload(), "bindings": []},
            lifecycle,
        )

        self.assertEqual(issues[0]["reason"], "lifecycle_value_not_resource")

        lifecycle["bindings"][0].pop("id")
        _transducer, issues = boundary_lifecycle_transducer_v1(
            {"id": "plain-frame", "transport": transport.to_payload(), "bindings": []},
            lifecycle,
        )
        self.assertEqual(issues[0]["reason"], "binding_identity_missing")

    def test_callback_ingress_comes_from_canonical_execution_closure(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            callback_package = _checked_callback_package(
                root, "fixture-callback"
            )
            transfer_plan, closure, environment = _write_execution_inputs(
                root,
                [
                    _machine_ir_transfer(
                        rva=rva, size=1, mnemonic="ret"
                    )
                    for rva in (0x1100, 0x1200, 0x1300)
                ],
                callback_escapes=[{
                    "instruction_rva": 0x1000,
                    "dll": "fixture.dll",
                    "identity": "RegisterCallback",
                    "protocol_id": "fixture-callback",
                    "targets": [0x1100, 0x1200, 0x1300],
                    "action": "register",
                    "lifetime": "until_replaced_or_process_exit",
                    "delivery": {"thread": "same_or_foreign", "timing": "deferred"},
                }],
                boundary_packages={
                    "callback:fixture-callback": callback_package,
                },
            )
            authorities, _outcomes, _seh, blockers, compact = _derive_ingress_authorities(
                interface={"image_id": "fixture", "kind": "dll", "export_directory": {"slots": []}},
                roots={"roots": []},
                transfer_plan=transfer_plan,
                execution_closure=json.loads(
                    closure.read_text(encoding="utf-8")
                ),
                resolved_external_environment=environment,
            )
            self.assertEqual(blockers, [])
            self.assertEqual(authorities, [])
            self.assertEqual(len(compact["domains"]), 1)
            self.assertEqual(
                compact["domains"][0]["target_rvas"],
                [0x1100, 0x1200, 0x1300],
            )
            self.assertEqual(len(compact["publications"]), 1)
            self.assertEqual(
                compact["publications"][0]["domain_id"],
                compact["domains"][0]["id"],
            )

    def test_callback_domain_preserves_independent_closure_blocker(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            callback_package = _checked_callback_package(
                root, "fixture-callback"
            )
            targets = [0x1100, 0x1200, 0x1300]
            closure_blocker = {
                "code": "unresolved_reachable_indirect_target",
                "source_rva": 0x1000,
                "site": "call:00001000:0",
                "provenance": [],
            }
            transfer_plan, closure, environment = _write_execution_inputs(
                root,
                [
                    _machine_ir_transfer(rva=rva, size=1, mnemonic="ret")
                    for rva in targets
                ],
                blockers=[closure_blocker],
                callback_escapes=[{
                    "instruction_rva": 0x1000,
                    "dll": "fixture.dll",
                    "identity": "RegisterCallback",
                    "protocol_id": "fixture-callback",
                    "targets": targets,
                    "action": "register",
                    "lifetime": "until_replaced_or_process_exit",
                    "delivery": {
                        "thread": "same_or_foreign", "timing": "deferred",
                    },
                }],
                boundary_packages={
                    "callback:fixture-callback": callback_package,
                },
            )
            authorities, _outcomes, _seh, blockers, compact = (
                _derive_ingress_authorities(
                    interface={
                        "image_id": "fixture", "kind": "dll",
                        "export_directory": {"slots": []},
                    },
                    roots={"roots": []},
                    transfer_plan=transfer_plan,
                    execution_closure=json.loads(
                        closure.read_text(encoding="utf-8")
                    ),
                    resolved_external_environment=environment,
                )
            )
            self.assertEqual(authorities, [])
            self.assertEqual(
                blockers[0], {
                    "category": "execution_closure_blocker",
                    "closure_blocker": closure_blocker,
                },
            )
            self.assertEqual(len(blockers), 1)
            self.assertEqual(len(compact["domains"]), 1)
            self.assertEqual(compact["domains"][0]["target_rvas"], targets)
            self.assertEqual(len(compact["publications"]), 1)
            self.assertEqual(
                compact["publications"][0]["domain_id"],
                compact["domains"][0]["id"],
            )

    def test_incomplete_execution_closure_is_preserved_as_ingress_blocker(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            transfer_plan, closure, environment = _write_execution_inputs(
                root,
                [
                    _machine_ir_transfer(
                        rva=rva, size=1, mnemonic="ret"
                    )
                    for rva in (0x1100, 0x1200, 0x1300)
                ],
                blockers=[{
                    "code": "reachable_exception_outcome_unresolved",
                    "source_rva": 0x1100,
                    "effect_index": 0,
                    "operation": "divide_if",
                    "occurrence_kind": "effect",
                    "call_index": None,
                }],
            )
            authorities, _outcomes, _seh, blockers, compact = _derive_ingress_authorities(
                interface={"image_id": "fixture", "kind": "dll", "export_directory": {"slots": []}},
                roots={"roots": []},
                transfer_plan=transfer_plan,
                execution_closure=closure,
                resolved_external_environment=environment,
            )
            self.assertEqual(authorities, [])
            self.assertEqual(blockers, [{
                "category": "execution_closure_blocker",
                "closure_blocker": {
                    "code": "reachable_exception_outcome_unresolved",
                    "source_rva": 0x1100,
                    "effect_index": 0,
                    "operation": "divide_if",
                    "occurrence_kind": "effect",
                    "call_index": None,
                },
            }])
            self.assertEqual(compact, {"domains": [], "publications": []})

    def test_stale_execution_closure_transfer_binding_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            transfer_plan, closure, environment = _write_execution_inputs(
                root,
                [_machine_ir_transfer(rva=0x1100, size=1, mnemonic="ret")],
            )
            value = json.loads(closure.read_text(encoding="utf-8"))
            value["bindings"]["executable_transfer_plan_sha256"] = "0" * 64
            core = {key: item for key, item in value.items() if key != "closure_sha256"}
            value["closure_sha256"] = canonical_sha256_v3(core)
            write_json(closure, value)
            with self.assertRaisesRegex(
                NativeIngressError, "does not bind the exact executable transfer plan"
            ):
                _derive_ingress_authorities(
                    interface={"image_id": "fixture", "kind": "dll", "export_directory": {"slots": []}},
                    roots={"roots": []},
                    transfer_plan=transfer_plan,
                    execution_closure=closure,
                    resolved_external_environment=environment,
                )
    def test_callback_escape_without_checked_boundary_is_a_stable_blocker(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            transfer_plan, closure, environment = _write_execution_inputs(
                root,
                [_machine_ir_transfer(rva=0x1100, size=1, mnemonic="ret")],
                callback_escapes=[{
                    "instruction_rva": 0x1000,
                    "dll": "fixture.dll",
                    "identity": "RegisterCallback",
                    "protocol_id": "fixture-callback",
                    "targets": [0x1100, 0x1200, 0x1300],
                    "action": "register",
                    "lifetime": "until_replaced_or_process_exit",
                    "delivery": {"thread": "same_or_foreign", "timing": "deferred"},
                }],
            )
            authorities, _outcomes, _seh, blockers, compact = _derive_ingress_authorities(
                interface={"image_id": "fixture", "kind": "dll", "export_directory": {"slots": []}},
                roots={"roots": []},
                transfer_plan=transfer_plan,
                execution_closure=json.loads(
                    closure.read_text(encoding="utf-8")
                ),
                resolved_external_environment=environment,
            )
            self.assertEqual(authorities, [])
            self.assertEqual(len(blockers), 1)
            self.assertEqual(
                blockers[0]["category"],
                "callback_call_protocol_missing_or_ambiguous",
            )
            self.assertEqual(blockers[0]["protocol_id"], "fixture-callback")
            self.assertEqual(blockers[0]["admitted_target_count"], 3)
            self.assertEqual(compact, {"domains": [], "publications": []})

    def test_resource_lifetime_retains_its_checked_end_event(self) -> None:
        self.assertEqual(
            _capability_lifetime(
                "until_resource_event_or_process_exit:class_unregistered"
            ),
            ("until_resource_event_or_process_exit", "class_unregistered"),
        )
        with self.assertRaisesRegex(
            ToolkitInputError, "lacks its checked end event"
        ):
            _capability_lifetime("until_resource_event_or_process_exit")

    def test_shared_bridge_aggregates_every_capability_identity(self) -> None:
        plan = _native_ingress_plan(0x1010)
        public = plan["ingresses"][0]
        callback = json.loads(json.dumps(public))
        callback.update({
            "role": "callback",
            "capability_id": "fixture-callback",
        })
        plan["ingresses"].append(callback)
        source = render_native_ingress_source(plan)
        self.assertIn(
            "{ 0U, 0x00001010U, 0U, 1U, 0U, 1U, 1U, 0x0000000fU, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 1U, 1U, 0U },",
            source,
        )
        self.assertIn(
            '__asm__ volatile ("movl %%fs:0x18,%0" : "=r" (state->fs_base));',
            source,
        )

        protected = json.loads(json.dumps(plan))
        protected["ingresses"][0].update({
            "role": "callback",
            "capability_id": "fixture-callback-two",
        })
        source = render_native_ingress_source(protected)
        self.assertIn(
            "{ 0U, 0x00001010U, 0U, 1U, 0U, 2U, 0U, 0x0000000fU, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 1U, 0U, 0U },",
            source,
        )
        self.assertIn("spx_native_capability_authorize", source)
        self.assertIn("if (capability_active == 0U)", source)
        self.assertIn("generation->owner_thread != owner_thread", source)

    def test_reviewed_loader_lifecycle_gates_image_generation(self) -> None:
        plan = _native_ingress_plan(0x1010)
        plan["ingresses"][0]["role"] = "dll_entry"
        plan["ingresses"][0]["lifecycle_protocol"] = {
            "kind": "reviewed_pe32_loader_lifecycle_v1",
            "role": "dll_entry",
        }
        source = render_native_ingress_source(plan)
        self.assertIn("static volatile uint32_t spx_native_image_active = 0U;", source)
        self.assertIn("spx_native_preflight_loader_lifecycle", source)
        self.assertIn("DLL_PROCESS_ATTACH", source)
        self.assertIn("DLL_PROCESS_DETACH", source)
        self.assertIn("&spx_native_image_active, 0U", source)

    def test_no_return_protocol_rejects_a_normal_return(self) -> None:
        plan = _native_ingress_plan(0x1010)
        plan["outcome_protocols"] = [{
            "id": "fixture-no-return", "outcomes": ["no_return"]
        }]
        plan["ingresses"][0]["outcome_protocol_id"] = "fixture-no-return"
        source = render_native_ingress_source(plan)
        self.assertIn("(descriptor->outcome_mask & 0x01U) == 0U", source)

    def test_checked_ingress_materializes_physical_return_stack(self) -> None:
        plan = _native_ingress_plan(0x1010)
        header = render_native_ingress_header(plan)
        source = render_native_ingress_source(plan)
        self.assertIn(
            "frame->output->esp =\n"
            "      frame->input->esp + 4U + descriptor->cleanup_bytes;",
            source,
        )
        self.assertGreaterEqual(
            source.count(
                "!spx_native_materialize_normal_return_frame(descriptor, frame)"
            ),
            2,
        )
        self.assertIn("spx_native_capability_is_active", header)
        self.assertIn("spx_native_realize_registered_code_result", header)
        self.assertIn(
            "spx_native_realize_registered_code_result(\n"
            "        spx_native_ingress_target_rva(bridge_index, descriptor),\n"
            "        frame->output->eax, &native_value)",
            source,
        )
        self.assertIn("else if (realization == 2U)", source)
        self.assertIn("status = SPX_CALL_UNIMPLEMENTED;", source)

    def test_handcrafted_nonlocal_plan_cannot_bypass_authority(self) -> None:
        plan = _native_ingress_plan(0x1010)
        plan["outcome_protocols"] = [{
            "id": "fixture-nonlocal",
            "outcomes": ["nonlocal"],
            "nonlocal_protocol_ids": ["fixture-nonlocal-transition"],
        }]
        plan["ingresses"][0]["outcome_protocol_id"] = "fixture-nonlocal"
        with self.assertRaisesRegex(
            ToolkitInputError,
            "nonlocal dispatch is unsupported until its checked transfer-v2",
        ):
            render_native_ingress_source(plan)

    def test_finish_failure_recovers_the_captured_host_frame(self) -> None:
        assembly = render_native_ingress_assembly(_native_ingress_plan(0x1010))
        self.assertIn(
            ".Lspx_ingress_trap_0:\n"
            "    mov esp, edi\n"
            "    mov DWORD PTR [esp + 28], 1\n"
            "    popad\n"
            "    popfd\n"
            "    ret",
            assembly,
        )

    def test_compact_callback_domains_share_one_fixed_stride_gateway(self) -> None:
        plan = _native_ingress_plan(0x1010, callbacks=((0x2020, 4),))
        callback = plan["ingresses"].pop()
        plan["bridges"].pop()
        domain_id = "callback-domain-v1:" + "a" * 64
        family_id = "callback-bridge-family-v1:" + "b" * 64
        plan.update({
            "callback_domains": [{
                "id": domain_id,
                "protocol_id": "fixture-callback",
                "target_rvas": [0x2020, 0x2030],
                "call_protocol": {"id": "fixture-callback"},
                "physical_frame": {
                    **callback["physical_frame"],
                    "id": callback["physical_frame_id"],
                },
                "lifecycle_protocol": {},
                "lifecycle_receipt": {"status": "complete"},
                "outcome_groups": [{
                    "outcome_protocol_id": "fixture-normal-outcome",
                    "target_rvas": [0x2020, 0x2030],
                }],
                "bridge_family_id": family_id,
                "trampoline_table_symbol": "spx_callback_trampolines_0000",
                "trampoline_stride_bytes": 10,
            }],
            "callback_publications": [{
                "id": "callback-publication-v1:" + "c" * 64,
                "domain_id": domain_id,
                "escape_id": "callback-escape-v1:" + "d" * 64,
                "instruction_rva": 0x1810,
                "dll": "fixture.dll",
                "identity": "register_callback",
                "action": "register",
                "lifetime": "until_replaced_or_process_exit",
                "delivery": {"thread": "same_or_foreign"},
            }],
            "callback_bridge_families": [{
                "id": family_id,
                "symbol": "spx_callback_bridge_family_0000",
                "cleanup_bytes": 4,
                "physical_frame_ids": [callback["physical_frame_id"]],
                "domain_ids": [domain_id],
            }],
        })
        compact = compact_callback_runtime_v1(plan)
        self.assertEqual([row.flat_index for row in compact.targets], [0, 1])
        self.assertEqual(compact.domains[0].flat_first, 0)
        assembly = render_native_ingress_assembly(plan)
        self.assertEqual(
            assembly.count(".long _spx_callback_bridge_family_0000 - . - 4"),
            2,
        )
        self.assertIn(
            "_spx_callback_bridge_family_0000:\n"
            "    pushfd\n"
            "    pushad\n"
            "    mov eax, esp\n"
            "    add DWORD PTR [eax + 12], 4\n"
            "    mov edx, DWORD PTR [esp + 36]",
            assembly,
        )
        self.assertIn("    add esp, 4\n    ret 4", assembly)
        source = render_native_ingress_source(plan)
        self.assertIn(
            "spx_native_static_ingress_descriptor_count + flat_target_index",
            source,
        )
        self.assertIn(
            "source + sizeof(*capture) + callback_prefix",
            source,
        )
        self.assertIn("spx_native_capabilities[2U]", source)
        self.assertIn("spx_native_capabilities[2U];", source)
        self.assertNotIn("spx_native_capabilities[2U] = {", source)
        self.assertIn("spx_native_capability_count = 2U", source)
        self.assertIn(
            "spx_native_capability_lifetime_range_count =\n    1U", source
        )
        self.assertIn(
            "lifetime = spx_native_capability_lifetime_for(capability_index)",
            source,
        )
        self.assertIn(
            "if (lifetime->lifetime_mode == 1U) generation->active = 0U;",
            source,
        )
        self.assertIn("spx_native_compact_target_assignments", source)
        self.assertIn(
            "spx_native_ingress_descriptor_storage_count = 2U", source
        )
        self.assertIn(
            "spx_native_ingress_descriptor_count =\n    3U", source
        )
        self.assertIn("spx_native_compact_descriptor_ranges", source)
        self.assertIn(
            "spx_native_compact_descriptor_range_count =\n    1U", source
        )
        self.assertIn("spx_native_compact_target_rvas", source)
        self.assertIn("if (assigned != flat_target_index) return 0U;", source)
        compiler = shutil.which("i686-w64-mingw32-gcc")
        if compiler is not None:
            with tempfile.TemporaryDirectory() as temporary:
                path = Path(temporary) / "compact-callbacks.s"
                path.write_text(assembly, encoding="ascii")
                subprocess.run(
                    [compiler, "-c", str(path), "-o", str(path.with_suffix(".o"))],
                    check=True,
                    text=True,
                    capture_output=True,
                )

    def test_uncommitted_capabilities_are_owned_by_the_ingress_generation(self) -> None:
        source = render_native_ingress_source(_native_ingress_plan(0x1010))
        self.assertIn("owner_thread, owner_ingress", source)
        self.assertIn("spx_native_capability_expire_ingress(frame->generation)", source)
        self.assertIn("spx_native_capability_commit(", source)

    def test_seh_gateway_selects_the_exact_establisher_frame(self) -> None:
        source = render_native_ingress_source(_native_ingress_plan(0x1010))
        self.assertIn("spx_native_frame_for_establisher(", source)
        self.assertIn("if (observed == expected)", source)
        self.assertIn(
            "descriptor = spx_native_ingress_descriptor_for(\n"
            "        handler_frame->bridge_index)",
            source,
        )
        self.assertIn(
            "fault_frame->output->original_rva == seh->source_rva",
            source,
        )
        self.assertIn(
            "spx_native_abandon_frames_above(\n"
            "          base, header, header->exception_frame_index)",
            source,
        )

    def test_runtime_rejects_unresolved_unwind_effects(self) -> None:
        plan = _native_ingress_plan(0x1010)
        plan["seh_protocols"] = [{
            "id": "fixture-unwind",
            "unwind_effect_ids": ["fixture-finally"],
        }]
        with self.assertRaisesRegex(
            ToolkitInputError, "unresolved unwind effect"
        ):
            render_native_ingress_source(plan)
