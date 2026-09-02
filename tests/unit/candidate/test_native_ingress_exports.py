from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from tests.pe_fixtures import (
    pe32_data_export_image,
    pe32_export_image,
    pe32_image_with_writable_data,
)
from tests.unit.candidate.native_ingress_support import (
    machine_ir_transfer as _machine_ir_transfer,
    native_ingress_plan as _native_ingress_plan,
)

from spaghetti_extractor.artifacts.artifact_set import canonical_sha256_v3
from spaghetti_extractor.candidate.build_objects import _payload_symbol_rvas
from spaghetti_extractor.candidate.native_ingress_plan import (
    _write_native_ingress_plan_v2 as write_native_ingress_plan,
    write_pe32_machine_object_authority_v2,
)
from spaghetti_extractor.candidate.native_ingress_derivation import (
    _derive_ingress_authorities,
    _reviewed_loader_call,
)
from spaghetti_extractor.candidate.native_ingress_errors import NativeIngressError
from spaghetti_extractor.candidate.native_ingress_runtime import (
    _capability_lifetime,
    _seh_projection_masks,
    boundary_lifecycle_transducer_v1,
    physical_frame_transducer_v1,
    render_native_ingress_assembly,
    render_native_ingress_header,
    render_native_ingress_source,
)
from spaghetti_extractor.candidate.module_composer import compose_pe32_native_module
from spaghetti_extractor.candidate.outcomes import (
    CheckedSEHProtocolV1,
    PinnedCodeLayoutAuthorityV2,
)
from spaghetti_extractor.candidate.project import write_pe32_module_interface
from spaghetti_extractor.candidate.formats import (
    NATIVE_REALIZATION_BUILD_MANIFEST_FORMAT,
)
from spaghetti_extractor.calls.frame import PhysicalCallFrameV2
from spaghetti_extractor.errors import ToolkitInputError
from spaghetti_extractor.external.resolved import bind_launch_policy_v1
from spaghetti_extractor.pe32.behavioral_roots import generate_behavioral_roots
from spaghetti_extractor.roundtrip_fuzz.image_io import write_spx_load_image_contract
from spaghetti_extractor.testkit.transfer_fixture import write_fixture_transfer_plan
from spaghetti_extractor.transfer.formats import MODULE_EXECUTION_CLOSURE_FORMAT
from spaghetti_extractor.util import sha256_bytes, sha256_file, write_json


_EMPTY_RELOCATIONS = {"format": "fixture-relocations-v1", "complete": True, "relocations": []}


def _realization_build_fixture(
    root: Path, *, plan: Path, linked: Path, objects: Path, load_contract: Path,
    symbols: list[dict[str, object]],
) -> tuple[Path, Path]:
    environment_core = {
        "format": "spaghetti-extractor-resolved-external-environment-v1",
        "status": "complete",
        "blockers": [],
    }
    environment = root / "resolved-external-environment.json"
    write_json(environment, environment_core)
    relocation_inventory = root / "payload-relocations.json"
    write_json(relocation_inventory, _EMPTY_RELOCATIONS)
    import pefile

    pe = pefile.PE(str(linked), fast_load=True)
    try:
        image_base = int(pe.OPTIONAL_HEADER.ImageBase)
    finally:
        pe.close()
    linker_map = root / "payload.map"
    linker_map.write_text(
        "".join(
            f"0x{image_base + int(row['rva']):08x} _{row['symbol']}\n"
            for row in symbols
        ),
        encoding="ascii",
    )
    core = {
        "format": NATIVE_REALIZATION_BUILD_MANIFEST_FORMAT,
        "status": "linked",
        "acceptance_authority": "none",
        "inputs": {
            "native_ingress_plan": {"artifact_sha256": sha256_file(plan)},
            "load_image_contract": {
                "artifact_sha256": sha256_file(load_contract),
            },
            "linked_semantic_module": {
                "resolved_external_environment_sha256": sha256_file(
                    environment
                ),
                "machine_object_authority_sha256": sha256_file(objects),
            },
        },
        "outputs": {
            "payload": {"sha256": sha256_file(linked)},
            "linker_map": {"sha256": sha256_file(linker_map)},
            "payload_relocation_inventory": {
                "sha256": sha256_file(relocation_inventory),
                "complete": True,
            },
        },
        "policy": {"image_base": image_base},
    }
    manifest = root / "native-realization-build-manifest.json"
    write_json(manifest, {
        **core,
        "hashes": {
            "algorithm": "sha256",
            "manifest_core_sha256": canonical_sha256_v3(core),
        },
    })
    return manifest, environment


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



class NativeIngressExportTests(unittest.TestCase):
    def test_data_export_is_a_loader_realized_object_anchor(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            original = root / "fixture.dll"
            original.write_bytes(
                pe32_data_export_image(b"\x11\x22\x33\x44\0\0\0\0")
            )
            contract = root / "load.json"
            write_spx_load_image_contract(original_pe=original, out=contract)
            interface_root = root / "interface"
            interface = write_pe32_module_interface(
                image_id="fixture", original_pe=original,
                load_image_contract=contract, out=interface_root,
            )
            authority = write_pe32_machine_object_authority_v2(
                module_interface=interface_root / "module-interface.json",
                out=root / "objects",
            )
            anchor = authority["data_export_anchors"][0]
            rule = next(row for row in authority["rules"] if row["id"] == anchor["rule_id"])
            self.assertEqual(rule["locator"]["kind"], "image_rva")
            self.assertEqual(rule["locator"]["rva"] + anchor["byte_offset"], 0x2000)
            self.assertEqual(interface["export_directory"]["slots"][0]["kind"], "data")

            roots_path = root / "behavioral-roots.json"
            write_json(roots_path, generate_behavioral_roots(original))
            transfer_plan, execution_closure, environment = _write_execution_inputs(
                root,
                [_machine_ir_transfer(rva=0x1000, size=1, mnemonic="ret")],
            )
            plan_root = root / "plan"
            plan = write_native_ingress_plan(
                module_interface=interface_root / "module-interface.json",
                behavioral_roots=roots_path,
                object_authority=root / "objects" / "machine-object-authority.json",
                transfer_plan=transfer_plan,
                execution_closure=execution_closure,
                resolved_external_environment=environment,
                out=plan_root,
            )
            self.assertEqual(plan["status"], "complete")
            self.assertIn(
                "tls_private_stack_v1",
                plan["runtime_requirements"]["features"],
            )
            self.assertNotIn(
                "tls_private_private_stack_v1",
                plan["runtime_requirements"]["features"],
            )
            linker_map = root / "fixture.map"
            linker_map.write_text(
                "0x00501000 _spx_ingress_0000\n"
                "0x00502004 _spx_native_tls_index_cell_pointer\n"
                "0x00502008 _spx_native_module_base_pointer\n",
                encoding="ascii",
            )
            link_root = root / "link"
            build_manifest, environment = _realization_build_fixture(
                root, plan=plan_root / "native-ingress-plan.json",
                linked=original,
                objects=root / "objects" / "machine-object-authority.json",
                load_contract=contract,
                symbols=[
                    {"symbol": "spx_ingress_0000", "rva": 0x1000},
                    {"symbol": "spx_native_tls_index_cell_pointer", "rva": 0x2004},
                    {"symbol": "spx_native_module_base_pointer", "rva": 0x2008},
                ],
            )
            compose_pe32_native_module(
                linked_skeleton=original,
                linked_relocation_inventory=root / "payload-relocations.json",
                load_image_contract=contract,
                recovered_executable_data=None,
                original_module_interface=interface_root / "module-interface.json",
                native_ingress_plan=plan_root / "native-ingress-plan.json",
                native_build_manifest=build_manifest,
                resolved_external_environment=environment,
                object_authority=root / "objects" / "machine-object-authority.json",
                out=root / "composed",
                candidate_filename="fixture.dll",
            )
            import pefile
            candidate_pe = pefile.PE(str(root / "composed" / "fixture.dll"))
            try:
                self.assertEqual(
                    candidate_pe.DIRECTORY_ENTRY_EXPORT.symbols[0].address,
                    0x2000,
                )
                self.assertEqual(candidate_pe.get_data(0x2000, 4), b"\x11\x22\x33\x44")
            finally:
                candidate_pe.close()

    def test_plan_is_derived_and_equivalent_loader_export_share_bridge(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            original = root / "fixture.dll"
            original.write_bytes(pe32_export_image(
                b"\xc3" + b"\x90" * 15 + b"\xc3", symbol="Ping", dll="fixture.dll"
            ))
            load_contract = root / "load.json"
            write_spx_load_image_contract(original_pe=original, out=load_contract)
            interface_root = root / "interface"
            write_pe32_module_interface(
                image_id="fixture", original_pe=original,
                load_image_contract=load_contract, out=interface_root,
            )
            roots_path = root / "behavioral-roots.json"
            write_json(roots_path, generate_behavioral_roots(original))
            objects = root / "objects"
            write_pe32_machine_object_authority_v2(
                module_interface=interface_root / "module-interface.json", out=objects
            )
            unit = _machine_ir_transfer(rva=0x1000, size=0x20, mnemonic="ret")
            export_package = _checked_export_package(root)
            transfer_plan, execution_closure, environment = _write_execution_inputs(
                root, [unit],
                boundary_packages={"export:Ping": export_package},
            )
            plan_root = root / "plan"
            plan = write_native_ingress_plan(
                module_interface=interface_root / "module-interface.json",
                behavioral_roots=roots_path,
                object_authority=objects / "machine-object-authority.json",
                transfer_plan=transfer_plan,
                execution_closure=execution_closure,
                resolved_external_environment=environment,
                out=plan_root,
            )
            self.assertEqual(plan["status"], "complete")
            self.assertEqual({row["role"] for row in plan["ingresses"]}, {"dll_entry", "export"})
            self.assertEqual(len(plan["bridges"]), 1)
            self.assertEqual(
                {row["bridge_symbol"] for row in plan["ingresses"]},
                {"spx_ingress_0000"},
            )
            self.assertIn("spx_native_runtime_context_current", render_native_ingress_source(plan))
            self.assertIn("_spx_ingress_0000:", render_native_ingress_assembly(plan))
            self.assertIn(
                "_spx_native_raise_exception_gateway:",
                render_native_ingress_assembly(plan),
            )
            self.assertIn("SPX_NATIVE_TLS_RUNTIME_OFFSET", render_native_ingress_header(plan))

            linker_map = root / "fixture.map"
            linker_map.write_text(
                "0x00501010 _spx_ingress_0000\n"
                "0x00502100 _spx_native_tls_index_cell_pointer\n"
                "0x00502104 _spx_native_module_base_pointer\n",
                encoding="ascii",
            )
            required_symbols = {
                "spx_ingress_0000",
                "spx_native_tls_index_cell_pointer",
                "spx_native_module_base_pointer",
            }
            all_symbol_rvas = _payload_symbol_rvas(
                linker_map,
                image_base=json.loads(
                    (interface_root / "module-interface.json").read_text(
                        encoding="utf-8"
                    )
                )["loader"]["preferred_base"],
            )
            symbol_rvas = {
                symbol: all_symbol_rvas[symbol]
                for symbol in sorted(required_symbols)
            }
            self.assertEqual(
                set(symbol_rvas),
                {
                    "spx_ingress_0000",
                    "spx_native_tls_index_cell_pointer",
                    "spx_native_module_base_pointer",
                },
            )
            build_manifest, environment = _realization_build_fixture(
                root, plan=plan_root / "native-ingress-plan.json",
                linked=original,
                objects=objects / "machine-object-authority.json",
                load_contract=load_contract,
                symbols=[
                    {"symbol": symbol, "rva": rva}
                    for symbol, rva in sorted(symbol_rvas.items())
                ],
            )
            composed = compose_pe32_native_module(
                linked_skeleton=original,
                linked_relocation_inventory=root / "payload-relocations.json",
                load_image_contract=load_contract,
                recovered_executable_data=None,
                original_module_interface=interface_root / "module-interface.json",
                native_ingress_plan=plan_root / "native-ingress-plan.json",
                native_build_manifest=build_manifest,
                resolved_external_environment=environment,
                object_authority=objects / "machine-object-authority.json",
                out=root / "composed",
                candidate_filename="fixture.dll",
            )
            self.assertEqual(composed["candidate"]["path"], "fixture.dll")
            self.assertNotIn("executable_anchors", composed["policy"])
            import pefile
            candidate_pe = pefile.PE(str(root / "composed" / "fixture.dll"))
            try:
                self.assertEqual(candidate_pe.OPTIONAL_HEADER.AddressOfEntryPoint, 0x1010)
                self.assertEqual(
                    candidate_pe.DIRECTORY_ENTRY_EXPORT.symbols[0].address,
                    0x1010,
                )
            finally:
                candidate_pe.close()

    def test_checked_terminal_fault_derives_native_outcome_and_seh(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            original = root / "fixture.dll"
            original.write_bytes(pe32_export_image(
                b"\xc3" + b"\x90" * 15 + b"\xc3",
                symbol="Ping",
                dll="fixture.dll",
            ))
            load_contract = root / "load.json"
            write_spx_load_image_contract(original_pe=original, out=load_contract)
            interface_root = root / "interface"
            write_pe32_module_interface(
                image_id="fixture",
                original_pe=original,
                load_image_contract=load_contract,
                out=interface_root,
            )
            roots_path = root / "behavioral-roots.json"
            write_json(roots_path, generate_behavioral_roots(original))
            objects = root / "objects"
            write_pe32_machine_object_authority_v2(
                module_interface=interface_root / "module-interface.json",
                out=objects,
            )
            transition_sha256 = "d" * 64
            transition_id = "exceptional-transition-v3:" + "e" * 64
            transfer_plan, execution_closure, environment = _write_execution_inputs(
                root,
                [_machine_ir_transfer(rva=0x1000, size=0x20, mnemonic="ret")],
                boundary_packages={"export:Ping": _checked_export_package(root)},
                runtime_support_imports=[{
                    "support": "exception_escape",
                    "identity": {
                        "dll": "kernel32.dll",
                        "symbol": "RaiseException",
                        "ordinal": None,
                    },
                    "contract": {"profile_id": "fixture"},
                    "boundary": {"schema": "fixture"},
                }],
                exception_continuations=[{
                    "unit_id": "semantic-transfer:typed-00001000",
                    "source_rva": 0x1000,
                    "effect_index": 0,
                    "fault_index": 0,
                    "fault_sha256": "f" * 64,
                    "transition_id": transition_id,
                    "transition_sha256": transition_sha256,
                    "operation": "divide_if",
                    "occurrence_kind": "effect",
                    "call_index": None,
                    "disposition": "terminates",
                    "handler_unit_id": None,
                    "handler_rva": None,
                    "resumption_unit_id": None,
                    "resumption_rva": None,
                    "unwind_unit_ids": [],
                    "state_projection": None,
                    "guard": {"op": "true"},
                    "root_rvas": [0x1000],
                }],
            )
            plan = write_native_ingress_plan(
                module_interface=interface_root / "module-interface.json",
                behavioral_roots=roots_path,
                object_authority=objects / "machine-object-authority.json",
                transfer_plan=transfer_plan,
                execution_closure=execution_closure,
                resolved_external_environment=environment,
                out=root / "plan",
            )
            self.assertEqual(plan["status"], "complete")
            self.assertEqual(len(plan["seh_protocols"]), 1)
            seh = plan["seh_protocols"][0]
            self.assertEqual(
                seh["exceptional_transition"],
                {"id": transition_id, "sha256": transition_sha256},
            )
            self.assertEqual(seh["exception"]["code"], 0xC0000094)
            self.assertTrue(seh["exception"]["continuable"])
            self.assertEqual(seh["portals"], [{
                "source_rva": 0x1000,
                "candidate_symbol": (
                    "spx_exception_portal_" + transition_sha256[:24]
                ),
            }])
            self.assertTrue(all(
                "exceptional" in next(
                    protocol["outcomes"]
                    for protocol in plan["outcome_protocols"]
                    if protocol["id"] == ingress["outcome_protocol_id"]
                )
                for ingress in plan["ingresses"]
            ))
            self.assertEqual(plan["required_support_imports"], [{
                "dll": "kernel32.dll",
                "symbol": "RaiseException",
                "ordinal": None,
                "purpose": "checked_exception_escape",
                "ownership": "runtime_support",
            }])

            stale_closure = json.loads(
                execution_closure.read_text(encoding="utf-8")
            )
            stale_transition = stale_closure["exception_continuations"][0]
            stale_transition.update({
                "resumption_unit_id": "semantic-transfer:missing-continuation",
                "resumption_rva": 0x1120,
                "state_projection": {
                    "registers": ["edi"], "flags": [], "x87": [],
                    "stack": [], "exception_record": ["ExceptionCode"],
                    "context": ["Edi"],
                },
            })
            stale_core = {
                key: value for key, value in stale_closure.items()
                if key != "closure_sha256"
            }
            stale_closure["closure_sha256"] = canonical_sha256_v3(stale_core)
            write_json(execution_closure, stale_closure)
            with self.assertRaisesRegex(
                NativeIngressError,
                "exception continuations are malformed",
            ):
                write_native_ingress_plan(
                    module_interface=interface_root / "module-interface.json",
                    behavioral_roots=roots_path,
                    object_authority=objects / "machine-object-authority.json",
                    transfer_plan=transfer_plan,
                    execution_closure=execution_closure,
                    resolved_external_environment=environment,
                    out=root / "blocked-plan",
                )

    def test_checked_call_exception_uses_exact_instruction_portal(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            original = root / "fixture.dll"
            original.write_bytes(pe32_export_image(
                b"\xc3" + b"\x90" * 15 + b"\xc3",
                symbol="Ping",
                dll="fixture.dll",
            ))
            load_contract = root / "load.json"
            write_spx_load_image_contract(original_pe=original, out=load_contract)
            interface_root = root / "interface"
            write_pe32_module_interface(
                image_id="fixture",
                original_pe=original,
                load_image_contract=load_contract,
                out=interface_root,
            )
            roots_path = root / "behavioral-roots.json"
            write_json(roots_path, generate_behavioral_roots(original))
            objects = root / "objects"
            write_pe32_machine_object_authority_v2(
                module_interface=interface_root / "module-interface.json",
                out=objects,
            )
            unit = _machine_ir_transfer(
                rva=0x1000,
                size=9,
                mnemonic="call",
                event={
                    "kind": "external_call",
                    "instruction_rva": 0x1004,
                    "target_rva": 0,
                    "return_rva": 0x1009,
                    "dll": "kernel32.dll",
                    "symbol": "RaiseException",
                    "ordinal": None,
                    "native_exception_operations": ["divide_if"],
                },
            )
            unit["instructions"] = [
                {
                    "rva_start": 0x1000,
                    "rva_end": 0x1004,
                    "size": 4,
                    "instruction_sha256": sha256_bytes(b"four-byte-prefix"),
                    "mnemonic": "nop",
                    "operands": [],
                    "registers_read": [],
                    "registers_written": [],
                    "groups": [],
                },
                {
                    "rva_start": 0x1004,
                    "rva_end": 0x1009,
                    "size": 5,
                    "instruction_sha256": sha256_bytes(b"five-byte-call"),
                    "mnemonic": "call",
                    "operands": [],
                    "registers_read": [],
                    "registers_written": [],
                    "groups": ["call"],
                },
            ]
            transition_sha256 = "d" * 64
            transition_id = "exceptional-transition-v3:" + "e" * 64
            transfer_plan, execution_closure, environment = _write_execution_inputs(
                root,
                [unit],
                boundary_packages={"export:Ping": _checked_export_package(root)},
                runtime_support_imports=[{
                    "support": "exception_escape",
                    "identity": {
                        "dll": "kernel32.dll",
                        "symbol": "RaiseException",
                        "ordinal": None,
                    },
                    "contract": {"profile_id": "fixture"},
                    "boundary": {"schema": "fixture"},
                }],
                exception_continuations=[{
                    "unit_id": "semantic-transfer:typed-00001000",
                    "source_rva": 0x1000,
                    "effect_index": 0,
                    "fault_index": 0,
                    "fault_sha256": "f" * 64,
                    "transition_id": transition_id,
                    "transition_sha256": transition_sha256,
                    "operation": "divide_if",
                    "occurrence_kind": "call",
                    "call_index": 0,
                    "disposition": "terminates",
                    "handler_unit_id": None,
                    "handler_rva": None,
                    "resumption_unit_id": None,
                    "resumption_rva": None,
                    "unwind_unit_ids": [],
                    "state_projection": None,
                    "guard": {"op": "true"},
                    "root_rvas": [0x1000],
                }],
            )

            plan = write_native_ingress_plan(
                module_interface=interface_root / "module-interface.json",
                behavioral_roots=roots_path,
                object_authority=objects / "machine-object-authority.json",
                transfer_plan=transfer_plan,
                execution_closure=execution_closure,
                resolved_external_environment=environment,
                out=root / "plan",
            )

            self.assertEqual(plan["status"], "complete", plan["blockers"])
            self.assertEqual(plan["seh_protocols"][0]["portals"], [{
                "source_rva": 0x1004,
                "candidate_symbol": (
                    "spx_exception_portal_" + transition_sha256[:24]
                ),
            }])

    def test_process_root_exception_terminates_without_escape_import(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            original = root / "fixture.exe"
            original.write_bytes(pe32_image_with_writable_data(
                b"\xc3", relocation_offsets=[]
            ))
            load_contract = root / "load.json"
            write_spx_load_image_contract(original_pe=original, out=load_contract)
            interface_root = root / "interface"
            write_pe32_module_interface(
                image_id="fixture",
                original_pe=original,
                load_image_contract=load_contract,
                out=interface_root,
            )
            roots_path = root / "behavioral-roots.json"
            write_json(roots_path, generate_behavioral_roots(original))
            objects = root / "objects"
            write_pe32_machine_object_authority_v2(
                module_interface=interface_root / "module-interface.json",
                out=objects,
            )
            transfer_plan, execution_closure, environment = (
                _write_execution_inputs(
                    root,
                    [_machine_ir_transfer(
                        rva=0x1000, size=1, mnemonic="ret"
                    )],
                    exception_continuations=[{
                        "unit_id": "semantic-transfer:typed-00001000",
                        "source_rva": 0x1000,
                        "effect_index": 0,
                        "fault_index": 0,
                        "fault_sha256": "f" * 64,
                        "transition_id": (
                            "exceptional-transition-v3:" + "e" * 64
                        ),
                        "transition_sha256": "d" * 64,
                        "operation": "divide_if",
                        "occurrence_kind": "effect",
                        "call_index": None,
                        "disposition": "terminates",
                        "handler_unit_id": None,
                        "handler_rva": None,
                        "resumption_unit_id": None,
                        "resumption_rva": None,
                        "unwind_unit_ids": [],
                        "state_projection": None,
                        "guard": {"op": "true"},
                        "root_rvas": [0x1000],
                    }],
                )
            )
            plan = write_native_ingress_plan(
                module_interface=interface_root / "module-interface.json",
                behavioral_roots=roots_path,
                object_authority=objects / "machine-object-authority.json",
                transfer_plan=transfer_plan,
                execution_closure=execution_closure,
                resolved_external_environment=environment,
                out=root / "plan",
            )
            self.assertEqual(plan["status"], "complete", plan["blockers"])
            self.assertEqual(plan["required_support_imports"], [])
            self.assertIn(
                "checked_process_root_termination_v1",
                plan["runtime_requirements"]["features"],
            )
            self.assertEqual(
                plan["seh_protocols"][0]["escape_disposition"],
                "terminate_process_root",
            )
            source = render_native_ingress_source(plan)
            termination = source.index("if (seh->escape_disposition == 1U)")
            escape_import = source.index(
                "if (spx_native_raise_exception_iat_pointer == 0"
            )
            self.assertLess(termination, escape_import)
            self.assertIn("spx_native_terminate(", source[termination:escape_import])

    def test_checked_handler_object_projection_blocks_native_ingress(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            original = root / "fixture.dll"
            original.write_bytes(pe32_export_image(
                b"\xc3" + b"\x90" * 15 + b"\xc3",
                symbol="Ping",
                dll="fixture.dll",
            ))
            load_contract = root / "load.json"
            write_spx_load_image_contract(original_pe=original, out=load_contract)
            interface_root = root / "interface"
            write_pe32_module_interface(
                image_id="fixture",
                original_pe=original,
                load_image_contract=load_contract,
                out=interface_root,
            )
            roots_path = root / "behavioral-roots.json"
            write_json(roots_path, generate_behavioral_roots(original))
            objects = root / "objects"
            write_pe32_machine_object_authority_v2(
                module_interface=interface_root / "module-interface.json",
                out=objects,
            )
            transition_sha256 = "d" * 64
            transfer_plan, execution_closure, environment = (
                _write_execution_inputs(
                    root,
                    [
                        _machine_ir_transfer(
                            rva=0x1000, size=0x10, mnemonic="ret"
                        ),
                        _machine_ir_transfer(
                            rva=0x1010, size=1, mnemonic="ret"
                        ),
                    ],
                    boundary_packages={
                        "export:Ping": _checked_export_package(root)
                    },
                    exception_continuations=[{
                        "unit_id": "semantic-transfer:typed-00001000",
                        "source_rva": 0x1000,
                        "effect_index": 0,
                        "fault_index": 0,
                        "fault_sha256": "f" * 64,
                        "transition_id": (
                            "exceptional-transition-v3:" + "e" * 64
                        ),
                        "transition_sha256": transition_sha256,
                        "operation": "divide_if",
                        "occurrence_kind": "effect",
                        "call_index": None,
                        "disposition": "handled",
                        "handler_unit_id": (
                            "semantic-transfer:typed-00001010"
                        ),
                        "handler_rva": 0x1010,
                        "resumption_unit_id": None,
                        "resumption_rva": None,
                        "unwind_unit_ids": [],
                        "state_projection": {
                            "registers": [],
                            "flags": [],
                            "x87": [],
                            "stack": [],
                            "exception_record": [
                                "ExceptionCode",
                                "ExceptionRecord[1].ExceptionCode",
                            ],
                            "context": ["eax"],
                        },
                        "guard": {"op": "true"},
                        "root_rvas": [0x1000],
                    }],
                )
            )
            plan = write_native_ingress_plan(
                module_interface=interface_root / "module-interface.json",
                behavioral_roots=roots_path,
                object_authority=objects / "machine-object-authority.json",
                transfer_plan=transfer_plan,
                execution_closure=execution_closure,
                resolved_external_environment=environment,
                out=root / "plan",
            )
            self.assertEqual(plan["status"], "incomplete")
            self.assertIn(
                {
                    "category": (
                        "native_ingress_exception_object_"
                        "materialization_unavailable"
                    ),
                    "seh_protocol_id": plan["seh_protocols"][0]["id"],
                    "required_authority": "checked_guest_resumption",
                    "exception_record_fields": [
                        "ExceptionCode",
                        "ExceptionRecord[1].ExceptionCode",
                    ],
                    "context_fields": ["eax"],
                },
                plan["blockers"],
            )
            self.assertNotIn(
                "checked_seh_protocol_incomplete",
                {row["category"] for row in plan["blockers"]},
            )

    def test_numeric_original_exception_address_fails_without_pinned_layout(self) -> None:
        protocol = CheckedSEHProtocolV1.create(
            transition_id="exception:divide", transition_sha256="a" * 64,
            exception={
                "code": 0xC0000094, "flags_mask": 0, "flags_value": 0,
                "parameter_count": 0, "continuable": True,
                "access_violation": None,
            },
            projections={
                "registers": ["eax"], "flags": ["eflags"], "x87": [],
                "stack": ["esp"], "exception_record": ["ExceptionAddress"],
                "context": ["Eip"],
            },
            handler_unit_id="unit:handler", handler_rva=0x1100,
            resumption_unit_id="unit:resume", resumption_rva=0x1120,
            unwind_effect_ids=[], escape_disposition="escape_callable_root",
            gateway_handler_symbol="spx_seh_gateway_divide",
            portals=[{"source_rva": 0x1010, "candidate_symbol": "spx_exception_1010"}],
            observed_address_fields=["Eip", "ExceptionAddress"],
        )
        self.assertEqual(protocol.status, "incomplete")
        self.assertIn(
            "numeric_original_exception_address_requires_pinned_layout",
            protocol.issues,
        )

    def test_nested_exception_record_projection_is_bounded_and_canonical(
        self,
    ) -> None:
        protocol = CheckedSEHProtocolV1.create(
            transition_id="exception:nested", transition_sha256="a" * 64,
            exception={
                "code": 0xE0000001, "flags_mask": 0, "flags_value": 0,
                "parameter_count": 0, "continuable": True,
                "access_violation": None,
            },
            projections={
                "registers": [], "flags": [], "x87": [], "stack": [],
                "exception_record": ["ExceptionRecord[1].ExceptionCode"],
                "context": [],
            },
            handler_unit_id="unit:handler", handler_rva=0x1100,
            resumption_unit_id="unit:resume", resumption_rva=0x1120,
            unwind_effect_ids=[], escape_disposition="escape_callable_root",
            gateway_handler_symbol="spx_native_seh_gateway",
            portals=[{
                "source_rva": 0x1010,
                "candidate_symbol": "spx_exception_1010",
            }],
        )
        self.assertEqual(protocol.status, "complete")
        self.assertEqual(protocol.issues, ())
        self.assertEqual(
            CheckedSEHProtocolV1.parse(protocol.to_payload()), protocol
        )
        self.assertEqual(
            _seh_projection_masks(protocol.to_payload()),
            (0, 0, 0, 0, 0x004, 0),
        )
