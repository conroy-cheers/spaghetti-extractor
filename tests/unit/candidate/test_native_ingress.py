from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from tests.pe_fixtures import pe32_data_export_image, pe32_export_image
from tests.unit.candidate.native_engine._support import (
    _machine_ir_transfer,
    _native_ingress_plan,
)

from spaghetti_extractor.artifacts.artifact_set import canonical_sha256_v3
from spaghetti_extractor.candidate.native_ingress import (
    write_native_ingress_link_receipt,
    write_native_ingress_plan,
    write_pe32_machine_object_authority_v2,
)
from spaghetti_extractor.candidate.native_ingress_derivation import (
    _reviewed_loader_call,
)
from spaghetti_extractor.candidate.native_ingress_runtime import (
    _capability_lifetime,
    _seh_projection_masks,
    render_native_ingress_assembly,
    render_native_ingress_header,
    render_native_ingress_source,
)
from spaghetti_extractor.candidate.module_composer import compose_pe32_native_module
from spaghetti_extractor.candidate.outcomes import CheckedSEHProtocolV1
from spaghetti_extractor.candidate.project import write_pe32_module_interface
from spaghetti_extractor.calls.frame import PhysicalCallFrameV2
from spaghetti_extractor.errors import ToolkitInputError
from spaghetti_extractor.pe32.behavioral_roots import generate_behavioral_roots
from spaghetti_extractor.roundtrip_fuzz.image_io import write_spx_load_image_contract
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
        package / "boundary-lifecycle-receipt.json",
        checked["lifecycle_receipt"],
    )
    return package


class NativeIngressTests(unittest.TestCase):
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
            "{ 0U, 0x00001010U, 0U, 1U, 0U, 1U, 1U, 0x0000000fU },",
            source,
        )

        protected = json.loads(json.dumps(plan))
        protected["ingresses"][0].update({
            "role": "callback",
            "capability_id": "fixture-callback-two",
        })
        source = render_native_ingress_source(protected)
        self.assertIn(
            "{ 0U, 0x00001010U, 0U, 1U, 0U, 2U, 0U, 0x0000000fU },",
            source,
        )
        self.assertIn("capability_active |= __atomic_load_n", source)

    def test_seh_x87_context_projection_is_typed_and_complete(self) -> None:
        self.assertEqual(
            _seh_projection_masks({
                "projections": {
                    "registers": ["eax"],
                    "flags": ["eflags"],
                    "stack": ["esp"],
                    "context": [],
                    "x87": ["control_word", "status_word", "stack", "environment"],
                }
            }),
            (0x20, 1, 1, 0xFF),
        )
        plan = _native_ingress_plan(0x1010)
        plan["seh_protocols"] = [{
            "exception": {
                "code": 0xC0000094,
                "flags_mask": 0,
                "flags_value": 0,
                "parameter_count": 0,
                "continuable": True,
                "access_violation": None,
            },
            "projections": {
                "registers": ["eax"],
                "flags": ["eflags"],
                "stack": ["esp"],
                "context": [],
                "x87": ["all"],
            },
            "escape_disposition": "escape_callable_root",
            "handler_rva": 0x1100,
            "resumption_rva": 0x1120,
            "gateway_handler_symbol": "spx_seh_gateway_divide",
            "portals": [{
                "source_rva": 0x1010,
                "candidate_symbol": "spx_exception_1010",
            }],
        }]
        source = render_native_ingress_source(plan)
        self.assertIn("spx_native_import_context_x87", source)
        self.assertIn("spx_native_capture_current_x87", source)
        compiler = shutil.which("i686-w64-mingw32-gcc")
        if compiler is not None:
            with tempfile.TemporaryDirectory() as temporary:
                assembly = Path(temporary) / "seh-ingress.s"
                assembly.write_text(
                    render_native_ingress_assembly(plan), encoding="ascii"
                )
                subprocess.run(
                    [compiler, "-c", str(assembly), "-o", str(assembly.with_suffix(".o"))],
                    check=True,
                    text=True,
                    capture_output=True,
                )

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
            machine_ir = root / "machine-ir.jsonl"
            machine_ir.write_text(
                json.dumps(
                    _machine_ir_transfer(rva=0x1000, size=1, mnemonic="ret"),
                    sort_keys=True,
                ) + "\n",
                encoding="utf-8",
            )
            closure = root / "root-closure"
            closure.mkdir()
            write_json(closure / "manifest.json", {"format": "fixture-root-closure-v1"})
            plan_root = root / "plan"
            plan = write_native_ingress_plan(
                module_interface=interface_root / "module-interface.json",
                behavioral_roots=roots_path,
                object_authority=root / "objects" / "machine-object-authority.json",
                machine_ir=machine_ir,
                root_closure=closure,
                out=plan_root,
            )
            self.assertEqual(plan["status"], "complete")
            linker_map = root / "fixture.map"
            linker_map.write_text(
                "0x00501000 _spx_ingress_0000\n"
                "0x00502004 _spx_native_tls_index_cell_pointer\n",
                encoding="ascii",
            )
            link_root = root / "link"
            write_native_ingress_link_receipt(
                native_ingress_plan=plan_root / "native-ingress-plan.json",
                linked_module=original,
                linker_map=linker_map,
                out=link_root,
            )
            base_manifest = root / "base-composition.json"
            write_json(base_manifest, {
                "format": "fixture-linked-module-v1",
                "status": "composed",
                "candidate": {"sha256": sha256_file(original)},
            })
            compose_pe32_native_module(
                base_candidate=original,
                base_composition_manifest=base_manifest,
                original_module_interface=interface_root / "module-interface.json",
                native_ingress_plan=plan_root / "native-ingress-plan.json",
                native_ingress_link_receipt=(
                    link_root / "native-ingress-link-receipt.json"
                ),
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
            machine_ir = root / "machine-ir.jsonl"
            machine_ir.write_text(json.dumps(unit, sort_keys=True) + "\n", encoding="utf-8")
            closure = root / "root-closure"
            closure.mkdir()
            write_json(closure / "manifest.json", {"format": "fixture-root-closure-v1"})
            plan_root = root / "plan"
            plan = write_native_ingress_plan(
                module_interface=interface_root / "module-interface.json",
                behavioral_roots=roots_path,
                object_authority=objects / "machine-object-authority.json",
                machine_ir=machine_ir,
                root_closure=closure,
                call_protocol_packages=[_checked_export_package(root)],
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
            self.assertIn("SPX_NATIVE_TLS_RUNTIME_OFFSET", render_native_ingress_header(plan))

            linker_map = root / "fixture.map"
            linker_map.write_text(
                "0x00501010 _spx_ingress_0000\n"
                "0x00502100 _spx_native_tls_index_cell_pointer\n",
                encoding="ascii",
            )
            receipt = write_native_ingress_link_receipt(
                native_ingress_plan=plan_root / "native-ingress-plan.json",
                linked_module=original,
                linker_map=linker_map,
                out=root / "link",
            )
            self.assertEqual(receipt["status"], "complete")
            self.assertEqual(
                {row["symbol"] for row in receipt["symbols"]},
                {"spx_ingress_0000", "spx_native_tls_index_cell_pointer"},
            )
            base_manifest = root / "base-composition.json"
            write_json(base_manifest, {
                "format": "fixture-linked-module-v1",
                "status": "composed",
                "candidate": {"sha256": sha256_file(original)},
            })
            composed = compose_pe32_native_module(
                base_candidate=original,
                base_composition_manifest=base_manifest,
                original_module_interface=interface_root / "module-interface.json",
                native_ingress_plan=plan_root / "native-ingress-plan.json",
                native_ingress_link_receipt=(
                    root / "link" / "native-ingress-link-receipt.json"
                ),
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


if __name__ == "__main__":
    unittest.main()
