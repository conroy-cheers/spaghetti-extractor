from __future__ import annotations

from tests.unit.candidate.native_engine._support import *


class NativeEngineCallbackModelTests(NativeEngineTestCase):
    def test_callback_result_saved_to_a_dominating_slot_is_passed_through(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            abi = {
                "world_effect": "callbackRegistration",
                "callback_source": {"kind": "argument_word", "argument": 0},
                "argument_words": 1,
                "argument_base_offset": 0,
                "callback_abi": {
                    "kind": "generic_callback",
                    "argument_words": 1,
                    "stack_cleanup_bytes": 4,
                    "nullable": True,
                },
                "callback_result": {
                    "register": "eax",
                    "origin": "previous_registered_callback",
                    "nullable": True,
                },
            }
            first = _machine_ir_transfer(event={
                "kind": "external_call",
                "instruction_rva": 0x1000,
                "return_rva": 0x1001,
                "dll": "kernel32.dll",
                "symbol": "SetHandler",
                "ordinal": None,
                "arguments": [{"op": "const", "value": 0, "width": 32}],
                "stack_inputs": [{
                    "offset": 0,
                    "width": 4,
                    "value": {"op": "const", "value": 0, "width": 32},
                }],
                "abi_contract": abi,
            }, rva=0x1000, size=1)
            write = _machine_ir_transfer(rva=0x1001, size=1, mnemonic="mov")
            write["semantics"]["ordered_events"] = [{
                "family": "memory",
                "kind": "write",
                "instruction_rva": 0x1001,
                "address": {"op": "const", "value": 0x430000, "width": 32},
                "width": 4,
                "value": {"op": "reg", "name": "eax", "width": 32},
            }]
            write["semantics"]["outcome"] = {
                "kind": "fallthrough",
                "target_rva": 0x1002,
            }
            second = _machine_ir_transfer(event={
                "kind": "external_call",
                "instruction_rva": 0x1002,
                "return_rva": 0x1003,
                "dll": "kernel32.dll",
                "symbol": "SetHandler",
                "ordinal": None,
                "arguments": [{
                    "op": "load",
                    "address": {"op": "const", "value": 0x430000, "width": 32},
                    "width": 4,
                }],
                "stack_inputs": [{
                    "offset": 0,
                    "width": 4,
                    "value": {
                        "op": "load",
                        "address": {"op": "const", "value": 0x430000, "width": 32},
                        "width": 4,
                    },
                }],
                "abi_contract": abi,
            }, rva=0x1002, size=1)
            machine = self._write(root, [first, write, second])

            plan = plan_stage_b_native_engine(
                machine_ir=machine,
                entry_rva=0x1000,
                import_iat_vas={("kernel32.dll", "SetHandler"): 0x432000},
            )

            self.assertEqual(plan.status, "ready", plan.blockers)
            self.assertEqual(len(plan.callback_passthroughs), 1)
            self.assertEqual(plan.callback_passthroughs[0].storage_va, 0x430000)
            self.assertEqual(
                plan.callback_passthroughs[0].storage_invariant,
                "dominating_previous_registered_callback",
            )

    def test_nullable_callback_result_slot_accepts_checked_initial_zero(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            abi = {
                "world_effect": "callbackRegistration",
                "callback_source": {"kind": "argument_word", "argument": 0},
                "argument_words": 1,
                "argument_base_offset": 0,
                "callback_abi": {
                    "kind": "generic_callback",
                    "argument_words": 1,
                    "stack_cleanup_bytes": 4,
                    "nullable": True,
                },
                "callback_result": {
                    "register": "eax",
                    "origin": "previous_registered_callback",
                    "nullable": True,
                },
            }
            first = _machine_ir_transfer(event={
                "kind": "external_call",
                "instruction_rva": 0x1000,
                "return_rva": 0x1001,
                "dll": "kernel32.dll",
                "symbol": "SetHandler",
                "ordinal": None,
                "arguments": [{"op": "const", "value": 0, "width": 32}],
                "stack_inputs": [{
                    "offset": 0,
                    "width": 4,
                    "value": {"op": "const", "value": 0, "width": 32},
                }],
                "abi_contract": abi,
            }, rva=0x1000, size=1)
            write = _machine_ir_transfer(rva=0x1001, size=1, mnemonic="mov")
            write["semantics"]["ordered_events"] = [{
                "family": "memory",
                "kind": "write",
                "instruction_rva": 0x1001,
                "address": {"op": "const", "value": 0x430000, "width": 32},
                "width": 4,
                "value": {"op": "reg", "name": "eax", "width": 32},
            }]
            write["semantics"]["outcome"] = {"kind": "return"}
            second = _machine_ir_transfer(event={
                "kind": "external_call",
                "instruction_rva": 0x2000,
                "return_rva": 0x2001,
                "dll": "kernel32.dll",
                "symbol": "SetHandler",
                "ordinal": None,
                "arguments": [{
                    "op": "load",
                    "address": {"op": "const", "value": 0x430000, "width": 32},
                    "width": 4,
                }],
                "stack_inputs": [{
                    "offset": 0,
                    "width": 4,
                    "value": {
                        "op": "load",
                        "address": {"op": "const", "value": 0x430000, "width": 32},
                        "width": 4,
                    },
                }],
                "abi_contract": abi,
            }, rva=0x2000, size=1)
            machine = self._write(root, [first, write, second])

            without_zero = plan_stage_b_native_engine(
                machine_ir=machine,
                entry_rva=0x1000,
                import_iat_vas={("kernel32.dll", "SetHandler"): 0x432000},
            )
            self.assertEqual(without_zero.status, "incomplete")

            plan = plan_stage_b_native_engine(
                machine_ir=machine,
                entry_rva=0x1000,
                import_iat_vas={("kernel32.dll", "SetHandler"): 0x432000},
                initial_zero_ranges=((0x430000, 0x431000),),
            )
            self.assertEqual(plan.status, "ready", plan.blockers)
            self.assertEqual(
                plan.callback_passthroughs[0].storage_invariant,
                "initial_zero_or_previous_registered_callback",
            )

    def test_tls_callback_plan_binds_exact_transfer_abi_and_export_symbol(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            machine = self._write(root, [_transfer()])
            callback = {
                "rva": 0x1420,
                "kind": "tls_callback",
                "stack_cleanup_bytes": 12,
            }
            plan = plan_stage_b_native_engine(
                state_machine=machine,
                entry_rva=0x1420,
                callback_targets=[callback],
            )
            self.assertEqual(plan.status, "ready", plan.blockers)
            target = plan.callback_targets[0]
            self.assertEqual(target.kind, "tls_callback")
            self.assertEqual(target.stack_cleanup_bytes, 12)
            self.assertEqual(target.symbol, "stage_b_payload_callback_00001420")
            payload = plan.payload(state_machine_sha256=sha256_bytes(machine.read_bytes()))
            self.assertEqual(payload["callback_targets"], [0x1420])
            self.assertEqual(
                payload["callback_abis"][0]["symbol"],
                "stage_b_payload_callback_00001420",
            )
            self.assertRegex(payload["callback_abis"][0]["transfer_sha256"], r"^[0-9a-f]{64}$")
            package = root / "callback-package"
            write_stage_b_native_engine_package(
                state_machine=machine,
                entry_rva=0x1420,
                callback_targets=[callback],
                out=package,
            )
            assembly = (package / "native-engine-bridges.S").read_text(
                encoding="ascii"
            )
            callback_assembly = assembly.split(
                "stage_b_payload_callback_00001420:", 1
            )[1]
            entry_assembly = assembly.split("stage_b_payload_entry:", 1)[1].split(
                "stage_b_native_entry_dispatch_return:", 1
            )[0]
            wrapper = (package / "native-engine-wrapper.c").read_text(
                encoding="ascii"
            )
            self.assertIn("_stage_b_native_callback_failure_0000", callback_assembly)
            self.assertIn("_stage_b_native_root_callback_fault", callback_assembly)
            self.assertIn("stage_b_native_root_callback_fault_rva = callback_rva;", wrapper)
            self.assertIn("stage_b_native_root_callback_fault_state = *output;", wrapper)
            self.assertIn(
                "mov esp, OFFSET FLAT:_stage_b_native_callback_stack + 65536",
                entry_assembly,
            )
            self.assertIn("and esp, -16", entry_assembly)
            self.assertNotIn("jne _stage_b_native_halt", callback_assembly)

    def test_generic_callback_requires_and_records_explicit_cleanup(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            plan = plan_stage_b_native_engine(
                state_machine=self._write(root, [_transfer()]),
                entry_rva=0x1420,
                callback_targets=[{
                    "rva": 0x1420,
                    "kind": "generic_callback",
                    "stack_cleanup_bytes": 8,
                }],
            )
            self.assertEqual(plan.status, "ready", plan.blockers)
            self.assertEqual(plan.callback_targets[0].stack_cleanup_bytes, 8)

    def test_structured_callback_uses_hash_bound_provenance_and_patches_field(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = {
                "kind": "argument_pointee",
                "argument": 0,
                "offset": 4,
            }
            callback_abi = {
                "kind": "generic_callback",
                "argument_words": 4,
                "stack_cleanup_bytes": 16,
                "nullable": False,
            }
            registration = _machine_ir_transfer(
                rva=0x2000,
                size=6,
                event={
                    "kind": "external_call",
                    "instruction_rva": 0x2000,
                    "return_rva": 0x2006,
                    "dll": "user32.dll",
                    "symbol": "RegisterClassA",
                    "ordinal": None,
                    "arguments": [
                        {"op": "reg", "name": "eax", "width": 32}
                    ],
                    "stack_inputs": [{
                        "offset": 0,
                        "width": 4,
                        "value": {
                            "op": "reg",
                            "name": "eax",
                            "width": 32,
                        },
                    }],
                    "abi_contract": {
                        "template": "pe32-stdcall-v1",
                        "argument_words": 1,
                        "argument_base_offset": 0,
                        "contract_id": "register-class-a",
                        "profile_binding": {
                            "profile_id": "fixture-user32",
                            "profile_sha256": "1" * 64,
                            "entry_key": "machine_import_signatures",
                            "entry_index": 0,
                        },
                        "disposition": "returns",
                        "result_register_relations": [
                            {"register": "eax", "relation": "exact"}
                        ],
                        "memory_effect": "argumentRanges",
                        "memory_footprints": [],
                        "world_effect": "callbackRegistration",
                        "callback_effect": "explicit",
                        "callback_source": source,
                        "callback_lifetime": (
                            "until_class_unregistered_or_process_exit"
                        ),
                        "callback_abi": callback_abi,
                    },
                },
            )
            callback = _machine_ir_transfer(
                rva=0x3000, size=1, mnemonic="ret"
            )
            callback["semantics"]["outcome"] = {"kind": "return"}
            machine = self._write(root, [registration, callback])
            manifest = root / "machine-ir-manifest.json"
            callback_evidence = {
                "format": "stage-a-callback-registration-provenance-v1",
                "record_kind": "callback_registration",
                "status": "complete",
                "unit_id": registration["id"],
                "event_index": 0,
                "instruction_rva": 0x2000,
                "callback_source": source,
                "callback_abi": callback_abi,
                "callback_lifetime": (
                    "until_class_unregistered_or_process_exit"
                ),
                "callback_behavior": "registration",
                "target_rvas": [0x3000],
                "target_unit_ids": [callback["id"]],
                "failure": None,
            }
            manifest.write_text(json.dumps({
                "format": "stage-a-machine-ir-v2",
                "artifacts": {
                    "machine_ir": {
                        "format": "stage-a-machine-ir-v2",
                        "sha256": sha256_bytes(machine.read_bytes()),
                    },
                },
                "control": {
                    "internal_call_preservation": {
                        "fixed_point_complete": True,
                        "summaries": [],
                    },
                    "external_interface_provenance": {
                        "callback_registrations": [callback_evidence],
                    },
                },
            }), encoding="utf-8")

            identity_payload = {
                "kind": "import",
                "dll": "user32.dll",
                "symbol": "RegisterClassA",
                "ordinal": None,
            }
            checked_contract = checked_external_site_contract_from_event(
                event=registration["semantics"]["external_events"][0],
                identity=ExternalSiteIdentity.imported(
                    identity_payload, context="callback fixture"
                ),
                transfer_kind="call",
                disposition="returns_here",
                callback_evidence=callback_evidence,
                context="callback fixture",
            )
            canonical_external_sites = _canonical_external_sites(
                root,
                unit=registration,
                event_index=0,
                identity=identity_payload,
                contract=checked_contract,
                callback_target_rvas=(0x3000,),
            )

            plan = plan_stage_b_native_engine(
                machine_ir=machine,
                machine_ir_manifest=manifest,
                entry_rva=0x2000,
                import_iat_vas={
                    ("user32.dll", "RegisterClassA"): 0x432000
                },
                base_relocation_evidence=_relocation_evidence([]),
                canonical_external_sites=canonical_external_sites,
            )

            self.assertEqual(plan.status, "ready", plan.blockers)
            self.assertEqual([item.rva for item in plan.callback_targets], [0x3000])
            self.assertEqual(
                plan.external_sites[0].callback_source_kind,
                "argument_pointee",
            )
            self.assertEqual(len(plan.callback_adapter_receipts), 1)
            receipt = plan.callback_adapter_receipts[0].payload()
            self.assertEqual(receipt["source"], source)
            self.assertEqual(receipt["abi"], callback_abi)
            self.assertEqual(
                receipt["lifetime"],
                "until_class_unregistered_or_process_exit",
            )
            self.assertEqual(
                receipt["invocation"],
                "nested-machine-ir-callback-adapter-v1",
            )
            self.assertEqual(receipt["target_rvas"], [0x3000])
            self.assertEqual(
                receipt["adapter_entries"],
                [plan.callback_adapters[0].payload()],
            )
            self.assertRegex(receipt["receipt_sha256"], r"^[0-9a-f]{64}$")
            package = root / "package"
            result = write_stage_b_native_engine_package(
                machine_ir=machine,
                machine_ir_manifest=manifest,
                entry_rva=0x2000,
                import_iat_vas={
                    ("user32.dll", "RegisterClassA"): 0x432000
                },
                base_relocation_evidence=_relocation_evidence([]),
                canonical_external_sites=canonical_external_sites,
                out=package,
            )
            self.assertEqual(result["callback_adapter_receipts"], [receipt])
            wrapper = (package / "native-engine-wrapper.c").read_text(
                encoding="ascii"
            )
            self.assertIn("stage_b_native_callback_adapter_for(", wrapper)
            self.assertIn("callback_container_address", wrapper)
            self.assertIn("entry->callback_pointee_offset", wrapper)


if __name__ == "__main__":
    unittest.main()
