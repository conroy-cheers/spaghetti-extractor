from __future__ import annotations

from tests.unit.candidate.native_engine._support import *


class NativeEngineValidationTests(NativeEngineTestCase):
    def test_register_iat_origin_fails_closed_at_ambiguous_join(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            rows = []
            for rva, iat in ((0x1000, 0x43219C), (0x2000, 0x4321A0)):
                row = _machine_ir_transfer(rva=rva, size=6, mnemonic="mov")
                row["semantics"]["register_writes"] = [{
                    "register": "edi",
                    "value": {
                        "op": "load",
                        "width": 4,
                        "address": {"op": "const", "width": 32, "value": iat},
                    },
                }]
                row["semantics"]["outcome"] = {
                    "kind": "jump", "target_rva": 0x3000
                }
                rows.append(row)
            rows.append(_machine_ir_transfer(
                event={
                    "kind": "indirect_call",
                    "instruction_rva": 0x3000,
                    "return_rva": 0x3002,
                    "target": {"op": "reg", "name": "edi", "width": 32},
                },
                rva=0x3000,
                size=2,
            ))

            plan = plan_stage_b_native_engine(
                machine_ir=self._write(root, rows),
                entry_rva=0x1000,
                import_iat_vas={
                    ('kernel32.dll', 'VirtualAlloc'): 0x43219C,
                    ('kernel32.dll', 'VirtualFree'): 0x4321A0,
                },
            )

            self.assertIsNone(plan.external_sites[0].iat_va)
            self.assertIsNone(plan.external_sites[0].dll)

    def test_register_iat_origin_fails_closed_after_overwrite(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            load = _machine_ir_transfer(rva=0x1000, size=6, mnemonic="mov")
            load["semantics"]["register_writes"] = [{
                "register": "edi",
                "value": {
                    "op": "load", "width": 4,
                    "address": {"op": "const", "width": 32, "value": 0x43219C},
                },
            }]
            overwrite = _machine_ir_transfer(rva=0x1006, size=1, mnemonic="xor")
            overwrite["semantics"]["register_writes"] = [{
                "register": "edi",
                "value": {"op": "const", "width": 32, "value": 0},
            }]
            call = _machine_ir_transfer(
                event={
                    "kind": "indirect_call",
                    "instruction_rva": 0x1007,
                    "return_rva": 0x1009,
                    "target": {"op": "reg", "name": "edi", "width": 32},
                },
                rva=0x1007,
                size=2,
            )

            plan = plan_stage_b_native_engine(
                machine_ir=self._write(root, [load, overwrite, call]),
                entry_rva=0x1000,
                import_iat_vas={('kernel32.dll', 'VirtualAlloc'): 0x43219C},
            )

            self.assertIsNone(plan.external_sites[0].iat_va)

    def test_byte_free_iat_loaded_indirect_bridge_rejects_ambiguous_identity(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            target = {
                "op": "load",
                "width": 4,
                "address": {"op": "const", "value": 0x43219C, "width": 32},
            }
            unit = _machine_ir_transfer(
                event={
                    "kind": "indirect_call",
                    "instruction_rva": 0x142A,
                    "return_rva": 0x142C,
                    "target": target,
                },
                size=2,
            )
            del unit["semantics"]["ordered_events"][0]["arguments"]

            with self.assertRaisesRegex(StageAInputError, "ambiguous import"):
                plan_stage_b_native_engine(
                    machine_ir=self._write(root, [unit]),
                    entry_rva=0x142A,
                    import_iat_vas={
                        ("msvcrt.dll", "__p___argv"): 0x43219C,
                        ("msvcrt.dll", "__p__environ"): 0x43219C,
                    },
                )

    def test_byte_free_bridge_rejects_incomplete_abi_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            unit = _machine_ir_transfer(event={
                "kind": "external_call",
                "instruction_rva": 0x142A,
                "return_rva": 0x1430,
                "dll": "kernel32.dll",
                "symbol": "Sleep",
                "ordinal": None,
            })
            del unit["semantics"]["ordered_events"][0]["flag_inputs"]
            with self.assertRaises(StageAInputError):
                plan_stage_b_native_engine(
                    machine_ir=self._write(root, [unit]),
                    entry_rva=0x142A,
                    import_iat_vas={("kernel32.dll", "Sleep"): 0x43219C},
                )

    def test_relative_import_call_requires_exact_original_iat_binding(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            row = _transfer(event={
                "kind": "external_call",
                "instruction_rva": 0x142A,
                "return_rva": 0x142F,
                "dll": "kernel32.dll",
                "symbol": "Sleep",
                "ordinal": None,
            })
            row["instructions"][0].update({
                "bytes": "e8d10b0000",
                "size": 5,
                "mnemonic": "call",
                "op_str": "0x2000",
            })
            machine = self._write(root, [row])
            missing = plan_stage_b_native_engine(
                state_machine=machine, entry_rva=0x1420
            )
            bound = plan_stage_b_native_engine(
                state_machine=machine,
                entry_rva=0x1420,
                import_iat_vas={("kernel32.dll", "Sleep"): 0x43219C},
            )
            self.assertEqual(missing.status, "incomplete")
            self.assertEqual(
                missing.blockers[0]["category"], "external_import_iat_evidence_missing"
            )
            self.assertEqual(bound.status, "ready")
            self.assertEqual(bound.external_sites[0].iat_va, 0x43219C)

    def test_diagnostic_import_origin_rejects_conflicting_branch_join(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            first_iat = 0x43219C
            second_iat = 0x4321A0
            branch = _machine_ir_transfer(rva=0x1000, size=2, mnemonic="jcc")
            branch["semantics"]["outcome"] = {
                "kind": "branch",
                "true_target_rva": 0x1010,
                "false_target_rva": 0x1020,
            }

            def load_import(rva: int, iat_va: int) -> dict:
                row = _machine_ir_transfer(rva=rva, size=6, mnemonic="mov")
                row["semantics"]["register_writes"] = [{
                    "register": "ebx",
                    "value": {
                        "op": "load",
                        "width": 4,
                        "address": {
                            "op": "const",
                            "value": iat_va,
                            "width": 32,
                        },
                    },
                }]
                row["semantics"]["outcome"] = {
                    "kind": "jump",
                    "target_rva": 0x1030,
                }
                return row

            indirect = _machine_ir_transfer(
                rva=0x1030,
                size=2,
                event={
                    "kind": "indirect_call",
                    "instruction_rva": 0x1030,
                    "return_rva": 0x1032,
                    "target": {"op": "reg", "name": "ebx", "width": 32},
                },
            )
            machine = self._write(root, [
                branch,
                load_import(0x1010, first_iat),
                load_import(0x1020, second_iat),
                indirect,
            ])

            diagnostic = plan_stage_b_native_engine(
                machine_ir=machine,
                entry_rva=0x1000,
                import_iat_vas={
                    ("kernel32.dll", "HeapAlloc"): first_iat,
                    ("kernel32.dll", "HeapFree"): second_iat,
                },
                candidate_mode=STRUCTURAL_DIAGNOSTIC_CANDIDATE_MODE,
            )

            site = next(
                item for item in diagnostic.external_sites
                if item.instruction_rva == 0x1030
            )
            self.assertEqual((site.dll, site.symbol, site.iat_va), (None, None, None))
            self.assertIsNone(site.target_resolution_evidence)
            self.assertNotIn(
                "diagnostic_internal_call_abi_hypothesis",
                {item["category"] for item in diagnostic.diagnostic_frontiers},
            )

    def test_tls_callback_rejects_non_stdcall_cleanup(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            plan = plan_stage_b_native_engine(
                state_machine=self._write(root, [_transfer()]),
                entry_rva=0x1420,
                callback_targets=[{
                    "rva": 0x1420,
                    "kind": "tls_callback",
                    "stack_cleanup_bytes": 0,
                }],
            )
            self.assertEqual(plan.status, "incomplete")
            self.assertEqual(plan.blockers[0]["category"], "callback_abi_ambiguous")

    def test_callback_registration_without_checked_contract_cannot_authorize_adapter(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            callback_va = 0x403000
            caller = _machine_ir_transfer(
                rva=0x1400,
                size=5,
                event={
                    "kind": "internal_call",
                    "instruction_rva": 0x1400,
                    "return_rva": 0x1405,
                    "target_rva": 0x2000,
                    "stack_inputs": [{
                        "offset": 0,
                        "width": 4,
                        "value": {"op": "const", "value": callback_va, "width": 32},
                    }],
                },
            )
            thunk = _machine_ir_transfer(
                rva=0x2000,
                size=6,
                mnemonic="jmp",
                event={
                    "kind": "external_call",
                    "instruction_rva": 0x2000,
                    "return_rva": 0x2006,
                    "dll": "msvcrt.dll",
                    "symbol": "atexit",
                    "ordinal": None,
                    "arguments": [{
                        "op": "load",
                        "width": 4,
                        "address": {
                            "op": "add32",
                            "args": [
                                {"op": "const", "value": 4, "width": 32},
                                {"op": "reg", "name": "esp", "width": 32},
                            ],
                        },
                    }],
                    "stack_inputs": [{
                        "offset": 4,
                        "width": 4,
                        "value": {
                            "op": "load",
                            "width": 4,
                            "address": {
                                "op": "add32",
                                "args": [
                                    {"op": "const", "value": 4, "width": 32},
                                    {"op": "reg", "name": "esp", "width": 32},
                                ],
                            },
                        },
                    }],
                    "abi_contract": {
                        "template": "pe32-cdecl-v1",
                        "argument_words": 1,
                        "argument_base_offset": 4,
                        "contract_id": 2,
                        "world_effect": "callbackRegistration",
                        "callback_source": {"kind": "argument_word", "argument": 0},
                        "callback_abi": {
                            "kind": "generic_callback",
                            "argument_words": 0,
                            "stack_cleanup_bytes": 0,
                            "nullable": False,
                        },
                    },
                },
            )
            thunk["semantics"]["outcome"] = {
                "kind": "external_jump",
                "dll": "msvcrt.dll",
                "symbol": "atexit",
                "ordinal": None,
            }
            callback = _machine_ir_transfer(
                rva=0x3000, size=1, mnemonic="nop"
            )
            machine = self._write(root, [caller, thunk, callback])
            plan = plan_stage_b_native_engine(
                machine_ir=machine,
                entry_rva=0x1400,
                import_iat_vas={("msvcrt.dll", "atexit"): 0x43219C},
                base_relocation_evidence=_relocation_evidence([]),
            )
            self.assertEqual(plan.status, "incomplete")
            self.assertEqual([target.rva for target in plan.callback_targets], [0x3000])
            self.assertEqual(len(plan.callback_adapters), 1)
            self.assertEqual(plan.callback_adapter_receipts, ())
            self.assertEqual(
                plan.blockers[-1]["category"],
                "callback_adapter_receipt_missing",
            )
            self.assertEqual(
                plan.callback_adapters[0].payload(),
                {
                    "id": 0,
                    "instruction_rva": 0x2000,
                    "argument_index": 0,
                    "original_rva": 0x3000,
                    "callback_rva": 0x3000,
                    "symbol": "stage_b_payload_callback_00003000",
                    "matching": "runtime-image-base-plus-rva",
                },
            )

    def test_callback_registration_rejects_unresolved_target_provenance(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            row = _machine_ir_transfer(
                rva=0x2000,
                size=6,
                mnemonic="jmp",
                event={
                    "kind": "external_call",
                    "instruction_rva": 0x2000,
                    "return_rva": 0x2006,
                    "dll": "msvcrt.dll",
                    "symbol": "atexit",
                    "ordinal": None,
                    "abi_contract": {
                        "template": "pe32-cdecl-v1",
                        "argument_words": 1,
                        "argument_base_offset": 4,
                        "contract_id": 2,
                        "world_effect": "callbackRegistration",
                        "callback_source": {"kind": "argument_word", "argument": 0},
                        "callback_abi": {
                            "kind": "generic_callback",
                            "argument_words": 0,
                            "stack_cleanup_bytes": 0,
                            "nullable": False,
                        },
                    },
                },
            )
            row["semantics"]["outcome"] = {
                "kind": "external_jump",
                "dll": "msvcrt.dll",
                "symbol": "atexit",
                "ordinal": None,
            }
            plan = plan_stage_b_native_engine(
                machine_ir=self._write(root, [row]),
                entry_rva=0x2000,
                import_iat_vas={("msvcrt.dll", "atexit"): 0x43219C},
                base_relocation_evidence=_relocation_evidence([]),
            )
            self.assertEqual(plan.status, "incomplete")
            self.assertEqual(
                plan.blockers[0]["category"],
                "callback_target_provenance_incomplete",
            )

    def test_malformed_typed_x87_guidance_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            row = _x87_replay_transfer()
            row["instructions"][0]["mnemonic"] = "fadd"
            plan = plan_stage_b_native_engine(
                state_machine=self._write(root, [row]), entry_rva=0x1420
            )
            self.assertEqual(plan.status, "incomplete")
            self.assertEqual(plan.blockers[0]["category"], "x87_physical_state_unqualified")
            self.assertIn("mnemonic differs", plan.blockers[0]["observed"])

    def test_x87_absolute_disp32_replay_is_rejected_for_dynamicbase(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            row = _x87_replay_transfer()
            encoded = bytes.fromhex("d90578563412")
            digest = sha256_bytes(encoded)
            row["instruction_bytes_sha256"] = digest
            row["original"] = {
                "rva_start": 0x1420,
                "rva_end": 0x1420 + len(encoded),
                "size": len(encoded),
            }
            row["instructions"] = [{
                "rva": 0x1420,
                "size": len(encoded),
                "bytes": encoded.hex(),
                "mnemonic": "fld",
                "op_str": "dword ptr [0x12345678]",
            }]
            row["outcome"] = {
                "kind": "fallthrough",
                "target_rva": 0x1420 + len(encoded),
            }
            replay = row["fpu_state"]["replay"]
            replay.update({
                "rva_end": 0x1420 + len(encoded),
                "bytes": encoded.hex(),
                "bytes_sha256": digest,
                "instructions": [{
                    "rva": 0x1420,
                    "size": len(encoded),
                    "bytes": encoded.hex(),
                }],
            })
            plan = plan_stage_b_native_engine(
                state_machine=self._write(root, [row]), entry_rva=0x1420
            )
            self.assertEqual(plan.status, "incomplete")
            self.assertEqual(plan.blockers[0]["category"], "x87_replay_aslr_unsafe")
            self.assertIn("HIGHLOW", plan.blockers[0]["next_action"])

    def test_x87_relocation_evidence_must_bind_same_reference_contract(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            machine = self._write(root, [_absolute_x87_replay_transfer()])
            with self.assertRaisesRegex(
                StageAInputError, "bind different reference contracts"
            ):
                plan_stage_b_native_engine(
                    state_machine=machine,
                    entry_rva=0x1420,
                    base_relocation_evidence=_relocation_evidence(
                        reference_contract_sha256="e" * 64
                    ),
                )

    def test_x87_relocation_evidence_rejects_unqualified_cells(self) -> None:
        base = {
            "source_rva": 0x1422,
            "type": 3,
            "kind": "highlow",
            "width": 4,
            "preferred_value": 0x401234,
        }
        cases = {
            "non_highlow": [{**base, "type": 2, "kind": "other"}],
            "width_mismatch": [{**base, "width": 2}],
            "out_of_instruction": [{**base, "source_rva": 0x1423}],
            "preferred_mismatch": [{**base, "preferred_value": 0x401238}],
        }
        for name, relocations in cases.items():
            with self.subTest(name=name), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                plan = plan_stage_b_native_engine(
                    state_machine=self._write(root, [_absolute_x87_replay_transfer()]),
                    entry_rva=0x1420,
                    base_relocation_evidence=_relocation_evidence(relocations),
                )
                self.assertEqual(plan.status, "incomplete")
                self.assertEqual(
                    plan.blockers[0]["category"], "x87_replay_aslr_unsafe"
                )
        for name, relocations in {
            "duplicate": [base, dict(base)],
            "overlap": [base, {**base, "source_rva": 0x1424}],
        }.items():
            with self.subTest(name=name), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                with self.assertRaisesRegex(StageAInputError, "duplicate|overlap"):
                    plan_stage_b_native_engine(
                        state_machine=self._write(
                            root, [_absolute_x87_replay_transfer()]
                        ),
                        entry_rva=0x1420,
                        base_relocation_evidence=_relocation_evidence(relocations),
                    )

    def test_rejects_return_rva_not_matching_exact_instruction(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            machine = self._write(root, [_transfer(event={
                "kind": "external_call",
                "instruction_rva": 0x142A,
                "return_rva": 0x1431,
                "dll": "kernel32.dll",
                "symbol": "Sleep",
                "ordinal": None,
            })])
            plan = plan_stage_b_native_engine(
                state_machine=machine, entry_rva=0x1420
            )
            self.assertEqual(plan.status, "incomplete")
            self.assertEqual(plan.blockers[0]["category"], "external_return_rva_mismatch")

    def test_duplicate_machine_ir_unit_id_fails_before_dispatch_generation(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            first = _machine_ir_transfer(rva=0x1000, size=1, mnemonic="ret")
            second = _machine_ir_transfer(rva=0x2000, size=1, mnemonic="ret")
            second["id"] = first["id"]
            machine_ir = self._write(root, [first, second])

            with self.assertRaisesRegex(StageAInputError, "duplicate.*transfer id"):
                plan_stage_b_native_engine(
                    machine_ir=machine_ir,
                    entry_rva=0x1000,
                )


if __name__ == "__main__":
    unittest.main()
