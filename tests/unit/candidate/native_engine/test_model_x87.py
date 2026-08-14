from __future__ import annotations

from tests.unit.candidate.native_engine._support import *


class NativeEngineX87ModelTests(NativeEngineTestCase):
    def test_typed_x87_operation_preserves_physical_fnsave_contract(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            machine = self._write(root, [_x87_replay_transfer()])
            plan = plan_stage_b_native_engine(
                state_machine=machine, entry_rva=0x1420
            )
            self.assertEqual(plan.status, "ready", plan.blockers)
            self.assertEqual(len(plan.x87_operations), 1)
            package = root / "package"
            result = write_stage_b_native_engine_package(
                state_machine=machine,
                entry_rva=0x1420,
                callback_targets=[{
                    "rva": 0x1420,
                    "kind": "tls_callback",
                    "stack_cleanup_bytes": 12,
                }],
                out=package,
            )
            self.assertEqual(result["status"], "ready", result)
            header = (package / "native-engine-wrapper.h").read_text(encoding="ascii")
            source = (package / "native-engine-wrapper.c").read_text(encoding="ascii")
            assembly = (package / "native-engine-bridges.S").read_text(encoding="ascii")
            self.assertIn("physical_registers[8][10]", header)
            self.assertIn("uint16_t tag_word", header)
            self.assertIn("FNSAVE image must be 108 bytes", source)
            self.assertIn("physical_registers[(top + i) & 7U][j]", source)
            self.assertIn(
                "physical_registers[physical][j]",
                source,
            )
            self.assertIn("top = (image->status_word >> 11U) & 7U", source)
            self.assertIn("entry->bridge();", source)
            self.assertIn("fnsave", assembly)
            self.assertIn("frstor", assembly)
            self.assertIn("    fld1", assembly)
            self.assertNotIn(".byte", assembly)
            manifest = (package / "native-engine-plan.json").read_text(encoding="utf-8")
            self.assertNotIn("instruction_bytes", manifest)
            x87_capture = assembly.split(
                "_stage_b_native_x87_capture_0000:", maxsplit=1
            )[1]
            self.assertIn("push eax", x87_capture)
            self.assertNotIn("pushad", x87_capture)
            self.assertIn("mov ecx, DWORD PTR [esp]", x87_capture)
            self.assertIn("mov ebx, DWORD PTR [esp + 4]", x87_capture)
            self.assertIn("mov DWORD PTR [edx + 0], ecx", x87_capture)
            for offset in (4, 8, 12, 16, 20, 24, 28):
                self.assertNotIn(
                    f"mov DWORD PTR [edx + {offset}], ecx", x87_capture
                )
            for flag, offset in (("setc", 32), ("setz", 36), ("sets", 40),
                                 ("seto", 44), ("setp", 48)):
                self.assertIn(
                    f"{flag} BYTE PTR [edx + {offset}]", x87_capture
                )
            self.assertIn("and ebx, 0x00000cd5", x87_capture)
            self.assertIn("mov DWORD PTR [edx + 240], ecx", x87_capture)

    def test_byte_free_indexed_image_x87_operand_uses_checked_relocation(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            rva = 0xE548
            unit = _machine_ir_x87_transfer(
                rva=rva, mnemonic="fld", encoded=bytes.fromhex("dd04d5e0794200")
            )
            operand = {
                "kind": "memory",
                "segment": None,
                "base": None,
                "index": "edx",
                "scale": 8,
                "displacement": 0x4279E0,
                "width_bits": 64,
                "access": "read",
            }
            unit["instructions"][0]["operands"] = [operand]
            unit["instructions"][0]["registers_read"] = ["edx"]
            unit["instructions"][0]["registers_written"] = ["fpsw"]
            unit["x87_micro_ops"][0]["operands"] = [operand]
            unit["x87_micro_ops"][0]["implicit_registers_read"] = ["edx"]
            unit["x87_micro_ops"][0]["implicit_registers_written"] = ["fpsw"]
            unit["source"]["semantic_export"] = {
                "format": "stage-a-semantic-export-binding-v1",
                "reference_contract_sha256": "c" * 64,
                "semantic_transfer_sha256": "e" * 64,
            }
            package = root / "package"
            result = write_stage_b_native_engine_package(
                machine_ir=self._write(root, [unit]),
                entry_rva=rva,
                base_relocation_evidence=_relocation_evidence([{
                    "source_rva": rva + 3,
                    "type": 3,
                    "kind": "highlow",
                    "width": 4,
                    "preferred_value": 0x4279E0,
                }]),
                out=package,
            )
            self.assertEqual(result["status"], "ready", result["blockers"])
            plan = json.loads(
                (package / "native-engine-plan.json").read_text(encoding="ascii")
            )
            operation = plan["x87_operations"][0]
            self.assertEqual(operation["operation"]["operand"]["address"], {
                "base": None,
                "index": "edx",
                "scale": 8,
                "displacement": 0,
                "image_rva": 0x279E0,
            })
            assembly = (package / "native-engine-bridges.S").read_text(
                encoding="ascii"
            )
            self.assertIn(
                "fld QWORD PTR [___ImageBase + 0x000279e0 + edx * 8]",
                assembly,
            )
            self.assertNotIn(".byte", assembly)

    def test_x87_callback_passes_preserved_input_fnsave_pointer(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            machine = self._write(root, [_x87_replay_transfer()])
            package = root / "package"
            write_stage_b_native_engine_package(
                state_machine=machine,
                entry_rva=0x1420,
                callback_targets=[{
                    "rva": 0x1420,
                    "kind": "tls_callback",
                    "stack_cleanup_bytes": 12,
                }],
                out=package,
            )
            assembly = (package / "native-engine-bridges.S").read_text(
                encoding="ascii"
            )
            callback_call = assembly.split(
                "_stage_b_native_callback_x87_buffers_ready_0000:", 1
            )[1].split(
                "_stage_b_native_callback_dispatch_return_00001420:", 1
            )[0]
            self.assertIn("    mov esi, ecx", callback_call)
            self.assertIn(
                "    push eax\n"
                "    push esi\n"
                "    push ebx\n"
                "    push edx\n"
                "    push 12\n"
                "    push 0x00001420\n"
                "    call _stage_b_native_run_callback",
                callback_call,
            )
            self.assertNotIn("    push eax\n    push ecx\n", callback_call)

    def test_x87_absolute_disp32_accepts_exact_hash_bound_highlow(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            machine = self._write(root, [_absolute_x87_replay_transfer()])
            plan = plan_stage_b_native_engine(
                state_machine=machine,
                entry_rva=0x1420,
                base_relocation_evidence=_relocation_evidence(),
            )
            self.assertEqual(plan.status, "ready", plan.blockers)
            operation = plan.x87_operations[0]
            self.assertEqual(operation.relocation_source_rva, 0x1422)
            self.assertEqual(operation.operation.mnemonic, "fld")
            self.assertEqual(operation.operation.operand.image_rva, 0x1234)
            self.assertEqual(operation.preferred_value, 0x401234)
            self.assertEqual(operation.target_rva, 0x1234)
            self.assertEqual((operation.relocation_type, operation.relocation_width), (3, 4))
            payload = plan.payload(state_machine_sha256=sha256_bytes(machine.read_bytes()))
            relocation = payload["x87_operations"][0]["base_relocation"]
            self.assertEqual(relocation["reference_contract_sha256"], "c" * 64)
            self.assertEqual(relocation["pe_sha256"], "d" * 64)
            package = root / "package"
            write_stage_b_native_engine_package(
                state_machine=machine,
                entry_rva=0x1420,
                base_relocation_evidence=_relocation_evidence(),
                out=package,
            )
            assembly = (package / "native-engine-bridges.S").read_text(
                encoding="ascii"
            )
            self.assertIn("fld DWORD PTR [___ImageBase + 0x00001234]", assembly)
            self.assertNotIn(".byte", assembly)
            self.assertNotIn(".long", assembly)
            self.assertNotIn("0x34, 0x12, 0x40, 0x00", assembly)

    def test_x87_absolute_disp32_accepts_matching_fixed_image_base(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            machine = self._write(root, [_absolute_x87_replay_transfer()])
            package = root / "package"
            result = write_stage_b_native_engine_package(
                state_machine=machine,
                entry_rva=0x1420,
                fixed_image_base=0x400000,
                out=package,
            )
            self.assertEqual(result["status"], "ready", result["blockers"])
            plan = json.loads(
                (package / "native-engine-plan.json").read_text(encoding="ascii")
            )
            operation = plan["x87_operations"][0]
            self.assertIsNone(operation["base_relocation"])
            self.assertEqual(operation["address_binding"], {
                "kind": "fixed_image_base",
                "image_base": 0x400000,
                "target_rva": 0x1234,
            })
            self.assertEqual(plan["image_base_policy"], {
                "kind": "fixed",
                "image_base": 0x400000,
            })
            assembly = (package / "native-engine-bridges.S").read_text(
                encoding="ascii"
            )
            self.assertIn("fld DWORD PTR [___ImageBase + 0x00001234]", assembly)

    def test_relocation_evidence_does_not_require_export_on_non_x87_rows(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            plan = plan_stage_b_native_engine(
                state_machine=self._write(root, [_transfer()]),
                entry_rva=0x1420,
                base_relocation_evidence=_relocation_evidence(),
            )
            self.assertEqual(plan.status, "ready", plan.blockers)


if __name__ == "__main__":
    unittest.main()
