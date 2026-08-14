from __future__ import annotations

from tests.unit.candidate.native_engine._support import *


class NativeEngineReceiptTests(NativeEngineTestCase):
    def test_qualified_external_tail_import_records_continuation_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            row = _transfer(event={
                "kind": "external_call",
                "instruction_rva": 0x142A,
                "return_rva": 0x1430,
                "dll": "msvcrt.dll",
                "symbol": "atexit",
                "ordinal": None,
            })
            row["instructions"][0].update({
                "bytes": "ff259c214300",
                "size": 6,
                "mnemonic": "jmp",
                "op_str": "dword ptr [0x43219c]",
            })
            row["outcome"] = {
                "kind": "external_jump", "dll": "msvcrt.dll", "symbol": "atexit"
            }
            machine = self._write(root, [row])
            plan = plan_stage_b_native_engine(
                state_machine=machine, entry_rva=0x1420
            )
            self.assertEqual(plan.status, "ready", plan.blockers)
            site = plan.external_sites[0]
            self.assertEqual(site.disposition, "tail_jump")
            self.assertEqual(site.iat_va, 0x43219C)
            payload = plan.payload(state_machine_sha256=sha256_bytes(machine.read_bytes()))
            self.assertEqual(
                payload["external_sites"][0]["continuation_evidence"],
                {
                    "kind": "replace-saved-caller-return",
                    "stack_offset": 0,
                    "width": 4,
                    "restored_at_capture": True,
                    "normal_call_frame_shift": False,
                },
            )
            self.assertRegex(
                payload["external_sites"][0]["transfer_sha256"],
                r"^[0-9a-f]{64}$",
            )
            package = root / "tail-package"
            write_stage_b_native_engine_package(
                state_machine=machine, entry_rva=0x1420, out=package
            )
            assembly = (package / "native-engine-bridges.S").read_text(
                encoding="ascii"
            )
            wrapper = (package / "native-engine-wrapper.c").read_text(
                encoding="ascii"
            )
            self.assertIn(
                "mov DWORD PTR [esp], OFFSET FLAT:_stage_b_native_capture",
                assembly,
            )
            self.assertIn("mov DWORD PTR [ecx - 4], ebx", assembly)
            self.assertNotIn("add esp, 4", assembly)
            self.assertNotIn("runtime->read", wrapper)
            self.assertIn("stage_b_native_fixed_flat_read_u32(", wrapper)
            self.assertIn("input->esp, &frame.saved_continuation", wrapper)
            self.assertIn("frame.continuation_replaced != 0U", wrapper)

    def test_package_is_deterministic_and_marks_generation_only_authority(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            machine = self._write(root, [_transfer(event={
                "kind": "external_call",
                "instruction_rva": 0x142A,
                "return_rva": 0x1430,
                "dll": "kernel32.dll",
                "symbol": "Sleep",
                "ordinal": None,
            })])
            first = write_stage_b_native_engine_package(
                state_machine=machine, entry_rva=0x1420, out=root / "first"
            )
            second = write_stage_b_native_engine_package(
                state_machine=machine, entry_rva=0x1420, out=root / "second"
            )
            self.assertEqual(first["status"], "ready")
            self.assertIn(
                "static and behavioral qualification required",
                first["authority"],
            )
            self.assertEqual(
                [item["sha256"] for item in first["sources"]],
                [item["sha256"] for item in second["sources"]],
            )
            assembly = (root / "first" / "native-engine-bridges.S").read_text(
                encoding="ascii"
            )
            self.assertNotRegex(assembly, r"(?i)\bint3\b")
            self.assertIn("_stage_b_payload_entry:", assembly)
            self.assertIn("call _stage_b_native_run_entry", assembly)
            self.assertIn("pushfd", assembly)
            self.assertIn("popfd", assembly)
            self.assertIn("pushad", assembly)
            self.assertIn("popad", assembly)
            self.assertIn("mov DWORD PTR [esp], edx", assembly)
            self.assertIn("OFFSET FLAT:_stage_b_native_capture", assembly)
            self.assertIn(".globl _stage_b_native_bridge", assembly)
            self.assertIn(".globl _stage_b_native_capture", assembly)
            self.assertNotIn(".stgbcl", assembly)
            self.assertNotIn("_stage_b_native_bridge_0000", assembly)
            wrapper = (root / "first" / "native-engine-wrapper.c").read_text(
                encoding="ascii"
            )
            self.assertIn("stage_b_native_runtime_run_at_rva(", wrapper)
            self.assertIn('"c" (modeled_eax)', wrapper)
            self.assertIn('"b" (modeled_esp)', wrapper)
            self.assertIn('"S" (expected_return)', wrapper)
            self.assertIn('"D" (observed_return)', wrapper)
            self.assertIn("stage_b_native_diagnostic_value", wrapper)
            self.assertIn("stage_b_native_diagnostic_aux", wrapper)
            self.assertIn("stage_b_native_diagnostic_detail", wrapper)
            self.assertIn("stage_b_native_diagnostic_value = 0U", wrapper)
            self.assertIn("stage_b_native_diagnostic_aux = 0U", wrapper)
            self.assertIn("stage_b_native_diagnostic_detail = 0U", wrapper)
            self.assertNotIn("static stage_b_runtime", wrapper)
            self.assertNotIn("stage_b_native_read(", wrapper)
            self.assertIn("stage_b_native_original_iat_target", wrapper)
            self.assertIn("frame.call_target", wrapper)
            self.assertIn("frame.parent = stage_b_native_active_bridge", wrapper)
            self.assertIn("stage_b_native_active_bridge = frame.parent", wrapper)
            self.assertIn("output->df = 0U", wrapper)
            self.assertIn("output->eflags &= ~(1U << 10)", wrapper)
            self.assertIn("offsetof(stage_b_machine_state, eflags) == 240U", wrapper)
            self.assertIn("state->eflags = 2U |", wrapper)
            self.assertNotIn("state->eflags & ~represented", wrapper)
            layout = (root / "first" / "native-engine-layout.c").read_text(
                encoding="ascii"
            )
            self.assertIn("stage_b_engine_layout_table", layout)
            self.assertIn("x87_stack[7].value_bytes", layout)
            self.assertIn("x87_stack[7].empty", layout)
            self.assertIn("offsetof(stage_b_machine_state, eflags)", layout)

    def test_rooted_implementation_receipt_covers_each_dispatch_and_target(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            entry = _machine_ir_transfer(rva=0x1000, size=1, mnemonic="nop")
            target = _machine_ir_transfer(rva=0x2000, size=1, mnemonic="ret")
            entry["control"] = {
                "kind": "fallthrough",
                "direct_targets": [0x2000],
                "has_indirect_target": False,
            }
            target["control"] = {
                "kind": "return",
                "direct_targets": [],
                "has_indirect_target": False,
            }
            target["semantics"]["outcome"] = {"kind": "return"}
            machine_ir = self._write(root, [entry, target])
            manifest = root / "machine-ir-manifest.json"
            manifest.write_text(json.dumps(_implementation_manifest(
                machine_ir,
                roots=[entry["id"]],
                reachable=[entry["id"], target["id"]],
            ), sort_keys=True), encoding="utf-8")

            plan = plan_stage_b_native_engine(
                machine_ir=machine_ir,
                machine_ir_manifest=manifest,
                entry_rva=0x1000,
            )

            self.assertEqual(plan.status, "ready", plan.blockers)
            receipt = plan.implementation_dispatch_receipt.payload()
            self.assertEqual(receipt["status"], "complete")
            self.assertEqual(
                [entry["implementation_class"] for entry in receipt["entries"]],
                ["machine_ir_fallback", "machine_ir_fallback"],
            )
            self.assertEqual(
                [(edge["source_rva"], edge["target_rva"]) for edge in receipt["targets"]],
                [(0x1000, 0x2000)],
            )
            self.assertTrue(
                receipt["policy"]["static_hybrid_closure_receipt_required_for_candidate"]
            )

    def test_rooted_implementation_receipt_rejects_missing_target_dispatch(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            entry = _machine_ir_transfer(rva=0x1000, size=1, mnemonic="nop")
            entry["control"] = {
                "kind": "jump",
                "direct_targets": [0x2000],
                "has_indirect_target": False,
            }
            entry["semantics"]["outcome"] = {
                "kind": "jump",
                "target_rva": 0x2000,
            }
            machine_ir = self._write(root, [entry])
            manifest = root / "machine-ir-manifest.json"
            manifest.write_text(json.dumps(_implementation_manifest(
                machine_ir,
                roots=[entry["id"]],
                reachable=[entry["id"]],
            ), sort_keys=True), encoding="utf-8")

            plan = plan_stage_b_native_engine(
                machine_ir=machine_ir,
                machine_ir_manifest=manifest,
                entry_rva=0x1000,
            )

            self.assertEqual(plan.status, "incomplete")
            self.assertIn(
                "reachable_implementation_target_missing",
                {blocker["category"] for blocker in plan.blockers},
            )

    def test_returning_internal_call_receipts_callee_and_continuation(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            caller = _machine_ir_transfer(
                rva=0x1000,
                size=1,
                event={
                    "kind": "internal_call",
                    "instruction_rva": 0x1000,
                    "return_rva": 0x1001,
                    "target_rva": 0x2000,
                },
            )
            continuation = _machine_ir_transfer(
                rva=0x1001, size=1, mnemonic="ret"
            )
            callee = _machine_ir_transfer(rva=0x2000, size=1, mnemonic="ret")
            caller["control"] = {
                "kind": "fallthrough",
                "direct_targets": [0x1001],
                "has_indirect_target": False,
            }
            for unit in (continuation, callee):
                unit["control"] = {
                    "kind": "return",
                    "direct_targets": [],
                    "has_indirect_target": False,
                }
                unit["semantics"]["outcome"] = {"kind": "return"}
            machine_ir = self._write(root, [caller, continuation, callee])
            summary = {
                "status": "complete",
                "target_unit_id": callee["id"],
                "target_rva": 0x2000,
                "preserved_registers": [],
                "return_behavior": {
                    "status": "complete",
                    "may_return": True,
                    "may_not_return": False,
                },
            }
            manifest = root / "machine-ir-manifest.json"
            manifest.write_text(json.dumps(_implementation_manifest(
                machine_ir,
                roots=[caller["id"]],
                reachable=[caller["id"], continuation["id"], callee["id"]],
                summaries=[summary],
            ), sort_keys=True), encoding="utf-8")

            plan = plan_stage_b_native_engine(
                machine_ir=machine_ir,
                machine_ir_manifest=manifest,
                entry_rva=0x1000,
            )

            self.assertEqual(plan.status, "ready", plan.blockers)
            targets = plan.implementation_dispatch_receipt.payload()["targets"]
            self.assertIn(
                ("internal_call", 0x2000),
                {(target["kind"], target["target_rva"]) for target in targets},
            )
            self.assertIn(
                ("call_continuation", 0x1001),
                {(target["kind"], target["target_rva"]) for target in targets},
            )


if __name__ == "__main__":
    unittest.main()
