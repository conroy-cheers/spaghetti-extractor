from __future__ import annotations

from tests.unit.candidate.native_engine._support import *


class NativeEngineFailurePolicyTests(NativeEngineTestCase):
    def test_machine_ir_engine_defers_only_incomplete_potential_units(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            entry = _machine_ir_transfer(rva=0x1420, size=1, mnemonic="nop")
            potential = _machine_ir_transfer(rva=0x2000, size=1, mnemonic="in")
            potential["status"] = "incomplete"
            potential["reachable"] = False
            potential["reachability"] = "potential"
            machine_ir = self._write(root, [entry, potential])

            with self.assertRaisesRegex(StageAInputError, "not a qualified"):
                plan_stage_b_native_engine(
                    machine_ir=machine_ir,
                    entry_rva=0x1420,
                )

            plan = plan_stage_b_native_engine(
                machine_ir=machine_ir,
                entry_rva=0x1420,
                candidate_mode=STRUCTURAL_DIAGNOSTIC_CANDIDATE_MODE,
                allow_deferred_potential_transfers=True,
            )
            self.assertEqual(plan.status, "ready", plan.blockers)
            self.assertEqual(plan.transfer_count, 1)
            self.assertEqual(len(plan.deferred_transfers), 1)
            payload = plan.payload(state_machine_sha256="f" * 64)
            self.assertEqual(payload["semantic_coverage"]["status"], "incomplete")
            self.assertEqual(
                payload["execution_policy"],
                "fail_closed_on_deferred_potential_transfer_v1",
            )
            self.assertEqual(
                payload["candidate_mode"],
                STRUCTURAL_DIAGNOSTIC_CANDIDATE_MODE,
            )

    def test_incomplete_rooted_scope_is_diagnostic_but_not_static_closed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            entry = _machine_ir_transfer(rva=0x1000, size=1, mnemonic="nop")
            potential = _machine_ir_transfer(rva=0x2000, size=1, mnemonic="ret")
            potential["reachable"] = False
            potential["reachability"] = "potential"
            machine_ir = self._write(root, [entry, potential])
            manifest = root / "machine-ir-manifest.json"
            manifest.write_text(json.dumps(_implementation_manifest(
                machine_ir,
                roots=[entry["id"]],
                reachable=[entry["id"]],
                potential=[potential["id"]],
            ), sort_keys=True), encoding="utf-8")

            strict = plan_stage_b_native_engine(
                machine_ir=machine_ir,
                machine_ir_manifest=manifest,
                entry_rva=0x1000,
            )
            diagnostic = plan_stage_b_native_engine(
                machine_ir=machine_ir,
                machine_ir_manifest=manifest,
                entry_rva=0x1000,
                candidate_mode=STRUCTURAL_DIAGNOSTIC_CANDIDATE_MODE,
            )

            self.assertEqual(strict.status, "incomplete")
            self.assertIn(
                "implementation_reachability_incomplete",
                {blocker["category"] for blocker in strict.blockers},
            )
            self.assertEqual(diagnostic.status, "ready", diagnostic.blockers)
            self.assertEqual(
                diagnostic.implementation_dispatch_receipt.status,
                "diagnostic",
            )
            self.assertEqual(
                diagnostic.implementation_dispatch_receipt.potential_unit_ids,
                (potential["id"],),
            )
            self.assertIn(
                "rooted_reachability_incomplete",
                {
                    frontier["category"]
                    for frontier in diagnostic.diagnostic_frontiers
                },
            )
            self.assertFalse(
                diagnostic.implementation_dispatch_receipt.payload()["policy"][
                    "static_hybrid_closure_receipt_required_for_candidate"
                ]
            )

    def test_diagnostic_runtime_guard_carries_import_across_unproved_call(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            iat_va = 0x43219C
            load = _machine_ir_transfer(rva=0x1000, size=6, mnemonic="mov")
            load["semantics"]["register_writes"] = [{
                "register": "ebx",
                "value": {
                    "op": "load",
                    "width": 4,
                    "address": {"op": "const", "value": iat_va, "width": 32},
                },
            }]
            load["semantics"]["outcome"] = {
                "kind": "fallthrough",
                "target_rva": 0x1010,
            }
            internal = _machine_ir_transfer(
                rva=0x1010,
                size=5,
                event={
                    "kind": "internal_call",
                    "instruction_rva": 0x1010,
                    "return_rva": 0x1015,
                    "target_rva": 0x2000,
                },
            )
            internal["semantics"]["register_writes"] = [{
                "register": register,
                "value": {
                    "op": "call_response",
                    "call_index": 0,
                    "register": register,
                    "width": 32,
                },
            } for register in (
                "eax", "ebp", "ebx", "ecx", "edi", "edx", "esi", "esp"
            )]
            indirect = _machine_ir_transfer(
                rva=0x1015,
                size=2,
                event={
                    "kind": "indirect_call",
                    "instruction_rva": 0x1015,
                    "return_rva": 0x1017,
                    "target": {"op": "reg", "name": "ebx", "width": 32},
                },
            )
            callee = _machine_ir_transfer(rva=0x2000, size=1, mnemonic="ret")
            callee["semantics"]["outcome"] = {"kind": "return"}
            machine = self._write(root, [load, internal, indirect, callee])

            strict = plan_stage_b_native_engine(
                machine_ir=machine,
                entry_rva=0x1000,
                import_iat_vas={("kernel32.dll", "HeapAlloc"): iat_va},
            )
            diagnostic = plan_stage_b_native_engine(
                machine_ir=machine,
                entry_rva=0x1000,
                import_iat_vas={("kernel32.dll", "HeapAlloc"): iat_va},
                candidate_mode=STRUCTURAL_DIAGNOSTIC_CANDIDATE_MODE,
            )

            strict_site = next(
                item for item in strict.external_sites
                if item.instruction_rva == 0x1015
            )
            diagnostic_site = next(
                item for item in diagnostic.external_sites
                if item.instruction_rva == 0x1015
            )
            self.assertEqual(
                (strict_site.dll, strict_site.symbol, strict_site.iat_va),
                (None, None, None),
            )
            self.assertIsNone(strict_site.target_resolution_evidence)
            self.assertEqual(
                (diagnostic_site.dll, diagnostic_site.symbol, diagnostic_site.iat_va),
                ("kernel32.dll", "HeapAlloc", iat_va),
            )
            evidence = diagnostic_site.target_resolution_evidence
            self.assertIsNotNone(evidence)
            assert evidence is not None
            self.assertEqual(evidence["kind"], "runtime-guarded-import-origin-v1")
            self.assertFalse(evidence["proof_authority"])
            self.assertEqual(
                evidence["runtime_guard"],
                "indirect-target-equals-current-iat-cell",
            )
            self.assertEqual(evidence["diagnostic_dependencies"], [{
                "kind": "pe32-internal-call-abi-hypothesis-v1",
                "proof_authority": False,
                "transfer_rva": 0x1010,
                "instruction_rva": 0x1010,
                "target_rva": 0x2000,
                "register": "ebx",
                "assumption": "pe32-callee-preserved-register",
            }])
            frontiers = [
                item for item in diagnostic.diagnostic_frontiers
                if item["category"] == "diagnostic_internal_call_abi_hypothesis"
            ]
            self.assertEqual(len(frontiers), 1)
            self.assertEqual(frontiers[0]["instruction_rva"], 0x1015)

    def test_unqualified_x87_transfer_remains_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            row = _transfer()
            row["fpu_state"] = {
                "model": "symbolic_x87_stack_v1",
                "stack": [{"op": "fpu_reg", "args": [index]} for index in range(8)],
            }
            plan = plan_stage_b_native_engine(
                state_machine=self._write(root, [row]), entry_rva=0x1420
            )
            self.assertEqual(plan.status, "incomplete")
            self.assertEqual(
                plan.blockers[0]["category"], "x87_physical_state_unqualified"
            )

    def test_callback_rva_without_abi_remains_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            machine = self._write(root, [_transfer()])
            plan = plan_stage_b_native_engine(
                state_machine=machine,
                entry_rva=0x1420,
                callback_targets=[0x1420],
            )
            self.assertEqual(plan.status, "incomplete")
            self.assertEqual(
                plan.blockers[0]["category"], "callback_abi_ambiguous"
            )

    def test_portable_selection_is_one_fail_closed_dispatch_class(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            unit = _machine_ir_transfer(rva=0x1000, size=1, mnemonic="ret")
            unit["control"] = {
                "kind": "return",
                "direct_targets": [],
                "has_indirect_target": False,
            }
            unit["semantics"]["outcome"] = {"kind": "return"}
            machine_ir = self._write(root, [unit])
            manifest = root / "machine-ir-manifest.json"
            manifest.write_text(json.dumps(_implementation_manifest(
                machine_ir,
                roots=[unit["id"]],
                reachable=[unit["id"]],
            ), sort_keys=True), encoding="utf-8")
            selection = {
                "unit_id": unit["id"],
                "rva": 0x1000,
                "replacement_id": "portable-return",
                "cluster_id": "cluster-return",
                "component_manifest_sha256": "c" * 64,
                "fallback_on_unimplemented": False,
            }

            plan = plan_stage_b_native_engine(
                machine_ir=machine_ir,
                machine_ir_manifest=manifest,
                entry_rva=0x1000,
                selected_portable_components=[selection],
            )
            entry = plan.implementation_dispatch_receipt.payload()["entries"][0]
            self.assertEqual(entry["implementation_class"], "selected_portable_component")
            self.assertEqual(entry["dispatch_lookup"], "stage_b_region_override_lookup")
            self.assertFalse(entry["fallback_on_unimplemented"])

            with self.assertRaisesRegex(StageAInputError, "duplicate portable"):
                plan_stage_b_native_engine(
                    machine_ir=machine_ir,
                    machine_ir_manifest=manifest,
                    entry_rva=0x1000,
                    selected_portable_components=[selection, selection],
                )
            permissive = dict(selection)
            permissive["fallback_on_unimplemented"] = True
            with self.assertRaisesRegex(StageAInputError, "must disable"):
                plan_stage_b_native_engine(
                    machine_ir=machine_ir,
                    machine_ir_manifest=manifest,
                    entry_rva=0x1000,
                    selected_portable_components=[permissive],
                )


if __name__ == "__main__":
    unittest.main()
