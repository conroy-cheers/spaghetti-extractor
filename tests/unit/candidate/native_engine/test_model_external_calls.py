from __future__ import annotations

from tests.unit.candidate.native_engine._support import *


class NativeEngineExternalCallModelTests(NativeEngineTestCase):
    def test_plans_exact_external_callsite_without_a_prototype(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            machine = self._write(root, [_transfer(event={
                "kind": "external_call",
                "instruction_rva": 0x142A,
                "return_rva": 0x1430,
                "dll": "KERNEL32.dll",
                "symbol": "Sleep",
                "ordinal": None,
            })])
            plan = plan_stage_b_native_engine(
                state_machine=machine, entry_rva=0x1420
            )
            self.assertEqual(plan.status, "ready")
            self.assertEqual(plan.external_sites[0].dll, "kernel32.dll")
            self.assertEqual(plan.external_sites[0].instruction_bytes.hex(), "ff159c214300")
            self.assertEqual(plan.external_sites[0].iat_va, 0x43219C)
            self.assertEqual(plan.external_sites[0].disposition, "returns_here")

    def test_plans_byte_free_machine_ir_external_bridge(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            event = {
                "kind": "external_call",
                "instruction_rva": 0x142A,
                "return_rva": 0x1430,
                "dll": "KERNEL32.dll",
                "symbol": "Sleep",
                "ordinal": None,
            }
            machine_ir = self._write(root, [_machine_ir_transfer(event=event)])
            package = root / "package"
            plan = plan_stage_b_native_engine(
                machine_ir=machine_ir,
                entry_rva=0x142A,
                import_iat_vas={("kernel32.dll", "Sleep"): 0x43219C},
            )
            result = write_stage_b_native_engine_package(
                machine_ir=machine_ir,
                entry_rva=0x142A,
                import_iat_vas={("kernel32.dll", "Sleep"): 0x43219C},
                out=package,
            )
            site = plan.external_sites[0]
            self.assertEqual(plan.status, "ready", plan.blockers)
            self.assertEqual(plan.input_mode, "sanitized_machine_ir_v2")
            self.assertIsNone(site.instruction_bytes)
            self.assertRegex(site.source_instruction_sha256, r"^[0-9a-f]{64}$")
            self.assertRegex(site.event_identity_sha256 or "", r"^[0-9a-f]{64}$")
            self.assertRegex(site.abi_metadata_sha256 or "", r"^[0-9a-f]{64}$")
            self.assertEqual(result["input_mode"], "sanitized_machine_ir_v2")
            for artifact in package.iterdir():
                if artifact.suffix not in {".json", ".c", ".h", ".S"}:
                    continue
                generated = artifact.read_text(encoding="ascii")
                self.assertNotIn("instruction_bytes", generated)
                self.assertNotIn(".byte", generated)

    def test_byte_free_indirect_bridge_binds_target_expression(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            target = {"op": "reg", "name": "ebx", "width": 32}
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
            plan = plan_stage_b_native_engine(
                machine_ir=self._write(root, [unit]), entry_rva=0x142A
            )
            self.assertEqual(plan.status, "ready", plan.blockers)
            self.assertEqual(plan.external_sites[0].target_expression, target)
            self.assertEqual(plan.external_sites[0].site_kind, "dynamic_target")

    def test_byte_free_iat_loaded_indirect_bridge_binds_import_identity(self) -> None:
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

            plan = plan_stage_b_native_engine(
                machine_ir=self._write(root, [unit]),
                entry_rva=0x142A,
                import_iat_vas={("msvcrt.dll", "__p___argv"): 0x43219C},
            )

            site = plan.external_sites[0]
            self.assertEqual(site.site_kind, "dynamic_target")
            self.assertEqual(site.dll, "msvcrt.dll")
            self.assertEqual(site.symbol, "__p___argv")
            self.assertEqual(site.iat_va, 0x43219C)
            self.assertEqual(site.payload()["import"], {
                "dll": "msvcrt.dll",
                "symbol": "__p___argv",
                "ordinal": None,
            })

    def test_register_held_iat_origin_binds_indirect_call(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            load = _machine_ir_transfer(rva=0x1000, size=6, mnemonic="mov")
            load["semantics"]["register_writes"] = [{
                "register": "edi",
                "value": {
                    "op": "load",
                    "width": 4,
                    "address": {"op": "const", "width": 32, "value": 0x43219C},
                },
            }]
            call = _machine_ir_transfer(
                event={
                    "kind": "indirect_call",
                    "instruction_rva": 0x1006,
                    "return_rva": 0x1008,
                    "target": {"op": "reg", "name": "edi", "width": 32},
                },
                rva=0x1006,
                size=2,
            )

            plan = plan_stage_b_native_engine(
                machine_ir=self._write(root, [load, call]),
                entry_rva=0x1000,
                import_iat_vas={('kernel32.dll', 'VirtualAlloc'): 0x43219C},
            )

            site = plan.external_sites[0]
            self.assertEqual(site.symbol, "VirtualAlloc")
            self.assertEqual(site.iat_va, 0x43219C)

    def test_register_held_iat_origin_crosses_checked_import_call(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            load = _machine_ir_transfer(rva=0x1000, size=6, mnemonic="mov")
            load["semantics"]["register_writes"] = [{
                "register": "edi",
                "value": {
                    "op": "load",
                    "width": 4,
                    "address": {"op": "const", "width": 32, "value": 0x43219C},
                },
            }]
            first = _machine_ir_transfer(
                event={
                    "kind": "indirect_call",
                    "instruction_rva": 0x1006,
                    "return_rva": 0x1008,
                    "target": {"op": "reg", "name": "edi", "width": 32},
                },
                rva=0x1006,
                size=2,
            )
            first["semantics"]["register_writes"] = [{
                "register": register,
                "value": {
                    "op": "call_response",
                    "call_index": 0,
                    "register": register,
                    "width": 32,
                },
            } for register in ("eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp")]
            second = _machine_ir_transfer(
                event={
                    "kind": "indirect_call",
                    "instruction_rva": 0x1008,
                    "return_rva": 0x100A,
                    "target": {"op": "reg", "name": "edi", "width": 32},
                },
                rva=0x1008,
                size=2,
            )

            plan = plan_stage_b_native_engine(
                machine_ir=self._write(root, [load, first, second]),
                entry_rva=0x1000,
                import_iat_vas={('kernel32.dll', 'VirtualAlloc'): 0x43219C},
            )

            self.assertEqual(
                [site.symbol for site in plan.external_sites],
                ["VirtualAlloc", "VirtualAlloc"],
            )

    def test_direct_e8_to_checked_local_thunk_stays_internal(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            caller = _transfer()
            caller["ordered_events"] = [{
                "family": "external",
                "kind": "internal_call",
                "instruction_rva": 0x142A,
                "return_rva": 0x142F,
                "target_rva": 0x2000,
            }]
            caller["instructions"] = [{
                "rva": 0x142A,
                "size": 5,
                "bytes": "e8d10b0000",
                "mnemonic": "call",
                "op_str": "0x2000",
            }]
            thunk = _transfer()
            thunk["id"] = "semantic-transfer:thunk"
            thunk["original"] = {"rva_start": 0x2000, "rva_end": 0x2006}
            thunk["instructions"] = [{
                "rva": 0x2000,
                "size": 6,
                "bytes": "ff259c214300",
                "mnemonic": "jmp",
                "op_str": "dword ptr [0x43219c]",
            }]
            thunk["ordered_events"] = [{
                "family": "external",
                "kind": "external_call",
                "instruction_rva": 0x2000,
                "return_rva": 0x2006,
                "dll": "kernel32.dll",
                "symbol": "Sleep",
                "ordinal": None,
            }]
            thunk["outcome"] = {
                "kind": "external_jump",
                "dll": "kernel32.dll",
                "symbol": "Sleep",
            }
            plan = plan_stage_b_native_engine(
                state_machine=self._write(root, [caller, thunk]),
                entry_rva=0x1420,
            )
            self.assertEqual(plan.status, "ready", plan.blockers)
            self.assertEqual(len(plan.external_sites), 1)
            self.assertEqual(plan.external_sites[0].instruction_rva, 0x2000)
            self.assertEqual(plan.external_sites[0].disposition, "tail_jump")

    def test_plans_prototype_free_dynamic_indirect_call_bridge(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            row = _transfer()
            row["ordered_events"] = [{
                "family": "external",
                "kind": "indirect_call",
                "instruction_rva": 0x142A,
                "return_rva": 0x142C,
            }]
            row["instructions"] = [{
                "rva": 0x142A,
                "size": 2,
                "bytes": "ffd3",
                "mnemonic": "call",
                "op_str": "ebx",
            }]
            machine = self._write(root, [row])
            plan = plan_stage_b_native_engine(
                state_machine=machine, entry_rva=0x1420
            )
            self.assertEqual(plan.status, "ready")
            self.assertEqual(plan.indirect_call_count, 1)
            self.assertEqual(plan.external_sites[0].site_kind, "dynamic_target")
            self.assertIsNone(plan.external_sites[0].dll)
            self.assertIsNone(plan.external_sites[0].symbol)
            self.assertEqual(plan.external_sites[0].instruction_bytes, b"\xff\xd3")

    def test_hash_bound_internal_summary_propagates_import_origin(self) -> None:
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
            } for register in ("eax", "ebp", "ebx", "ecx", "edi", "edx", "esi", "esp")]
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
            manifest = root / "machine-ir-manifest.json"
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
                        "summaries": [{
                            "status": "complete",
                            "target_rva": 0x2000,
                            "preserved_registers": ["ebx"],
                        }],
                    },
                },
            }), encoding="utf-8")

            plan = plan_stage_b_native_engine(
                machine_ir=machine,
                machine_ir_manifest=manifest,
                entry_rva=0x1000,
                import_iat_vas={("kernel32.dll", "HeapAlloc"): iat_va},
            )

            site = next(item for item in plan.external_sites if item.instruction_rva == 0x1015)
            self.assertEqual((site.dll, site.symbol, site.iat_va), (
                "kernel32.dll", "HeapAlloc", iat_va,
            ))
            stale = json.loads(manifest.read_text(encoding="utf-8"))
            stale["artifacts"]["machine_ir"]["sha256"] = "0" * 64
            manifest.write_text(json.dumps(stale), encoding="utf-8")
            with self.assertRaisesRegex(StageAInputError, "does not bind the exact"):
                plan_stage_b_native_engine(
                    machine_ir=machine,
                    machine_ir_manifest=manifest,
                    entry_rva=0x1000,
                    import_iat_vas={("kernel32.dll", "HeapAlloc"): iat_va},
                )

    def test_uses_evaluated_target_for_absolute_indirect_call(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            row = _transfer()
            row["ordered_events"] = [{
                "family": "external",
                "kind": "indirect_call",
                "instruction_rva": 0x142A,
                "return_rva": 0x1430,
            }]
            row["instructions"] = [{
                "rva": 0x142A,
                "size": 6,
                "bytes": "ff159c214300",
                "mnemonic": "call",
                "op_str": "dword ptr [0x43219c]",
            }]
            plan = plan_stage_b_native_engine(
                state_machine=self._write(root, [row]), entry_rva=0x1420
            )
            self.assertEqual(plan.status, "ready")
            self.assertEqual(plan.external_sites[0].site_kind, "dynamic_target")


if __name__ == "__main__":
    unittest.main()
