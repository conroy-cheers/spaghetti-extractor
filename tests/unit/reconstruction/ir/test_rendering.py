from __future__ import annotations

from tests.unit.reconstruction.ir._support import *


class ReconstructionIRRenderingTests(unittest.TestCase):
    def test_exports_deterministic_full_span_ir_with_exact_effects_and_control(self) -> None:
        call = b"\xff\x15\x40\x20\x40\x00"
        code = call + b"\xc3"
        write = {
            "register": "eax",
            "value": {
                "op": "add32",
                "args": [_expr_register("eax"), {"op": "const", "value": 1, "width": 32}],
            },
        }
        external = {
            "kind": "external_call",
            "instruction_rva": 0x1000,
            "return_rva": 0x1006,
            "dll": "KERNEL32.dll",
            "symbol": "GetLastError",
            "ordinal": None,
            "arguments": [],
        }
        rows = [
            _row(
                "semantic-transfer:first",
                0x1000,
                call,
                outcome={"kind": "fallthrough", "target_rva": 0x1006},
                register_writes=[write],
                external_events=[external],
                ordered_events=[{"family": "external", **external}],
            ),
            _row(
                "semantic-transfer:return",
                0x1006,
                b"\xc3",
                outcome={"kind": "return", "value": _expr_register("eax")},
            ),
        ]

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            original = root / "original.exe"
            machine = root / "state-machine.jsonl"
            original.write_bytes(
                pe32_import_image(code, symbol="GetLastError")
            )
            _write_machine(machine, rows)

            first = export_machine_ir_package(
                state_machine=machine, original_pe=original, out=root / "first"
            )
            second = export_machine_ir_package(
                state_machine=machine, original_pe=original, out=root / "second"
            )
            manifest = _read_json(first.manifest)
            units = _read_jsonl(first.machine_ir)

            self.assertEqual(first.status, "qualified")
            self.assertEqual(manifest["format"], MACHINE_IR_FORMAT)
            self.assertEqual(manifest["coverage"]["counts"]["unknown_bytes"], 0)
            self.assertEqual(manifest["control"]["direct_targets"][0]["target_rva"], 0x1006)
            self.assertEqual(manifest["external"]["events"][0]["symbol"], "GetLastError")
            self.assertEqual(units[0]["semantics"]["register_writes"], [write])
            self.assertEqual(
                units[0]["source"]["instruction_bytes_sha256"],
                sha256_bytes(call),
            )
            self.assertEqual(
                units[0]["control"]["decoded_reconciliation"]["status"],
                "complete",
            )
            self.assertEqual(
                (first.machine_ir).read_bytes(), (second.machine_ir).read_bytes()
            )
            self.assertEqual(
                (first.manifest).read_bytes(), (second.manifest).read_bytes()
            )
            self.assertEqual(_raw_instruction_keys(units), set())
            self.assertEqual(_raw_instruction_keys(manifest), set())

    def test_final_export_reuses_only_exactly_bound_prepared_units(self) -> None:
        rows = [
            _row(
                "semantic-transfer:first",
                0x1000,
                b"\x90",
                outcome={"kind": "jump", "target_rva": 0x1001},
            ),
            _row(
                "semantic-transfer:return",
                0x1001,
                b"\xc3",
                outcome={"kind": "return", "value": _expr_register("eax")},
            ),
        ]
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            original = root / "original.exe"
            provisional_machine = root / "provisional-state-machine.jsonl"
            final_machine = root / "final-state-machine.jsonl"
            original.write_bytes(pe32_image(b"\x90\xc3", virtual_size=2))
            _write_machine(provisional_machine, rows[:1])
            _write_machine(final_machine, rows)

            provisional = export_machine_ir_package(
                state_machine=provisional_machine,
                original_pe=original,
                out=root / "provisional",
            )
            reused = export_machine_ir_package(
                state_machine=final_machine,
                original_pe=original,
                prepared_machine_ir=provisional.machine_ir.parent,
                out=root / "reused",
            )
            clean = export_machine_ir_package(
                state_machine=final_machine,
                original_pe=original,
                out=root / "clean",
            )
            manifest = _read_json(reused.manifest)

            self.assertEqual(manifest["counts"]["prepared_units_reused"], 1)
            self.assertEqual(manifest["counts"]["prepared_units_computed"], 1)
            self.assertEqual(reused.machine_ir.read_bytes(), clean.machine_ir.read_bytes())

            provisional.machine_ir.write_bytes(
                provisional.machine_ir.read_bytes() + b"\n"
            )
            with self.assertRaisesRegex(
                MachineIRExportError, "prepared machine IR input or artifact binding is stale"
            ):
                export_machine_ir_package(
                    state_machine=final_machine,
                    original_pe=original,
                    prepared_machine_ir=provisional.machine_ir.parent,
                    out=root / "stale",
                )

    def test_prepared_unit_phase_is_deterministic_and_reusable(self) -> None:
        rows = [
            _row(
                "semantic-transfer:first",
                0x1000,
                b"\x90",
                outcome={"kind": "jump", "target_rva": 0x1001},
            ),
            _row(
                "semantic-transfer:return",
                0x1001,
                b"\xc3",
                outcome={"kind": "return", "value": _expr_register("eax")},
            ),
        ]
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            original = root / "original.exe"
            direct_machine = root / "direct-state-machine.jsonl"
            final_machine = root / "final-state-machine.jsonl"
            original.write_bytes(pe32_image(b"\x90\xc3", virtual_size=2))
            _write_machine(direct_machine, rows[:1])
            _write_machine(final_machine, rows)

            direct = prepare_machine_ir_units_package(
                state_machine=direct_machine,
                original_pe=original,
                out=root / "direct",
            )
            final = prepare_machine_ir_units_package(
                state_machine=final_machine,
                original_pe=original,
                prepared_machine_ir=direct.prepared_units.parent,
                out=root / "final",
            )
            clean = prepare_machine_ir_units_package(
                state_machine=final_machine,
                original_pe=original,
                out=root / "clean",
            )
            manifest = _read_json(final.manifest)

            self.assertEqual(manifest["format"], PREPARED_MACHINE_IR_FORMAT)
            self.assertEqual(manifest["counts"]["units_reused"], 1)
            self.assertEqual(manifest["counts"]["units_computed"], 1)
            self.assertEqual(
                final.prepared_units.read_bytes(), clean.prepared_units.read_bytes()
            )
            self.assertEqual(_raw_instruction_keys(manifest), set())
            self.assertEqual(
                _raw_instruction_keys(_read_jsonl(final.prepared_units)), set()
            )

            malformed_manifest = _read_json(final.manifest)
            malformed_manifest["artifacts"] = []
            final.manifest.write_text(
                json.dumps(malformed_manifest), encoding="utf-8"
            )
            with self.assertRaisesRegex(
                MachineIRExportError,
                "prepared machine IR input or artifact binding is stale",
            ):
                export_machine_ir_package(
                    state_machine=final_machine,
                    original_pe=original,
                    prepared_machine_ir=final.prepared_units.parent,
                    out=root / "malformed",
                )

    def test_x87_replay_becomes_typed_mnemonic_operand_micro_op_without_bytes(self) -> None:
        encoded = b"\xd9\x00"  # fld dword ptr [eax]
        row = _row(
            "semantic-transfer:x87",
            0x1000,
            encoded,
            status="incomplete",
            outcome={"kind": "fallthrough", "target_rva": 0x1002},
            fpu_state=_x87_state(0x1000, encoded),
        )
        return_row = _row(
            "semantic-transfer:return",
            0x1002,
            b"\xc3",
            outcome={"kind": "return"},
        )

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            original = root / "original.exe"
            machine = root / "state-machine.jsonl"
            original.write_bytes(
                pe32_image(encoded + b"\xc3", virtual_size=len(encoded) + 1)
            )
            _write_machine(machine, [row, return_row])

            package = export_machine_ir_package(
                state_machine=machine, original_pe=original, out=root / "out"
            )
            unit = _read_jsonl(package.machine_ir)[0]
            serialized = package.machine_ir.read_text(encoding="utf-8")

            self.assertEqual(package.status, "qualified")
            self.assertEqual(len(unit["x87_micro_ops"]), 1)
            micro_op = unit["x87_micro_ops"][0]
            self.assertEqual(micro_op["mnemonic"], "fld")
            self.assertEqual(
                micro_op["operands"][0],
                {
                    "kind": "memory",
                    "segment": None,
                    "base": "eax",
                    "index": None,
                    "scale": 1,
                    "displacement": 0,
                    "width_bits": 32,
                    "access": "read",
                },
            )
            self.assertEqual(micro_op["instruction_sha256"], sha256_bytes(encoded))
            self.assertEqual(_raw_instruction_keys(unit), set())
            self.assertNotIn(encoded.hex(), serialized)
            self.assertNotIn("replay", unit["semantics"]["fpu_state"])

    def test_package_uses_stable_filenames(self) -> None:
        row = _row(
            "semantic-transfer:return",
            0x1000,
            b"\xc3",
            outcome={"kind": "return"},
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            original = root / "original.exe"
            machine = root / "state-machine.jsonl"
            original.write_bytes(pe32_image(b"\xc3", virtual_size=1))
            _write_machine(machine, [row])
            package = export_machine_ir_package(
                state_machine=machine, original_pe=original, out=root / "out"
            )
            self.assertEqual(package.machine_ir.name, MACHINE_IR_FILENAME)
            self.assertEqual(package.manifest.name, MACHINE_IR_MANIFEST_FILENAME)


if __name__ == "__main__":
    unittest.main()
