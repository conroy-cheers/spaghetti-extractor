from __future__ import annotations

from tests.unit.reconstruction.ir._support import *


class ReconstructionIRValidationTests(unittest.TestCase):
    def test_byte_free_boundary_allows_numeric_byte_counts_only(self) -> None:
        _assert_byte_free({"size": {"kind": "fixed", "bytes": 16}})
        for raw in ("90", [0x90], True, -1):
            with self.subTest(raw=raw):
                with self.assertRaisesRegex(AssertionError, "raw instruction field"):
                    _assert_byte_free({"bytes": raw})

    def test_ret_misdeclared_as_jump_self_loop_violates_reconciliation(self) -> None:
        row = _row(
            "semantic-transfer:false-loop",
            0x1000,
            b"\xc3",
            outcome={"kind": "jump", "target_rva": 0x1000},
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
            manifest = _read_json(package.manifest)
            unit = _read_jsonl(package.machine_ir)[0]
            reconciliation = unit["control"]["decoded_reconciliation"]

            self.assertEqual(package.status, "violated")
            self.assertEqual(unit["status"], "incomplete")
            self.assertEqual(reconciliation["status"], "violated")
            self.assertEqual(
                reconciliation["terminal_instruction"]["return_class"],
                "near_return",
            )
            self.assertIn(
                "return_class_mismatch",
                {check["code"] for check in reconciliation["checks"]},
            )
            self.assertIn(
                "decoded_control_reconciliation",
                {issue["category"] for issue in manifest["issues"]},
            )

    def test_decoded_direct_target_mismatch_violates_reconciliation(self) -> None:
        row = _row(
            "semantic-transfer:wrong-target",
            0x1000,
            b"\xeb\xfe",
            outcome={"kind": "jump", "target_rva": 0x1001},
        )

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            original = root / "original.exe"
            machine = root / "state-machine.jsonl"
            original.write_bytes(pe32_image(b"\xeb\xfe", virtual_size=2))
            _write_machine(machine, [row])

            package = export_machine_ir_package(
                state_machine=machine, original_pe=original, out=root / "out"
            )
            reconciliation = _read_jsonl(package.machine_ir)[0]["control"][
                "decoded_reconciliation"
            ]

            self.assertEqual(package.status, "violated")
            self.assertEqual(reconciliation["status"], "violated")
            target_check = next(
                check
                for check in reconciliation["checks"]
                if check["code"] == "direct_targets_mismatch"
            )
            self.assertEqual(target_check["expected"], [0x1000])
            self.assertEqual(target_check["actual"], [0x1001])

    def test_decoded_external_call_identity_mismatch_violates_reconciliation(
        self,
    ) -> None:
        call = b"\xff\x15\x40\x20\x40\x00"
        event = {
            "kind": "external_call",
            "instruction_rva": 0x1000,
            "return_rva": 0x1006,
            "dll": "KERNEL32.dll",
            "symbol": "SetLastError",
            "ordinal": None,
            "arguments": [],
        }
        rows = [
            _row(
                "semantic-transfer:call",
                0x1000,
                call,
                outcome={"kind": "fallthrough", "target_rva": 0x1006},
                external_events=[event],
                ordered_events=[{"family": "external", **event}],
            ),
            _row(
                "semantic-transfer:return",
                0x1006,
                b"\xc3",
                outcome={"kind": "return"},
            ),
        ]

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            original = root / "original.exe"
            machine = root / "state-machine.jsonl"
            original.write_bytes(
                pe32_import_image(call + b"\xc3", symbol="GetLastError")
            )
            _write_machine(machine, rows)

            package = export_machine_ir_package(
                state_machine=machine, original_pe=original, out=root / "out"
            )
            reconciliation = _read_jsonl(package.machine_ir)[0]["control"][
                "decoded_reconciliation"
            ]

            self.assertEqual(package.status, "violated")
            self.assertEqual(reconciliation["status"], "violated")
            self.assertIn(
                "call_event_0_import_mismatch",
                {check["code"] for check in reconciliation["checks"]},
            )

    def test_writable_pointer_slot_cannot_refine_indirect_decode(self) -> None:
        call = b"\xff\x15\x40\x20\x40\x00"
        event = {
            "kind": "internal_call",
            "instruction_rva": 0x1000,
            "return_rva": 0x1006,
            "target_rva": 0x1010,
        }
        row = _row(
            "semantic-transfer:call",
            0x1000,
            call,
            outcome={"kind": "fallthrough", "target_rva": 0x1006},
            external_events=[event],
            ordered_events=[{"family": "external", **event}],
        )

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            original = root / "original.exe"
            machine = root / "state-machine.jsonl"
            original.write_bytes(
                pe32_image_with_pointer_slot(
                    call.ljust(0x10, b"\x90") + b"\xc3",
                    target_rva=0x1010,
                    writable=True,
                )
            )
            _write_machine(machine, [row])

            package = export_machine_ir_package(
                state_machine=machine, original_pe=original, out=root / "out"
            )
            reconciliation = _read_jsonl(package.machine_ir)[0]["control"][
                "decoded_reconciliation"
            ]

            self.assertEqual(package.status, "violated")
            self.assertIn(
                "call_event_0_kind_mismatch",
                {check["code"] for check in reconciliation["checks"]},
            )

    def test_immutable_pointer_slot_rejects_wrong_internal_target(self) -> None:
        call = b"\xff\x15\x40\x20\x40\x00"
        event = {
            "kind": "internal_call",
            "instruction_rva": 0x1000,
            "return_rva": 0x1006,
            "target_rva": 0x1011,
        }
        row = _row(
            "semantic-transfer:call",
            0x1000,
            call,
            outcome={"kind": "fallthrough", "target_rva": 0x1006},
            external_events=[event],
            ordered_events=[{"family": "external", **event}],
        )

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            original = root / "original.exe"
            machine = root / "state-machine.jsonl"
            original.write_bytes(
                pe32_image_with_pointer_slot(
                    call.ljust(0x10, b"\x90") + b"\xc3",
                    target_rva=0x1010,
                )
            )
            _write_machine(machine, [row])

            package = export_machine_ir_package(
                state_machine=machine, original_pe=original, out=root / "out"
            )
            reconciliation = _read_jsonl(package.machine_ir)[0]["control"][
                "decoded_reconciliation"
            ]

            self.assertEqual(package.status, "violated")
            self.assertIn(
                "call_event_0_immutable_target_mismatch",
                {check["code"] for check in reconciliation["checks"]},
            )

    def test_schedule_sanitization_rejects_corrupted_source_digests(self) -> None:
        record = {"index": 0, "bytes": "90"}
        record["record_sha256"] = sha256_bytes(
            json.dumps(record, sort_keys=True, separators=(",", ":")).encode("utf-8")
        )
        schedule = {"records": [record]}
        schedule["schedule_sha256"] = sha256_bytes(
            json.dumps(schedule, sort_keys=True, separators=(",", ":")).encode("utf-8")
        )

        corrupted_record = json.loads(json.dumps(schedule))
        corrupted_record["records"][0]["index"] = 1
        corrupted_record_body = dict(corrupted_record)
        del corrupted_record_body["schedule_sha256"]
        corrupted_record["schedule_sha256"] = sha256_bytes(
            json.dumps(
                corrupted_record_body, sort_keys=True, separators=(",", ":")
            ).encode("utf-8")
        )
        with self.assertRaisesRegex(
            MachineIRExportError, "source schedule record 0 digest does not match"
        ):
            _sanitize_schedule(corrupted_record, "semantic-transfer:test")

        corrupted_schedule = json.loads(json.dumps(schedule))
        corrupted_schedule["records"].append(dict(record))
        with self.assertRaisesRegex(
            MachineIRExportError,
            "source instruction effect schedule digest does not match",
        ):
            _sanitize_schedule(corrupted_schedule, "semantic-transfer:test")

    def test_reports_source_mapped_executable_coverage_gap(self) -> None:
        code = b"\xc3\x90"
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
            original.write_bytes(pe32_image(code, virtual_size=len(code)))
            _write_machine(machine, [row])

            package = export_machine_ir_package(
                state_machine=machine, original_pe=original, out=root / "out"
            )
            manifest = _read_json(package.manifest)
            issue = next(
                item
                for item in manifest["issues"]
                if item["category"] == "unclassified_executable_span"
            )

            self.assertEqual(package.status, "incomplete")
            self.assertEqual(issue["status"], "incomplete")
            self.assertEqual(issue["location"]["rva_start"], 0x1001)
            self.assertEqual(issue["location"]["rva_end"], 0x1002)
            self.assertEqual(manifest["coverage"]["counts"]["unknown_bytes"], 1)

    def test_reports_source_mapped_violation_for_unit_outside_executable_section(self) -> None:
        image = bytearray(pe32_image(b"\xc3", virtual_size=1))
        section_header = 0x80 + 4 + 20 + 224
        struct.pack_into("<I", image, section_header + 36, 0x40000020)
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
            original.write_bytes(image)
            _write_machine(machine, [row])

            package = export_machine_ir_package(
                state_machine=machine, original_pe=original, out=root / "out"
            )
            manifest = _read_json(package.manifest)
            issue = next(
                item
                for item in manifest["issues"]
                if item["category"] == "semantic_unit_outside_executable_section"
            )

            self.assertEqual(package.status, "violated")
            self.assertEqual(issue["status"], "violated")
            self.assertEqual(issue["location"]["unit_id"], "semantic-transfer:return")
            self.assertEqual(issue["location"]["rva_start"], 0x1000)

    def test_rejects_duplicate_unit_ids_before_writing_package(self) -> None:
        first = _row(
            "semantic-transfer:duplicate",
            0x1000,
            b"\x90",
            outcome={"kind": "jump", "target_rva": 0x1001},
        )
        second = _row(
            "semantic-transfer:duplicate",
            0x1001,
            b"\xc3",
            outcome={"kind": "return"},
        )

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            original = root / "original.exe"
            machine = root / "state-machine.jsonl"
            out = root / "out"
            original.write_bytes(pe32_image(b"\x90\xc3", virtual_size=2))
            _write_machine(machine, [first, second])

            with self.assertRaisesRegex(MachineIRExportError, "duplicate machine unit id") as raised:
                export_machine_ir_package(
                    state_machine=machine, original_pe=original, out=out
                )

            self.assertEqual(raised.exception.code, "duplicate_machine_unit_id")
            self.assertFalse(out.exists())

    def test_rejects_stale_digest_and_original_pe_byte_mismatch(self) -> None:
        row = _row(
            "semantic-transfer:return",
            0x1000,
            b"\xc3",
            outcome={"kind": "return"},
        )
        stale = dict(row)
        stale["outcome"] = {"kind": "jump", "target_rva": 0x1000}

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            original = root / "original.exe"
            machine = root / "state-machine.jsonl"
            original.write_bytes(pe32_image(b"\xc3", virtual_size=1))
            _write_machine(machine, [stale])
            with self.assertRaisesRegex(MachineIRExportError, "stale contract digest") as stale_error:
                export_machine_ir_package(
                    state_machine=machine, original_pe=original, out=root / "stale"
                )
            self.assertEqual(
                stale_error.exception.code, "state_machine_contract_digest_mismatch"
            )

            _write_machine(machine, [row])
            original.write_bytes(pe32_image(b"\x90", virtual_size=1))
            with self.assertRaisesRegex(MachineIRExportError, "supplied original PE") as pe_error:
                export_machine_ir_package(
                    state_machine=machine, original_pe=original, out=root / "mismatch"
                )
            self.assertEqual(pe_error.exception.code, "original_pe_unit_binding_mismatch")

    def test_rejects_raw_instruction_material_hidden_in_semantic_effects(self) -> None:
        row = _row(
            "semantic-transfer:return",
            0x1000,
            b"\xc3",
            outcome={"kind": "return"},
            ordered_events=[{"family": "fault", "bytes": "c3"}],
        )

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            original = root / "original.exe"
            machine = root / "state-machine.jsonl"
            original.write_bytes(pe32_image(b"\xc3", virtual_size=1))
            _write_machine(machine, [row])

            with self.assertRaisesRegex(MachineIRExportError, "raw instruction material") as raised:
                export_machine_ir_package(
                    state_machine=machine, original_pe=original, out=root / "out"
                )
            self.assertEqual(raised.exception.code, "raw_instruction_bytes_in_semantics")

    def test_rejects_malformed_semantic_inventory(self) -> None:
        row = _row(
            "semantic-transfer:return",
            0x1000,
            b"\xc3",
            outcome={"kind": "return"},
        )
        malformed = dict(row)
        malformed["external_events"] = "not-an-inventory"
        malformed = normalize_stage_a_semantic_transfer(malformed)

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            original = root / "original.exe"
            machine = root / "state-machine.jsonl"
            original.write_bytes(pe32_image(b"\xc3", virtual_size=1))
            _write_machine(machine, [malformed])

            with self.assertRaisesRegex(MachineIRExportError, "external_events") as raised:
                export_machine_ir_package(
                    state_machine=machine, original_pe=original, out=root / "out"
                )
            self.assertEqual(raised.exception.code, "malformed_semantic_unit_effects")


if __name__ == "__main__":
    unittest.main()
