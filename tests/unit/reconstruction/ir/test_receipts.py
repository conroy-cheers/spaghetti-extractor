from __future__ import annotations

from tests.unit.reconstruction.ir._support import *


class ReconstructionIRReceiptTests(unittest.TestCase):
    def test_schedule_sanitization_preserves_and_reseals_integrity(self) -> None:
        record = {
            "index": 0,
            "bytes": "90",
            "bytes_sha256": sha256_bytes(b"\x90"),
            "effects": {"raw_bytes": "90", "register_writes": []},
        }
        record["record_sha256"] = sha256_bytes(
            json.dumps(record, sort_keys=True, separators=(",", ":")).encode("utf-8")
        )
        schedule = {
            "format": "spaghetti-extractor-static-instruction-effects-v1",
            "records": [record],
            "blockers": [],
        }
        schedule["schedule_sha256"] = sha256_bytes(
            json.dumps(schedule, sort_keys=True, separators=(",", ":")).encode("utf-8")
        )

        sanitized = _sanitize_schedule(schedule, "semantic-transfer:test")
        sanitized_record = sanitized["records"][0]

        self.assertEqual(
            sanitized["source_schedule_sha256"], schedule["schedule_sha256"]
        )
        self.assertEqual(
            sanitized_record["source_record_sha256"], record["record_sha256"]
        )
        self.assertEqual(_raw_instruction_keys(sanitized), set())
        record_body = dict(sanitized_record)
        del record_body["record_sha256"]
        self.assertEqual(
            sanitized_record["record_sha256"],
            sha256_bytes(
                json.dumps(record_body, sort_keys=True, separators=(",", ":")).encode(
                    "utf-8"
                )
            ),
        )
        schedule_body = dict(sanitized)
        del schedule_body["schedule_sha256"]
        self.assertEqual(
            sanitized["schedule_sha256"],
            sha256_bytes(
                json.dumps(schedule_body, sort_keys=True, separators=(",", ":")).encode(
                    "utf-8"
                )
            ),
        )

        corrupted_record = dict(sanitized_record)
        corrupted_record["index"] = 1
        corrupted_record_body = dict(corrupted_record)
        del corrupted_record_body["record_sha256"]
        self.assertNotEqual(
            corrupted_record["record_sha256"],
            sha256_bytes(
                json.dumps(
                    corrupted_record_body, sort_keys=True, separators=(",", ":")
                ).encode("utf-8")
            ),
        )

    def test_optional_static_program_contract_is_hash_bound_and_projects_block_root(self) -> None:
        row = _row(
            "semantic-transfer:return",
            0x1000,
            b"\xc3",
            outcome={"kind": "return"},
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            original = root / "original.exe"
            static_program = root / "static-program-contract.json"
            machine = root / "state-machine.jsonl"
            original.write_bytes(pe32_image(b"\xc3", virtual_size=1))
            _write_static_program_contract(static_program, original)
            row["static_program_export"] = {
                "format": "spaghetti-extractor-static-program-semantic-binding-v2",
                "static_program_contract_sha256": sha256_file(static_program),
                "semantic_transfer_sha256": "b" * 64,
            }
            _write_machine(machine, [row])

            package = export_machine_ir_package(
                state_machine=machine,
                original_pe=original,
                static_program_contract=static_program,
                out=root / "out",
            )
            manifest = _read_json(package.manifest)

            self.assertEqual(package.status, "qualified")
            self.assertEqual(
                manifest["inputs"]["static_program_contract"]["sha256"],
                sha256_file(static_program),
            )
            self.assertEqual(manifest["control"]["roots"][0]["block_id"], "return")
            self.assertEqual(manifest["control"]["roots"][0]["rva"], 0x1000)
            self.assertEqual(
                manifest["static_program_inventory"]["roots"]["status"],
                "complete",
            )


if __name__ == "__main__":
    unittest.main()
