from __future__ import annotations

import csv
import json
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.isa_conformance import ISAConformanceError
from spaghetti_extractor import isa_conformance_80386 as sst80386


REVISION = "a" * 40


def _source_row(
    *,
    index: int = 0,
    source_hash: str = "1" * 40,
    immediate: int = 1,
) -> dict:
    instruction = [0x66, 0x05, *immediate.to_bytes(4, "little")]
    cs = 0x100
    eip = 0x200
    linear = (cs << 4) + eip
    initial_regs = {
        "cr0": 0x7FFF0000,
        "cr3": 0,
        "eax": 0x0F,
        "ebx": 2,
        "ecx": 3,
        "edx": 4,
        "esi": 5,
        "edi": 6,
        "ebp": 7,
        "esp": 0x8000,
        "cs": cs,
        "ds": 0,
        "es": 0,
        "fs": 0,
        "gs": 0,
        "ss": 0,
        "eip": eip,
        "eflags": 0x2,
        "dr6": 0xFFFF0FF0,
        "dr7": 0,
    }
    protocol = instruction + [0xF4]
    return {
        "idx": index,
        "name": f"add eax,{immediate:X}h",
        "bytes": protocol,
        "initial": {
            "regs": initial_regs,
            "ram": [[linear + offset, byte] for offset, byte in enumerate(protocol)],
            "queue": [],
        },
        "final": {
            "regs": {
                "eax": (0x0F + immediate) & 0xFFFFFFFF,
                "eip": eip + len(protocol),
                "eflags": 0x12,
            },
            "ram": [],
            "queue": [],
        },
        "cycles": [],
        "hash": source_hash,
    }


def _write_inputs(root: Path, rows: list[dict]) -> tuple[Path, Path, Path]:
    tests_json = root / "6605.json"
    tests_json.write_text(json.dumps(rows), encoding="utf-8")
    metadata = root / "80386.csv"
    with metadata.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=sst80386._CSV_FIELDS)
        writer.writeheader()
        row = {field: "" for field in sst80386._CSV_FIELDS}
        row.update(
            {
                "op": "05",
                "ct": "2500",
                "66": "1",
                "mnemonic": "ADD",
                "op1": "AX",
                "op2": "imm16/32",
                "f_mod": "o..szapc",
                "f_def": "o..szapc",
                "description": "Add",
            }
        )
        writer.writerow(row)
    revocations = root / "revocation_list.txt"
    revocations.write_text("# pinned revocations\n", encoding="utf-8")
    return tests_json, metadata, revocations


def _import(root: Path, rows: list[dict], **kwargs):
    tests_json, metadata, revocations = _write_inputs(root, rows)
    return sst80386.import_singlestep_80386_json(
        tests_json=tests_json,
        metadata_csv=metadata,
        revocations=revocations,
        source_revision=REVISION,
        **kwargs,
    )


class StageAISAConformance80386ImportTests(unittest.TestCase):
    def test_register_vector_is_normalized_to_protected_32_and_audited(self):
        with tempfile.TemporaryDirectory() as temporary:
            result = _import(Path(temporary), [_source_row()])

        self.assertEqual(len(result.corpus.cases), 1)
        case = result.corpus.cases[0]
        self.assertEqual(case.instruction_bytes, bytes([0x05, 1, 0, 0, 0]))
        self.assertEqual(case.initial_state.eip, sst80386.PE32_TEST_EIP)
        self.assertEqual(case.expected.final_state.eip, sst80386.PE32_TEST_EIP + 5)
        self.assertEqual(case.expected.final_state.gprs.eax, 0x10)
        self.assertEqual(case.defined_outputs.eflags & 0x10, 0x10)
        self.assertEqual(case.expected.final_state.eflags & 0x10, 0x10)
        self.assertFalse(result.manifest["trust"]["proof_authority"])
        self.assertFalse(result.manifest["trust"]["closes_stage_a_proof"])
        self.assertEqual(result.manifest["counts"]["imported"], 1)
        self.assertEqual(
            result.manifest["decisions"][0]["reason"],
            sst80386.ImportReason.QUALIFIED.value,
        )

    def test_revoked_vectors_are_visible_and_never_imported(self):
        rows = [
            _source_row(index=0, source_hash="1" * 40),
            _source_row(index=1, source_hash="2" * 40),
        ]
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            tests_json, metadata, revocations = _write_inputs(root, rows)
            revocations.write_text("# revoked\n" + "1" * 40 + "\n", encoding="utf-8")
            result = sst80386.import_singlestep_80386_json(
                tests_json=tests_json,
                metadata_csv=metadata,
                revocations=revocations,
                source_revision=REVISION,
            )

        self.assertEqual(len(result.corpus.cases), 1)
        self.assertIn("-00001-", result.corpus.cases[0].id)
        self.assertEqual(
            result.manifest["counts"]["by_reason"][
                sst80386.ImportReason.REVOKED.value
            ],
            1,
        )

    def test_memory_and_hidden_machine_effects_fail_closed(self):
        memory = _source_row(index=0, source_hash="1" * 40)
        memory["final"]["ram"] = [[0x2000, 7]]
        hidden = _source_row(index=1, source_hash="2" * 40)
        hidden["final"]["regs"]["cs"] = 3
        valid = _source_row(index=2, source_hash="3" * 40)
        with tempfile.TemporaryDirectory() as temporary:
            result = _import(Path(temporary), [memory, hidden, valid])

        reasons = result.manifest["counts"]["by_reason"]
        self.assertEqual(reasons[sst80386.ImportReason.SOURCE_MEMORY_EFFECT.value], 1)
        self.assertEqual(reasons[sst80386.ImportReason.FORM.value], 1)
        self.assertEqual(result.manifest["counts"]["imported"], 1)

    def test_instruction_ram_protocol_is_checked(self):
        malformed = _source_row(index=0, source_hash="1" * 40)
        malformed["initial"]["ram"][0][1] ^= 0xFF
        valid = _source_row(index=1, source_hash="2" * 40)
        with tempfile.TemporaryDirectory() as temporary:
            result = _import(Path(temporary), [malformed, valid])

        self.assertEqual(
            result.manifest["counts"]["by_reason"][
                sst80386.ImportReason.SOURCE_EIP.value
            ],
            1,
        )
        self.assertEqual(result.manifest["counts"]["imported"], 1)

    def test_unknown_source_fields_and_ambiguous_metadata_are_rejected(self):
        malformed = _source_row()
        malformed["surprise"] = True
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaisesRegex(ISAConformanceError, "unknown fields"):
                _import(Path(temporary), [malformed])

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            tests_json, metadata, revocations = _write_inputs(root, [_source_row()])
            lines = metadata.read_text(encoding="utf-8").splitlines()
            metadata.write_text("\n".join([*lines, lines[-1]]) + "\n", encoding="utf-8")
            with self.assertRaisesRegex(ISAConformanceError, "matched 2 metadata rows"):
                sst80386.import_singlestep_80386_json(
                    tests_json=tests_json,
                    metadata_csv=metadata,
                    revocations=revocations,
                    source_revision=REVISION,
                )

    def test_sharding_and_limits_are_deterministic_and_audited(self):
        rows = [
            _source_row(index=0, source_hash="0" * 15 + "1" + "0" * 24),
            _source_row(index=1, source_hash="0" * 15 + "2" + "0" * 24),
            _source_row(index=2, source_hash="0" * 15 + "4" + "0" * 24),
        ]
        with tempfile.TemporaryDirectory() as temporary:
            result = _import(
                Path(temporary),
                rows,
                shard_index=0,
                shard_count=2,
                max_cases=1,
            )

        self.assertEqual(len(result.corpus.cases), 1)
        reasons = result.manifest["counts"]["by_reason"]
        self.assertEqual(reasons[sst80386.ImportReason.OTHER_SHARD.value], 1)
        self.assertEqual(reasons[sst80386.ImportReason.SAMPLE_LIMIT.value], 1)

    def test_undefined_metadata_flags_are_removed_from_the_output_mask(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            tests_json, metadata, revocations = _write_inputs(root, [_source_row()])
            rows = list(csv.DictReader(metadata.read_text(encoding="utf-8").splitlines()))
            rows[0]["f_undef"] = ".....a.."
            with metadata.open("w", encoding="utf-8", newline="") as handle:
                writer = csv.DictWriter(handle, fieldnames=sst80386._CSV_FIELDS)
                writer.writeheader()
                writer.writerows(rows)
            result = sst80386.import_singlestep_80386_json(
                tests_json=tests_json,
                metadata_csv=metadata,
                revocations=revocations,
                source_revision=REVISION,
            )

        self.assertEqual(result.corpus.cases[0].defined_outputs.eflags & 0x10, 0)


if __name__ == "__main__":
    unittest.main()
