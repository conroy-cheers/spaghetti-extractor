from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.authority._schema import AnalysisV3Error
from spaghetti_extractor.authority.source_plan import prepare_analysis_source_v3


def _unit(unit_id: str, start: int, targets: list[int]) -> dict[str, object]:
    return {
        "format": "stage-a-machine-ir-v2",
        "record_kind": "unit",
        "id": unit_id,
        "status": "qualified",
        "source": {
            "original": {"rva_start": start, "rva_end": start + 8},
            "instruction_bytes_sha256": f"{start:064x}",
        },
        "control": {
            "kind": "direct_jump" if targets else "return",
            "direct_targets": targets,
            "has_indirect_target": False,
        },
    }


def _write_machine_ir(path: Path, rows: list[dict[str, object]]) -> None:
    path.write_text(
        "".join(json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n" for row in rows),
        encoding="ascii",
    )


class AnalysisSourcePlanV3Tests(unittest.TestCase):
    def test_plan_is_deterministic_and_records_direct_dependencies(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            machine_ir = root / "machine-ir.jsonl"
            binary = root / "fixture.exe"
            binary.write_bytes(b"MZfixture")
            rows = [_unit("unit:b", 0x1010, []), _unit("unit:a", 0x1000, [0x1010])]
            _write_machine_ir(machine_ir, rows)

            first = prepare_analysis_source_v3(
                machine_ir=machine_ir, binary=binary, output_directory=root / "first"
            )
            second = prepare_analysis_source_v3(
                machine_ir=machine_ir, binary=binary, output_directory=root / "second"
            )

            self.assertEqual(first, second)
            self.assertEqual(first["unit_count"], 2)
            self.assertEqual(first["unresolved_direct_targets"]["count"], 0)
            self.assertEqual(
                (root / "first" / "plan.json").read_bytes(),
                (root / "second" / "plan.json").read_bytes(),
            )
            structural = json.loads(
                (root / "first" / first["structural_inventory"]["filename"]).read_text(
                    encoding="ascii"
                )
            )
            self.assertEqual(
                [row["unit_id"] for row in structural["units"]],
                ["unit:a", "unit:b"],
            )
            self.assertEqual(structural["units"][0]["dependencies"], ["unit:b"])
            self.assertEqual(first["shard_bucket_count"], 4)
            self.assertEqual(
                sorted(unit for shard in first["shards"] for unit in shard["unit_ids"]),
                ["unit:a", "unit:b"],
            )
            for row in first["shards"]:
                shard = root / "first" / "shards" / row["filename"]
                self.assertTrue(shard.is_file())
                self.assertEqual(
                    {
                        json.loads(line)["id"]
                        for line in shard.read_text(encoding="ascii").splitlines()
                    },
                    set(row["unit_ids"]),
                )
            self.assertFalse((root / "first" / "units").exists())
            boundaries = first["preplanned_boundaries"]
            self.assertEqual(
                boundaries["format"],
                "spaghetti-extractor-scheduling-boundaries-v3",
            )
            for family in ("structural", "dependency"):
                descriptor = boundaries[family]
                self.assertTrue(
                    (root / "first" / descriptor["schedule"]["filename"]).is_file()
                )
                self.assertTrue(
                    (root / "first" / descriptor["pack_index"]["filename"]).is_file()
                )

    def test_unresolved_direct_target_is_an_explicit_frontier(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            machine_ir = root / "machine-ir.jsonl"
            binary = root / "fixture.exe"
            binary.write_bytes(b"MZfixture")
            _write_machine_ir(machine_ir, [_unit("unit:a", 0x1000, [0xDEAD])])

            plan = prepare_analysis_source_v3(
                machine_ir=machine_ir, binary=binary, output_directory=root / "out"
            )

            self.assertEqual(plan["unresolved_direct_targets"]["count"], 1)
            unresolved = json.loads(
                (root / "out" / plan["unresolved_direct_targets"]["filename"]).read_text(
                    encoding="ascii"
                )
            )
            self.assertEqual(
                unresolved["targets"],
                [{"source_unit_id": "unit:a", "target_rva": 0xDEAD}],
            )

    def test_duplicate_entries_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            machine_ir = root / "machine-ir.jsonl"
            binary = root / "fixture.exe"
            binary.write_bytes(b"MZfixture")
            _write_machine_ir(
                machine_ir,
                [_unit("unit:a", 0x1000, []), _unit("unit:b", 0x1000, [])],
            )

            with self.assertRaises(AnalysisV3Error) as raised:
                prepare_analysis_source_v3(
                    machine_ir=machine_ir,
                    binary=binary,
                    output_directory=root / "out",
                )

            self.assertEqual(raised.exception.code, "ambiguous_structural_entry")


if __name__ == "__main__":
    unittest.main()
