from __future__ import annotations

import copy
import json
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.recovered_executable_data import (
    RecoveredExecutableDataRange,
    RecoveredExecutableDataError,
    build_recovered_executable_data_contract,
    load_recovered_executable_data_contract,
    recover_executable_data_ranges,
)
from spaghetti_extractor.stage_binary import _parse_stage_a_pe
from spaghetti_extractor.util import sha256_bytes

from tests.pe_fixtures import pe32_image


def _fixture_control(table: bytes, remap: bytes) -> dict[str, object]:
    return {
        "roots": [{"kind": "pe_entrypoint", "rva": 0x1000}],
        "direct_targets": [],
        "reachability": {
            "reachable_units": ["semantic-transfer:entry"],
        },
        "recovered_indirect_targets": [
            {
                "id": "indirect-exit:fixture",
                "source_unit_id": "semantic-transfer:entry",
                "status": "recovered",
                "closure": "checked_finite_target_inventory",
                "target_rvas": [0x1000],
                "unit_binding": {"status": "complete"},
                "table": {
                    "rva_start": 0x1010,
                    "rva_end": 0x1010 + len(table),
                    "bytes_sha256": sha256_bytes(table),
                },
                "index": {
                    "remap": {
                        "rva_start": 0x1010 + len(table),
                        "rva_end": 0x1010 + len(table) + len(remap),
                        "bytes_sha256": sha256_bytes(remap),
                    }
                },
            }
        ],
    }


class RecoveredExecutableDataTests(unittest.TestCase):
    def test_precontrol_recovery_does_not_require_unit_binding_or_reachability(self) -> None:
        table = bytes.fromhex("0010400000104000")
        remap = bytes.fromhex("0001")
        image = b"\xc3" + bytes(15) + table + remap
        control = _fixture_control(table, remap)
        recovery = control["recovered_indirect_targets"][0]
        recovery["unit_binding"] = {"status": "incomplete"}
        with tempfile.TemporaryDirectory() as temporary:
            original = Path(temporary) / "original.exe"
            original.write_bytes(pe32_image(image, virtual_size=len(image)))
            binary = _parse_stage_a_pe(original)
            try:
                ranges = recover_executable_data_ranges(
                    binary=binary,
                    recoveries=[recovery],
                )
            finally:
                binary.pe.close()

        self.assertEqual(
            [(item.rva_start, item.rva_end) for item in ranges],
            [(0x1010, 0x1018), (0x1018, 0x101A)],
        )
        self.assertEqual(
            [item.kinds for item in ranges],
            [("finite_target_table",), ("finite_index_remap",)],
        )

    def test_exports_only_hash_bound_immutable_table_ranges(self) -> None:
        table = bytes.fromhex("0010400000104000")
        remap = bytes.fromhex("0001")
        image = b"\xc3" + bytes(15) + table + remap
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            original = root / "original.exe"
            artifact = root / "recovered-executable-data.json"
            original.write_bytes(pe32_image(image, virtual_size=len(image)))
            binary = _parse_stage_a_pe(original)
            try:
                contract = build_recovered_executable_data_contract(
                    binary=binary,
                    control=_fixture_control(table, remap),
                    source_map=[
                        {
                            "unit_id": "semantic-transfer:entry",
                            "rva_start": 0x1000,
                            "rva_end": 0x1001,
                        }
                    ],
                    machine_ir_sha256="a" * 64,
                )
            finally:
                binary.pe.close()
            artifact.write_text(
                json.dumps(contract.to_payload(), sort_keys=True), encoding="ascii"
            )
            loaded = load_recovered_executable_data_contract(artifact)

            self.assertEqual(
                [(item.rva_start, item.rva_end) for item in loaded.ranges],
                [(0x1010, 0x1018), (0x1018, 0x101A)],
            )
            self.assertEqual([item.data for item in loaded.ranges], [table, remap])
            self.assertNotIn(str(original), artifact.read_text(encoding="ascii"))
            self.assertFalse(
                loaded.to_payload()["constraints"]["executable_code_bytes_exported"]
            )

    def test_recovers_bounded_noop_padding_adjacent_to_immutable_data(self) -> None:
        table = bytes.fromhex("0010400000104000")
        remap = bytes.fromhex("0001")
        padding = bytes.fromhex("90909090")
        image = b"\xc3" + bytes(15) + table + remap + padding + b"\x55"
        with tempfile.TemporaryDirectory() as temporary:
            original = Path(temporary) / "original.exe"
            original.write_bytes(pe32_image(image, virtual_size=len(image)))
            binary = _parse_stage_a_pe(original)
            try:
                ranges = recover_executable_data_ranges(
                    binary=binary,
                    recoveries=_fixture_control(table, remap)[
                        "recovered_indirect_targets"
                    ],
                )
            finally:
                binary.pe.close()

        self.assertEqual(
            [(item.rva_start, item.rva_end) for item in ranges],
            [(0x1010, 0x1018), (0x1018, 0x101A), (0x101A, 0x101E)],
        )
        self.assertEqual(ranges[-1].kinds, ("alignment_padding",))

    def test_recovers_identity_register_move_padding_before_immutable_data(self) -> None:
        table = bytes.fromhex("0010400000104000")
        remap = bytes.fromhex("0001")
        for padding in (bytes.fromhex("8bff"), bytes.fromhex("2e8bc0")):
            with self.subTest(padding=padding.hex()):
                prefix = b"\xc3" + bytes(15 - len(padding)) + padding
                image = prefix + table + remap
                with tempfile.TemporaryDirectory() as temporary:
                    original = Path(temporary) / "original.exe"
                    original.write_bytes(
                        pe32_image(image, virtual_size=len(image))
                    )
                    binary = _parse_stage_a_pe(original)
                    try:
                        ranges = recover_executable_data_ranges(
                            binary=binary,
                            recoveries=_fixture_control(table, remap)[
                                "recovered_indirect_targets"
                            ],
                        )
                    finally:
                        binary.pe.close()

                self.assertEqual(ranges[0].rva_start, 0x1010 - len(padding))
                self.assertEqual(ranges[0].data, padding)
                self.assertEqual(ranges[0].kinds, ("alignment_padding",))

    def test_does_not_classify_nonidentity_instruction_or_pointer_gap(self) -> None:
        table = bytes.fromhex("0010400000104000")
        remap = bytes.fromhex("0001")
        nonidentity_move = bytes.fromhex("8bc1")
        pointer_gap = bytes.fromhex("30104000")
        prefix = b"\xc3" + bytes(13) + nonidentity_move
        image = prefix + table + pointer_gap + remap
        control = _fixture_control(table, remap)
        recovery = control["recovered_indirect_targets"][0]
        recovery["index"]["remap"].update(
            {
                "rva_start": 0x101C,
                "rva_end": 0x101E,
            }
        )
        with tempfile.TemporaryDirectory() as temporary:
            original = Path(temporary) / "original.exe"
            original.write_bytes(pe32_image(image, virtual_size=len(image)))
            binary = _parse_stage_a_pe(original)
            try:
                ranges = recover_executable_data_ranges(
                    binary=binary,
                    recoveries=[recovery],
                )
            finally:
                binary.pe.close()

        self.assertEqual(
            [(item.rva_start, item.rva_end) for item in ranges],
            [(0x1010, 0x1018), (0x101C, 0x101E)],
        )

    def test_classifies_recovery_bound_pointer_to_exact_code_unit(self) -> None:
        table = bytes.fromhex("0010400000104000")
        pointer_gap = bytes.fromhex("00104000")
        remap = bytes.fromhex("0001")
        image = b"\xc3" + bytes(15) + table + pointer_gap + remap
        control = _fixture_control(table, remap)
        recovery = control["recovered_indirect_targets"][0]
        recovery["index"]["remap"].update(
            {"rva_start": 0x101C, "rva_end": 0x101E}
        )
        with tempfile.TemporaryDirectory() as temporary:
            original = Path(temporary) / "original.exe"
            original.write_bytes(pe32_image(image, virtual_size=len(image)))
            binary = _parse_stage_a_pe(original)
            try:
                ranges = recover_executable_data_ranges(
                    binary=binary,
                    recoveries=[recovery],
                    known_code_unit_rvas={0x1000},
                )
            finally:
                binary.pe.close()

        self.assertEqual(
            [(item.rva_start, item.rva_end) for item in ranges],
            [(0x1010, 0x1018), (0x1018, 0x101C), (0x101C, 0x101E)],
        )
        self.assertEqual(ranges[1].kinds, ("static_code_pointer_slot",))
        self.assertEqual(
            RecoveredExecutableDataRange.parse(
                ranges[1].to_payload(), label="static code-pointer slot"
            ),
            ranges[1],
        )

    def test_does_not_partially_classify_long_noop_run(self) -> None:
        table = bytes.fromhex("0010400000104000")
        remap = bytes.fromhex("0001")
        image = b"\xc3" + bytes(15) + table + remap + bytes.fromhex("90" * 16)
        with tempfile.TemporaryDirectory() as temporary:
            original = Path(temporary) / "original.exe"
            original.write_bytes(pe32_image(image, virtual_size=len(image)))
            binary = _parse_stage_a_pe(original)
            try:
                ranges = recover_executable_data_ranges(
                    binary=binary,
                    recoveries=_fixture_control(table, remap)[
                        "recovered_indirect_targets"
                    ],
                )
            finally:
                binary.pe.close()

        self.assertEqual(
            [(item.rva_start, item.rva_end) for item in ranges],
            [(0x1010, 0x1018), (0x1018, 0x101A)],
        )

    def test_corrupted_range_bytes_fail_hash_validation(self) -> None:
        table = bytes.fromhex("0010400000104000")
        remap = bytes.fromhex("0001")
        image = b"\xc3" + bytes(15) + table + remap
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            original = root / "original.exe"
            artifact = root / "recovered-executable-data.json"
            original.write_bytes(pe32_image(image, virtual_size=len(image)))
            binary = _parse_stage_a_pe(original)
            try:
                payload = build_recovered_executable_data_contract(
                    binary=binary,
                    control=_fixture_control(table, remap),
                    source_map=[
                        {
                            "unit_id": "semantic-transfer:entry",
                            "rva_start": 0x1000,
                            "rva_end": 0x1001,
                        }
                    ],
                    machine_ir_sha256="a" * 64,
                ).to_payload()
            finally:
                binary.pe.close()
            corrupted = copy.deepcopy(payload)
            corrupted["ranges"][0]["bytes_hex"] = "ff" + corrupted["ranges"][0][
                "bytes_hex"
            ][2:]
            artifact.write_text(json.dumps(corrupted), encoding="ascii")

            with self.assertRaisesRegex(
                RecoveredExecutableDataError, "byte hash mismatch"
            ):
                load_recovered_executable_data_contract(artifact)

    def test_reachable_transfer_overlap_fails_closed(self) -> None:
        table = bytes.fromhex("0010400000104000")
        remap = bytes.fromhex("0001")
        image = b"\xc3" + bytes(15) + table + remap
        with tempfile.TemporaryDirectory() as temporary:
            original = Path(temporary) / "original.exe"
            original.write_bytes(pe32_image(image, virtual_size=len(image)))
            binary = _parse_stage_a_pe(original)
            try:
                with self.assertRaisesRegex(
                    RecoveredExecutableDataError, "overlaps rooted reachable transfer"
                ):
                    build_recovered_executable_data_contract(
                        binary=binary,
                        control=_fixture_control(table, remap),
                        source_map=[
                            {
                                "unit_id": "semantic-transfer:entry",
                                "rva_start": 0x1000,
                                "rva_end": 0x1011,
                            }
                        ],
                        machine_ir_sha256="a" * 64,
                    )
            finally:
                binary.pe.close()


if __name__ == "__main__":
    unittest.main()
