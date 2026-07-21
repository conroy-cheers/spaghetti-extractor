from __future__ import annotations

import struct
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from spaghetti_extractor.relational.analyses.control import (
    _bounded_immutable_relocation_table_jump_candidates,
)
from spaghetti_extractor.relational.contract import (
    _split_relocation_backed_internal_cutpoints,
)
from spaghetti_extractor.relational.binary_inventory import (
    _immutable_relocation_instruction_starts,
    _relocation_split_spans,
)


class _FakePe:
    def __init__(self, chunks: dict[int, bytes]) -> None:
        self._bytes = {
            start + offset: value
            for start, data in chunks.items()
            for offset, value in enumerate(data)
        }

    def get_data(self, rva: int, size: int) -> bytes:
        return bytes(self._bytes.get(rva + offset, 0) for offset in range(size))


class _FakeBinary:
    image_base = 0x400000
    size_of_headers = 0

    def __init__(self, chunks: dict[int, bytes]) -> None:
        self.pe = _FakePe(chunks)
        self.imports: list[object] = []
        self.sections = [SimpleNamespace(
            rva_start=0x0800,
            rva_end=0x4000,
            executable=True,
            writable=False,
        )]


class StageAInternalCutpointTests(unittest.TestCase):
    @staticmethod
    def _regions() -> list[dict[str, object]]:
        return [
            {
                "id": "source",
                "root": True,
                "original": {"rva": 0x0800, "size": 1},
                "candidate": {"rva": 0x0800, "size": 1},
            },
            {
                "id": "mapped-target",
                "root": False,
                "original": {"rva": 0x1000, "size": 6},
                "candidate": {"rva": 0x2000, "size": 17},
            },
        ]

    @staticmethod
    def _binaries(
        original_targets: list[int], candidate_targets: list[int]
    ) -> tuple[_FakeBinary, _FakeBinary]:
        original_table = b"".join(
            struct.pack("<I", 0x400000 + target) for target in original_targets
        )
        candidate_table = b"".join(
            struct.pack("<I", 0x400000 + target) for target in candidate_targets
        )
        original = _FakeBinary({
            0x0800: b"\xc3",
            0x1000: b"\xb8\x00\x00\x00\x00\xc3",
            0x3000: original_table,
        })
        candidate = _FakeBinary({
            0x0800: b"\xc3",
            0x2000: (
                b"\xb8\x00\x00\x00\x00"
                b"\xb8\x00\x00\x00\x00"
                b"\xb8\x00\x00\x00\x00\x90\xc3"
            ),
            0x3000: candidate_table,
        })
        return original, candidate

    @staticmethod
    def _table_target(base: int) -> dict[str, object]:
        return {
            "op": "read32",
            "address": {
                "op": "add",
                "left": {
                    "op": "shift_left",
                    "value": {"op": "input_reg", "reg": "eax"},
                    "amount": 2,
                },
                "right": {"op": "constant", "value": base},
            },
        }

    def test_paired_internal_boundaries_form_a_finite_jump_frontier(self) -> None:
        original, candidate = self._binaries([0x1005], [0x2010])
        relocations = [{"rva": 0x3000, "type": 3}]
        with patch(
            "spaghetti_extractor.relational.contract._raw_base_relocations",
            return_value=relocations,
        ):
            regions = _split_relocation_backed_internal_cutpoints(
                self._regions(), original, candidate
            )

        self.assertEqual(len(regions), 3)
        self.assertEqual(regions[1]["original"], {"rva": 0x1000, "size": 5})
        self.assertEqual(regions[1]["candidate"], {"rva": 0x2000, "size": 16})
        self.assertEqual(regions[2]["original"], {"rva": 0x1005, "size": 1})
        self.assertEqual(regions[2]["candidate"], {"rva": 0x2010, "size": 1})

        code_targets = [
            {
                "id": index,
                "region_index": index,
                "original_rva": int(region["original"]["rva"]),
                "candidate_rva": int(region["candidate"]["rva"]),
                "original_aliases": [],
                "candidate_aliases": [],
            }
            for index, region in enumerate(regions)
        ]
        regions[0]["bounds"] = [{
            "original": "eax",
            "candidate": "eax",
            "unsigned_lt": 1,
        }]
        regions[0]["code_targets"] = [code_targets[2]]
        regions[1]["code_targets"] = []
        regions[2]["code_targets"] = []
        contract = {
            "regions": regions,
            "code_targets": code_targets,
            "value_targets": [{
                "id": 0,
                "original_value": 0x403000,
                "candidate_value": 0x403000,
                "mapped_size": 4,
                "relocation_offsets": [0],
            }],
        }
        behaviors = [
            {
                "original_ir": {"outcome": {
                    "op": "indirect_jump",
                    "target": self._table_target(0x403000),
                }},
                "candidate_ir": {"outcome": {
                    "op": "indirect_jump",
                    "target": self._table_target(0x403000),
                }},
            },
            {
                "original_ir": {"outcome": {"op": "returned"}},
                "candidate_ir": {"outcome": {"op": "returned"}},
            },
            {
                "original_ir": {"outcome": {"op": "returned"}},
                "candidate_ir": {"outcome": {"op": "returned"}},
            },
        ]

        claims = _bounded_immutable_relocation_table_jump_candidates(
            original, candidate, contract, behaviors
        )

        self.assertEqual(len(claims), 1)
        self.assertEqual(claims[0]["entry_target_ids"], [2])
        self.assertEqual(claims[0]["target_ids"], [2])

    def test_relocated_indirect_operand_pairs_moved_table_rows(self) -> None:
        original_table_rva = 0x3000
        candidate_table_rva = 0x3100
        original_jump = b"\xff\x24\x85" + struct.pack(
            "<I", _FakeBinary.image_base + original_table_rva
        )
        candidate_jump = b"\xff\x24\x85" + struct.pack(
            "<I", _FakeBinary.image_base + candidate_table_rva
        )
        original = _FakeBinary({
            0x0800: original_jump,
            0x1000: b"\xb8\x00\x00\x00\x00\xc3",
            original_table_rva: struct.pack("<I", 0x401005),
        })
        candidate = _FakeBinary({
            0x0800: candidate_jump,
            0x2000: (
                b"\xb8\x00\x00\x00\x00"
                b"\xb8\x00\x00\x00\x00"
                b"\xb8\x00\x00\x00\x00\x90\xc3"
            ),
            candidate_table_rva: struct.pack("<I", 0x402010),
        })
        regions = self._regions()
        regions[0]["original"]["size"] = len(original_jump)
        regions[0]["candidate"]["size"] = len(candidate_jump)
        original_relocations = [
            {"rva": 0x0803, "type": 3},
            {"rva": original_table_rva, "type": 3},
        ]
        candidate_relocations = [
            {"rva": 0x0803, "type": 3},
            {"rva": candidate_table_rva, "type": 3},
        ]
        with patch(
            "spaghetti_extractor.relational.contract._raw_base_relocations",
            side_effect=[original_relocations, candidate_relocations],
        ):
            regions = _split_relocation_backed_internal_cutpoints(
                regions, original, candidate
            )

        self.assertEqual(len(regions), 3)
        self.assertEqual(regions[2]["original"], {"rva": 0x1005, "size": 1})
        self.assertEqual(regions[2]["candidate"], {"rva": 0x2010, "size": 1})

        code_targets = [
            {
                "id": index,
                "region_index": index,
                "original_rva": int(region["original"]["rva"]),
                "candidate_rva": int(region["candidate"]["rva"]),
                "original_aliases": [],
                "candidate_aliases": [],
            }
            for index, region in enumerate(regions)
        ]
        regions[0]["bounds"] = [{
            "original": "eax",
            "candidate": "eax",
            "unsigned_lt": 1,
        }]
        regions[0]["code_targets"] = [code_targets[2]]
        regions[1]["code_targets"] = []
        regions[2]["code_targets"] = []
        contract = {
            "regions": regions,
            "code_targets": code_targets,
            "value_targets": [{
                "id": 0,
                "original_value": 0x403000,
                "candidate_value": 0x403100,
                "mapped_size": 4,
                "relocation_offsets": [0],
            }],
        }
        behaviors = [
            {
                "original_ir": {"outcome": {
                    "op": "indirect_jump",
                    "target": self._table_target(0x403000),
                }},
                "candidate_ir": {"outcome": {
                    "op": "indirect_jump",
                    "target": self._table_target(0x403100),
                }},
            },
            {
                "original_ir": {"outcome": {"op": "returned"}},
                "candidate_ir": {"outcome": {"op": "returned"}},
            },
            {
                "original_ir": {"outcome": {"op": "returned"}},
                "candidate_ir": {"outcome": {"op": "returned"}},
            },
        ]
        claims = _bounded_immutable_relocation_table_jump_candidates(
            original, candidate, contract, behaviors
        )

        self.assertEqual(len(claims), 1)
        self.assertEqual(claims[0]["entry_target_ids"], [2])

    def test_duplicate_relocation_cell_is_not_promoted(self) -> None:
        original, candidate = self._binaries([0x1005], [0x2010])
        duplicate_relocations = [
            {"rva": 0x3000, "type": 3},
            {"rva": 0x3000, "type": 3},
        ]
        with patch(
            "spaghetti_extractor.relational.contract._raw_base_relocations",
            return_value=duplicate_relocations,
        ):
            regions = _split_relocation_backed_internal_cutpoints(
                self._regions(), original, candidate
            )

        self.assertEqual(regions, self._regions())

    def test_order_reversing_internal_pairs_are_not_promoted(self) -> None:
        target_code = (
            b"\xb8\x00\x00\x00\x00"
            b"\xb8\x00\x00\x00\x00\xc3"
        )
        original = _FakeBinary({
            0x0800: b"\xc3",
            0x1000: target_code,
            0x3000: struct.pack("<II", 0x401005, 0x40100A),
        })
        candidate = _FakeBinary({
            0x0800: b"\xc3",
            0x2000: target_code,
            0x3000: struct.pack("<II", 0x40200A, 0x402005),
        })
        regions = self._regions()
        regions[1]["original"]["size"] = len(target_code)
        regions[1]["candidate"]["size"] = len(target_code)
        relocations = [
            {"rva": 0x3000, "type": 3},
            {"rva": 0x3004, "type": 3},
        ]
        with patch(
            "spaghetti_extractor.relational.contract._raw_base_relocations",
            return_value=relocations,
        ):
            split = _split_relocation_backed_internal_cutpoints(
                regions, original, candidate
            )

        self.assertEqual(split, regions)

    def test_ambiguous_internal_pairing_is_not_split(self) -> None:
        original, candidate = self._binaries(
            [0x1005, 0x1005], [0x2010, 0x200F]
        )
        relocations = [
            {"rva": 0x3000, "type": 3},
            {"rva": 0x3004, "type": 3},
        ]
        with patch(
            "spaghetti_extractor.relational.contract._raw_base_relocations",
            return_value=relocations,
        ):
            regions = _split_relocation_backed_internal_cutpoints(
                self._regions(), original, candidate
            )

        self.assertEqual(regions, self._regions())

    def test_mid_instruction_relocation_target_is_not_split(self) -> None:
        original, candidate = self._binaries([0x1001], [0x2001])
        relocations = [{"rva": 0x3000, "type": 3}]
        with patch(
            "spaghetti_extractor.relational.contract._raw_base_relocations",
            return_value=relocations,
        ):
            regions = _split_relocation_backed_internal_cutpoints(
                self._regions(), original, candidate
            )

        self.assertEqual(regions, self._regions())

    def test_side_isa_superset_uses_only_exact_relocation_boundaries(self) -> None:
        original, _candidate = self._binaries([0x1005], [0x2010])
        relocations = [{"rva": 0x3000, "type": 3}]
        with patch(
            "spaghetti_extractor.relational.binary_inventory._raw_base_relocations",
            return_value=relocations,
        ):
            relocation_starts = _immutable_relocation_instruction_starts(original)

        self.assertEqual(relocation_starts, {0x1005})
        span = {"rva_start": 0x1000, "size": 6}
        self.assertEqual(
            _relocation_split_spans(
                original, span, relocation_starts, "valid-relocation-cut"
            ),
            [
                {"rva_start": 0x1000, "size": 5},
                {"rva_start": 0x1005, "size": 1},
            ],
        )
        self.assertEqual(
            _relocation_split_spans(
                original, span, {0x1001}, "mid-instruction-cut"
            ),
            [span],
        )


if __name__ == "__main__":
    unittest.main()
