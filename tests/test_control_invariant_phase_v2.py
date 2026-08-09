from __future__ import annotations

import unittest
from types import SimpleNamespace

from spaghetti_extractor.control_invariant_phase_v2 import (
    CONTROL_INVARIANT_PHASE_V2_FORMAT,
    derive_checked_control_invariants_v2,
)
from spaghetti_extractor.control_analysis_v2 import exact_control_inventory_v2
from spaghetti_extractor.static_indirect_replay_v2 import (
    replay_exact_static_recoveries_v2,
)


BINARY_SHA = "1" * 64
MACHINE_IR_SHA = "2" * 64
IMAGE_BASE = 0x400000
TABLE_RVA = 0x1100


def _reg(name: str) -> dict:
    return {"op": "reg", "name": name, "width": 32}


def _const(value: int) -> dict:
    return {"op": "const", "value": value, "width": 32}


def _source(start: int, end: int, digest: str) -> dict:
    return {
        "contract_sha256": digest * 64,
        "instruction_bytes_sha256": digest * 64,
        "original": {"rva_start": start, "rva_end": end},
    }


def _units() -> list[dict]:
    selector = {"op": "and32", "args": [_reg("eax"), _const(3)]}
    return [
        {
            "id": "unit:entry",
            "status": "qualified",
            "source": _source(0x900, 0x902, "a"),
            "control": {"direct_targets": [0x1000]},
            "semantics": {
                "outcome": {"kind": "branch"},
                "edge_conditions": [{
                    "target_rva": 0x1000,
                    "condition": {
                        "op": "not",
                        "args": [{
                            "op": "eq",
                            "args": [
                                {"op": "and32", "args": [_reg("edi"), _const(3)]},
                                _const(0),
                            ],
                        }],
                    },
                }],
                "register_writes": [],
                "flag_writes": [],
                "faults": [],
            },
        },
        {
            "id": "unit:copy-index",
            "status": "qualified",
            "source": _source(0x1000, 0x1002, "b"),
            "control": {"direct_targets": [0x1002]},
            "semantics": {
                "outcome": {"kind": "jump", "target_rva": 0x1002},
                "edge_conditions": [{
                    "target_rva": 0x1002,
                    "condition": {"op": "true"},
                }],
                "register_writes": [{"register": "eax", "value": _reg("edi")}],
                "flag_writes": [],
                "faults": [],
            },
        },
        {
            "id": "unit:dispatch",
            "status": "qualified",
            "source": _source(0x1002, 0x1009, "c"),
            "control": {
                "direct_targets": [],
                "has_indirect_target": True,
                "kind": "indirect_jump",
            },
            "semantics": {
                "outcome": {
                    "kind": "indirect_jump",
                    "target": {
                        "op": "load",
                        "width": 4,
                        "address": {
                            "op": "add32",
                            "args": [
                                _const(IMAGE_BASE + TABLE_RVA),
                                {
                                    "op": "mul32",
                                    "args": [selector, _const(4)],
                                },
                            ],
                        },
                    },
                },
                "register_writes": [],
                "flag_writes": [],
                "faults": [],
            },
        },
        *[
            {
                "id": f"unit:target-{index}",
                "status": "qualified",
                "source": _source(rva, rva + 1, digest),
                "control": {"direct_targets": []},
                "semantics": {
                    "outcome": {"kind": "return"},
                    "register_writes": [],
                    "flag_writes": [],
                    "faults": [],
                },
            }
            for index, (rva, digest) in enumerate(
                ((0x1200, "d"), (0x1210, "e"), (0x1220, "f")), start=1
            )
        ],
    ]


class _FakePE:
    def __init__(self, entries: tuple[int, ...]) -> None:
        self._table = b"".join(value.to_bytes(4, "little") for value in entries)

    def get_data(self, rva: int, size: int) -> bytes:
        offset = rva - TABLE_RVA
        return b"" if offset < 0 else self._table[offset : offset + size]


def _binary(entries: tuple[int, ...]) -> SimpleNamespace:
    return SimpleNamespace(
        sha256=BINARY_SHA,
        image_base=IMAGE_BASE,
        pe=_FakePE(entries),
        sections=[{
            "name": ".text",
            "rva_start": 0x1000,
            "rva_end": 0x1300,
            "readable": True,
            "writable": False,
            "executable": True,
        }],
    )


class ControlInvariantPhaseV2Tests(unittest.TestCase):
    def test_proves_static_dispatch_subset_through_backward_region(self) -> None:
        result = derive_checked_control_invariants_v2(
            units=_units(),
            binary=_binary((
                IMAGE_BASE + 0x9000,
                IMAGE_BASE + 0x1200,
                IMAGE_BASE + 0x1210,
                IMAGE_BASE + 0x1220,
            )),
            machine_ir_sha256=MACHINE_IR_SHA,
        )

        self.assertEqual(result["format"], CONTROL_INVARIANT_PHASE_V2_FORMAT)
        self.assertEqual(result["status"], "complete", result["issues"])
        self.assertEqual(result["counts"]["checked_facts"], 1)
        self.assertEqual(result["rows"][0]["synthesis_attempts"], 2)
        self.assertEqual(
            result["rows"][0]["region_members"],
            ["unit:copy-index", "unit:dispatch"],
        )
        record = result["authority_records"][0]
        self.assertEqual(record["unit_id"], "unit:dispatch")
        self.assertEqual(record["fact"]["values"], [1, 2, 3])
        self.assertEqual(record["binary_sha256"], BINARY_SHA)
        self.assertEqual(record["machine_ir_sha256"], MACHINE_IR_SHA)

        replay = replay_exact_static_recoveries_v2(
            binary=_binary((
                IMAGE_BASE + 0x9000,
                IMAGE_BASE + 0x1200,
                IMAGE_BASE + 0x1210,
                IMAGE_BASE + 0x1220,
            )),
            units=_units(),
            indirect_exits=exact_control_inventory_v2(_units())["indirect_exits"],
            checked_control_invariants=result["authority_records"],
            machine_ir_sha256=MACHINE_IR_SHA,
        )
        self.assertEqual(replay[0]["status"], "recovered", replay[0])
        self.assertEqual(
            replay[0]["target_unit_ids"],
            ["unit:target-1", "unit:target-2", "unit:target-3"],
        )
        self.assertEqual(
            replay[0]["control_invariant_dependencies"],
            [record["authority_id"]],
        )

    def test_full_valid_table_needs_no_control_constraint(self) -> None:
        result = derive_checked_control_invariants_v2(
            units=_units(),
            binary=_binary((
                IMAGE_BASE + 0x1200,
                IMAGE_BASE + 0x1210,
                IMAGE_BASE + 0x1220,
                IMAGE_BASE + 0x1200,
            )),
            machine_ir_sha256=MACHINE_IR_SHA,
        )

        self.assertEqual(result["status"], "complete")
        self.assertEqual(result["rows"], [])
        self.assertEqual(result["authority_records"], [])


if __name__ == "__main__":
    unittest.main()
