from __future__ import annotations

import unittest
from types import SimpleNamespace

from spaghetti_extractor.indirect_target_dependency_v2 import (
    has_value_independent_target_set_v2,
)
from spaghetti_extractor.static_indirect_replay_v2 import (
    replay_exact_static_recoveries_v2,
)


IMAGE_BASE = 0x400000
TABLE_RVA = 0x1100


def constant(value: int) -> dict[str, object]:
    return {"op": "constant", "value": value}


def index() -> dict[str, object]:
    return {"op": "input_reg", "reg": "eax"}


def table_expression() -> dict[str, object]:
    return {
        "op": "load",
        "width": 4,
        "address": {
            "op": "add",
            "left": constant(IMAGE_BASE + TABLE_RVA),
            "right": {
                "op": "mul",
                "left": index(),
                "right": constant(4),
            },
        },
    }


def unit(
    identity: str,
    start: int,
    end: int,
    *,
    direct_targets: list[int] | None = None,
    edge_conditions: list[dict[str, object]] | None = None,
    instructions: list[dict[str, object]] | None = None,
) -> dict[str, object]:
    return {
        "id": identity,
        "source": {"original": {"rva_start": start, "rva_end": end}},
        "control": {"direct_targets": direct_targets or []},
        "instructions": instructions or [],
        "semantics": {
            "external_events": [],
            "edge_conditions": edge_conditions or [],
            "outcome": {
                "kind": "fallthrough",
                "target_rva": (direct_targets or [end])[0],
            },
        },
    }


class FakePE:
    def __init__(self, table: bytes) -> None:
        self.table = table

    def get_data(self, rva: int, size: int) -> bytes:
        offset = rva - TABLE_RVA
        if offset < 0:
            return b""
        return self.table[offset : offset + size]


def binary(*targets: int) -> SimpleNamespace:
    table = b"".join((IMAGE_BASE + rva).to_bytes(4, "little") for rva in targets)
    return SimpleNamespace(
        image_base=IMAGE_BASE,
        sections=[
            {
                "name": ".text",
                "rva_start": 0x1000,
                "rva_end": 0x1080,
                "readable": True,
                "writable": False,
                "executable": True,
            },
            {
                "name": ".rdata",
                "rva_start": TABLE_RVA,
                "rva_end": TABLE_RVA + len(table),
                "readable": True,
                "writable": False,
                "executable": False,
            },
        ],
        pe=FakePE(table),
    )


def fixture(*, with_bound: bool = True) -> tuple[list[dict[str, object]], dict[str, object]]:
    guard = {
        "op": "unsigned_less",
        "left": index(),
        "right": constant(2),
    }
    units = [
        unit(
            "guard",
            0x1000,
            0x1005,
            direct_targets=[0x1010],
            edge_conditions=(
                [{"target_rva": 0x1010, "condition": guard}]
                if with_bound
                else []
            ),
        ),
        unit("dispatch", 0x1010, 0x1016),
        unit("target-a", 0x1020, 0x1024),
        unit("target-b", 0x1030, 0x1034),
    ]
    exit_record = {
        "id": "indirect-exit:fixture",
        "source_unit_id": "dispatch",
        "source_rva": 0x1010,
        "source_event_index": None,
        "kind": "indirect_jump",
        "target_expression": table_expression(),
    }
    return units, exit_record


class StaticIndirectReplayV2Tests(unittest.TestCase):
    def test_replays_guarded_immutable_table_from_exact_inputs(self) -> None:
        units, exit_record = fixture()

        recovery = replay_exact_static_recoveries_v2(
            binary=binary(0x1020, 0x1030),
            units=units,
            indirect_exits=[exit_record],
        )[0]

        self.assertEqual(recovery["status"], "recovered")
        self.assertEqual(recovery["kind"], "indirect_jump")
        self.assertEqual(
            recovery["recovery_kind"], "pe32_indexed_absolute_jump_table"
        )
        self.assertEqual(recovery["target_unit_ids"], ["target-a", "target-b"])
        self.assertTrue(has_value_independent_target_set_v2(recovery))

    def test_noncanonical_table_target_remains_incomplete(self) -> None:
        units, exit_record = fixture()

        recovery = replay_exact_static_recoveries_v2(
            binary=binary(0x1020, 0x1040),
            units=units,
            indirect_exits=[exit_record],
        )[0]

        self.assertEqual(recovery["status"], "incomplete")
        self.assertFalse(has_value_independent_target_set_v2(recovery))

    def test_missing_selector_bound_remains_incomplete(self) -> None:
        units, exit_record = fixture(with_bound=False)

        recovery = replay_exact_static_recoveries_v2(
            binary=binary(0x1020, 0x1030),
            units=units,
            indirect_exits=[exit_record],
        )[0]

        self.assertEqual(recovery["status"], "incomplete")
        self.assertEqual(recovery["failure"]["code"], "unresolved_index_bound")


if __name__ == "__main__":
    unittest.main()
