from __future__ import annotations

import unittest

from spaghetti_extractor.machine_ir.entry_coordinates import (
    normalize_unit_expression_to_component_entry,
)


def _const(value: int) -> dict:
    return {"op": "const", "value": value, "width": 32}


def _reg(name: str) -> dict:
    return {"op": "reg", "name": name, "width": 32}


def _add(value: int, expression: dict) -> dict:
    return {"op": "add32", "args": [_const(value), expression]}


def _load(address: dict) -> dict:
    return {"op": "load", "width": 4, "address": address}


def _unit(identity: str, start: int, semantics: dict) -> dict:
    return {
        "id": identity,
        "source": {"original": {"rva_start": start, "rva_end": start + 4}},
        "semantics": {
            "register_writes": [],
            "flag_writes": [],
            "memory_events": [],
            "external_events": [],
            **semantics,
        },
    }


class EntryCoordinateTests(unittest.TestCase):
    def test_forwards_exact_stack_write_into_later_expression(self) -> None:
        entry_esp = _reg("esp")
        adjusted_esp = {
            "op": "sub32",
            "args": [entry_esp, _const(28)],
        }
        units = [
            _unit(
                "entry",
                0x1000,
                {
                    "register_writes": [
                        {"register": "esp", "value": adjusted_esp}
                    ],
                    "memory_events": [
                        {
                            "kind": "write",
                            "address": _add(8, adjusted_esp),
                            "width": 4,
                            "value": _load(_add(12, entry_esp)),
                        }
                    ],
                    "outcome": {"kind": "fallthrough", "target_rva": 0x1004},
                },
            ),
            _unit("call", 0x1004, {"outcome": {"kind": "return"}}),
        ]

        result = normalize_unit_expression_to_component_entry(
            units,
            entry_unit_id="entry",
            target_unit_id="call",
            expression=_load(_add(8, _reg("esp"))),
        )

        self.assertEqual(result["status"], "complete")
        self.assertEqual(result["expression"], _load(_add(12, entry_esp)))

    def test_target_memory_prefix_can_supply_external_argument(self) -> None:
        units = [
            _unit(
                "entry",
                0x1000,
                {
                    "memory_events": [
                        {
                            "kind": "write",
                            "address": _reg("esp"),
                            "width": 4,
                            "value": _load(_add(4, _reg("esp"))),
                        }
                    ],
                    "outcome": {"kind": "return"},
                },
            )
        ]

        result = normalize_unit_expression_to_component_entry(
            units,
            entry_unit_id="entry",
            target_unit_id="entry",
            target_memory_event_count=1,
            expression=_load(_reg("esp")),
        )

        self.assertEqual(result["status"], "complete")
        self.assertEqual(result["expression"], _load(_add(4, _reg("esp"))))

    def test_possible_alias_fails_closed(self) -> None:
        units = [
            _unit(
                "entry",
                0x1000,
                {
                    "memory_events": [
                        {
                            "kind": "write",
                            "address": _reg("ebx"),
                            "width": 4,
                            "value": _const(7),
                        }
                    ],
                    "outcome": {"kind": "fallthrough", "target_rva": 0x1004},
                },
            ),
            _unit("target", 0x1004, {"outcome": {"kind": "return"}}),
        ]

        result = normalize_unit_expression_to_component_entry(
            units,
            entry_unit_id="entry",
            target_unit_id="target",
            expression=_load(_reg("esp")),
        )

        self.assertEqual(result["status"], "incomplete")
        self.assertEqual(result["code"], "entry_coordinate_possible_alias")

    def test_branching_prefix_fails_closed(self) -> None:
        units = [
            _unit(
                "entry",
                0x1000,
                {
                    "outcome": {
                        "kind": "branch",
                        "true_target_rva": 0x1004,
                        "false_target_rva": 0x1008,
                    }
                },
            ),
            _unit("target", 0x1004, {"outcome": {"kind": "return"}}),
        ]

        result = normalize_unit_expression_to_component_entry(
            units,
            entry_unit_id="entry",
            target_unit_id="target",
            expression=_reg("eax"),
        )

        self.assertEqual(result["status"], "incomplete")
        self.assertEqual(result["code"], "entry_coordinate_nonlinear_prefix")


if __name__ == "__main__":
    unittest.main()
