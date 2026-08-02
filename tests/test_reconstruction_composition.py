from __future__ import annotations

import unittest

from spaghetti_extractor.reconstruction_composition import (
    compose_linear_reconstruction_cluster,
)


def _reg(name: str) -> dict:
    return {"op": "reg", "name": name, "width": 32}


def _const(value: int) -> dict:
    return {"op": "const", "value": value, "width": 32}


def _add(left: dict, right: dict) -> dict:
    return {"op": "add32", "args": [left, right]}


def _load(address: dict) -> dict:
    return {"op": "load", "address": address, "width": 4}


def _unit(identity: str, start: int, end: int, semantics: dict) -> dict:
    return {
        "id": identity,
        "status": "qualified",
        "source": {"original": {"rva_start": start, "rva_end": end}},
        "semantics": {
            "register_writes": [],
            "flag_writes": [],
            "memory_events": [],
            "external_events": [],
            "faults": [],
            **semantics,
        },
    }


class ReconstructionCompositionTests(unittest.TestCase):
    def test_linear_cluster_substitutes_stack_state_across_cutpoints(self) -> None:
        units = [
            _unit(
                "u0", 0x1000, 0x1004,
                {"outcome": {"kind": "fallthrough", "target_rva": 0x1004}},
            ),
            _unit(
                "u1", 0x1004, 0x1008,
                {
                    "register_writes": [
                        {"register": "esp", "value": _add(_const(80), _reg("esp"))}
                    ],
                    "outcome": {"kind": "fallthrough", "target_rva": 0x1008},
                },
            ),
            _unit(
                "u2", 0x1008, 0x100C,
                {
                    "memory_events": [
                        {"kind": "read", "address": _reg("esp"), "width": 4},
                        {
                            "kind": "read",
                            "address": _add(_const(4), _reg("esp")),
                            "width": 4,
                        },
                    ],
                    "register_writes": [
                        {"register": "esi", "value": _load(_reg("esp"))},
                        {"register": "esp", "value": _add(_const(12), _reg("esp"))},
                    ],
                    "outcome": {"kind": "jump", "target_rva": 0x2000},
                },
            ),
        ]

        result = compose_linear_reconstruction_cluster(units, entry_unit_id="u0")

        self.assertEqual(result["status"], "complete")
        semantics = result["summary_unit"]["semantics"]
        self.assertEqual(
            [event["address"] for event in semantics["memory_events"]],
            [_add(_const(80), _reg("esp")), _add(_const(84), _reg("esp"))],
        )
        writes = {item["register"]: item["value"] for item in semantics["register_writes"]}
        self.assertEqual(writes["esi"], _load(_add(_const(80), _reg("esp"))))
        self.assertEqual(writes["esp"], _add(_const(92), _reg("esp")))
        self.assertEqual(semantics["stack_delta"]["net_bytes"], 92)
        self.assertEqual(semantics["outcome"], {"kind": "jump", "target_rva": 0x2000})

    def test_internal_branch_fails_closed(self) -> None:
        units = [
            _unit(
                "entry", 0x1000, 0x1004,
                {
                    "outcome": {
                        "kind": "branch",
                        "condition": {"op": "flag", "name": "zf"},
                        "true_target_rva": 0x1004,
                        "false_target_rva": 0x1008,
                    }
                },
            ),
            _unit("left", 0x1004, 0x1008, {"outcome": {"kind": "return"}}),
            _unit("right", 0x1008, 0x100C, {"outcome": {"kind": "return"}}),
        ]

        result = compose_linear_reconstruction_cluster(units, entry_unit_id="entry")

        self.assertEqual(result["status"], "incomplete")
        self.assertEqual(result["issues"][0]["code"], "nonlinear_internal_exit")

    def test_later_load_records_prior_cluster_writes(self) -> None:
        address = _add(_const(4), _reg("ebx"))
        write = {
            "kind": "write",
            "address": address,
            "width": 4,
            "value": _const(7),
        }
        units = [
            _unit(
                "writer",
                0x1000,
                0x1004,
                {
                    "memory_events": [write],
                    "outcome": {"kind": "fallthrough", "target_rva": 0x1004},
                },
            ),
            _unit(
                "reader",
                0x1004,
                0x1008,
                {
                    "register_writes": [
                        {"register": "eax", "value": _load(address)}
                    ],
                    "outcome": {"kind": "return"},
                },
            ),
        ]

        result = compose_linear_reconstruction_cluster(units, entry_unit_id="writer")

        self.assertEqual(result["status"], "complete")
        registers = {
            item["register"]: item["value"]
            for item in result["summary_unit"]["semantics"]["register_writes"]
        }
        self.assertEqual(
            registers["eax"],
            {
                "op": "load_after_writes",
                "address": address,
                "width": 4,
                "prior_writes": [
                    {
                        "address": address,
                        "width": 4,
                        "value": _const(7),
                        "cluster_event_index": 0,
                    }
                ],
            },
        )

    def test_disconnected_member_fails_closed(self) -> None:
        units = [
            _unit("entry", 0x1000, 0x1004, {"outcome": {"kind": "return"}}),
            _unit("orphan", 0x2000, 0x2004, {"outcome": {"kind": "return"}}),
        ]

        result = compose_linear_reconstruction_cluster(units, entry_unit_id="entry")

        self.assertEqual(result["status"], "incomplete")
        self.assertEqual(result["issues"][0]["code"], "unvisited_cluster_units")


if __name__ == "__main__":
    unittest.main()
