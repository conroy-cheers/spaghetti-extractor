from __future__ import annotations

import unittest

from spaghetti_extractor.components.interface_ir import LogicalTypeV1
from spaghetti_extractor.components.machine_binding import MachineProjectionV1
from spaghetti_extractor.components.relation_ir import RelationExpressionV1
from spaghetti_extractor.components.relation_projection import (
    _coerce_projection,
    _machine_expression,
    _observe_projection,
    _projection_place,
    _projection_sort,
    _realize_projection,
)


class RelationProjectionTests(unittest.TestCase):
    def test_control_condition_is_a_boolean_machine_flag(self) -> None:
        projection = MachineProjectionV1.parse(
            {"kind": "control_condition", "at": "exit"}
        )

        place = _projection_place(projection)
        sort = _projection_sort(projection)

        self.assertEqual(place["kind"], "flag")
        self.assertEqual(place["phase"], "exit")
        self.assertIsNone(place["width"])
        self.assertEqual(sort, {"kind": "bool"})
        RelationExpressionV1.parse(_machine_expression(place, sort))

    def test_boolean_observation_decodes_to_c_integer_truth_value(self) -> None:
        flag = {
            "op": "machine",
            "sort": {"kind": "bool"},
            "args": [],
            "attributes": {
                "place": {
                    "kind": "flag",
                    "phase": "exit",
                    "width": None,
                    "selector": {"kind": "control_condition", "at": "exit"},
                }
            },
        }

        decoded = _coerce_projection(flag, {"kind": "bitvector", "width": 32})

        self.assertEqual(decoded["op"], "ite")
        self.assertEqual(
            [argument["attributes"].get("value") for argument in decoded["args"][1:]],
            [1, 0],
        )
        RelationExpressionV1.parse(decoded)

    def test_c_integer_truth_value_encodes_to_boolean_condition(self) -> None:
        logical = {
            "op": "logical",
            "sort": {"kind": "bitvector", "width": 32},
            "args": [],
            "attributes": {
                "path": {"root": "result", "id": "retry", "fields": []}
            },
        }

        encoded = _coerce_projection(logical, {"kind": "bool"})

        self.assertEqual(encoded["op"], "not")
        self.assertEqual(encoded["args"][0]["op"], "eq")
        self.assertEqual(encoded["args"][0]["args"][1]["attributes"]["value"], 0)
        RelationExpressionV1.parse(encoded)

    def test_finite_control_target_lowers_to_bidirectional_table(self) -> None:
        projection = MachineProjectionV1.parse(
            {
                "kind": "finite_control_target",
                "at": "exit",
                "unit_id": "unit:dispatch",
                "selector_parameter_id": "selector",
                "target_inventory_sha256": "0" * 64,
                "routes": [
                    {
                        "selector_value": 0,
                        "logical_value": 7,
                        "target_rva": 16,
                        "target_address": 4194320,
                    },
                    {
                        "selector_value": 1,
                        "logical_value": 9,
                        "target_rva": 32,
                        "target_address": 4194336,
                    },
                ],
            }
        )
        route_type = LogicalTypeV1("route", "enum", "uint32_t")
        logical = {
            "op": "logical",
            "sort": {"kind": "bitvector", "width": 32},
            "args": [],
            "attributes": {
                "path": {"root": "result", "id": "route", "fields": []}
            },
        }

        observed = _observe_projection(projection, route_type)
        realized = _realize_projection(projection, logical, route_type)

        self.assertEqual(observed["op"], "ite")
        self.assertEqual(observed["args"][1]["attributes"]["value"], 7)
        self.assertEqual(observed["args"][2]["attributes"]["value"], 9)
        self.assertEqual(realized[0]["place"]["kind"], "control_target")
        self.assertEqual(realized[0]["place"]["width"], 32)
        self.assertEqual(realized[0]["value"]["op"], "ite")
        RelationExpressionV1.parse(observed)
        RelationExpressionV1.parse(realized[0]["value"])


if __name__ == "__main__":
    unittest.main()
