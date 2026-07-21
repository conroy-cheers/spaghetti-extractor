from __future__ import annotations

import unittest

from spaghetti_extractor.relational.analyses.predicates import (
    attach_no_write_bound_edge_pullbacks,
    attach_no_write_state_predicate_pullbacks,
    bound_edge_pullback_supported,
    state_predicate_pullback_supported,
)
from spaghetti_extractor.relational.analyses.region_local import (
    _refine_contract_bounds,
)
from spaghetti_extractor.relational.analyses.segments import (
    _attach_branch_exact_memory_requirements,
    _paired_exact_guard_claim,
)
from spaghetti_extractor.relational.lean.expressions import (
    _lean_paired_exact_expr_witness,
)


def _input(register: str) -> dict[str, object]:
    return {"op": "input_reg", "reg": register}


def _constant(value: int) -> dict[str, object]:
    return {"op": "constant", "value": value}


def _add(left: dict[str, object], right: dict[str, object]) -> dict[str, object]:
    return {"op": "add", "left": left, "right": right}


def _behavior(target: int, *, stack_delta: int = 0) -> dict[str, object]:
    registers = {
        register: _input(register)
        for register in ("eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp")
    }
    if stack_delta:
        registers["esp"] = _add(_input("esp"), _constant(stack_delta & 0xFFFFFFFF))
    side = {
        "registers": registers,
        "writes": [],
        "flags": None,
        "outcome": {"op": "jump", "target": target},
    }
    return {"original_ir": side, "candidate_ir": side}


def _branch_behavior(taken: int, fallthrough: int) -> dict[str, object]:
    pair = _behavior(taken)
    side = pair["original_ir"]
    side["outcome"] = {
        "op": "branch",
        "condition": {"op": "bool_constant", "value": True},
        "taken": taken,
        "fallthrough": fallthrough,
    }
    return {"original_ir": side, "candidate_ir": side}


def _predicate(offset: int) -> dict[str, object]:
    address = _add(_input("esp"), _constant(offset))
    return {
        "original": {"op": "bool_constant", "value": True},
        "candidate": {"op": "bool_constant", "value": True},
        "exact_memory_reads": [{
            "original_address": address,
            "candidate_address": address,
            "bytes": 8,
        }],
        "source": "fixture",
    }


class StatePredicatePullbackAnalysisTests(unittest.TestCase):
    def test_refines_written_table_index_to_decoded_output_expression(self) -> None:
        index = {
            "op": "bit_and",
            "left": _input("eax"),
            "right": _constant(255),
        }
        address = _add(
            {"op": "shift_left", "value": index, "amount": 2},
            _constant(0x420000),
        )
        contract = {"regions": [{
            "numeric_id": 1,
            "bounds": [{
                "original": "edx", "candidate": "edx", "unsigned_lt": 108,
            }],
            "values": [{
                "mapped_size": 432,
                "original_value": 0x420000,
                "candidate_value": 0x420000,
            }],
        }]}
        side = _behavior(2)["original_ir"]
        side["registers"]["edx"] = index
        side["outcome"] = {"op": "indirect_jump", "target": {
            "op": "read32", "address": address,
        }}

        refined = _refine_contract_bounds(
            contract, [{"original_ir": side, "candidate_ir": side}]
        )

        bound = refined["regions"][0]["bounds"][0]
        self.assertEqual(bound["original_expression"], index)
        self.assertEqual(bound["candidate_expression"], index)
        self.assertEqual(bound["expression_source"], "lean_exact_effective_address")

    def test_branch_guard_supplies_successor_expression_bound(self) -> None:
        index = {
            "op": "bit_and",
            "left": _input("eax"),
            "right": _constant(255),
        }
        condition = {
            "op": "unsigned_less",
            "left": index,
            "right": _constant(108),
        }
        pair = _behavior(2)
        for side in ("original_ir", "candidate_ir"):
            pair[side]["outcome"] = {
                "op": "branch",
                "condition": condition,
                "taken": 2,
                "fallthrough": 3,
            }
        contract = {"regions": [
            {"numeric_id": 1},
            {"numeric_id": 2, "bounds": [{
                "original": "edx",
                "candidate": "edx",
                "original_expression": index,
                "candidate_expression": index,
                "unsigned_lt": 108,
            }]},
            {"numeric_id": 3},
        ]}

        normalized, report = attach_no_write_bound_edge_pullbacks(
            contract, [pair, _behavior(4), _behavior(4)]
        )

        self.assertEqual(report["attached_predicate_count"], 1)
        source_predicate = normalized["regions"][0]["state_predicates"][0]
        self.assertEqual(source_predicate["original"]["op"], "or")
        self.assertTrue(bound_edge_pullback_supported(
            normalized["regions"][0], normalized["regions"][1], pair
        ))

    def test_bound_pullback_fails_closed_for_write_cycle_and_unsupported_expr(self) -> None:
        bound = {
            "original": "eax", "candidate": "eax", "unsigned_lt": 4,
        }
        cyclic = {"regions": [
            {"numeric_id": 1},
            {"numeric_id": 2, "bounds": [bound]},
        ]}
        normalized, report = attach_no_write_bound_edge_pullbacks(
            cyclic, [_behavior(2), _behavior(1)]
        )
        self.assertEqual(report["attached_predicate_count"], 0)
        self.assertEqual(report["skipped_cycle_edge_count"], 1)
        self.assertNotIn("state_predicates", normalized["regions"][0])

        write_pair = _behavior(2)
        write_pair["original_ir"]["writes"] = [{
            "address": _input("esp"), "value": _constant(0),
        }]
        self.assertFalse(bound_edge_pullback_supported(
            {"numeric_id": 1}, {"numeric_id": 2, "bounds": [bound]}, write_pair
        ))

        unsupported = {**bound, "original_expression": {"op": "read32", "address": _input("eax")}}
        _, unsupported_report = attach_no_write_bound_edge_pullbacks(
            {"regions": [{"numeric_id": 1}, {"numeric_id": 2, "bounds": [unsupported]}]},
            [_behavior(2), _behavior(3)],
        )
        self.assertEqual(unsupported_report["unsupported_bound_count"], 1)

    def test_branch_nonzero_stack_scalar_requests_checked_exact_read(self) -> None:
        address = _add(_input("esp"), _constant(8))
        read = {"op": "read32", "address": address}
        condition = {
            "op": "equal",
            "left": {"op": "sub", "left": read, "right": _constant(3)},
            "right": _constant(0),
        }
        behavior = {
            "original_ir": {
                "outcome": {
                    "op": "branch", "condition": condition,
                    "taken": 2, "fallthrough": 3,
                },
            },
            "candidate_ir": {
                "outcome": {
                    "op": "branch", "condition": condition,
                    "taken": 2, "fallthrough": 3,
                },
            },
        }
        contract = {
            "regions": [{
                "numeric_id": 1,
                "input_relations": [],
                "flag_inputs": [],
            }],
            "static_word_relation_slots": [],
        }

        normalized, report = _attach_branch_exact_memory_requirements(
            contract, [behavior], None, None  # type: ignore[arg-type]
        )

        self.assertEqual(report["attached_region_count"], 1)
        predicate = normalized["regions"][0]["state_predicates"][0]
        self.assertEqual(predicate["exact_memory_reads"], [{
            "original_address": address,
            "candidate_address": address,
            "bytes": 4,
        }])
        claim = _paired_exact_guard_claim(
            normalized, normalized["regions"][0], condition, condition
        )
        self.assertEqual(claim["profile"], "paired_exact_guard_v1")
        witness_source = _lean_paired_exact_expr_witness(claim["witness"])
        self.assertIn("PairedExactExprWitness.statePredicateRead32", witness_source)

    def test_branch_zero_stack_word_does_not_request_exactness(self) -> None:
        address = _add(_input("esp"), _constant(8))
        read = {"op": "read32", "address": address}
        condition = {
            "op": "equal",
            "left": {"op": "bit_and", "left": read, "right": read},
            "right": _constant(0),
        }
        behavior = {
            "original_ir": {"outcome": {
                "op": "branch", "condition": condition,
                "taken": 2, "fallthrough": 3,
            }},
            "candidate_ir": {"outcome": {
                "op": "branch", "condition": condition,
                "taken": 2, "fallthrough": 3,
            }},
        }
        contract = {"regions": [{
            "numeric_id": 1,
            "stack_windows": [{
                "range_id": 0,
                "original_register": "esp",
                "candidate_register": "esp",
                "bytes_below": 0,
                "bytes_above": 16,
            }],
        }]}

        normalized, report = _attach_branch_exact_memory_requirements(
            contract, [behavior], None, None  # type: ignore[arg-type]
        )

        self.assertEqual(report["attached_region_count"], 0)
        self.assertNotIn("state_predicates", normalized["regions"][0])

    def test_pulls_exact_reads_through_affine_stack_update(self) -> None:
        contract = {
            "regions": [
                {"numeric_id": 1},
                {"numeric_id": 2, "state_predicates": [_predicate(72)]},
            ]
        }
        behaviors = [_behavior(2, stack_delta=-60), _behavior(3)]

        normalized, report = attach_no_write_state_predicate_pullbacks(
            contract, behaviors
        )

        self.assertEqual(report["attached_predicate_count"], 1)
        source_predicate = normalized["regions"][0]["state_predicates"][0]
        pulled_address = source_predicate["exact_memory_reads"][0]["original_address"]
        self.assertEqual(
            pulled_address,
            _add(
                _add(_input("esp"), _constant((-60) & 0xFFFFFFFF)),
                _constant(72),
            ),
        )
        self.assertTrue(
            state_predicate_pullback_supported(
                normalized["regions"][0], normalized["regions"][1], behaviors[0]
            )
        )

    def test_pulled_read32_uses_lean_post_write_canonical_form(self) -> None:
        pair = _behavior(2)
        source_value = {
            "op": "read32",
            "address": _add(_input("esp"), _constant(4)),
        }
        pair["original_ir"]["registers"]["eax"] = source_value
        pair["candidate_ir"]["registers"]["eax"] = source_value
        target_address = _add(
            _input("eax"),
            {
                "op": "read32",
                "address": _add(_input("eax"), _constant(60)),
            },
        )
        target_predicate = {
            "original": {"op": "bool_constant", "value": True},
            "candidate": {"op": "bool_constant", "value": True},
            "exact_memory_reads": [{
                "original_address": target_address,
                "candidate_address": target_address,
                "bytes": 4,
            }],
            "source": "fixture",
        }
        contract = {
            "regions": [
                {"numeric_id": 1},
                {"numeric_id": 2, "state_predicates": [target_predicate]},
            ]
        }

        normalized, report = attach_no_write_state_predicate_pullbacks(
            contract, [pair, _behavior(3)]
        )

        self.assertEqual(report["attached_predicate_count"], 1)
        pulled = normalized["regions"][0]["state_predicates"][0]
        pulled_address = pulled["exact_memory_reads"][0]["original_address"]
        assembled_read = pulled_address["right"]
        self.assertEqual(assembled_read["op"], "bit_or")
        self.assertEqual(assembled_read["left"]["left"]["op"], "read8")
        self.assertEqual(
            assembled_read["left"]["right"],
            {
                "op": "shift_left",
                "value": {
                    "op": "read8",
                    "address": _add(
                        _add(source_value, _constant(60)), _constant(1)
                    ),
                },
                "amount": 8,
            },
        )
        self.assertTrue(
            state_predicate_pullback_supported(
                normalized["regions"][0], normalized["regions"][1], pair
            )
        )

    def test_does_not_generate_unbounded_predicates_inside_cycle(self) -> None:
        contract = {
            "regions": [
                {"numeric_id": 1},
                {"numeric_id": 2, "state_predicates": [_predicate(8)]},
            ]
        }
        behaviors = [_behavior(2, stack_delta=-4), _behavior(1, stack_delta=4)]

        normalized, report = attach_no_write_state_predicate_pullbacks(
            contract, behaviors
        )

        self.assertEqual(report["attached_predicate_count"], 0)
        self.assertEqual(report["skipped_cycle_edge_count"], 1)
        self.assertNotIn("state_predicates", normalized["regions"][0])

    def test_pulls_predicate_from_each_no_write_branch_successor(self) -> None:
        contract = {
            "regions": [
                {"numeric_id": 1},
                {"numeric_id": 2, "state_predicates": [_predicate(8)]},
                {"numeric_id": 3, "state_predicates": [_predicate(12)]},
            ]
        }
        behaviors = [
            _branch_behavior(2, 3),
            _behavior(4),
            _behavior(4),
        ]

        normalized, report = attach_no_write_state_predicate_pullbacks(
            contract, behaviors
        )

        self.assertEqual(report["eligible_edge_count"], 2)
        source_predicates = normalized["regions"][0]["state_predicates"]
        self.assertEqual(len(source_predicates), 2)
        self.assertTrue(all(
            predicate["original"]["op"] == "or"
            for predicate in source_predicates
        ))
        self.assertTrue(state_predicate_pullback_supported(
            normalized["regions"][0], normalized["regions"][1], behaviors[0]
        ))
        self.assertTrue(state_predicate_pullback_supported(
            normalized["regions"][0], normalized["regions"][2], behaviors[0]
        ))

    def test_does_not_strengthen_cyclic_invariant_from_exit_successor(self) -> None:
        contract = {
            "regions": [
                {"numeric_id": 1},
                {"numeric_id": 2},
                {"numeric_id": 3, "state_predicates": [_predicate(8)]},
            ]
        }
        behaviors = [
            _behavior(2),
            _branch_behavior(1, 3),
            _behavior(4),
        ]

        normalized, report = attach_no_write_state_predicate_pullbacks(
            contract, behaviors
        )

        self.assertEqual(report["attached_predicate_count"], 0)
        self.assertGreaterEqual(report["skipped_cycle_edge_count"], 1)
        self.assertNotIn("state_predicates", normalized["regions"][1])

    def test_write_or_unsupported_address_fails_closed(self) -> None:
        target = {"numeric_id": 2, "state_predicates": [_predicate(8)]}
        source = {"numeric_id": 1, "state_predicates": [_predicate(8)]}
        pair = _behavior(2)
        pair["original_ir"]["writes"] = [{"address": _input("esp"), "value": _constant(0)}]
        self.assertFalse(state_predicate_pullback_supported(source, target, pair))

        unsupported = _predicate(8)
        unsupported["exact_memory_reads"][0]["original_address"] = {
            "op": "input_x87_control"
        }
        target["state_predicates"] = [unsupported]
        pair = _behavior(2)
        self.assertFalse(state_predicate_pullback_supported(source, target, pair))


if __name__ == "__main__":
    unittest.main()
