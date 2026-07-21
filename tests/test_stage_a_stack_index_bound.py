from __future__ import annotations

import copy
import unittest

from spaghetti_extractor.relational.contract import (
    _checked_stack_bound_expression_witness,
)
from spaghetti_extractor.relational.analyses.predicates import (
    attach_no_write_state_predicate_pullbacks,
    state_predicate_pullback_supported,
)
from spaghetti_extractor.relational.analyses.region_local import (
    _refine_contract_bounds,
)
from spaghetti_extractor.relational.analyses.stack import (
    _attach_checked_stack_index_bounds,
)
from spaghetti_extractor.relational.lean.expressions import _lean_state_invariant
from spaghetti_extractor.relational.lean.segments import (
    _lean_stack_register_bound_claim,
)


def _input(register: str) -> dict[str, object]:
    return {"op": "input_reg", "reg": register}


def _constant(value: int) -> dict[str, object]:
    return {"op": "constant", "value": value}


def _add(left: dict[str, object], right: dict[str, object]) -> dict[str, object]:
    return {"op": "add", "left": left, "right": right}


def _stack_word() -> dict[str, object]:
    return {"op": "read32", "address": _add(_input("esp"), _constant(132))}


def _behavior_pair() -> dict[str, object]:
    stack_word = _stack_word()
    table_address = _add(
        _constant(0x4214C8),
        {"op": "shift_left", "value": stack_word, "amount": 2},
    )
    registers = {
        register: _input(register)
        for register in ("eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp")
    }
    registers["eax"] = stack_word
    side = {
        "registers": registers,
        "writes": [],
        "flags": None,
        "outcome": {
            "op": "indirect_jump",
            "target": {"op": "read32", "address": table_address},
        },
    }
    return {"original_ir": copy.deepcopy(side), "candidate_ir": side}


def _contract() -> dict[str, object]:
    return {
        "regions": [{
            "numeric_id": 4583,
            "bounds": [{
                "original": "eax",
                "candidate": "eax",
                "unsigned_lt": 119,
            }],
            "values": [{
                "original_value": 0x4214C8,
                "candidate_value": 0x4214C8,
                "mapped_size": 119 * 4,
            }],
            "stack_windows": [{
                "range_id": 0,
                "original_register": "esp",
                "candidate_register": "esp",
                "bytes_below": 0,
                "bytes_above": 140,
            }],
        }],
    }


def _refined_fixture() -> tuple[dict[str, object], list[dict[str, object]]]:
    behaviors = [_behavior_pair()]
    return _refine_contract_bounds(_contract(), behaviors), behaviors


class StackIndexBoundTests(unittest.TestCase):
    def test_accepts_unique_decoded_stack_load_with_checked_evidence(self) -> None:
        contract, behaviors = _refined_fixture()
        bound = contract["regions"][0]["bounds"][0]
        self.assertEqual(
            bound["stack_bound_request"]["profile"],
            "decoded_stack_register_bound_request_v1",
        )
        self.assertNotIn("original_expression", bound)

        report = _attach_checked_stack_index_bounds(
            contract["regions"], behaviors
        )

        self.assertEqual(report["accepted_count"], 1)
        self.assertEqual(report["rejected_count"], 0)
        self.assertEqual(
            bound["expression_source"], "checked_stack_register_bound_v1"
        )
        self.assertEqual(bound["original_expression"], _stack_word())
        region = contract["regions"][0]
        claim = region["stack_index_bound_claims"][0]
        self.assertEqual(claim["upper_exclusive"], 119)
        self.assertEqual(claim["predicate"], region["state_predicates"][0])
        self.assertIn(
            "upperExclusive := 119", _lean_stack_register_bound_claim(claim)
        )
        self.assertIn("bounds := []", _lean_state_invariant({"bounds": [bound]}))
        self.assertTrue(_checked_stack_bound_expression_witness(bound, 119))

        tampered = copy.deepcopy(bound)
        tampered["stack_bound_predicate"]["exact_memory_reads"][0]["bytes"] = 1
        self.assertFalse(_checked_stack_bound_expression_witness(tampered, 119))

    def test_rejects_missing_stack_window_evidence(self) -> None:
        contract, behaviors = _refined_fixture()
        contract["regions"][0]["stack_windows"] = []

        report = _attach_checked_stack_index_bounds(
            contract["regions"], behaviors
        )

        self.assertEqual(report["accepted_count"], 0)
        self.assertEqual(report["rejected"][0]["reason"], "stack_window_missing")
        self.assertNotIn(
            "original_expression", contract["regions"][0]["bounds"][0]
        )

    def test_rejects_ambiguous_stack_window_evidence(self) -> None:
        contract, behaviors = _refined_fixture()
        duplicate = copy.deepcopy(contract["regions"][0]["stack_windows"][0])
        duplicate["range_id"] = 1
        contract["regions"][0]["stack_windows"].append(duplicate)

        report = _attach_checked_stack_index_bounds(
            contract["regions"], behaviors
        )

        self.assertEqual(report["accepted_count"], 0)
        self.assertEqual(
            report["rejected"][0]["reason"], "stack_window_ambiguous"
        )
        self.assertEqual(contract["regions"][0]["stack_index_bound_claims"], [])

    def test_rejects_decoded_write_clobber(self) -> None:
        contract, behaviors = _refined_fixture()
        behaviors[0]["candidate_ir"]["writes"] = [{
            "address": _input("esp"),
            "value": _constant(0),
        }]

        report = _attach_checked_stack_index_bounds(
            contract["regions"], behaviors
        )

        self.assertEqual(report["accepted_count"], 0)
        self.assertEqual(report["rejected"][0]["reason"], "decoded_write_clobber")
        self.assertNotIn(
            "original_expression", contract["regions"][0]["bounds"][0]
        )

    def test_predecessor_guard_proves_stack_bound_without_copying_predicate(self) -> None:
        contract, target_behaviors = _refined_fixture()
        _attach_checked_stack_index_bounds(contract["regions"], target_behaviors)
        target = contract["regions"][0]
        stack_word = _stack_word()
        strict_above_ten = {
            "op": "and",
            "left": {
                "op": "not",
                "value": {
                    "op": "unsigned_less",
                    "left": stack_word,
                    "right": _constant(10),
                },
            },
            "right": {
                "op": "not",
                "value": {
                    "op": "equal",
                    "left": {
                        "op": "sub",
                        "left": stack_word,
                        "right": _constant(10),
                    },
                    "right": _constant(0),
                },
            },
        }
        source_predicate = {
            "original": {"op": "bool_constant", "value": True},
            "candidate": {"op": "bool_constant", "value": True},
            "exact_memory_reads": [{
                "original_address": stack_word["address"],
                "candidate_address": stack_word["address"],
                "bytes": 4,
            }],
            "source": "fixture_exact_stack_word",
        }
        source = {"numeric_id": 4582, "state_predicates": [source_predicate]}
        registers = {
            register: _input(register)
            for register in (
                "eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp"
            )
        }
        side = {
            "registers": registers,
            "writes": [],
            "flags": None,
            "outcome": {
                "op": "branch",
                "condition": strict_above_ten,
                "taken": 9000,
                "fallthrough": 4583,
            },
        }
        source_behavior = {
            "original_ir": copy.deepcopy(side),
            "candidate_ir": side,
        }

        self.assertTrue(
            state_predicate_pullback_supported(source, target, source_behavior)
        )
        normalized, report = attach_no_write_state_predicate_pullbacks(
            {"regions": [source, target]},
            [source_behavior, target_behaviors[0]],
        )
        self.assertEqual(report["attached_predicate_count"], 0)
        self.assertEqual(len(normalized["regions"][0]["state_predicates"]), 1)


if __name__ == "__main__":
    unittest.main()
