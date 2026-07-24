from __future__ import annotations

import copy
import unittest

from spaghetti_extractor.relational.lean.acceptance import (
    _acceptance_segment_imports,
    _checked_infeasible_branch_edge,
    _lean_acceptance_running_node,
    _retain_checked_linked_control_links,
    _whole_program_acceptance_plan,
)
from spaghetti_extractor.relational.schema import PROTOCOL_CALLBACK_CONTROL_FORMAT


TRUE_GUARD = {"op": "bool_constant", "value": True}
EXACT_EAX = {
    "original": "eax",
    "candidate": "eax",
    "relation": "exact",
}


def _behavior(outcome: dict[str, object]) -> dict[str, object]:
    normalized = {"outcome": outcome, "writes": []}
    return {
        "original_ir": copy.deepcopy(normalized),
        "candidate_ir": copy.deepcopy(normalized),
    }


def _unrepresented_self_control_fixture() -> tuple[
    dict[str, object],
    list[dict[str, object]],
    dict[str, object],
    dict[str, object],
]:
    returned = {
        "op": "returned",
        "target": {
            "op": "read32",
            "address": {"op": "input_reg", "reg": "esp"},
        },
    }
    behaviors = [
        _behavior(returned),
        _behavior({"op": "jump", "target": 1}),
    ]
    regions = [
        {
            "numeric_id": 0,
            "root": True,
            "input_relations": [EXACT_EAX],
            "output_relations": [EXACT_EAX],
            "flag_inputs": [],
            "flag_outputs": [],
            "stack_windows": [],
        },
        {
            "numeric_id": 1,
            "root": False,
            "input_relations": [],
            "output_relations": [],
            "flag_inputs": [],
            "flag_outputs": [],
            "stack_windows": [],
        },
    ]
    contract = {
        "regions": regions,
        "code_targets": [
            {"id": 0, "original_rva": 0, "candidate_rva": 0},
            {"id": 1, "original_rva": 1, "candidate_rva": 1},
        ],
        "machine_import_call_contracts": [],
    }
    graph = {
        "nodes": [
            {
                "id": 0,
                "target_id": 0,
                "root": True,
                "outgoing_edge_ids": [],
            },
            {
                "id": 1,
                "target_id": 1,
                "root": False,
                "outgoing_edge_ids": [0],
            },
        ],
        "edges": [{
            "id": 0,
            "source_node_id": 1,
            "source_target_id": 1,
            "target_node_id": 1,
            "target_target_id": 1,
            "kind": "jump",
            "candidate_kind": "jump",
            "original_guard": TRUE_GUARD,
            "candidate_guard": TRUE_GUARD,
            "infeasible": False,
        }],
        "root_node_ids": [0],
        "evidence": {
            "reachable_product_local_complete": False,
            "decoded_control_candidates": [],
            "declared_reachable_node_ids": [0, 1],
        },
    }
    register_relations = {
        "edges": [],
        "regions": [
            {
                "return_pop_claim": {
                    "profile": "esp_relative_return_pop_v1",
                },
                "output_claims": [{
                    "kind": "identity",
                    "output": EXACT_EAX,
                }],
            },
            {},
        ],
    }
    return contract, behaviors, graph, register_relations


def _constant_branch_fixture() -> tuple[
    dict[str, object],
    list[dict[str, object]],
    dict[str, object],
    dict[str, object],
    list[dict[str, object]],
]:
    contract, behaviors, graph, register_relations = (
        _unrepresented_self_control_fixture()
    )
    condition = copy.deepcopy(TRUE_GUARD)
    behaviors[0] = _behavior({
        "op": "branch",
        "condition": condition,
        "taken": 0,
        "fallthrough": 1,
    })
    graph["nodes"][0]["outgoing_edge_ids"] = [0, 1]
    graph["edges"] = [
        {
            "id": 0,
            "source_node_id": 0,
            "source_target_id": 0,
            "target_node_id": 0,
            "target_target_id": 0,
            "kind": "branchTaken",
            "candidate_kind": "branchTaken",
            "original_guard": copy.deepcopy(condition),
            "candidate_guard": copy.deepcopy(condition),
            "infeasible": False,
        },
        {
            "id": 1,
            "source_node_id": 0,
            "source_target_id": 0,
            "target_node_id": 1,
            "target_target_id": 1,
            "kind": "branchFallthrough",
            "candidate_kind": "branchFallthrough",
            "original_guard": {"op": "not", "value": copy.deepcopy(condition)},
            "candidate_guard": {"op": "not", "value": copy.deepcopy(condition)},
            "infeasible": True,
        },
    ]
    register_relations["edges"] = [{
        "source_region_index": 0,
        "target_region_index": 0,
        "return_slot_transfer_claims": [],
        "return_slot_transfer_rules": [],
    }]
    segment_candidates = [
        {
            "edge_index": edge_id,
            "source_region_index": 0,
            "target_region_index": target_id,
            "certificate_profile": "composable_local_no_write_v1",
        }
        for edge_id, target_id in ((0, 0), (1, 1))
    ]
    return contract, behaviors, graph, register_relations, segment_candidates


class StageARelationalSelfControlAcceptanceTests(unittest.TestCase):
    def test_linked_control_retains_only_depth_one_resume_witnesses(self) -> None:
        shallow_inventory = {"locations": [{"original": 0, "candidate": 0}]}
        deep_inventory = {"locations": [{"original": 4, "candidate": 4}]}
        shallow_link = {
            "call_source_target_id": 1,
            "resume_node_id": 2,
            "resume_target_id": 2,
            "resume_continuation": 9,
            "resume_inventory": shallow_inventory,
        }
        deep_link = {
            "call_source_target_id": 3,
            "resume_node_id": 4,
            "resume_target_id": 4,
            "resume_continuation": 10,
            "resume_inventory": deep_inventory,
        }
        profile, rejected = _retain_checked_linked_control_links({
            "states": [
                {
                    "node_id": 2,
                    "continuation_target_id": 9,
                    "active_frame": shallow_inventory,
                    "minimum_depth": 1,
                },
                {
                    "node_id": 4,
                    "continuation_target_id": 10,
                    "active_frame": deep_inventory,
                    "minimum_depth": 2,
                },
            ],
            "links": [shallow_link, deep_link],
            "link_gaps": [],
            "counts": {"link_candidates": 2, "link_gaps": 0},
        })

        self.assertEqual(profile["links"], [shallow_link])
        self.assertEqual(profile["counts"]["link_candidates"], 1)
        self.assertEqual(profile["counts"]["link_gaps"], 1)
        self.assertEqual(profile["counts"]["rejected_link_candidates"], 1)
        self.assertEqual(rejected, [{
            "reason": "resume_state_depth_one_witness_missing",
            "call_source_target_id": 3,
            "resume_node_id": 4,
            "resume_target_id": 4,
            "resume_continuation": 10,
            "candidate_minimum_depths": [2],
        }])

    def test_unrepresented_control_uses_checked_vacuous_step(self) -> None:
        contract, behaviors, graph, register_relations = (
            _unrepresented_self_control_fixture()
        )

        plan = _whole_program_acceptance_plan(
            contract,
            behaviors,
            graph,
            register_relations,
            [],
            [],
        )

        step = next(item for item in plan["node_steps"] if item["node_id"] == 1)
        blocker_codes = {item["code"] for item in plan["blockers"]}
        self.assertEqual(step["kind"], "control_unrepresented")
        self.assertEqual(
            step["profile"],
            "control-state-unrepresented-v1",
        )
        self.assertEqual(step["edges"], [{
            "edge_id": 0,
            "target_node_id": 1,
            "target_region_index": 1,
            "target_target_id": 1,
        }])
        self.assertEqual(_acceptance_segment_imports([step], {}), "")
        self.assertNotIn("direct_jump_node_profile_unmet", blocker_codes)
        self.assertNotIn("jump_control_profile_missing", blocker_codes)
        self.assertIn("reachable_product_local_incomplete", blocker_codes)

        source = _lean_acceptance_running_node(step, contract["regions"], behaviors)
        self.assertIn("(show ProductControlState from", source)
        self.assertIn("List.contains_iff_mem.mp controlMember.2", source)
        self.assertIn("False.elim (stateAbsent stateMember)", source)
        self.assertNotIn("transitionSystem.step", source)

    def test_all_ordinary_absent_control_states_use_the_checked_profile(self) -> None:
        cases = (
            ({"op": "jump", "target": 1}, ("jump",)),
            ({
                "op": "branch",
                "condition": TRUE_GUARD,
                "taken": 1,
                "fallthrough": 1,
            }, ("branchTaken", "branchFallthrough")),
            ({"op": "call", "target": 1, "continuation": 1}, ("call",)),
            ({
                "op": "returned",
                "target": {
                    "op": "read32",
                    "address": {"op": "input_reg", "reg": "esp"},
                },
            }, ()),
        )
        blocker_codes = {
            "direct_jump_node_profile_unmet",
            "guarded_branch_profile_unmet",
            "jump_control_profile_missing",
            "branch_control_profile_missing",
            "return_node_profile_unmet",
            "direct_call_control_profile_unmet",
        }

        for outcome, edge_kinds in cases:
            with self.subTest(op=outcome["op"]):
                contract, behaviors, graph, register_relations = (
                    _unrepresented_self_control_fixture()
                )
                behaviors[1] = _behavior(outcome)
                graph["nodes"][1]["outgoing_edge_ids"] = list(
                    range(len(edge_kinds))
                )
                graph["edges"] = [{
                    "id": edge_id,
                    "source_node_id": 1,
                    "source_target_id": 1,
                    "target_node_id": 1,
                    "target_target_id": 1,
                    "kind": kind,
                    "candidate_kind": kind,
                    "original_guard": TRUE_GUARD,
                    "candidate_guard": TRUE_GUARD,
                    "infeasible": False,
                } for edge_id, kind in enumerate(edge_kinds)]

                plan = _whole_program_acceptance_plan(
                    contract,
                    behaviors,
                    graph,
                    register_relations,
                    [],
                    [],
                )

                step = next(
                    item for item in plan["node_steps"] if item["node_id"] == 1
                )
                emitted_codes = {item["code"] for item in plan["blockers"]}
                self.assertEqual(step["kind"], "control_unrepresented")
                self.assertTrue(blocker_codes.isdisjoint(emitted_codes))

    def test_nonidentical_absent_control_state_is_still_proved_vacuous(self) -> None:
        contract, behaviors, graph, register_relations = (
            _unrepresented_self_control_fixture()
        )
        behaviors[1]["candidate_ir"]["outcome"]["target"] = 0

        plan = _whole_program_acceptance_plan(
            contract,
            behaviors,
            graph,
            register_relations,
            [],
            [],
        )

        step = next(item for item in plan["node_steps"] if item["node_id"] == 1)
        self.assertEqual(step["kind"], "control_unrepresented")
        self.assertNotIn(
            "direct_jump_node_profile_unmet",
            {item["code"] for item in plan["blockers"]},
        )

    def test_all_absent_noncallback_control_states_use_checked_absence(self) -> None:
        outcomes = (
            {"op": "external_call", "continuation": 1},
            {"op": "indirect_call", "continuation": 1},
            {"op": "indirect_jump"},
            {"op": "call_unmapped_return", "target": 1},
            {"op": "atomic_compare_exchange", "continuation": 1},
        )

        for outcome in outcomes:
            with self.subTest(op=outcome["op"]):
                contract, behaviors, graph, register_relations = (
                    _unrepresented_self_control_fixture()
                )
                behaviors[1] = _behavior(outcome)

                plan = _whole_program_acceptance_plan(
                    contract,
                    behaviors,
                    graph,
                    register_relations,
                    [],
                    [],
                )

                step = next(
                    item for item in plan["node_steps"] if item["node_id"] == 1
                )
                self.assertEqual(step["kind"], "control_unrepresented")

    def test_constant_infeasible_branch_omits_unreachable_target_obligations(
        self,
    ) -> None:
        contract, behaviors, graph, register_relations, segments = (
            _constant_branch_fixture()
        )
        impossible_edge = graph["edges"][1]
        self.assertTrue(_checked_infeasible_branch_edge(impossible_edge))
        status_only_edge = copy.deepcopy(impossible_edge)
        status_only_edge["original_guard"] = {"op": "input_flag", "index": 0}
        status_only_edge["candidate_guard"] = {"op": "input_flag", "index": 0}
        self.assertFalse(_checked_infeasible_branch_edge(status_only_edge))

        plan = _whole_program_acceptance_plan(
            contract,
            behaviors,
            graph,
            register_relations,
            segments,
            [],
        )

        step = next(item for item in plan["node_steps"] if item["node_id"] == 0)
        blocker_codes = {item["code"] for item in plan["blockers"]}
        self.assertEqual(step["kind"], "branch")
        self.assertNotIn("guarded_branch_profile_unmet", blocker_codes)
        self.assertNotIn("branch_target_control_state_missing", blocker_codes)
        infeasible = next(edge for edge in step["edges"] if edge["edge_id"] == 1)
        self.assertTrue(infeasible["infeasible"])
        self.assertNotIn("target_control_state", infeasible)

        source = _lean_acceptance_running_node(step, contract["regions"], behaviors)
        self.assertIn(
            "simp [region0OutcomeCondition, BoolExpr.eval, Expr.eval] "
            "at originalCondition",
            source,
        )

    def test_protocol_callback_control_is_not_treated_as_unrepresented(self) -> None:
        contract, behaviors, graph, register_relations = (
            _unrepresented_self_control_fixture()
        )
        behaviors[1] = _behavior({
            "op": "returned",
            "target": {
                "op": "read32",
                "address": {"op": "input_reg", "reg": "esp"},
            },
        })
        graph["nodes"][1]["outgoing_edge_ids"] = []
        graph["edges"] = []
        contract["protocol_callback_control"] = {
            "format": PROTOCOL_CALLBACK_CONTROL_FORMAT,
            "states": [{
                "target_id": 1,
                "active_frame_offset": {
                    "original_register": "esp",
                    "original": 0,
                    "candidate_register": "esp",
                    "candidate": 0,
                },
                "return_invariant": {"kind": "terminal"},
            }],
        }

        plan = _whole_program_acceptance_plan(
            contract,
            behaviors,
            graph,
            register_relations,
            [],
            [],
        )

        self.assertNotIn(
            "control_unrepresented",
            {item["kind"] for item in plan["node_steps"]},
        )
        self.assertIn(
            "return_node_profile_unmet",
            {item["code"] for item in plan["blockers"]},
        )


if __name__ == "__main__":
    unittest.main()
