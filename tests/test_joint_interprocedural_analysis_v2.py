from __future__ import annotations

import copy
import unittest

from spaghetti_extractor.artifact_identity_v2 import canonical_sha256
from spaghetti_extractor.control_analysis_v2 import exact_control_inventory_v2
from spaghetti_extractor.joint_interprocedural_analysis_v2 import (
    build_proposal_control_graph_v2,
    merge_recovery_proposals_v2,
    validate_joint_replay_v2,
)


def _unit(unit_id: str, rva: int, *, indirect: bool = False) -> dict[str, object]:
    return {
        "id": unit_id,
        "source": {"original": {"rva_start": rva, "rva_end": rva + 4}},
        "semantics": {
            "external_events": [],
            "memory_events": [],
            "outcome": {"target": {"name": "eax", "op": "reg", "width": 32}},
        },
        "control": {
            "direct_targets": [],
            "has_indirect_target": indirect,
            "kind": "indirect_jump" if indirect else "return",
        },
    }


def _base() -> dict[str, object]:
    return {
        "roots": [{"unit_id": "root", "kind": "pe_entrypoint"}],
    }


def _stack_binding(graph_id: str) -> dict[str, object]:
    return {
        "rooted_graph_id": graph_id,
        "call_site_effects_sha256": canonical_sha256([]),
    }


class JointInterproceduralAnalysisV2Tests(unittest.TestCase):
    def test_exact_control_preserves_and_normalizes_target_guard(self) -> None:
        loaded = {
            "op": "load",
            "width": 4,
            "address": {"op": "reg", "name": "esi", "width": 32},
        }
        root = _unit("root", 0x1000)
        root["semantics"]["register_writes"] = [
            {"register": "eax", "value": loaded}
        ]
        root["semantics"]["edge_conditions"] = [{
            "target_rva": 0x1010,
            "condition": {
                "op": "not",
                "args": [{
                    "op": "eq",
                    "args": [
                        {"op": "and32", "args": [loaded, loaded]},
                        {"op": "const", "value": 0, "width": 32},
                    ],
                }],
            },
        }]
        root["control"]["direct_targets"] = [0x1010]

        exact = exact_control_inventory_v2([root, _unit("target", 0x1010)])

        self.assertEqual(
            exact["direct_edges"],
            [{
                "source_unit_id": "root",
                "target_unit_id": "target",
                "guard": {
                    "op": "not",
                    "args": [{
                        "op": "eq",
                        "args": [
                            {"op": "reg", "name": "eax", "width": 32},
                            {"op": "const", "value": 0, "width": 32},
                        ],
                    }],
                },
            }],
        )

    def test_proposal_graph_closes_only_with_finite_exact_target(self) -> None:
        units = [_unit("root", 0x1000, indirect=True), _unit("target", 0x1010)]
        exact = exact_control_inventory_v2(units)["indirect_exits"][0]
        proposal = {
            **exact,
            "status": "recovered",
            "target_rvas": [0x1010],
            "target_unit_ids": ["target"],
            "external_targets": [],
        }

        graph = build_proposal_control_graph_v2(
            units=units, base_graph=_base(), recoveries=[proposal]
        )

        self.assertEqual(graph["status"], "complete", graph["issues"])
        self.assertEqual(graph["reachable_units"], ["root", "target"])

    def test_missing_and_conflicting_proposals_fail_closed(self) -> None:
        units = [_unit("root", 0x1000, indirect=True), _unit("target", 0x1010)]
        exact = exact_control_inventory_v2(units)["indirect_exits"][0]
        left = {
            **exact,
            "status": "recovered",
            "target_rvas": [0x1010],
            "target_unit_ids": ["target"],
            "external_targets": [],
        }
        right = {
            **left,
            "target_rvas": [],
            "target_unit_ids": [],
            "external_targets": [{"dll": "x.dll", "symbol": "f"}],
        }

        missing = merge_recovery_proposals_v2(exact_exits=[exact], proposal_sets=[])
        conflict = merge_recovery_proposals_v2(
            exact_exits=[exact], proposal_sets=[[left], [right]]
        )

        self.assertEqual(missing[0]["failure"]["code"], "finite_recovery_proposal_missing")
        self.assertEqual(conflict[0]["failure"]["code"], "conflicting_recovery_proposals")

    def test_proposal_drift_is_diagnostic_not_authority(self) -> None:
        units = [_unit("root", 0x1000, indirect=True), _unit("target", 0x1010)]
        exact = exact_control_inventory_v2(units)["indirect_exits"][0]
        proposal = {
            **exact,
            "status": "recovered",
            "target_rvas": [0x1010],
            "target_unit_ids": ["target"],
            "external_targets": [],
        }
        graph = build_proposal_control_graph_v2(
            units=units, base_graph=_base(), recoveries=[proposal]
        )
        cold = copy.deepcopy(proposal)
        cold["target_rvas"] = []
        cold["target_unit_ids"] = []
        cold["external_targets"] = [{"dll": "x.dll", "symbol": "f"}]

        result = validate_joint_replay_v2(
            proposal_graph=graph,
            proposal_recoveries=[proposal],
            stack_range_analysis={
                "status": "complete",
                "binding": _stack_binding(str(graph["id"])),
                "cold_replay": {
                    "status": "complete",
                    "deterministic": True,
                    "empty_initial_state": True,
                    "target_proposals_used": True,
                    "unseeded": False,
                },
            },
            global_slot_analysis={"status": "complete"},
            global_slot_authority={"status": "complete"},
            interprocedural={
                "fixed_point": {
                    "status": "complete",
                    "cold_replay_validated": True,
                    "authority_replay_validated": True,
                },
                "recovered_targets": [cold],
            },
            cold_graph=graph,
            authoritative_evidence_stable=True,
        )

        self.assertEqual(result["status"], "complete", result["issues"])
        self.assertEqual(
            result["proposal_diagnostics"][0]["code"],
            "cold_replay_target_differs_from_proposal",
        )

    def test_stack_replay_must_bind_the_exact_proposal_graph(self) -> None:
        graph = build_proposal_control_graph_v2(
            units=[_unit("root", 0x1000)], base_graph=_base(), recoveries=[]
        )

        result = validate_joint_replay_v2(
            proposal_graph=graph,
            proposal_recoveries=[],
            stack_range_analysis={
                "status": "complete",
                "binding": _stack_binding("stale-graph"),
                "cold_replay": {
                    "status": "complete",
                    "deterministic": True,
                    "empty_initial_state": True,
                },
            },
            global_slot_analysis={"status": "complete"},
            global_slot_authority={"status": "complete"},
            interprocedural={
                "fixed_point": {
                    "status": "complete",
                    "cold_replay_validated": True,
                    "authority_replay_validated": True,
                },
                "recovered_targets": [],
            },
            cold_graph=graph,
            authoritative_evidence_stable=True,
        )

        self.assertEqual(result["status"], "violated")
        self.assertFalse(result["checks"]["stack_range_replay_complete"])
        self.assertEqual(
            result["issues"][0]["code"],
            "authoritative_stack_graph_binding_mismatch",
        )

    def test_slot_replay_must_cover_exact_recovery_requirements(self) -> None:
        graph = build_proposal_control_graph_v2(
            units=[_unit("root", 0x1000)], base_graph=_base(), recoveries=[]
        )
        result = validate_joint_replay_v2(
            proposal_graph=graph,
            proposal_recoveries=[],
            stack_range_analysis={
                "status": "complete",
                "binding": _stack_binding(str(graph["id"])),
                "cold_replay": {
                    "status": "complete",
                    "deterministic": True,
                    "empty_initial_state": True,
                },
            },
            global_slot_analysis={
                "status": "complete",
                "bindings": {"image_base": 0x400000},
                "slots": [{"address": 0x403004}],
            },
            global_slot_authority={"status": "complete"},
            interprocedural={
                "fixed_point": {
                    "status": "complete",
                    "cold_replay_validated": True,
                    "authority_replay_validated": True,
                },
                "recovered_targets": [{
                    "id": "exit:slot",
                    "mutable_slot_dependencies": [{
                        "slot_rva": 0x3000,
                        "width_bytes": 4,
                        "read_sites": [],
                    }],
                }],
            },
            cold_graph=graph,
            authoritative_evidence_stable=True,
        )

        self.assertEqual(result["status"], "violated")
        self.assertFalse(
            result["checks"]["mutable_slot_requirement_inventory_exact"]
        )
        issue = next(
            row for row in result["issues"]
            if row["code"].endswith("inventory_mismatch")
        )
        self.assertEqual(issue["missing_slot_rvas"], [0x3000])
        self.assertEqual(issue["extra_slot_rvas"], [0x3004])

    def test_malformed_slot_requirement_is_a_violation(self) -> None:
        graph = build_proposal_control_graph_v2(
            units=[_unit("root", 0x1000)], base_graph=_base(), recoveries=[]
        )
        result = validate_joint_replay_v2(
            proposal_graph=graph,
            proposal_recoveries=[],
            stack_range_analysis={
                "status": "complete",
                "binding": _stack_binding(str(graph["id"])),
                "cold_replay": {
                    "status": "complete",
                    "deterministic": True,
                    "empty_initial_state": True,
                },
            },
            global_slot_analysis={"status": "complete", "slots": []},
            global_slot_authority={"status": "complete"},
            interprocedural={
                "fixed_point": {
                    "status": "complete",
                    "cold_replay_validated": True,
                    "authority_replay_validated": True,
                },
                "recovered_targets": [{
                    "id": "exit:slot",
                    "mutable_slot_dependencies": [{
                        "slot_rva": 0x3000,
                        "width_bytes": 8,
                    }],
                }],
            },
            cold_graph=graph,
            authoritative_evidence_stable=True,
        )

        self.assertEqual(result["status"], "violated")
        self.assertIn(
            "authoritative_mutable_slot_requirement_inventory_malformed",
            {row["code"] for row in result["issues"]},
        )


if __name__ == "__main__":
    unittest.main()
