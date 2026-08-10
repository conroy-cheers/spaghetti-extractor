from __future__ import annotations

import unittest

from spaghetti_extractor.artifact_identity_v2 import canonical_sha256
from spaghetti_extractor.joint_fixed_point_v2 import (
    JointFixedPointCallbacks,
    derive_joint_fixed_point_v2,
)


def _graph() -> dict[str, object]:
    return {
        "id": "proposal-graph",
        "status": "complete",
        "reachable_units": ["root"],
    }


def _interprocedural(
    *,
    generation: int,
    proposal_seed_count: int,
) -> dict[str, object]:
    return {
        "status": "complete",
        "call_summaries": {"generation": generation},
        "recovered_targets": [],
        "fixed_point": {
            "status": "complete",
            "cold_replay_validated": True,
            "authority_replay_validated": True,
            "cold_initial_recoveries_empty": True,
            "proposal_only": False,
            "static_recovery_authority_seeded": False,
            "cold_replay_signature": f"cold-{generation}",
            "proposal_seed_count": proposal_seed_count,
            "dependencies": [],
        },
    }


def _stack(
    call_summaries: dict[str, object], *, graph_id: str = "proposal-graph"
) -> dict[str, object]:
    generation = int(call_summaries.get("generation", 0))
    return {
        "status": "complete",
        "binding": {
            "rooted_graph_id": graph_id,
            "call_site_effects_sha256": canonical_sha256([]),
        },
        "entry_offsets": {},
        "checked_range_facts": [{"id": f"stack-{generation}"}],
        "cold_replay": {
            "status": "complete",
            "deterministic": True,
            "empty_initial_state": True,
        },
    }


class JointFixedPointV2Tests(unittest.TestCase):
    def test_prepared_proposal_is_reused_but_authority_is_unseeded(self) -> None:
        calls: list[tuple[int, bool]] = []

        def interprocedural(
            invariants, _stack_entry_offsets, _stack_range_facts, recoveries
        ):
            calls.append((len(invariants), recoveries is not None))
            return _interprocedural(
                generation=len(invariants),
                proposal_seed_count=0 if recoveries is None else len(recoveries),
            )

        def authority(_analysis, _stack, _graph, _interprocedural):
            return {
                "status": "complete",
                "global_slot_invariants": [{"content_id": "slot-a"}],
            }

        result = derive_joint_fixed_point_v2(
            proposal_graph=_graph(),
            proposal_recoveries=[{"id": "exit-a"}],
            callbacks=JointFixedPointCallbacks(
                derive_interprocedural=interprocedural,
                derive_stack_ranges=lambda graph, interprocedural: _stack(
                    dict(interprocedural["call_summaries"]),
                    graph_id=str(graph["id"]),
                ),
                derive_global_slots=lambda _graph, _ranges: {"status": "complete"},
                derive_global_slot_authority=authority,
                derive_graph=lambda _interprocedural: _graph(),
            ),
        )

        self.assertEqual(result["status"], "complete", result["issues"])
        self.assertEqual(
            result["interprocedural"]["fixed_point"]["proposal_seed_count"],
            0,
        )
        self.assertTrue(result["joint_fixed_point"]["converged"])
        self.assertTrue(
            result["joint_fixed_point"]["authoritative_interprocedural_unseeded"]
        )
        self.assertTrue(calls)
        self.assertFalse(any(seeded for _count, seeded in calls))
        first_authority = next(
            count for count, seeded in calls if not seeded
        )
        self.assertEqual(first_authority, 0)
        self.assertEqual(result["joint_fixed_point"]["rounds"], [])
        self.assertTrue(result["joint_fixed_point"]["prepared_proposal_reused"])
        self.assertGreaterEqual(
            len(result["joint_fixed_point"]["authoritative_rounds"]), 2
        )

    def test_proposal_bootstrap_only_seeds_replayable_slot_invariants(self) -> None:
        observed: list[tuple[int, bool]] = []

        proposal = _interprocedural(generation=0, proposal_seed_count=1)
        proposal["fixed_point"].update({
            "proposal_only": True,
            "cold_initial_recoveries_empty": False,
        })
        proposal["recovered_targets"] = [{
            "id": "exit-a",
            "status": "recovered",
            "proof_authority": False,
        }]

        def interprocedural(
            invariants, _stack_entry_offsets, _stack_range_facts, recoveries
        ):
            observed.append((len(invariants), recoveries is not None))
            return _interprocedural(
                generation=len(invariants),
                proposal_seed_count=0 if recoveries is None else len(recoveries),
            )

        def authority(_analysis, _stack, _graph, _interprocedural):
            return {
                "status": "complete",
                "global_slot_invariants": [{"content_id": "slot-a"}],
            }

        result = derive_joint_fixed_point_v2(
            proposal_graph=_graph(),
            proposal_recoveries=[{"id": "exit-a"}],
            proposal_interprocedural=proposal,
            callbacks=JointFixedPointCallbacks(
                derive_interprocedural=interprocedural,
                derive_stack_ranges=lambda graph, interprocedural: _stack(
                    dict(interprocedural["call_summaries"]),
                    graph_id=str(graph["id"]),
                ),
                derive_global_slots=lambda _graph, _ranges: {
                    "status": "complete"
                },
                derive_global_slot_authority=authority,
                derive_graph=lambda _interprocedural: _graph(),
            ),
        )

        self.assertEqual(result["status"], "complete", result["issues"])
        self.assertEqual(observed[0], (1, False))
        self.assertFalse(any(seeded for _count, seeded in observed))
        self.assertEqual(len(result["joint_fixed_point"]["rounds"]), 1)
        self.assertFalse(
            result["joint_fixed_point"]["rounds"][0]["proof_authority"]
        )
        self.assertTrue(
            result["joint_fixed_point"]["authoritative_interprocedural_unseeded"]
        )

    def test_nonconvergent_finite_lattice_remains_incomplete(self) -> None:
        def interprocedural(
            invariants, _stack_entry_offsets, _stack_range_facts, recoveries
        ):
            return _interprocedural(
                generation=len(invariants),
                proposal_seed_count=0 if recoveries is None else len(recoveries),
            )

        toggle = {"value": False}

        def authority(_analysis, _stack, _graph, _interprocedural):
            toggle["value"] = not toggle["value"]
            return {
                "status": "complete",
                "global_slot_invariants": [
                    {"content_id": "slot-a" if toggle["value"] else "slot-b"}
                ],
            }

        result = derive_joint_fixed_point_v2(
            proposal_graph=_graph(),
            proposal_recoveries=[],
            callbacks=JointFixedPointCallbacks(
                derive_interprocedural=interprocedural,
                derive_stack_ranges=lambda graph, interprocedural: _stack(
                    dict(interprocedural["call_summaries"]),
                    graph_id=str(graph["id"]),
                ),
                derive_global_slots=lambda _graph, _ranges: {"status": "complete"},
                derive_global_slot_authority=authority,
                derive_graph=lambda _interprocedural: _graph(),
            ),
            finite_round_budget=2,
        )

        self.assertEqual(result["status"], "incomplete")
        self.assertIn(
            "authoritative_joint_lattice_round_budget_exceeded",
            {row["code"] for row in result["issues"]},
        )

    def test_seeded_authoritative_result_is_a_violation(self) -> None:
        def interprocedural(
            _invariants, _stack_entry_offsets, _stack_range_facts, _recoveries
        ):
            result = _interprocedural(generation=0, proposal_seed_count=1)
            result["fixed_point"]["static_recovery_authority_seeded"] = True
            return result

        result = derive_joint_fixed_point_v2(
            proposal_graph=_graph(),
            proposal_recoveries=[],
            callbacks=JointFixedPointCallbacks(
                derive_interprocedural=interprocedural,
                derive_stack_ranges=lambda graph, interprocedural: _stack(
                    dict(interprocedural["call_summaries"]),
                    graph_id=str(graph["id"]),
                ),
                derive_global_slots=lambda _graph, _ranges: {"status": "complete"},
                derive_global_slot_authority=lambda *_args: {
                    "status": "complete",
                    "global_slot_invariants": [],
                },
                derive_graph=lambda _interprocedural: _graph(),
            ),
        )

        self.assertEqual(result["status"], "violated")
        self.assertIn(
            "authoritative_interprocedural_replay_seeded",
            {row["code"] for row in result["issues"]},
        )

    def test_checked_stack_entries_feed_the_next_round_and_cold_replay(self) -> None:
        observed: list[tuple[dict[str, tuple[int, ...]], bool]] = []

        def interprocedural(
            _invariants, stack_entry_offsets, _stack_range_facts, recoveries
        ):
            observed.append((dict(stack_entry_offsets), recoveries is not None))
            return _interprocedural(
                generation=len(stack_entry_offsets),
                proposal_seed_count=0 if recoveries is None else len(recoveries),
            )

        def stack(graph, _interprocedural):
            return {
                **_stack({}, graph_id=str(graph["id"])),
                "entry_offsets": {"root": [0], "continuation": [-8, -8]},
            }

        result = derive_joint_fixed_point_v2(
            proposal_graph=_graph(),
            proposal_recoveries=[],
            callbacks=JointFixedPointCallbacks(
                derive_interprocedural=interprocedural,
                derive_stack_ranges=stack,
                derive_global_slots=lambda _graph, _ranges: {"status": "complete"},
                derive_global_slot_authority=lambda *_args: {
                    "status": "complete",
                    "global_slot_invariants": [],
                },
                derive_graph=lambda _interprocedural: _graph(),
            ),
        )

        expected = {"continuation": (-8,), "root": (0,)}
        self.assertEqual(result["status"], "complete", result["issues"])
        self.assertEqual(observed[0], ({}, False))
        self.assertFalse(any(seeded for _offsets, seeded in observed))
        self.assertEqual(observed[-1], (expected, False))
        self.assertEqual(
            result["joint_fixed_point"]["authoritative_rounds"][-1]["stack_entry_units"],
            2,
        )

    def test_progress_reports_each_expensive_phase_without_changing_output(self) -> None:
        events: list[tuple[str, dict[str, object]]] = []

        def interprocedural(
            _invariants, _stack_entry_offsets, _stack_range_facts, _recoveries
        ):
            return _interprocedural(generation=0, proposal_seed_count=0)

        def run(progress=None):
            return derive_joint_fixed_point_v2(
                proposal_graph=_graph(),
                proposal_recoveries=[],
                callbacks=JointFixedPointCallbacks(
                    derive_interprocedural=interprocedural,
                    derive_stack_ranges=lambda graph, interprocedural: _stack(
                        dict(interprocedural["call_summaries"]),
                        graph_id=str(graph["id"]),
                    ),
                    derive_global_slots=lambda _graph, _ranges: {
                        "status": "complete",
                        "counts": {"complete_slots": 0, "incomplete_slots": 0},
                        "issues": [],
                    },
                    derive_global_slot_authority=lambda *_args: {
                        "status": "complete",
                        "global_slot_invariants": [],
                        "issues": [],
                    },
                    derive_graph=lambda _interprocedural: _graph(),
                ),
                progress=progress,
            )

        observed = run(lambda phase, details: events.append((phase, dict(details))))
        baseline = run()

        self.assertEqual(observed, baseline)
        phases = [phase for phase, _details in events]
        self.assertEqual(
            phases,
            [
                "round_started",
                "interprocedural_derived",
                "graph_derived",
                "stack_ranges_derived",
                "global_slots_derived",
                "global_slot_authority_derived",
                "round_finished",
                "round_started",
                "interprocedural_derived",
                "graph_derived",
                "stack_ranges_derived",
                "global_slots_derived",
                "global_slot_authority_derived",
                "round_finished",
                "joint_replay_started",
                "joint_replay_finished",
            ],
        )
        self.assertTrue(events[-3][1]["converged"])


if __name__ == "__main__":
    unittest.main()
