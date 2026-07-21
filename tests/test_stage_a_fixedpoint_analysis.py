import unittest

from spaghetti_extractor.relational.analyses.fixedpoint import (
    solve_monotone_fixed_point,
    solve_monotone_fixed_point_by_scc,
)
from spaghetti_extractor.relational.analyses.frames import (
    runtime_frame_alias_viability,
)


class StageAFixedPointAnalysisTests(unittest.TestCase):
    def test_frame_alias_viability_follows_successor_chain(self) -> None:
        location = ("esp", 0, "esp", 0)
        result = runtime_frame_alias_viability(
            ((0, location),),
            memory_ready=lambda _node, _location: True,
            required_edges=lambda node: (node,) if node < 2 else (),
            transfer_targets=lambda node, value, _edge: ((node + 1, value),),
        )

        self.assertFalse(result.budget_exceeded)
        self.assertEqual(result.viable, frozenset({
            (0, location), (1, location), (2, location),
        }))

    def test_frame_alias_viability_rejects_dead_successor(self) -> None:
        location = ("esp", 0, "esp", 0)
        result = runtime_frame_alias_viability(
            ((0, location),),
            memory_ready=lambda _node, _location: True,
            required_edges=lambda node: (node,) if node < 2 else (),
            transfer_targets=lambda node, value, _edge: (
                ((1, value),) if node == 0 else ()
            ),
        )

        self.assertFalse(result.budget_exceeded)
        self.assertEqual(result.explored, frozenset({(0, location), (1, location)}))
        self.assertEqual(result.viable, frozenset())

    def test_frame_alias_viability_checks_all_branch_successors(self) -> None:
        location = ("ebp", 8, "ebp", 8)
        targets = {10: 1, 11: 2}
        result = runtime_frame_alias_viability(
            ((0, location),),
            memory_ready=lambda _node, _location: True,
            required_edges=lambda node: (10, 11) if node == 0 else (),
            transfer_targets=lambda _node, value, edge: ((targets[edge], value),),
        )

        self.assertEqual(result.viable, frozenset({
            (0, location), (1, location), (2, location),
        }))

    def test_frame_alias_viability_accepts_closed_cycle(self) -> None:
        location = ("esp", 12, "esp", 12)
        result = runtime_frame_alias_viability(
            ((0, location),),
            memory_ready=lambda _node, _location: True,
            required_edges=lambda node: (node,),
            transfer_targets=lambda node, value, _edge: ((1 - node, value),),
        )

        self.assertEqual(result.viable, frozenset({(0, location), (1, location)}))

    def test_frame_alias_viability_fails_closed_on_unbounded_offsets(self) -> None:
        location = ("esp", 0, "esp", 0)
        result = runtime_frame_alias_viability(
            ((0, location),),
            memory_ready=lambda _node, _location: True,
            required_edges=lambda _node: (0,),
            transfer_targets=lambda _node, value, _edge: ((0, (
                value[0], value[1] + 4, value[2], value[3] + 4,
            )),),
            max_states=4,
        )

        self.assertTrue(result.budget_exceeded)
        self.assertEqual(result.viable, frozenset())

    def test_synchronous_chain_preserves_rounds_and_dirty_evaluations(self) -> None:
        result = solve_monotone_fixed_point(
            initial_input_states=[0, None],
            initial_output_states=[None, None],
            initial_output_reason_states=[None, None],
            successors=[[1], []],
            evaluate_output=lambda region, state, _previous: (
                state + region + 1,
                f"region-{region}",
            ),
            recompute_input=lambda region, outputs: (
                outputs[0] if region == 1 else 0
            ),
            max_iterations=8,
        )

        self.assertTrue(result.converged)
        self.assertEqual(result.iterations, 3)
        self.assertEqual(result.transfer_evaluations, 2)
        self.assertEqual(result.input_states, (0, 1))
        self.assertEqual(result.output_states, (1, 3))
        self.assertEqual(result.output_reason_states, ("region-0", "region-1"))

    def test_cycle_uses_monotone_output_join_until_stable(self) -> None:
        def evaluate(
            region: int, state: int, previous: int | None,
        ) -> tuple[int, str]:
            proposed = min(3, state + 1)
            return max(previous or 0, proposed), f"region-{region}"

        result = solve_monotone_fixed_point(
            initial_input_states=[0, None],
            initial_output_states=[None, None],
            initial_output_reason_states=[None, None],
            successors=[[1], [0]],
            evaluate_output=evaluate,
            recompute_input=lambda region, outputs: (
                outputs[1] if region == 0 else outputs[0]
            ),
            max_iterations=16,
        )

        self.assertTrue(result.converged)
        self.assertEqual(result.input_states, (3, 3))
        self.assertEqual(result.output_states, (3, 3))

    def test_nonconvergence_and_malformed_graph_fail_closed(self) -> None:
        result = solve_monotone_fixed_point(
            initial_input_states=[0],
            initial_output_states=[None],
            initial_output_reason_states=[None],
            successors=[[0]],
            evaluate_output=lambda _region, state, _previous: (
                state + 1,
                "growing",
            ),
            recompute_input=lambda _region, outputs: outputs[0],
            max_iterations=2,
        )
        self.assertFalse(result.converged)

        with self.assertRaisesRegex(ValueError, "outside"):
            solve_monotone_fixed_point(
                initial_input_states=[0],
                initial_output_states=[None],
                initial_output_reason_states=[None],
                successors=[[1]],
                evaluate_output=lambda _region, state, _previous: (
                    state,
                    "same",
                ),
                recompute_input=lambda _region, _outputs: 0,
                max_iterations=1,
            )

    def test_scc_solver_matches_global_solver_on_cycle_and_dag(self) -> None:
        successors = [[1], [0, 2], [3, 4], [4], []]
        initial = [0, None, None, None, None]

        def evaluate(
            region: int, state: int, previous: int | None,
        ) -> tuple[int, str]:
            proposed = min(7, state + (region % 2) + 1)
            return max(previous or 0, proposed), f"region-{region}"

        predecessors = [
            [source for source, targets in enumerate(successors) if target in targets]
            for target in range(len(successors))
        ]

        def recompute(region: int, outputs: list[int | None] | tuple[int | None, ...]):
            candidates = [
                outputs[source]
                for source in predecessors[region]
                if outputs[source] is not None
            ]
            if region == 0:
                candidates.append(0)
            return max(candidates) if candidates else None

        common = {
            "initial_input_states": initial,
            "initial_output_states": [None] * len(successors),
            "initial_output_reason_states": [None] * len(successors),
            "successors": successors,
            "evaluate_output": evaluate,
            "recompute_input": recompute,
            "max_iterations": 128,
        }
        global_result = solve_monotone_fixed_point(**common)
        scc_result = solve_monotone_fixed_point_by_scc(**common)

        self.assertTrue(global_result.converged)
        self.assertTrue(scc_result.converged)
        self.assertEqual(scc_result.input_states, global_result.input_states)
        self.assertEqual(scc_result.output_states, global_result.output_states)
        self.assertEqual(
            scc_result.output_reason_states,
            global_result.output_reason_states,
        )


if __name__ == "__main__":
    unittest.main()
