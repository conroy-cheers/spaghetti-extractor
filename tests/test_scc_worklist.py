from __future__ import annotations

import unittest

from spaghetti_extractor.analysis.scc_worklist import (
    SCCWorklist,
    decompose_scc,
    strongly_connected_components,
)


class SCCDecompositionTests(unittest.TestCase):
    def test_decomposition_and_condensation_are_canonical(self) -> None:
        edges = {
            ("b", "a"),
            ("a", "b"),
            ("b", "c"),
            ("c", "d"),
            ("d", "e"),
            ("e", "d"),
        }
        first = decompose_scc(["z", "e", "d", "c", "b", "a"], edges)
        second = decompose_scc(
            ["a", "b", "c", "d", "e", "z"], reversed(tuple(edges))
        )

        self.assertEqual(first, second)
        self.assertEqual(
            first.components,
            (("a", "b"), ("c",), ("d", "e"), ("z",)),
        )
        self.assertEqual(first.condensation_edges, ((0, 1), (1, 2)))
        self.assertEqual(first.component("b"), ("a", "b"))
        self.assertEqual(first.successors(0), (1,))
        self.assertEqual(first.predecessors(2), (1,))

    def test_adjacency_mapping_and_edge_list_agree(self) -> None:
        adjacency = {
            3: [1],
            1: [2],
            2: [1],
            0: [],
        }
        expected = ((0,), (3,), (1, 2))
        self.assertEqual(strongly_connected_components(adjacency), expected)
        self.assertEqual(
            strongly_connected_components(adjacency, [(0, 3)]),
            ((0,), (3,), (1, 2)),
        )

    def test_custom_key_supports_generic_nodes(self) -> None:
        class Node:
            def __init__(self, identity: str) -> None:
                self.identity = identity

            def __hash__(self) -> int:
                return hash(self.identity)

        first = Node("first")
        second = Node("second")
        result = decompose_scc(
            [second, first],
            [(first, second), (second, first)],
            key=lambda node: node.identity,
        )
        self.assertEqual(result.components, ((first, second),))

    def test_duplicate_custom_keys_are_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "unique key"):
            decompose_scc(["a", "b"], key=lambda _node: 0)


class SCCWorklistTests(unittest.TestCase):
    def test_initial_schedule_is_dependency_first_and_scc_granular(self) -> None:
        worklist = SCCWorklist(
            ["consumer", "cycle-a", "cycle-b", "provider"],
            [
                ("provider", "cycle-a"),
                ("cycle-a", "cycle-b"),
                ("cycle-b", "cycle-a"),
                ("cycle-b", "consumer"),
            ],
        )

        self.assertEqual(worklist.pop(), ("provider",))
        self.assertEqual(worklist.pop(), ("cycle-a", "cycle-b"))
        self.assertEqual(worklist.pop(), ("consumer",))
        self.assertFalse(worklist)
        with self.assertRaises(IndexError):
            worklist.pop()

    def test_growing_edges_invalidates_new_nodes_and_all_dependents(self) -> None:
        worklist = SCCWorklist(
            ["a", "b", "c"], [("a", "b"), ("b", "c")]
        )
        while worklist:
            worklist.pop()

        invalidated = worklist.add_edges((("d", "b"),))

        self.assertEqual(invalidated, (("d",), ("b",), ("c",)))
        self.assertEqual(worklist.pop(), ("d",))
        self.assertEqual(worklist.pop(), ("b",))
        self.assertEqual(worklist.pop(), ("c",))

    def test_edge_closing_cycle_invalidates_complete_merged_scc(self) -> None:
        worklist = SCCWorklist(["a", "b"], [("a", "b")])
        while worklist:
            worklist.pop()

        self.assertTrue(worklist.add_edge("b", "a"))
        self.assertEqual(worklist.pop(), ("a", "b"))
        self.assertFalse(worklist.add_edge("b", "a"))

    def test_changed_fact_schedules_dependents_but_not_acyclic_source(self) -> None:
        worklist = SCCWorklist(
            ["a", "b", "c"],
            [("a", "b"), ("b", "c")],
            schedule_all=False,
        )

        self.assertEqual(worklist.notify_changed("a"), (("b",), ("c",)))
        self.assertEqual(worklist.pop(), ("b",))
        self.assertEqual(worklist.pop(), ("c",))

    def test_changed_fact_reschedules_its_cyclic_component(self) -> None:
        worklist = SCCWorklist(
            ["a", "b", "c"],
            [("a", "b"), ("b", "a"), ("b", "c")],
            schedule_all=False,
        )

        self.assertEqual(
            worklist.notify_changed("a"), (("a", "b"), ("c",))
        )
        self.assertEqual(worklist.pop(), ("a", "b"))
        self.assertEqual(worklist.pop(), ("c",))

    def test_named_dependency_api_has_unambiguous_orientation(self) -> None:
        worklist = SCCWorklist[str](schedule_all=False)
        self.assertTrue(
            worklist.add_dependency(
                dependent="consumer", dependency="provider"
            )
        )
        self.assertEqual(worklist.edges, frozenset({("provider", "consumer")}))
        self.assertEqual(worklist.pop(), ("provider",))
        self.assertEqual(worklist.pop(), ("consumer",))


if __name__ == "__main__":
    unittest.main()
