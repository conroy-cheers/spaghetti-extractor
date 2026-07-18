import unittest

from spaghetti_extractor.relational.analyses.dataflow import (
    strongly_connected_components,
)


class StageADataflowAnalysisTests(unittest.TestCase):
    def test_partition_and_source_components_are_deterministic(self) -> None:
        first = strongly_connected_components([
            [1, 1],
            [2, 0],
            [3],
            [2],
            [],
        ])
        repeated = strongly_connected_components([
            [1],
            [0, 2],
            [3],
            [2],
            [],
        ])

        self.assertEqual(first, repeated)
        self.assertEqual(first.components, ((0, 1), (2, 3), (4,)))
        self.assertEqual(first.component_by_region, (0, 0, 1, 1, 2))
        self.assertEqual(first.source_component_ids, (0, 2))

    def test_empty_graph_has_no_components(self) -> None:
        analysis = strongly_connected_components([])
        self.assertEqual(analysis.components, ())
        self.assertEqual(analysis.component_by_region, ())
        self.assertEqual(analysis.source_component_ids, ())

    def test_out_of_range_successor_is_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "outside the region inventory"):
            strongly_connected_components([[1]])

    def test_long_chain_does_not_depend_on_python_recursion_depth(self) -> None:
        region_count = 5000
        analysis = strongly_connected_components([
            [region + 1] if region + 1 < region_count else []
            for region in range(region_count)
        ])

        self.assertEqual(len(analysis.components), region_count)
        self.assertEqual(analysis.components[0], (0,))
        self.assertEqual(analysis.components[-1], (region_count - 1,))
        self.assertEqual(analysis.source_component_ids, (0,))


if __name__ == "__main__":
    unittest.main()
