import copy
import unittest

from spaghetti_extractor.relational.analyses.dataflow import (
    parse_stable_dataflow_graph,
    stable_dataflow_graph,
    strongly_connected_components,
)
from spaghetti_extractor.relational.analyses.dataflow_schedule import (
    stable_dataflow_schedule,
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
        self.assertEqual(first.predecessor_component_ids, ((), (0,), ()))
        self.assertEqual(first.successor_component_ids, ((1,), (), ()))
        self.assertEqual(first.source_component_ids, (0, 2))
        self.assertEqual(first.topological_component_ids, (0, 1, 2))

    def test_empty_graph_has_no_components(self) -> None:
        analysis = strongly_connected_components([])
        self.assertEqual(analysis.components, ())
        self.assertEqual(analysis.component_by_region, ())
        self.assertEqual(analysis.predecessor_component_ids, ())
        self.assertEqual(analysis.successor_component_ids, ())
        self.assertEqual(analysis.source_component_ids, ())
        self.assertEqual(analysis.topological_component_ids, ())

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

    def test_stable_graph_is_independent_of_region_inventory_order(self) -> None:
        digest_a = "a" * 64
        digest_b = "b" * 64
        digest_c = "c" * 64
        first = stable_dataflow_graph(
            [[1], [0, 2], []],
            region_ids=["entry", "loop", "exit"],
            transfer_semantics_sha256=[digest_a, digest_b, digest_c],
        )
        reordered = stable_dataflow_graph(
            [[], [2], [1, 0]],
            region_ids=["exit", "entry", "loop"],
            transfer_semantics_sha256=[digest_c, digest_a, digest_b],
        )

        first_by_regions = {
            component.region_ids: component for component in first.components
        }
        reordered_by_regions = {
            component.region_ids: component for component in reordered.components
        }
        self.assertEqual(first.graph_sha256, reordered.graph_sha256)
        self.assertEqual(first.topological_pack_ids, reordered.topological_pack_ids)
        self.assertEqual(first_by_regions.keys(), reordered_by_regions.keys())
        for region_ids, component in first_by_regions.items():
            repeated = reordered_by_regions[region_ids]
            self.assertEqual(component.id, repeated.id)
            self.assertEqual(
                component.local_semantics_sha256,
                repeated.local_semantics_sha256,
            )
            self.assertEqual(component.boundary_sha256, repeated.boundary_sha256)
        self.assertEqual(
            {
                pack.id: (pack.component_ids, pack.predecessor_ids)
                for pack in first.packs
            },
            {
                pack.id: (pack.component_ids, pack.predecessor_ids)
                for pack in reordered.packs
            },
        )

        first_schedule = stable_dataflow_schedule(first)
        reordered_schedule = stable_dataflow_schedule(reordered)
        self.assertEqual(
            first_schedule.topological_pack_ids,
            reordered_schedule.topological_pack_ids,
        )
        self.assertEqual(
            {
                pack.id: (
                    pack.component_ids,
                    pack.predecessor_ids,
                    pack.local_semantics_sha256,
                )
                for pack in first_schedule.packs
            },
            {
                pack.id: (
                    pack.component_ids,
                    pack.predecessor_ids,
                    pack.local_semantics_sha256,
                )
                for pack in reordered_schedule.packs
            },
        )

    def test_unrelated_transfer_change_invalidates_only_its_component(self) -> None:
        baseline = stable_dataflow_graph(
            [[1], [], []],
            region_ids=["entry", "exit", "detached"],
            transfer_semantics_sha256=["a" * 64, "b" * 64, "c" * 64],
        )
        changed = stable_dataflow_graph(
            [[1], [], []],
            region_ids=["entry", "exit", "detached"],
            transfer_semantics_sha256=["a" * 64, "b" * 64, "d" * 64],
        )
        baseline_by_regions = {
            component.region_ids: component for component in baseline.components
        }
        changed_by_regions = {
            component.region_ids: component for component in changed.components
        }

        self.assertEqual(
            baseline_by_regions[("entry",)].local_semantics_sha256,
            changed_by_regions[("entry",)].local_semantics_sha256,
        )
        self.assertEqual(
            baseline_by_regions[("exit",)].local_semantics_sha256,
            changed_by_regions[("exit",)].local_semantics_sha256,
        )
        self.assertNotEqual(
            baseline_by_regions[("detached",)].local_semantics_sha256,
            changed_by_regions[("detached",)].local_semantics_sha256,
        )
        baseline_packs = {pack.id: pack for pack in baseline.packs}
        changed_packs = {pack.id: pack for pack in changed.packs}
        self.assertEqual(baseline_packs.keys(), changed_packs.keys())
        changed_pack_ids = {
            pack_id
            for pack_id in baseline_packs
            if (
                baseline_packs[pack_id].local_semantics_sha256
                != changed_packs[pack_id].local_semantics_sha256
            )
        }
        self.assertEqual(len(changed_pack_ids), 1)
        changed_pack = changed_packs[changed_pack_ids.pop()]
        detached_component_id = changed_by_regions[("detached",)].id
        self.assertIn(detached_component_id, changed_pack.component_ids)

    def test_packs_are_an_exact_topological_component_partition(self) -> None:
        graph = stable_dataflow_graph(
            [[1, 2], [3], [3], [4], [3]],
            region_ids=[f"region-{index}" for index in range(5)],
            transfer_semantics_sha256=[f"{index + 1:064x}" for index in range(5)],
        )
        packed_components = [
            component_id
            for pack in graph.packs
            for component_id in pack.component_ids
        ]
        self.assertEqual(graph.region_count, 5)
        self.assertCountEqual(
            packed_components,
            [component.id for component in graph.components],
        )
        self.assertEqual(len(packed_components), len(set(packed_components)))
        pack_position = {
            pack_id: position
            for position, pack_id in enumerate(graph.topological_pack_ids)
        }
        for pack in graph.packs:
            for predecessor_id in pack.predecessor_ids:
                self.assertLess(
                    pack_position[predecessor_id], pack_position[pack.id]
                )

    def test_linear_components_share_bounded_solver_packs(self) -> None:
        region_count = 257
        graph = stable_dataflow_graph(
            [
                [index + 1] if index + 1 < region_count else []
                for index in range(region_count)
            ],
            region_ids=[f"region-{index}" for index in range(region_count)],
            transfer_semantics_sha256=[
                f"{index + 1:064x}" for index in range(region_count)
            ],
        )

        schedule = stable_dataflow_schedule(graph)
        self.assertEqual(len(graph.components), region_count)
        self.assertLessEqual(len(schedule.packs), 6)
        self.assertTrue(all(
            pack.region_count <= 128 for pack in schedule.packs
        ))
        self.assertEqual(
            sum(pack.region_count for pack in schedule.packs), region_count
        )
        reparsed = parse_stable_dataflow_graph(graph.to_payload())
        self.assertEqual(reparsed, graph)

    def test_large_scc_is_isolated_and_pack_resources_use_region_count(self) -> None:
        large_count = 65
        graph = stable_dataflow_graph(
            [
                [((index + 1) % large_count)]
                for index in range(large_count)
            ] + [[] for _ in range(80)],
            region_ids=[f"region-{index}" for index in range(large_count + 80)],
            transfer_semantics_sha256=[
                f"{index + 1:064x}" for index in range(large_count + 80)
            ],
        )
        large_component = next(
            component
            for component in graph.components
            if len(component.region_ids) == large_count
        )
        large_pack = next(
            pack for pack in graph.packs if large_component.id in pack.component_ids
        )
        self.assertEqual(large_pack.component_ids, (large_component.id,))
        self.assertEqual(large_pack.resource_class, "medium")
        self.assertLess(len(graph.packs), len(graph.components))

    def test_stable_graph_rejects_ambiguous_or_malformed_identities(self) -> None:
        with self.assertRaisesRegex(ValueError, "must be unique"):
            stable_dataflow_graph(
                [[], []],
                region_ids=["same", "same"],
                transfer_semantics_sha256=["a" * 64, "b" * 64],
            )
        with self.assertRaisesRegex(ValueError, "SHA-256"):
            stable_dataflow_graph(
                [[]],
                region_ids=["region"],
                transfer_semantics_sha256=["not-a-digest"],
            )

    def test_serialized_graph_is_strictly_reconstructed(self) -> None:
        graph = stable_dataflow_graph(
            [[1], [2], [1]],
            region_ids=["entry", "loop", "backedge"],
            transfer_semantics_sha256=["a" * 64, "b" * 64, "c" * 64],
        )
        parsed = parse_stable_dataflow_graph(graph.to_payload())
        self.assertEqual(parsed, graph)

        tampered = copy.deepcopy(graph.to_payload())
        tampered["packs"][0]["local_semantics_sha256"] = "d" * 64
        with self.assertRaisesRegex(ValueError, "semantics"):
            parse_stable_dataflow_graph(tampered)

        tampered = copy.deepcopy(graph.to_payload())
        tampered["topological_component_ids"].reverse()
        with self.assertRaisesRegex(ValueError, "topological"):
            parse_stable_dataflow_graph(tampered)


if __name__ == "__main__":
    unittest.main()
