from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from spaghetti_extractor.libraries.abi_catalog import (
    LIBRARY_ABI_CATALOG_CODEC_V3,
    build_catalog_search_index,
)
from spaghetti_extractor.libraries.abi_records import FunctionMatchV3
from spaghetti_extractor.libraries.signature_graph import (
    build_target_signature_graph,
)
from spaghetti_extractor.libraries.constellations import _optimal_assignment
from spaghetti_extractor.libraries.v4_matching import (
    solve_library_release_hypotheses,
)

from .library_fixture_support import (
    abi_profile,
    catalog,
    function_signature,
    machine_unit,
    procedure_candidates,
    write_machine,
)


def _match(
    target: str,
    catalog_function: str,
    *evidence: str,
) -> FunctionMatchV3:
    return FunctionMatchV3(
        target_function_id=target,
        catalog_function_id=catalog_function,
        evidence=tuple(sorted(evidence)),
        abi_status="incomplete",
    )


class MaximumWeightAssignmentTests(unittest.TestCase):
    def test_injective_assignment_is_maximal_and_input_order_independent(self) -> None:
        rows = (
            _match("target-a", "catalog-a", "exact_bytes"),
            _match(
                "target-a",
                "catalog-b",
                "exact_bytes",
                "normalized_bytes",
            ),
            _match(
                "target-b",
                "catalog-a",
                "exact_bytes",
                "normalized_bytes",
            ),
            _match("target-b", "catalog-b", "exact_bytes"),
        )

        expected = (
            ("target-a", "catalog-b"),
            ("target-b", "catalog-a"),
        )
        for supplied in (rows, tuple(reversed(rows)), (rows[2], rows[0], rows[3], rows[1])):
            selected, ambiguous = _optimal_assignment(supplied)
            self.assertEqual(
                tuple(
                    (row.target_function_id, row.catalog_function_id)
                    for row in selected
                ),
                expected,
            )
            self.assertEqual(ambiguous, set())

    def test_equal_score_assignments_are_deterministic_but_incomplete(self) -> None:
        rows = tuple(
            _match(target, function, "exact_bytes")
            for target in ("target-a", "target-b")
            for function in ("catalog-a", "catalog-b")
        )

        selected, ambiguous = _optimal_assignment(tuple(reversed(rows)))

        self.assertEqual(
            tuple(
                (row.target_function_id, row.catalog_function_id)
                for row in selected
            ),
            (("target-a", "catalog-a"), ("target-b", "catalog-b")),
        )
        self.assertEqual(ambiguous, {"target-a", "target-b"})


class V4IslandScopingTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _graph(self, units: list[dict[str, object]]):
        machine = write_machine(self.root, units)
        graph = build_target_signature_graph(
            machine,
            self.root / "target-signatures.json",
            procedure_candidates=procedure_candidates(
                machine,
                tuple(
                    (f"procedure:{unit['id']}", (str(unit["id"]),))
                    for unit in units
                ),
            ),
        )
        return machine, graph

    def _solve(self, graph, functions):
        catalog_path = self.root / "catalog.json"
        LIBRARY_ABI_CATALOG_CODEC_V3.write(catalog_path, catalog(tuple(functions)))
        index = build_catalog_search_index(
            catalog_path, self.root / "search-index.json"
        )
        with patch(
            "spaghetti_extractor.libraries.v4_matching.discover_static_span_matches",
            return_value=(),
        ):
            return solve_library_release_hypotheses(
                target_id="fixture-target",
                target_signatures=graph,
                search_index=index,
                target_pe=self.root / "fixture.exe",
                out_dir=self.root / "release-hypotheses",
            )

    def test_unrelated_target_issues_do_not_contaminate_matching_island(self) -> None:
        _machine, graph = self._graph(
            [
                machine_unit("matched", 0x1000, "a" * 64, abi_profile()),
                machine_unit("unrelated", 0x1010, "b" * 64, None),
            ]
        )
        matched = next(row for row in graph.functions if "matched" in row.unit_ids)
        releases = self._solve(
            graph,
            (
                function_signature(
                    function_id="catalog-matched",
                    release="1.0",
                    exact_hash=None,
                    unit_merkle_hash=matched.unit_merkle_sha256,
                ),
            ),
        )

        self.assertIn(
            "target_function_abi_missing", {issue.code for issue in graph.issues}
        )
        self.assertEqual(len(releases), 1)
        island = releases[0].islands[0]
        self.assertEqual(island.identity_status, "complete")
        self.assertNotIn(
            "target_function_abi_missing", {issue.code for issue in island.issues}
        )

    def test_equal_score_catalog_matches_remain_an_explicit_v4_ambiguity(self) -> None:
        _machine, graph = self._graph(
            [machine_unit("matched", 0x1000, "a" * 64, abi_profile())]
        )
        target = graph.functions[0]
        releases = self._solve(
            graph,
            tuple(
                function_signature(
                    function_id=function_id,
                    release="1.0",
                    exact_hash=None,
                    unit_merkle_hash=target.unit_merkle_sha256,
                )
                for function_id in ("catalog-a", "catalog-b")
            ),
        )

        island = releases[0].islands[0]
        self.assertEqual(island.identity_status, "incomplete")
        self.assertEqual(island.catalog_function_ids, ("catalog-a",))
        self.assertIn(
            "maximum_weight_assignment_ambiguous",
            {issue.code for issue in island.issues},
        )

    def test_archive_member_coretention_is_required_but_section_gc_is_not(self) -> None:
        _machine, graph = self._graph(
            [machine_unit("matched", 0x1000, "a" * 64, abi_profile())]
        )
        target = graph.functions[0]
        for retention_model, expected in (
            ("archive_member", True),
            ("section_gc", False),
        ):
            with self.subTest(retention_model=retention_model):
                case = self.root / retention_model
                case.mkdir()
                first = function_signature(
                    function_id=f"{retention_model}-matched",
                    release="1.0",
                    exact_hash=None,
                    unit_merkle_hash=target.unit_merkle_sha256,
                    member_id="shared.obj",
                    retention_model=retention_model,
                )
                second = function_signature(
                    function_id=f"{retention_model}-unmatched",
                    release="1.0",
                    exact_hash="f" * 64,
                    member_id="shared.obj",
                    retention_model=retention_model,
                )
                catalog_path = case / "catalog.json"
                LIBRARY_ABI_CATALOG_CODEC_V3.write(
                    catalog_path, catalog((first, second))
                )
                index = build_catalog_search_index(
                    catalog_path, case / "search-index.json"
                )
                with patch(
                    "spaghetti_extractor.libraries.v4_matching.discover_static_span_matches",
                    return_value=(),
                ):
                    release = solve_library_release_hypotheses(
                        target_id="fixture-target",
                        target_signatures=graph,
                        search_index=index,
                        target_pe=self.root / "fixture.exe",
                        out_dir=case / "release-hypotheses",
                    )[0]
                codes = {issue.code for issue in release.islands[0].issues}
                self.assertEqual("retained_member_functions_unmatched" in codes, expected)


if __name__ == "__main__":
    unittest.main()
