from __future__ import annotations

import time
import unittest
from dataclasses import replace

from spaghetti_extractor.testkit import ImpactIndex, TestRecord, build_suite_plan


def _test(
    index: int,
    *,
    tier: str = "unit",
    target: str | None = None,
    dependencies: tuple[str, ...] = (),
    shard: str | None = None,
) -> TestRecord:
    path = f"tests/{tier}/test_{index:04d}.py"
    return TestRecord(
        id=path.removesuffix(".py"),
        path=path,
        module=f"tests.{tier}.test_{index:04d}",
        tier=tier,
        subsystem=target or tier,
        capabilities=() if target is None else (f"target:{target}",),
        target=target,
        dependencies=(),
        dependency_paths=dependencies,
        fixtures=(),
        resources=(),
        sha256=f"{index:064x}",
        input_sha256=f"{index + 1:064x}",
        shard=shard or f"pure-{index % 32:02d}",
    )


class TestPlanningTests(unittest.TestCase):
    def test_affected_selects_smoke_and_only_dependency_reachable_tests(self) -> None:
        index = ImpactIndex(
            repository=".",
            modules=(),
            tests=(
                _test(0, tier="smoke", shard="smoke"),
                _test(1, dependencies=("src/spaghetti_extractor/changed.py",)),
                _test(2, dependencies=("src/spaghetti_extractor/other.py",)),
            ),
        )

        plan = build_suite_plan(index, mode="affected", changed_paths=("src/spaghetti_extractor/changed.py",))

        self.assertEqual(plan.selected_tests, (index.tests[0].id, index.tests[1].id))
        self.assertNotIn(index.tests[2].id, plan.selected_tests)

    def test_full_excludes_target_and_benchmark_while_target_includes_smoke(self) -> None:
        rows = (
            _test(0, tier="smoke", shard="smoke"),
            _test(1),
            _test(2, tier="target", target="dxball", shard="target-dxball-00"),
            _test(3, tier="benchmark", shard="benchmark-a"),
        )
        index = ImpactIndex(repository=".", modules=(), tests=rows)

        full = build_suite_plan(index, mode="full")
        target = build_suite_plan(index, mode="target", target="dxball")

        self.assertEqual(full.selected_tests, (rows[0].id, rows[1].id))
        self.assertEqual(target.selected_tests, (rows[0].id, rows[2].id))

        catalog = build_suite_plan(index, mode="catalog")
        self.assertEqual(catalog.selected_tests, tuple(row.id for row in rows))

    def test_two_thousand_test_planning_stays_below_two_seconds(self) -> None:
        index = ImpactIndex(repository=".", modules=(), tests=tuple(_test(value) for value in range(2000)))

        started = time.perf_counter()
        first = build_suite_plan(index, mode="full")
        elapsed = time.perf_counter() - started
        second = build_suite_plan(index, mode="full")

        self.assertLess(elapsed, 2.0)
        self.assertEqual(first.as_dict(), second.as_dict())
        self.assertEqual(len(first.selected_tests), 2000)

    def test_test_framework_change_selects_complete_generic_gate(self) -> None:
        rows = (
            _test(0, tier="smoke", shard="smoke"),
            _test(1, dependencies=("src/spaghetti_extractor/one.py",)),
            _test(2, dependencies=("src/spaghetti_extractor/two.py",)),
        )
        index = ImpactIndex(repository=".", modules=(), tests=rows)

        plan = build_suite_plan(
            index,
            mode="affected",
            changed_paths=("src/spaghetti_extractor/testkit/discovery.py",),
        )

        self.assertEqual(set(plan.selected_tests), {row.id for row in rows})

    def test_nix_test_change_selects_only_its_owned_check(self) -> None:
        rows = (
            _test(0, tier="smoke", shard="smoke"),
            _test(1),
        )
        index = ImpactIndex(repository=".", modules=(), tests=rows)

        plan = build_suite_plan(
            index,
            mode="affected",
            changed_paths=("nix/tests/analysis-v3-machine-ir-input.nix",),
        )

        self.assertEqual(plan.selected_tests, (rows[0].id,))
        self.assertEqual(plan.nix_checks, ("analysis-v3-machine-ir-input",))

    def test_directory_resource_suppresses_redundant_read_only_children(self) -> None:
        row = _test(1, dependencies=("docs/README.md",))
        row = replace(row, resources=("docs",))
        index = ImpactIndex(repository=".", modules=(), tests=(row,))

        plan = build_suite_plan(index, mode="full")

        self.assertEqual(plan.shards[0].files, ("docs", row.path))


if __name__ == "__main__":
    unittest.main()
