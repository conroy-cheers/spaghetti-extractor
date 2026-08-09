from __future__ import annotations

import copy
import unittest

from spaghetti_extractor.hybrid_diagnostics_v2 import (
    HYBRID_BLOCKER_V2_ID_PREFIX,
    HYBRID_DIAGNOSTICS_V2_FORMAT,
    HybridDiagnosticsV2Error,
    build_hybrid_diagnostics_v2,
    make_blocker_record,
)


def _missing(
    category: str,
    *,
    blocked_by: tuple[str, ...] = (),
    frontiers: dict | None = None,
    details: dict | None = None,
) -> dict:
    return make_blocker_record(
        status="incomplete",
        category=category,
        message=f"evidence for {category} is missing",
        next_action=f"supply evidence for {category}",
        blocked_by=blocked_by,
        frontiers=frontiers,
        details=details,
    )


class HybridDiagnosticsV2Tests(unittest.TestCase):
    def test_separates_primary_repairs_and_retains_consequence_detail(self) -> None:
        scc = _missing(
            "control_summary",
            frontiers={
                "scc": [{"id": "scc:recursive-parser", "members": ["a", "b"]}]
            },
        )
        environment = _missing(
            "runtime_contract",
            frontiers={
                "environment": [{
                    "id": "environment:kernel32!ReadFile",
                    "dll": "kernel32.dll",
                    "symbol": "ReadFile",
                }]
            },
        )
        isa = _missing(
            "instruction_semantics",
            frontiers={
                "isa": [{
                    "id": "isa:x87-fcomip",
                    "mnemonic": "fcomip",
                    "operand_form": "st0-sti",
                }]
            },
        )
        candidate = _missing(
            "candidate_generation",
            blocked_by=(environment["id"], scc["id"]),
            frontiers={"isa": ["isa:consequence-only"]},
            details={
                "unit_id": "unit:entry",
                "trace": [{"event": "external_call", "index": 7}],
            },
        )
        package = _missing(
            "package_readiness",
            blocked_by=(candidate["id"],),
            details={"artifact": "candidate.exe", "produced": False},
        )

        records = [scc, environment, isa, candidate, package]
        report = build_hybrid_diagnostics_v2(reversed(records))

        self.assertEqual(report["format"], HYBRID_DIAGNOSTICS_V2_FORMAT)
        self.assertEqual(report["status"], "incomplete")
        self.assertEqual(report["counts"], {
            "blockers": 5,
            "incomplete_blockers": 5,
            "violated_blockers": 0,
            "primary_blockers": 3,
            "dependent_consequences": 2,
            "repair_tasks": 3,
            "integrity_violations": 0,
        })
        self.assertEqual(
            report["repair_task_ids"],
            sorted([scc["id"], environment["id"], isa["id"]]),
        )
        self.assertEqual(
            report["dependent_consequence_ids"],
            sorted([candidate["id"], package["id"]]),
        )

        by_id = {item["id"]: item for item in report["blockers"]}
        self.assertEqual(by_id[candidate["id"]]["details"], candidate["details"])
        self.assertEqual(by_id[package["id"]]["details"], package["details"])
        closure = {
            item["blocker_id"]: item["primary_blocker_ids"]
            for item in report["dependency_closure"]
        }
        expected_roots = sorted([environment["id"], scc["id"]])
        self.assertEqual(closure[candidate["id"]], expected_roots)
        self.assertEqual(closure[package["id"]], expected_roots)

        category_counts = {
            item["category"]: item["repair_tasks"]
            for item in report["primary_categories"]
        }
        self.assertEqual(category_counts, {
            "control_summary": 1,
            "instruction_semantics": 1,
            "runtime_contract": 1,
        })
        self.assertEqual(
            report["frontiers"]["scc"][0]["frontier"]["members"],
            ["a", "b"],
        )
        self.assertEqual(
            report["frontiers"]["environment"][0]["frontier"]["symbol"],
            "ReadFile",
        )
        self.assertEqual(
            report["frontiers"]["isa"][0]["frontier"]["mnemonic"],
            "fcomip",
        )
        self.assertNotIn(
            "isa:consequence-only",
            {
                item["frontier"]["id"]
                for item in report["frontiers"]["isa"]
            },
        )
        self.assertEqual(report, build_hybrid_diagnostics_v2(records))

    def test_no_blockers_is_complete(self) -> None:
        report = build_hybrid_diagnostics_v2([])

        self.assertEqual(report["status"], "complete")
        self.assertEqual(report["counts"]["repair_tasks"], 0)
        self.assertEqual(report["frontiers"], {
            "scc": [],
            "environment": [],
            "isa": [],
        })

    def test_missing_dependency_is_a_violated_graph_not_missing_evidence(self) -> None:
        missing_id = HYBRID_BLOCKER_V2_ID_PREFIX + "0" * 64
        blocker = _missing("candidate_generation", blocked_by=(missing_id,))

        report = build_hybrid_diagnostics_v2([blocker])

        self.assertEqual(report["status"], "violated")
        self.assertEqual(report["counts"]["incomplete_blockers"], 1)
        self.assertEqual(report["counts"]["violated_blockers"], 0)
        self.assertEqual(
            {item["code"] for item in report["integrity_violations"]},
            {"missing_dependency"},
        )

    def test_cycle_and_content_corruption_are_violations(self) -> None:
        blocker = _missing("recursive_summary")
        blocker["blocked_by"] = [blocker["id"]]

        report = build_hybrid_diagnostics_v2([blocker])

        self.assertEqual(report["status"], "violated")
        self.assertEqual(
            {item["code"] for item in report["integrity_violations"]},
            {"blocker_id_mismatch", "dependency_cycle"},
        )

    def test_converging_dependency_dag_is_not_a_cycle(self) -> None:
        primary = _missing("global_slot_invariant")
        left = _missing(
            "indirect_exit_certificate",
            blocked_by=(primary["id"],),
        )
        right = _missing(
            "indirect_exit_certificate",
            blocked_by=(primary["id"],),
            details={"site": "right"},
        )
        consequence = _missing(
            "rooted_reachability",
            blocked_by=(left["id"], right["id"]),
        )

        report = build_hybrid_diagnostics_v2(
            [consequence, right, primary, left]
        )

        self.assertEqual(report["status"], "incomplete")
        self.assertEqual(report["integrity_violations"], [])
        self.assertEqual(report["repair_task_ids"], [primary["id"]])
        closure = {
            item["blocker_id"]: item["primary_blocker_ids"]
            for item in report["dependency_closure"]
        }
        self.assertEqual(closure[consequence["id"]], [primary["id"]])

    def test_duplicate_id_is_corruption_not_an_extra_repair_task(self) -> None:
        blocker = _missing("runtime_contract")

        report = build_hybrid_diagnostics_v2([blocker, copy.deepcopy(blocker)])

        self.assertEqual(report["status"], "violated")
        self.assertEqual(report["counts"]["blockers"], 2)
        self.assertEqual(report["counts"]["repair_tasks"], 1)
        self.assertEqual(
            {item["code"] for item in report["integrity_violations"]},
            {"duplicate_blocker_id"},
        )

    def test_detail_mutation_and_frontier_contradiction_are_violated(self) -> None:
        first = _missing(
            "control_summary",
            frontiers={"scc": [{"id": "scc:shared", "members": ["a"]}]},
            details={"revision": 1},
        )
        corrupted = copy.deepcopy(first)
        corrupted["details"]["revision"] = 2
        second = _missing(
            "control_summary",
            frontiers={"scc": [{"id": "scc:shared", "members": ["b"]}]},
        )

        report = build_hybrid_diagnostics_v2([corrupted, second])

        self.assertEqual(report["status"], "violated")
        self.assertEqual(
            {item["code"] for item in report["integrity_violations"]},
            {"blocker_id_mismatch", "frontier_definition_conflict"},
        )
        self.assertEqual(report["counts"]["blockers"], 2)

    def test_explicit_contradiction_is_violated_and_schema_is_fail_closed(self) -> None:
        contradiction = make_blocker_record(
            status="violated",
            category="evidence_contradiction",
            message="two bound manifests disagree",
            next_action="regenerate the stale manifest",
            details={"expected": "a", "observed": "b"},
        )

        report = build_hybrid_diagnostics_v2([contradiction])

        self.assertEqual(report["status"], "violated")
        self.assertEqual(report["counts"]["violated_blockers"], 1)
        self.assertEqual(report["integrity_violations"], [])
        with self.assertRaisesRegex(
            HybridDiagnosticsV2Error, "incomplete or violated"
        ):
            make_blocker_record(
                status="complete",
                category="bad_status",
                message="this is not a blocker status",
                next_action="repair the producer",
            )


if __name__ == "__main__":
    unittest.main()
