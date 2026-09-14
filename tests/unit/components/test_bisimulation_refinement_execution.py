from __future__ import annotations

import hashlib
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from spaghetti_extractor.components.bisimulation_execution import (
    _cbmc_cover_queries,
    _run_bisimulation_obligation,
    _run_cover_queries,
    _run_partitioned_properties,
)
from tests.unit.components.test_inductive_relation import _interface, _operation


def _task(root: Path) -> dict[str, object]:
    task = {
        "compile_command": ["goto-cc", "property"],
        "cbmc": Path("cbmc"),
        "property_checker_command": {
            "backend": "cbmc",
            "goto_model_role": "shared_partitioned_property_queries",
            "strategy": (
                "inventory_function_grouped_paired_language_safety_with_entry_unwinding_reuse_v11"
            ),
            "maximum_parallel_queries": 4,
            "discovery_arguments": [
                "--json-ui",
                "--function",
                "$PROPERTY_FUNCTION",
                "--reachability-slice-fb",
                "--show-properties",
            ],
            "language_safety_discovery_arguments": [
                "--json-ui",
                "--function",
                "$PROPERTY_FUNCTION",
                "--no-assertions",
                "--unwind",
                "2",
                "--reachability-slice-fb",
                "--show-properties",
            ],
            "language_safety_baseline_discovery_arguments": [
                "--json-ui",
                "--function",
                "$PROPERTY_FUNCTION",
                "--no-standard-checks",
                "--no-assertions",
                "--unwind",
                "2",
                "--show-properties",
            ],
            "loop_discovery_arguments": [
                "--json-ui",
                "--function",
                "$PROPERTY_FUNCTION",
                "--show-loops",
            ],
            "assertion_arguments": [
                "--json-ui",
                "--function",
                "$PROPERTY_FUNCTION",
                "--no-standard-checks",
                "--property",
                "$PROPERTY_ID",
            ],
            "language_safety_queries": [
                {
                    "partition": "bounds",
                    "classes": ["array bounds"],
                    "arguments": [
                        "--json-ui",
                        "--function",
                        "$PROPERTY_FUNCTION",
                    ],
                },
                {
                    "partition": "pointer",
                    "classes": [
                        "pointer",
                        "pointer arithmetic",
                        "pointer dereference",
                        "pointer primitives",
                    ],
                    "arguments": [
                        "--json-ui",
                        "--function",
                        "$PROPERTY_FUNCTION",
                    ],
                },
                {
                    "partition": "division",
                    "classes": ["division-by-zero"],
                    "arguments": [
                        "--json-ui",
                        "--function",
                        "$PROPERTY_FUNCTION",
                    ],
                },
                {
                    "partition": "signed_overflow",
                    "classes": ["overflow"],
                    "arguments": [
                        "--json-ui",
                        "--function",
                        "$PROPERTY_FUNCTION",
                    ],
                },
                {
                    "partition": "undefined_shift",
                    "classes": ["undefined-shift"],
                    "arguments": [
                        "--json-ui",
                        "--function",
                        "$PROPERTY_FUNCTION",
                    ],
                },
                {
                    "partition": "unwinding",
                    "classes": ["unwind"],
                    "arguments": [
                        "--json-ui",
                        "--function",
                        "$PROPERTY_FUNCTION",
                    ],
                },
            ],
        },
        "cover_queries": [
            {
                "command": ["cbmc", "cover"],
                "expected_functions": ["spx_check"],
            }
        ],
        "goto_model": root / "model.goto",
        "proof_function": "spx_check",
        "required_assertion_descriptions": ["ordinary property"],
        "witness_functions": ["spx_check"],
        "proof_model_sha256": "1" * 64,
        "nonvacuity_proof_model_sha256": "1" * 64,
        "property_checker_command_sha256": "3" * 64,
        "nonvacuity_checker_command_sha256": "4" * 64,
        "shard_id": "run:entry",
        "operation_id": "run",
        "obligation_id": "entry",
    }
    task["property_checker_command"]["assertion_arguments"].append("--unwinding-assertions")
    task["property_checker_command"]["entry_assertion_arguments"] = [
        "--no-unwinding-assertions" if item == "--unwinding-assertions" else item
        for item in task["property_checker_command"]["assertion_arguments"]]
    for query in task["property_checker_command"]["language_safety_queries"]:
        query["arguments"] += ["--no-assertions", "--unwind", "2", "--slice-formula"]
        if query["partition"] == "unwinding":
            query["arguments"] += ["--no-standard-checks", "--unwinding-assertions"]
        else:
            query["arguments"] += ["--no-unwinding-assertions", "--reachability-slice-fb",
                                   "$PROPERTY_IDS"]
    return task



class BisimulationRefinementExecutionTests(unittest.TestCase):
    def test_required_assertion_manifest_fails_closed_on_missing_or_duplicate_goal(
        self,
    ) -> None:
        base_assertion = {
            "property_id": "proof.assertion.1",
            "description": "required semantic goal",
            "source_function": "proof",
        }
        for assertions in (
            [{
                "property_id": "proof.assertion.0",
                "description": "unrelated helper assertion",
                "source_function": "proof",
            }],
            [
                base_assertion,
                {
                    **base_assertion,
                    "property_id": "proof.assertion.2",
                },
            ],
        ):
            with (
                self.subTest(assertions=assertions),
                patch(
                    "spaghetti_extractor.components.bisimulation_execution.discover_cbmc_assertions",
                    return_value={
                        "status": "satisfied",
                        "code": "cbmc_assertion_inventory",
                        "properties": len(assertions),
                        "property_ids": [
                            assertion["property_id"] for assertion in assertions
                        ],
                        "assertions": assertions,
                        "output_sha256": "9" * 64,
                    },
                ),
                patch(
                    "spaghetti_extractor.components.bisimulation_execution.run_cbmc_properties"
                ) as run,
            ):
                result = _run_partitioned_properties(
                    cbmc=Path("cbmc"),
                    goto_model=Path("model.goto"),
                    command=_task(Path("."))["property_checker_command"],
                    proof_function="proof",
                    required_assertion_descriptions=["required semantic goal"],
                    timeout_seconds=60,
                )

            self.assertEqual(result["status"], "incomplete")
            self.assertEqual(
                result["code"], "cbmc_required_assertion_inventory_mismatch"
            )
            self.assertIn("required semantic goal", result["detail"])
            self.assertIn(f"({0 if len(assertions) == 1 else 2} sites)", result["detail"])
            run.assert_not_called()

    def test_exit_control_counterexample_query_runs_before_other_assertions(
        self,
    ) -> None:
        assertions = [
            {
                "property_id": "proof.assertion.1",
                "description": "ordinary helper assertion",
                "source_function": "helper",
            },
            {
                "property_id": "proof.assertion.2",
                "description": "spx-bisimulation-exit-control:run:proof",
                "source_function": "proof",
            },
            {
                "property_id": "proof.assertion.3",
                "description": "spx-bisimulation-exit-observable:run:value",
                "source_function": "proof",
            },
        ]
        observed: list[str] = []

        def result_for(*, command: list[str], timeout_seconds: int) -> dict[str, object]:
            del timeout_seconds
            if "source.safety.1" in command:
                return {
                    "status": "satisfied",
                    "code": "cbmc_properties_satisfied",
                    "properties": 7,
                    "property_ids": ["source.safety.1"],
                    "output_sha256": "1" * 64,
                }
            property_id = command[command.index("--property") + 1]
            observed.append(property_id)
            return {
                "status": "satisfied",
                "code": "cbmc_properties_satisfied",
                "properties": 2,
                "property_ids": [property_id, "source.unwind.1"],
                "output_sha256": property_id[-1] * 64,
            }

        command = _task(Path("."))["property_checker_command"]
        with (
            patch(
                "spaghetti_extractor.components.bisimulation_execution.discover_cbmc_assertions",
                return_value={
                    "status": "satisfied",
                    "code": "cbmc_assertion_inventory",
                    "properties": 3,
                    "property_ids": [item["property_id"] for item in assertions],
                    "assertions": assertions,
                    "output_sha256": "9" * 64,
                },
            ) as discover,
            patch(
                "spaghetti_extractor.components.bisimulation_execution.run_cbmc_properties",
                side_effect=result_for,
            ) as run,
            patch(
                "spaghetti_extractor.components.bisimulation_execution.discover_cbmc_safety_properties",
                return_value={
                    "status": "satisfied",
                    "code": "cbmc_safety_inventory",
                    "properties": 1,
                    "property_ids": ["source.safety.1"],
                    "safety_properties": [{
                        "property_id": "source.safety.1",
                        "class": "array bounds",
                        "description": "source bound",
                        "source_function": "proof",
                    }],
                    "output_sha256": "8" * 64,
                },
            ),
            patch(
                "spaghetti_extractor.components.bisimulation_execution.discover_cbmc_loops",
                return_value={
                    "status": "satisfied",
                    "code": "cbmc_loop_inventory",
                    "loops": [],
                    "unwinding_property_ids": [],
                    "output_sha256": "7" * 64,
                },
            ),
        ):
            result = _run_partitioned_properties(
                cbmc=Path("cbmc"),
                goto_model=Path("model.goto"),
                command=command,
                proof_function="proof",
                required_assertion_descriptions=["ordinary helper assertion"],
                timeout_seconds=60,
            )

        self.assertEqual(
            discover.call_args.kwargs["command"],
            [
                "cbmc",
                "model.goto",
                "--json-ui",
                "--function",
                "proof",
                "--reachability-slice-fb",
                "--show-properties",
            ],
        )
        self.assertEqual(result["status"], "satisfied")
        # No unwind receipt exists for this empty loop inventory. In particular,
        # the entry query must retain checks for dynamically discovered recursion.
        for call in run.mock_calls:
            if "--property" in call.kwargs["command"] and "--no-assertions" not in call.kwargs["command"]:
                self.assertIn("--unwinding-assertions", call.kwargs["command"])
        safety_command = next(
            call.kwargs["command"]
            for call in run.mock_calls
            if "source.safety.1" in call.kwargs["command"]
        )
        self.assertEqual(
            safety_command[safety_command.index("--function") + 1],
            "proof",
        )
        self.assertEqual(result["property_ids"], [
            "proof.assertion.1",
            "proof.assertion.2",
            "proof.assertion.3",
        ])
        self.assertEqual(observed[0], "proof.assertion.2")
        self.assertEqual(
            [
                item.get("property_id")
                for item in result["partitioned_evidence"]["queries"]
                if item["kind"] == "authored_assertion"
            ],
            ["proof.assertion.2", "proof.assertion.3", "proof.assertion.1"],
        )

    def test_nonvacuity_query_inventory_selects_scalable_strategy(self) -> None:
        one = _cbmc_cover_queries(
            cbmc=Path("/tools/cbmc"),
            goto_model=Path("model.goto"),
            proof_function="spx_check",
            witness_functions=["spx_witness"],
        )
        self.assertEqual(len(one), 1)
        self.assertEqual(one[0]["expected_functions"], ["spx_witness"])
        self.assertIn("spx_witness.coverage.1", one[0]["command"])
        self.assertEqual(
            one[0]["command"][-2:],
            ["--reachability-slice-fb", "--slice-formula"],
        )

        completion = _cbmc_cover_queries(
            cbmc=Path("/tools/cbmc"),
            goto_model=Path("model.goto"),
            proof_function="spx_check",
            witness_functions=["spx_check"],
        )
        self.assertEqual(
            completion[0]["command"][-2:],
            ["--reachability-slice-fb", "--slice-formula"],
        )

        two = _cbmc_cover_queries(
            cbmc=Path("/tools/cbmc"),
            goto_model=Path("model.goto"),
            proof_function="spx_check",
            witness_functions=["spx_route_0", "spx_route_1"],
        )
        self.assertEqual(len(two), 2)
        self.assertEqual(
            [query["expected_functions"] for query in two],
            [["spx_route_0"], ["spx_route_1"]],
        )
        self.assertTrue(all(
            query["command"][-2:]
            == ["--reachability-slice-fb", "--slice-formula"]
            for query in two
        ))

        mixed = _cbmc_cover_queries(
            cbmc=Path("/tools/cbmc"),
            goto_model=Path("model.goto"),
            proof_function="spx_check",
            witness_functions=["spx_check", "spx_selected_target"],
        )
        self.assertTrue(all(
            query["command"][-2:]
            == ["--reachability-slice-fb", "--slice-formula"]
            for query in mixed
        ))

        aggregate = _cbmc_cover_queries(
            cbmc=Path("/tools/cbmc"),
            goto_model=Path("model.goto"),
            proof_function="spx_check",
            witness_functions=["spx_route_0", "spx_route_1", "spx_route_2"],
        )
        self.assertEqual(len(aggregate), 1)
        self.assertEqual(
            aggregate[0]["command"][-2:],
            ["--reachability-slice-fb", "--slice-formula"],
        )

    def test_nonvacuity_query_results_are_aggregated_fail_closed(self) -> None:
        queries = [
            {"command": ["cbmc", "a"], "expected_functions": ["a"]},
            {"command": ["cbmc", "b"], "expected_functions": ["b"]},
        ]
        satisfied = {
            "status": "satisfied",
            "code": "cbmc_nonvacuity_witness",
            "properties": 1,
            "property_ids": ["a.coverage.1"],
            "witnessed_functions": ["a"],
            "output_sha256": "1" * 64,
        }
        failed = {
            "status": "incomplete",
            "code": "cbmc_nonvacuity_timeout",
            "detail": "exceeded 60 seconds",
            "output_sha256": "2" * 64,
        }
        with patch(
            "spaghetti_extractor.components.bisimulation_execution.run_cbmc_cover",
            side_effect=[
                satisfied,
                {
                    **satisfied,
                    "property_ids": ["b.coverage.1"],
                    "witnessed_functions": ["b"],
                },
            ],
        ):
            success = _run_cover_queries(queries, timeout_seconds=60)
        self.assertEqual(success["status"], "satisfied")
        self.assertEqual(success["properties"], 2)
        self.assertEqual(len(success["queries"]), 2)
        self.assertEqual(success["expected_functions"], ["a", "b"])
        self.assertEqual(success["witnessed_functions"], ["a", "b"])

        with patch(
            "spaghetti_extractor.components.bisimulation_execution.run_cbmc_cover",
            side_effect=[satisfied, failed],
        ):
            failure = _run_cover_queries(queries, timeout_seconds=60)
        self.assertEqual(failure["status"], "incomplete")
        self.assertEqual(failure["code"], "cbmc_nonvacuity_timeout")
        self.assertEqual(len(failure["output_sha256"]), 64)
        self.assertEqual(failure["queries"][1]["detail"], "exceeded 60 seconds")

    def test_property_counterexample_skips_the_relation_query(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "model.goto").write_bytes(b"property")
            property_violation = {
                "status": "violated",
                "code": "cbmc_property_failed",
                "output_sha256": "6" * 64,
            }
            with (
                patch(
                    "spaghetti_extractor.components.bisimulation_execution._run_compile",
                    return_value=None,
                ),
                patch(
                    "spaghetti_extractor.components.bisimulation_execution.discover_cbmc_assertions",
                    return_value={
                        "status": "satisfied",
                        "code": "cbmc_assertion_inventory",
                        "properties": 1,
                        "property_ids": ["spx_check.assertion.1"],
                        "assertions": [
                            {
                                "property_id": "spx_check.assertion.1",
                                "description": "ordinary property",
                                "source_function": "spx_check",
                            }
                        ],
                        "output_sha256": "7" * 64,
                    },
                ),
                patch(
                    "spaghetti_extractor.components.bisimulation_execution.run_cbmc_properties",
                    return_value=property_violation,
                ),
                patch(
                    "spaghetti_extractor.components.bisimulation_execution.discover_cbmc_safety_properties",
                    return_value={
                        "status": "satisfied",
                        "code": "cbmc_safety_inventory",
                        "properties": 1,
                        "property_ids": ["spx_check.array_bounds.1"],
                        "safety_properties": [{
                            "property_id": "spx_check.array_bounds.1",
                            "class": "array bounds",
                            "description": "source bound",
                            "source_function": "spx_check",
                        }],
                        "output_sha256": "8" * 64,
                    },
                ),
                patch(
                    "spaghetti_extractor.components.bisimulation_execution.discover_cbmc_loops",
                    return_value={
                        "status": "satisfied",
                        "code": "cbmc_loop_inventory",
                        "loops": [],
                        "unwinding_property_ids": [],
                        "output_sha256": "9" * 64,
                    },
                ),
                patch(
                    "spaghetti_extractor.components.bisimulation_execution.run_cbmc_cover"
                ) as cover,
            ):
                result = _run_bisimulation_obligation(
                    _task(root), timeout_seconds=60
                )

        self.assertEqual(result["status"], "violated")
        self.assertEqual(result["nonvacuity"]["status"], "satisfied")
        self.assertEqual(
            result["nonvacuity"]["code"],
            "cbmc_counterexample_inhabits_property_model",
        )
        self.assertEqual(
            result["nonvacuity"]["output_sha256"], result["output_sha256"]
        )
        self.assertEqual(len(result["output_sha256"]), 64)
        cover.assert_not_called()
        self.assertEqual(
            result["nonvacuity_goto_model_sha256"],
            result["goto_model_sha256"],
        )
        self.assertEqual(
            result["goto_model_sha256"],
            hashlib.sha256(b"property").hexdigest(),
        )
    def test_property_compile_failure_is_attributed_to_property_model(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            property_failure = {
                "status": "incomplete",
                "code": "goto_cc_failed",
                "output_sha256": "5" * 64,
            }
            with (
                patch(
                    "spaghetti_extractor.components.bisimulation_execution._run_compile",
                    return_value=property_failure,
                ),
            ):
                result = _run_bisimulation_obligation(
                    _task(root), timeout_seconds=60
                )

        self.assertEqual(result["status"], "incomplete")
        self.assertEqual(result["code"], "goto_cc_failed")
        self.assertIsNone(result["goto_model_sha256"])
        self.assertIsNone(result["nonvacuity_goto_model_sha256"])


if __name__ == "__main__":
    unittest.main()
