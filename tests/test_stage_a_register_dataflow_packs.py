import copy
import hashlib
import json
import unittest

from spaghetti_extractor.relational.analyses.dataflow import stable_dataflow_graph
from spaghetti_extractor.relational.register_dataflow_artifact import (
    REGISTER_ORDER,
    register_transfer_observation_sha256,
    register_transfer_semantics_sha256,
    register_transfer_table_payload,
)
from spaghetti_extractor.relational.register_dataflow_packs import (
    parse_register_dataflow_pack_input,
    project_register_dataflow_packs,
)
from spaghetti_extractor.relational.register_dataflow_compare import (
    compare_register_dataflow_aggregate,
)
from spaghetti_extractor.relational.register_dataflow_aggregate import (
    aggregate_register_dataflow_pack_results,
)
from spaghetti_extractor.relational.register_dataflow_solver import (
    parse_register_dataflow_pack_result,
    solve_register_dataflow_pack,
)
from spaghetti_extractor.relational.register_dataflow_summary import (
    parse_register_dataflow_pack_summary,
    summarize_register_dataflow_pack_result,
)
from spaghetti_extractor.relational.register_dataflow_solution import (
    validate_register_dataflow_solution,
)
from spaghetti_extractor.relational.register_transfer_core import (
    REGISTER_TRANSFER_CONTEXT_FORMAT,
    canonical_sha256,
)
from spaghetti_extractor.relational.register_transfer_ir import (
    compile_register_transfer_program,
    register_transfer_programs_payload,
)
from spaghetti_extractor.stage_binary import StageAInputError


class StageARegisterDataflowPackTests(unittest.TestCase):
    @staticmethod
    def _digest(value: object) -> str:
        return hashlib.sha256(
            json.dumps(
                value, sort_keys=True, separators=(",", ":")
            ).encode("utf-8")
        ).hexdigest()

    def _artifacts(self, *, force_pack_boundary: bool = False):
        region_ids = ["entry", "middle", "exit"]
        context_hashes = ["a" * 64, "b" * 64, "c" * 64]
        relations = [
            {"register": register, "relation": "exact"}
            for register in REGISTER_ORDER
        ]
        observation_sha256 = register_transfer_observation_sha256(
            input_relations=relations,
            fixed_immutable_probe=[],
        )
        transfer_hashes = [
            register_transfer_semantics_sha256(
                context_sha256=context_hash,
                observation_sha256=[observation_sha256],
            )
            for context_hash in context_hashes
        ]
        graph = stable_dataflow_graph(
            [[2], [2], []] if force_pack_boundary else [[1], [2], []],
            region_ids=region_ids,
            transfer_semantics_sha256=transfer_hashes,
        )
        regions = [
            {
                "id": region_id,
                "context_sha256": context_hash,
                "transfer_semantics_sha256": transfer_hash,
                "observations": [{
                    "sha256": observation_sha256,
                    "input_relations": relations,
                    "fixed_immutable_probe": [],
                    "output_relations": relations,
                    "reasons": {
                        register: "identity_transfer"
                        for register in REGISTER_ORDER
                    },
                }],
            }
            for region_id, context_hash, transfer_hash in zip(
                region_ids, context_hashes, transfer_hashes, strict=True
            )
        ]
        edge_pairs = (
            [("entry", "exit"), ("middle", "exit")]
            if force_pack_boundary
            else list(zip(region_ids[:-1], region_ids[1:], strict=True))
        )
        edges = [
            {
                "source_id": source,
                "target_id": target,
                "environment_barrier": False,
                "kind": "jump",
                "preserved_registers": [],
                "result_relations": [],
            }
            for source, target in edge_pairs
        ]
        edges.sort(key=lambda edge: (
            edge["target_id"],
            edge["source_id"],
            edge["kind"],
        ))
        table = register_transfer_table_payload(
            original_sha256="d" * 64,
            candidate_sha256="e" * 64,
            graph_sha256=graph.graph_sha256,
            regions=regions,
            propagation={
                "regions": [
                    {
                        "id": region_id,
                        "seed_relation": (
                            "exact"
                            if index == 0 or force_pack_boundary and index == 1
                            else None
                        ),
                        "stack_window_registers": [],
                    }
                    for index, region_id in enumerate(region_ids)
                ],
                "edges": edges,
            },
        )
        return graph.to_payload(), table

    @staticmethod
    def _transfer_context() -> dict[str, object]:
        body = {
            "format": REGISTER_TRANSFER_CONTEXT_FORMAT,
            "status": "untrusted_proposal_requires_lean_replay",
            "acceptance_authority": False,
            "original": {
                "sha256": "d" * 64,
                "image_base": 0x400000,
                "immutable_ranges": [{
                    "start": 0x400000, "bytes_hex": "00000000",
                }],
                "forbidden_ranges": [],
            },
            "candidate": {
                "sha256": "e" * 64,
                "image_base": 0x500000,
                "immutable_ranges": [{
                    "start": 0x500000, "bytes_hex": "00000000",
                }],
                "forbidden_ranges": [],
            },
            "value_targets": [],
            "code_targets": [],
        }
        return {**body, "context_sha256": canonical_sha256(body)}

    def _program_artifact(
        self,
        graph: dict[str, object],
        table: dict[str, object],
        *,
        immutable_read: bool = False,
    ) -> tuple[dict[str, object], dict[str, object]]:
        input_pairs = {register: register for register in REGISTER_ORDER}
        original_registers = {
            register: {"op": "input_reg", "reg": register}
            for register in REGISTER_ORDER
        }
        candidate_registers = copy.deepcopy(original_registers)
        if immutable_read:
            original_registers["eax"] = {
                "op": "read32",
                "address": {
                    "op": "add",
                    "left": {"op": "constant", "value": 0x400000},
                    "right": {"op": "constant", "value": 0},
                },
            }
            candidate_registers["eax"] = {
                "op": "read32",
                "address": {
                    "op": "add",
                    "left": {"op": "constant", "value": 0x500000},
                    "right": {"op": "constant", "value": 0},
                },
            }
        context = self._transfer_context()
        programs = [
            compile_register_transfer_program(
                region_id=region["id"],
                behavior_pair={
                    "original_ir": {"registers": original_registers},
                    "candidate_ir": {"registers": candidate_registers},
                },
                input_pairs=input_pairs,
                output_pairs=input_pairs,
                contract={},
                original_image_base=0x400000,
                candidate_image_base=0x500000,
                original_bin=object() if immutable_read else None,  # type: ignore[arg-type]
                candidate_bin=object() if immutable_read else None,  # type: ignore[arg-type]
                context_sha256=str(context["context_sha256"]),
            )
            for region in table["regions"]
        ]
        program_graph = stable_dataflow_graph(
            [[1], [2], []],
            region_ids=[program["region_id"] for program in programs],
            transfer_semantics_sha256=[
                program["program_sha256"] for program in programs
            ],
        ).to_payload()
        artifact = register_transfer_programs_payload(
            original_sha256="d" * 64,
            candidate_sha256="e" * 64,
            graph_sha256=program_graph["graph_sha256"],
            context=context,
            programs=programs,
            propagation=table["propagation"],
        )
        return program_graph, artifact

    def test_projection_is_exact_cover_and_inputs_are_self_authenticating(self):
        graph, table = self._artifacts()
        projection = project_register_dataflow_packs(
            graph_payload=graph,
            transfer_table_payload=table,
            expected_original_sha256="d" * 64,
            expected_candidate_sha256="e" * 64,
        )
        self.assertEqual(
            set(projection.inputs),
            set(projection.manifest["topological_pack_ids"]),
        )
        region_ids = [
            region["id"]
            for payload in projection.inputs.values()
            for region in payload["regions"]
        ]
        self.assertCountEqual(region_ids, ["entry", "middle", "exit"])
        for payload in projection.inputs.values():
            self.assertEqual(parse_register_dataflow_pack_input(payload), payload)

    def test_tampered_graph_table_or_pack_input_fails_closed(self) -> None:
        graph, table = self._artifacts()
        tampered_graph = copy.deepcopy(graph)
        tampered_graph["packs"][0]["predecessor_ids"] = ["unknown"]
        with self.assertRaisesRegex(StageAInputError, "graph is invalid"):
            project_register_dataflow_packs(
                graph_payload=tampered_graph,
                transfer_table_payload=table,
                expected_original_sha256="d" * 64,
                expected_candidate_sha256="e" * 64,
            )

        projection = project_register_dataflow_packs(
            graph_payload=graph,
            transfer_table_payload=table,
            expected_original_sha256="d" * 64,
            expected_candidate_sha256="e" * 64,
        )
        pack = copy.deepcopy(next(iter(projection.inputs.values())))
        pack["regions"][0]["seed_relation"] = "related_word"
        with self.assertRaisesRegex(StageAInputError, "digest"):
            parse_register_dataflow_pack_input(pack)

    def test_projected_pack_dag_replays_transfer_table(self) -> None:
        graph, table = self._artifacts(force_pack_boundary=True)
        projection = project_register_dataflow_packs(
            graph_payload=graph,
            transfer_table_payload=table,
            expected_original_sha256="d" * 64,
            expected_candidate_sha256="e" * 64,
            pack_region_budget=1,
        )
        results = {}
        for pack_id in projection.manifest["topological_pack_ids"]:
            pack = projection.inputs[pack_id]
            result = solve_register_dataflow_pack(
                pack_payload=pack,
                predecessor_payloads=[
                    summarize_register_dataflow_pack_result(
                        results[predecessor_id]
                    )
                    for predecessor_id in pack["predecessor_ids"]
                ],
            )
            self.assertEqual(result["status"], "complete")
            self.assertEqual(
                parse_register_dataflow_pack_result(
                    result,
                    expected_pack_id=pack_id,
                    expected_input_sha256=pack["input_sha256"],
                ),
                result,
            )
            results[pack_id] = result
        region_results = [
            region
            for result in results.values()
            for region in result["regions"]
        ]
        self.assertCountEqual(
            [region["id"] for region in region_results],
            ["entry", "middle", "exit"],
        )
        self.assertTrue(all(
            relation["relation"] == "exact"
            for region in region_results
            for relation in region["output_relations"]
        ))
        aggregate = aggregate_register_dataflow_pack_results(
            manifest_payload=projection.manifest,
            result_payloads=list(results.values()),
        )
        self.assertEqual(aggregate["status"], "complete")
        self.assertEqual(aggregate["region_count"], 3)

        legacy_regions = []
        for region in aggregate["regions"]:
            legacy_regions.append({
                "region_id": region["id"],
                "inputs": [
                    {
                        "original": relation["register"],
                        "candidate": relation["register"],
                        **{
                            key: value for key, value in relation.items()
                            if key != "register"
                        },
                    }
                    for relation in region["input_relations"]
                ],
                "outputs": [
                    {
                        "original": relation["register"],
                        "candidate": relation["register"],
                        **{
                            key: value for key, value in relation.items()
                            if key != "register"
                        },
                    }
                    for relation in region["output_relations"]
                ],
            })
        comparison = compare_register_dataflow_aggregate(
            aggregate_payload=aggregate,
            register_relations_payload={
                "format": "stage-a-relational-register-relations-v1",
                "dataflow_complete": True,
                "regions": legacy_regions,
            },
        )
        self.assertEqual(comparison["status"], "match")
        self.assertEqual(comparison["mismatch_count"], 0)

        changed_analysis = {
            "format": "stage-a-relational-register-relations-v1",
            "dataflow_complete": True,
            "regions": copy.deepcopy(legacy_regions),
        }
        changed_analysis["regions"][0]["outputs"][0]["relation"] = (
            "fixed_word"
        )
        changed_analysis["regions"][0]["outputs"][0]["value"] = 7
        comparison = compare_register_dataflow_aggregate(
            aggregate_payload=aggregate,
            register_relations_payload=changed_analysis,
        )
        self.assertEqual(comparison["status"], "mismatch")
        self.assertEqual(comparison["mismatch_count"], 1)

        tampered = copy.deepcopy(list(results.values()))
        dependent = next(
            result for result in tampered if result["predecessor_results"]
        )
        dependent["predecessor_results"][0]["sha256"] = "f" * 64
        body = {
            key: value for key, value in dependent.items()
            if key != "result_sha256"
        }
        dependent["result_sha256"] = self._digest(body)
        with self.assertRaisesRegex(StageAInputError, "predecessor binding"):
            aggregate_register_dataflow_pack_results(
                manifest_payload=projection.manifest,
                result_payloads=tampered,
            )

    def test_semantic_summary_excludes_audit_only_pack_metadata(self) -> None:
        graph, table = self._artifacts(force_pack_boundary=True)
        projection = project_register_dataflow_packs(
            graph_payload=graph,
            transfer_table_payload=table,
            expected_original_sha256="d" * 64,
            expected_candidate_sha256="e" * 64,
            pack_region_budget=1,
        )
        first_pack_id = projection.manifest["topological_pack_ids"][0]
        first_result = solve_register_dataflow_pack(
            pack_payload=projection.inputs[first_pack_id],
            predecessor_payloads=[],
        )
        first_summary = summarize_register_dataflow_pack_result(first_result)
        self.assertEqual(
            parse_register_dataflow_pack_summary(first_summary), first_summary
        )

        audit_variant = copy.deepcopy(first_result)
        audit_variant["iterations"] += 1
        body = {
            key: value for key, value in audit_variant.items()
            if key != "result_sha256"
        }
        audit_variant["result_sha256"] = self._digest(body)
        self.assertNotEqual(
            audit_variant["result_sha256"], first_result["result_sha256"]
        )
        self.assertEqual(
            summarize_register_dataflow_pack_result(audit_variant),
            first_summary,
        )

        dependent_pack_id = next(
            pack_id
            for pack_id in projection.manifest["topological_pack_ids"]
            if projection.inputs[pack_id]["predecessor_ids"]
        )
        predecessor_ids = projection.inputs[dependent_pack_id][
            "predecessor_ids"
        ]
        predecessor_results = {
            first_pack_id: first_result,
        }
        for predecessor_id in predecessor_ids:
            if predecessor_id not in predecessor_results:
                predecessor_results[predecessor_id] = (
                    solve_register_dataflow_pack(
                        pack_payload=projection.inputs[predecessor_id],
                        predecessor_payloads=[],
                    )
                )
        predecessor_summaries = {
            predecessor_id: summarize_register_dataflow_pack_result(result)
            for predecessor_id, result in predecessor_results.items()
        }
        invalid_predecessors = [
            (
                predecessor_results[predecessor_id]
                if predecessor_id == first_pack_id
                else predecessor_summaries[predecessor_id]
            )
            for predecessor_id in predecessor_ids
        ]
        with self.assertRaisesRegex(StageAInputError, "summary fields"):
            solve_register_dataflow_pack(
                pack_payload=projection.inputs[dependent_pack_id],
                predecessor_payloads=invalid_predecessors,
            )
        dependent_result = solve_register_dataflow_pack(
            pack_payload=projection.inputs[dependent_pack_id],
            predecessor_payloads=[
                predecessor_summaries[predecessor_id]
                for predecessor_id in predecessor_ids
            ],
        )
        self.assertEqual(dependent_result["status"], "complete")
        self.assertEqual(dependent_result["predecessor_results"], [
            {
                "id": predecessor_id,
                "sha256": predecessor_summaries[predecessor_id][
                    "summary_sha256"
                ],
            }
            for predecessor_id in sorted(predecessor_ids)
        ])

        tampered = copy.deepcopy(first_summary)
        tampered["regions"][0]["output_relations"][0]["relation"] = (
            "related_word"
        )
        with self.assertRaisesRegex(StageAInputError, "digest"):
            parse_register_dataflow_pack_summary(tampered)

    def test_unseen_transfer_input_returns_incomplete(self) -> None:
        graph, table = self._artifacts()
        projection = project_register_dataflow_packs(
            graph_payload=graph,
            transfer_table_payload=table,
            expected_original_sha256="d" * 64,
            expected_candidate_sha256="e" * 64,
        )
        results = {}
        for pack_id in projection.manifest["topological_pack_ids"]:
            pack = copy.deepcopy(projection.inputs[pack_id])
            if any(region["id"] == "middle" for region in pack["regions"]):
                middle = next(
                    region for region in pack["regions"]
                    if region["id"] == "middle"
                )
                for relation in middle["observations"][0]["input_relations"]:
                    relation["relation"] = "related_word"
                body = {
                    key: value for key, value in pack.items()
                    if key != "input_sha256"
                }
                pack["input_sha256"] = self._digest(body)
            result = solve_register_dataflow_pack(
                pack_payload=pack,
                predecessor_payloads=[
                    summarize_register_dataflow_pack_result(
                        results[predecessor_id]
                    )
                    for predecessor_id in pack["predecessor_ids"]
                ],
            )
            results[pack_id] = result
        incomplete = [
            result for result in results.values()
            if result["status"] == "incomplete"
        ]
        self.assertTrue(incomplete)
        self.assertTrue(any(
            gap["code"] in {
                "transfer_observation_missing", "predecessor_incomplete"
            }
            for result in incomplete
            for gap in result["missing_observations"]
        ))

    def test_program_packs_do_not_depend_on_observed_inputs(self) -> None:
        graph, table = self._artifacts()
        program_graph, programs = self._program_artifact(graph, table)
        projection = project_register_dataflow_packs(
            graph_payload=program_graph,
            transfer_table_payload=None,
            transfer_programs_payload=programs,
            expected_original_sha256="d" * 64,
            expected_candidate_sha256="e" * 64,
        )
        self.assertIsNotNone(projection.transfer_context)
        self.assertTrue(all(
            "program" in region and "observations" not in region
            for pack in projection.inputs.values()
            for region in pack["regions"]
        ))

        results = {}
        for pack_id in projection.manifest["topological_pack_ids"]:
            pack = projection.inputs[pack_id]
            result = solve_register_dataflow_pack(
                pack_payload=pack,
                predecessor_payloads=[
                    summarize_register_dataflow_pack_result(
                        results[predecessor_id]
                    )
                    for predecessor_id in pack["predecessor_ids"]
                ],
                transfer_context_payload=projection.transfer_context,
            )
            self.assertEqual(result["status"], "complete")
            results[pack_id] = result

        aggregate = aggregate_register_dataflow_pack_results(
            manifest_payload=projection.manifest,
            result_payloads=list(results.values()),
        )
        solution = validate_register_dataflow_solution(
            aggregate_payload=aggregate,
            transfer_programs_payload=programs,
            expected_original_sha256="d" * 64,
            expected_candidate_sha256="e" * 64,
            expected_graph_sha256=program_graph["graph_sha256"],
        )
        self.assertEqual(solution.region_ids, ("entry", "middle", "exit"))
        self.assertTrue(all(
            relation == {"relation": "exact"}
            for state in solution.output_states
            for relation in state.values()
        ))

        tampered = copy.deepcopy(aggregate)
        tampered["regions"][0]["output_relations"][0]["relation"] = (
            "related_word"
        )
        body = {
            key: value for key, value in tampered.items()
            if key != "aggregate_sha256"
        }
        tampered["aggregate_sha256"] = self._digest(body)
        with self.assertRaisesRegex(StageAInputError, "graph-closed|transfer"):
            validate_register_dataflow_solution(
                aggregate_payload=tampered,
                transfer_programs_payload=programs,
                expected_original_sha256="d" * 64,
                expected_candidate_sha256="e" * 64,
                expected_graph_sha256=program_graph["graph_sha256"],
            )

        altered_context = copy.deepcopy(projection.transfer_context)
        altered_context["value_targets"] = [{
            "original_value": 1, "candidate_value": 2,
        }]
        body = {
            key: value for key, value in altered_context.items()
            if key != "context_sha256"
        }
        altered_context["context_sha256"] = self._digest(body)
        first_pack = projection.inputs[
            projection.manifest["topological_pack_ids"][0]
        ]
        with self.assertRaisesRegex(StageAInputError, "does not match"):
            solve_register_dataflow_pack(
                pack_payload=first_pack,
                predecessor_payloads=[],
                transfer_context_payload=altered_context,
            )

    def test_solution_replay_normalizes_immutable_memory_context(self) -> None:
        graph, table = self._artifacts()
        program_graph, programs = self._program_artifact(
            graph, table, immutable_read=True,
        )
        projection = project_register_dataflow_packs(
            graph_payload=program_graph,
            transfer_table_payload=None,
            transfer_programs_payload=programs,
            expected_original_sha256="d" * 64,
            expected_candidate_sha256="e" * 64,
        )
        results = {}
        for pack_id in projection.manifest["topological_pack_ids"]:
            pack = projection.inputs[pack_id]
            results[pack_id] = solve_register_dataflow_pack(
                pack_payload=pack,
                predecessor_payloads=[
                    summarize_register_dataflow_pack_result(
                        results[predecessor_id]
                    )
                    for predecessor_id in pack["predecessor_ids"]
                ],
                transfer_context_payload=projection.transfer_context,
            )
        aggregate = aggregate_register_dataflow_pack_results(
            manifest_payload=projection.manifest,
            result_payloads=list(results.values()),
        )

        solution = validate_register_dataflow_solution(
            aggregate_payload=aggregate,
            transfer_programs_payload=programs,
            expected_original_sha256="d" * 64,
            expected_candidate_sha256="e" * 64,
            expected_graph_sha256=program_graph["graph_sha256"],
        )

        self.assertTrue(all(
            state["eax"] == {"relation": "fixed_word", "value": 0}
            for state in solution.output_states
        ))


if __name__ == "__main__":
    unittest.main()
