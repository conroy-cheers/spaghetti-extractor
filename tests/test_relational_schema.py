import tempfile
import unittest
from copy import deepcopy
from pathlib import Path

from spaghetti_extractor.relational.artifacts import write_text_if_changed
from spaghetti_extractor.relational.schema import (
    ModuleGraph,
    PreparedProofDigests,
    RELATIONAL_ACCEPTANCE_THEOREM,
    RELATIONAL_FINAL_ACCEPTANCE_THEOREM,
    RELATIONAL_LINKED_ACCEPTANCE_THEOREM,
    RELATIONAL_MIXED_CHUNKED_ACCEPTANCE_PROFILE,
    RELATIONAL_MIXED_CHUNKED_ACCEPTANCE_THEOREM,
    RELATIONAL_MIXED_CHUNKED_ACCEPTANCE_TYPE,
    SchemaError,
    StageAInterfaceManifest,
    choose_relational_acceptance_theorem,
    selected_relational_acceptance_theorem,
)
from spaghetti_extractor.relational.interfaces import stage_a_interface_manifest


class RelationalSchemaTests(unittest.TestCase):
    def test_acceptance_theorem_selection_requires_linked_authority(self):
        self.assertEqual(
            choose_relational_acceptance_theorem(
                ordinary_ready=True, linked_ready=True
            ),
            RELATIONAL_FINAL_ACCEPTANCE_THEOREM,
        )
        self.assertEqual(
            choose_relational_acceptance_theorem(
                ordinary_ready=False, linked_ready=True
            ),
            RELATIONAL_LINKED_ACCEPTANCE_THEOREM,
        )
        self.assertIsNone(choose_relational_acceptance_theorem(
            ordinary_ready=True, linked_ready=False
        ))
        self.assertIsNone(choose_relational_acceptance_theorem(
            ordinary_ready=False, linked_ready=False
        ))
        self.assertEqual(
            choose_relational_acceptance_theorem(
                ordinary_ready=False,
                linked_ready=False,
                mixed_chunked_ready=True,
            ),
            RELATIONAL_MIXED_CHUNKED_ACCEPTANCE_THEOREM,
        )

    def test_mixed_chunked_acceptance_requires_exact_theorem_and_profile(self):
        acceptance = {
            "status": "ready",
            "required_theorem": RELATIONAL_MIXED_CHUNKED_ACCEPTANCE_THEOREM,
            "theorem": RELATIONAL_MIXED_CHUNKED_ACCEPTANCE_THEOREM,
            "authority_profile": RELATIONAL_MIXED_CHUNKED_ACCEPTANCE_PROFILE,
            "mixed_chunked_acceptance": {
                "status": "ready",
                "theorem": RELATIONAL_MIXED_CHUNKED_ACCEPTANCE_THEOREM,
                "profile": RELATIONAL_MIXED_CHUNKED_ACCEPTANCE_PROFILE,
            },
        }
        self.assertEqual(
            selected_relational_acceptance_theorem(acceptance),
            RELATIONAL_MIXED_CHUNKED_ACCEPTANCE_THEOREM,
        )

        wrong_profile = deepcopy(acceptance)
        wrong_profile["authority_profile"] = "linked-raw-pe32"
        with self.assertRaisesRegex(SchemaError, "profile"):
            selected_relational_acceptance_theorem(wrong_profile)

        wrong_nested_profile = deepcopy(acceptance)
        wrong_nested_profile["mixed_chunked_acceptance"]["profile"] = (
            "mixed-native-pe32-chunked-open"
        )
        with self.assertRaisesRegex(SchemaError, "mixed authority"):
            selected_relational_acceptance_theorem(wrong_nested_profile)

        wrong_theorem = deepcopy(acceptance)
        wrong_theorem["theorem"] = RELATIONAL_LINKED_ACCEPTANCE_THEOREM
        with self.assertRaisesRegex(SchemaError, "does not match"):
            selected_relational_acceptance_theorem(wrong_theorem)

    def test_module_graph_parser_returns_immutable_nodes(self):
        graph = ModuleGraph.parse({
            "format": "stage-a-lean-module-graph-v1",
            "root_module": "RelationalBundle",
            "expected_final_theorem": None,
            "nodes": [{
                "id": "bundle",
                "modules": ["RelationalBundle"],
                "dependencies": [],
                "source_sha256": "a" * 64,
                "resource_class": "light",
                "estimated_memory_mb": 512,
            }],
        })

        self.assertEqual(graph.root_module, "RelationalBundle")
        self.assertEqual(graph.nodes[0].modules, ("RelationalBundle",))
        with self.assertRaises(AttributeError):
            graph.nodes[0].id = "changed"  # type: ignore[misc]

    def test_module_graph_parser_rejects_duplicate_nodes(self):
        node = {
            "id": "same",
            "modules": ["RelationalBundle"],
            "dependencies": [],
            "source_sha256": "a" * 64,
            "resource_class": "light",
            "estimated_memory_mb": 512,
        }
        with self.assertRaisesRegex(SchemaError, "must be unique"):
            ModuleGraph.parse({
                "format": "stage-a-lean-module-graph-v1",
                "root_module": "RelationalBundle",
                "expected_final_theorem": None,
                "nodes": [node, node],
            })

    def test_prepared_digest_parser_rejects_missing_hash(self):
        with self.assertRaisesRegex(SchemaError, "module_graph_sha256"):
            PreparedProofDigests.parse({
                "analysis_manifest_sha256": "m",
                "interface_manifest_sha256": "z",
                "relation_contract_sha256": "a",
                "proof_ir_sha256": "b",
                "semantic_ir_sha256": "c",
                "memory_contracts_sha256": "d",
                "static_word_relations_sha256": "s",
                "register_relations_sha256": "e",
                "runtime_frame_affine_sha256": "r",
                "stack_windows_sha256": "f",
                "segment_diagnostics_sha256": "g",
                "product_graph_sha256": "h",
                "isa_requirements_sha256": "q",
                "invariants_sha256": "i",
                "whole_program_acceptance_sha256": "j",
                "composition_progress_sha256": "k",
            })

    def test_parallel_interface_manifest_has_one_acceptance_owner(self):
        manifest = stage_a_interface_manifest()
        parsed = StageAInterfaceManifest.parse(manifest)

        self.assertEqual(
            parsed.acceptance_theorem,
            RELATIONAL_FINAL_ACCEPTANCE_THEOREM,
        )
        self.assertEqual(
            set(parsed.acceptance_theorems),
            {
                RELATIONAL_ACCEPTANCE_THEOREM,
                RELATIONAL_LINKED_ACCEPTANCE_THEOREM,
                RELATIONAL_MIXED_CHUNKED_ACCEPTANCE_THEOREM,
            },
        )
        mixed = next(
            row
            for row in manifest["acceptance"]["supported_theorems"]
            if row["theorem"] == RELATIONAL_MIXED_CHUNKED_ACCEPTANCE_THEOREM
        )
        self.assertEqual(mixed["canonical_type"], RELATIONAL_MIXED_CHUNKED_ACCEPTANCE_TYPE)
        self.assertEqual(
            mixed["profile"], RELATIONAL_MIXED_CHUNKED_ACCEPTANCE_PROFILE
        )
        self.assertIn("external-protocol", parsed.workstream_ids)
        self.assertIn("acceptance-integration", parsed.workstream_ids)
        self.assertIn("external-operation-profile", parsed.schema_ids)
        self.assertIn("external-operation-contract", parsed.schema_ids)
        self.assertIn("operation-provenance", parsed.schema_ids)
        external_operation = next(
            row
            for row in manifest["lean_interfaces"]
            if row["module"] == "StageA.RelationalExternalOperation"
        )
        self.assertIn(
            "ExternalOperation.PairedTargetResolution.operationValid",
            external_operation["declarations"],
        )
        state_products = next(
            artifact
            for artifact in manifest["artifacts"]
            if artifact["id"] == "state-products"
        )
        self.assertIn(
            "relational-static-word-relations.json", state_products["paths"]
        )
        state_workstream = next(
            workstream
            for workstream in manifest["workstreams"]
            if workstream["id"] == "state-and-frame-analysis"
        )
        self.assertIn(
            "src/spaghetti_extractor/relational/analyses/memory.py",
            state_workstream["owned_paths"],
        )
        overlapping = deepcopy(manifest)
        overlapping["workstreams"][1]["owned_paths"].append(
            overlapping["workstreams"][0]["owned_paths"][0]
        )
        with self.assertRaisesRegex(SchemaError, "must be disjoint"):
            StageAInterfaceManifest.parse(overlapping)

    def test_module_graph_parser_rejects_unknown_acceptance_theorem(self):
        with self.assertRaisesRegex(SchemaError, "not a supported acceptance theorem"):
            ModuleGraph.parse({
                "format": "stage-a-lean-module-graph-v1",
                "root_module": "RelationalAcceptance",
                "expected_final_theorem": "StageA.GeneratedRelational.looksEquivalent",
                "nodes": [{
                    "id": "acceptance",
                    "modules": ["RelationalAcceptance"],
                    "dependencies": [],
                    "source_sha256": "a" * 64,
                    "resource_class": "light",
                    "estimated_memory_mb": 512,
                }],
            })

    def test_write_text_if_changed_preserves_timestamp(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "artifact.txt"
            write_text_if_changed(path, "stable\n")
            timestamp = path.stat().st_mtime_ns
            write_text_if_changed(path, "stable\n")
            self.assertEqual(path.stat().st_mtime_ns, timestamp)


if __name__ == "__main__":
    unittest.main()
