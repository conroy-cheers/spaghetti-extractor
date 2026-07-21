import tempfile
import unittest
from copy import deepcopy
from pathlib import Path

from spaghetti_extractor.relational.artifacts import write_text_if_changed
from spaghetti_extractor.relational.schema import (
    ModuleGraph,
    PreparedProofDigests,
    SchemaError,
    StageAInterfaceManifest,
)
from spaghetti_extractor.relational.interfaces import stage_a_interface_manifest


class RelationalSchemaTests(unittest.TestCase):
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
            "StageA.GeneratedRelational.candidatePE32ProgramsEquivalent",
        )
        self.assertIn("external-protocol", parsed.workstream_ids)
        self.assertIn("acceptance-integration", parsed.workstream_ids)
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

    def test_write_text_if_changed_preserves_timestamp(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "artifact.txt"
            write_text_if_changed(path, "stable\n")
            timestamp = path.stat().st_mtime_ns
            write_text_if_changed(path, "stable\n")
            self.assertEqual(path.stat().st_mtime_ns, timestamp)


if __name__ == "__main__":
    unittest.main()
