import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.relational.artifacts import write_text_if_changed
from spaghetti_extractor.relational.schema import (
    ModuleGraph,
    PreparedProofDigests,
    SchemaError,
)


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
                "relation_contract_sha256": "a",
                "proof_ir_sha256": "b",
                "semantic_ir_sha256": "c",
                "memory_contracts_sha256": "d",
                "register_relations_sha256": "e",
                "stack_windows_sha256": "f",
                "product_graph_sha256": "g",
                "invariants_sha256": "h",
                "whole_program_acceptance_sha256": "i",
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
