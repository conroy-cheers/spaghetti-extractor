from __future__ import annotations

import unittest
from unittest.mock import PropertyMock, patch

from spaghetti_extractor.analysis_v3.graph import authority_graph_manifest_v3
from spaghetti_extractor.analysis_v3.registry import AUTHORITY_PHASE_REGISTRY_V3


class AuthorityGraphManifestV3Tests(unittest.TestCase):
    def test_registry_is_the_only_phase_inventory(self) -> None:
        manifest = authority_graph_manifest_v3(graph_id="fixture")
        phases = {row["phase_id"]: row for row in manifest["phases"]}

        self.assertEqual(set(phases), set(AUTHORITY_PHASE_REGISTRY_V3.names))
        self.assertEqual(
            manifest["external_artifact_kinds"],
            {
                "callback_evidence": "callback-evidence-v3",
                "exception_evidence": "exception-evidence-v3",
                "external_profiles": "external-profile-authority-v3",
                "external_site_evidence": "external-site-evidence-v3",
                "inductive_inputs": "inductive-inputs-v3",
                "implementation_capabilities": "implementation-capabilities-v3",
                "isa_evidence": "isa-qualification-evidence-v3",
                "launch_roots": "launch-root-evidence-v3",
                "machine_ir": "machine-ir-v3-input",
                "target_evidence": "indirect-target-evaluation-evidence-v3",
                "target_hints": "target-hints-v3",
            },
        )
        transitions = phases["transition-summaries-v3"]
        self.assertEqual(
            transitions["inputs"]["exact_units"],
            {"source": "phase", "id": "exact-units-v3"},
        )
        self.assertEqual(transitions["form"], "map_units")
        self.assertEqual(transitions["source_input"], "exact_units")
        self.assertTrue(transitions["phase_reference"].endswith(":TRANSITION_SUMMARIES_PHASE_V3"))
        semantic_index = phases["semantic-index-v3"]
        self.assertEqual(
            semantic_index["inputs"]["exact_units"],
            {"source": "phase", "id": "exact-units-v3"},
        )
        self.assertEqual(semantic_index["form"], "map_units")
        self.assertEqual(semantic_index["source_input"], "exact_units")
        self.assertEqual(
            phases["launch-root-closure-v3"]["inputs"]["semantic_index"],
            {"source": "phase", "id": "semantic-index-v3"},
        )

        for phase in phases.values():
            if phase["form"] == "map_units":
                self.assertIn("source_input", phase)
                self.assertIn(phase["source_input"], phase["inputs"])
            else:
                self.assertNotIn("source_input", phase)

    def test_manifest_identity_is_deterministic_and_output_bound(self) -> None:
        first = authority_graph_manifest_v3(
            graph_id="fixture", outputs=("inductive-authority-v3",)
        )
        second = authority_graph_manifest_v3(
            graph_id="fixture", outputs=("inductive-authority-v3",)
        )

        self.assertEqual(first, second)
        self.assertEqual(first["outputs"], ["inductive-authority-v3"])
        self.assertRegex(first["graph_id"], r"^fixture:[0-9a-f]{24}$")

    def test_phase_implementation_hash_does_not_invalidate_topology(self) -> None:
        before = authority_graph_manifest_v3(graph_id="fixture")
        with patch(
            "spaghetti_extractor.phase_framework_v3.PhaseDefinitionV3.definition_sha256",
            new_callable=PropertyMock,
            return_value="f" * 64,
        ):
            after = authority_graph_manifest_v3(graph_id="fixture")
        self.assertEqual(before, after)


if __name__ == "__main__":
    unittest.main()
