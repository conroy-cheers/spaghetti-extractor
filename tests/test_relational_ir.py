import unittest

from spaghetti_extractor.relational.ir import (
    CompositionProgressIR,
    ProductGraphIR,
    RelationalProofIR,
    WholeProgramAcceptanceIR,
)
from spaghetti_extractor.relational.phases import AnalysisArtifact, ExtractedProgramPair
from spaghetti_extractor.relational.schema import SchemaError
from spaghetti_extractor.relational.schema import RELATIONAL_FINAL_ACCEPTANCE_THEOREM


class RelationalIRTests(unittest.TestCase):

    def test_extracted_program_pair_requires_unique_region_ids(self):
        with self.assertRaisesRegex(SchemaError, "region ids must be unique"):
            ExtractedProgramPair.create(
                contract={"format": "contract", "regions": [
                    {"id": "entry"}, {"id": "entry"},
                ]},
                behaviors=[{"original": "a"}, {"original": "b"}],
                extraction={"status": "checked"},
            )

    def test_analysis_artifact_rejects_phase_format_drift(self):
        with self.assertRaisesRegex(SchemaError, "expected expected-v1"):
            AnalysisArtifact.parse(
                {"format": "wrong-v1", "status": "ready"},
                expected_format="expected-v1",
            )
    def test_proof_ir_rejects_duplicate_obligations(self):
        payload = {
            "format": "stage-a-relational-proof-ir-v1",
            "model": "model",
            "profile": "profile",
            "status": "incomplete",
            "families": [{"family": "control", "status": "incomplete"}],
            "obligations": [
                {"id": "same", "kind": "edge", "status": "incomplete"},
                {"id": "same", "kind": "edge", "status": "proved"},
            ],
        }
        with self.assertRaisesRegex(SchemaError, "obligation ids"):
            RelationalProofIR.parse(payload)

    def test_product_graph_requires_declared_roots(self):
        payload = {
            "format": "stage-a-relational-product-graph-v1",
            "model": "product",
            "status": "candidate_requires_lean_replay",
            "nodes": [{"id": 0}],
            "edges": [],
            "root_node_ids": [1],
            "counts": {},
            "evidence": {},
        }
        with self.assertRaisesRegex(SchemaError, "declared nodes"):
            ProductGraphIR.parse(payload)

    def test_acceptance_and_progress_require_phase_payloads(self):
        acceptance = {
            "format": "stage-a-whole-program-acceptance-v1",
            "status": "incomplete",
            "profile": "profile",
            "required_theorem": RELATIONAL_FINAL_ACCEPTANCE_THEOREM,
            "theorem": None,
            "blockers": [],
        }
        self.assertEqual(
            WholeProgramAcceptanceIR.parse(acceptance).required_theorem,
            RELATIONAL_FINAL_ACCEPTANCE_THEOREM,
        )
        progress = {
            "format": "stage-a-composition-progress-v1",
            "status": "incomplete",
            "counts": {"roots": 1},
            "frontiers": {},
            "acceptance": {},
        }
        self.assertEqual(CompositionProgressIR.parse(progress).counts["roots"], 1)
