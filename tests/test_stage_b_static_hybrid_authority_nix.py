from __future__ import annotations

import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class StageBStaticHybridAuthorityNixTests(unittest.TestCase):
    def test_v2_graph_has_the_required_content_addressed_phases(self) -> None:
        graph = (
            ROOT / "nix" / "stage-b-static-hybrid-authority-v2.nix"
        ).read_text(encoding="utf-8")
        phase = (ROOT / "nix" / "ca-python-json-phase.nix").read_text(
            encoding="utf-8"
        )

        for name in (
            "exactUnitPrep",
            "baseGraph",
            "interproceduralSeed",
            "jointInterproceduralV2",
            "interproceduralV2",
            "rootedClosure",
            "checkedExternalSites",
            "globalSlotAnalysis",
            "globalSlotAuthority",
            "entryRootClosure",
            "isaRequirements",
            "isaSelectionAuthority",
            "exceptionCertificates",
            "staticAuthority",
            "authorityBundle",
            "finalAudit",
        ):
            self.assertIn(name, graph)
        self.assertIn("__contentAddressed = true", phase)
        self.assertIn("python-module-closure.nix", phase)
        self.assertIn("every CA phase input must be a Nix store path", phase)
        self.assertNotIn("pkgs.writeText", phase)
        self.assertNotIn("wine", graph.lower())
        self.assertNotIn("wine", phase.lower())

    def test_dependency_edges_match_v2_authority_ownership(self) -> None:
        graph = (
            ROOT / "nix" / "stage-b-static-hybrid-authority-v2.nix"
        ).read_text(encoding="utf-8")

        self.assertIn("exact_unit_prep = exactUnitPrep.artifact", graph)
        self.assertIn("base_graph = baseGraph.artifact", graph)
        self.assertIn("interprocedural_v2 = interproceduralV2.artifact", graph)
        self.assertIn(
            "joint_interprocedural = jointInterproceduralV2.artifact", graph
        )
        joint_dependencies = graph[
            graph.index('jointInterproceduralV2 = mkPhase "jointInterproceduralV2"') :
            graph.index('globalSlotAnalysis = mkPhase "globalSlotAnalysis"')
        ]
        self.assertNotIn("stack_range_analysis", joint_dependencies)
        self.assertIn("rooted_closure = rootedClosure.artifact", graph)
        self.assertIn("checked_external_sites = checkedExternalSites.artifact", graph)
        self.assertIn("global_slot_authority = globalSlotAuthority.artifact", graph)
        self.assertIn("entry_root_closure = entryRootClosure.artifact", graph)
        self.assertIn("isa_requirements = isaRequirements.artifact", graph)
        self.assertIn("isa_selection_authority = isaSelectionAuthority.artifact", graph)
        self.assertIn("exception_certificates = exceptionCertificates.artifact", graph)
        self.assertIn("static_authority = staticAuthority.artifact", graph)
        self.assertIn("authority_bundle = authorityBundle.artifact", graph)

    def test_fixture_exercises_phase_specific_module_closures(self) -> None:
        fixture = (
            ROOT
            / "nix"
            / "tests"
            / "stage-b-static-hybrid-authority-v2.nix"
        ).read_text(encoding="utf-8")

        for module in (
            "spaghetti_extractor.reconstruction_ir",
            "spaghetti_extractor.reconstruction_control",
            "spaghetti_extractor.interprocedural_phase_v2",
            "spaghetti_extractor.joint_fixed_point_v2",
            "spaghetti_extractor.joint_interprocedural_analysis_v2",
            "spaghetti_extractor.artifact_projection_v2",
            "spaghetti_extractor.external_site_proposals_v2",
            "spaghetti_extractor.behavioral_roots",
            "spaghetti_extractor.callback_contracts",
            "spaghetti_extractor.exception_phase_v2",
            "spaghetti_extractor.static_hybrid_pipeline_v2",
            "spaghetti_extractor.analysis.isa_qualification",
            "spaghetti_extractor.isa_kernel_qualification",
            "spaghetti_extractor.machine_ir_isa_requirements_v2",
            "spaghetti_extractor.static_hybrid_authority_v2",
            "spaghetti_extractor.stage_b_candidate_authority_v2",
        ):
            self.assertIn(module, fixture)
        self.assertIn("__contentAddressed = true;", fixture)
        self.assertIn("auditMutation", fixture)
        self.assertIn("externalProfileMutation", fixture)
        self.assertIn("jointInterproceduralMutation", fixture)
        self.assertIn("final_audit_changed", fixture)
        self.assertIn("authority_bundle_changed", fixture)


if __name__ == "__main__":
    unittest.main()
