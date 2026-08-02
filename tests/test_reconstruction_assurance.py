from __future__ import annotations

import copy
import json
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.reconstruction_assurance import (
    ASSURANCE_REPORT_FORMAT,
    BUILD_BINDING_FORMAT,
    CACHE_EVIDENCE_FORMAT,
    EXTERNAL_PROTOCOL_FORMAT,
    FUNCTIONAL_RESULTS_FORMAT,
    ISA_EVIDENCE_FORMAT,
    LOWERING_EVIDENCE_FORMAT,
    MACHINE_IR_FORMAT,
    MUTATION_RESULTS_FORMAT,
    RECONSTRUCTION_QUALIFICATION_FORMAT,
    REGIONAL_REPLACEMENTS_FORMAT,
    SOURCE_BINDING_FORMAT,
    TIMING_EVIDENCE_FORMAT,
    AssuranceStatus,
    ReconstructionAssuranceError,
    build_assurance_report,
    build_reconstruction_qualification,
    parse_assurance_report,
    parse_reconstruction_qualification,
    write_assurance_report,
)


ORIGINAL = "1" * 64
IR = "2" * 64
SOURCE_MANIFEST = "3" * 64
SOURCE_TREE = "4" * 64
CANDIDATE = "5" * 64


def _evidence(
    format_name,
    bindings,
    counts,
    *,
    status="qualified",
    digest="a" * 64,
    evidence_classes=("exhaustive",),
    assumption_ids=(),
):
    return {
        "format": format_name,
        "status": status,
        "artifact_sha256": digest,
        "bindings": bindings,
        "counts": counts,
        "evidence_classes": list(evidence_classes),
        "assumption_ids": list(assumption_ids),
        "issues": [],
    }


def _inputs():
    common = {"original_sha256": ORIGINAL, "machine_ir_sha256": IR}
    return {
        "machine_ir": _evidence(
            MACHINE_IR_FORMAT,
            common,
            {
                "executable_bytes": 256,
                "classified_executable_bytes": 256,
                "units": 12,
                "reachable_units": 10,
                "unknown_reachable_units": 0,
                "unsupported_reachable_units": 0,
                "indirect_sites": 2,
                "closed_indirect_sites": 2,
                "external_sites": 3,
                "closed_external_sites": 3,
                "callbacks": 1,
                "closed_callbacks": 1,
            },
            digest=IR,
        ),
        "isa_evidence": _evidence(
            ISA_EVIDENCE_FORMAT,
            common,
            {
                "required_forms": 7,
                "qualified_forms": 7,
                "unsupported_reachable_forms": 0,
                "disputed_forms": 0,
            },
        ),
        "lowering_evidence": _evidence(
            LOWERING_EVIDENCE_FORMAT,
            common,
            {
                "reachable_units": 10,
                "lowered_units": 10,
                "unknown_reachable_units": 0,
                "unsupported_reachable_units": 0,
            },
        ),
        "external_protocol": _evidence(
            EXTERNAL_PROTOCOL_FORMAT,
            common,
            {
                "external_sites": 3,
                "closed_external_sites": 3,
                "callbacks": 1,
                "closed_callbacks": 1,
                "unknown_sites": 0,
            },
        ),
        "source_binding": _evidence(
            SOURCE_BINDING_FORMAT,
            {
                **common,
                "source_manifest_sha256": SOURCE_MANIFEST,
                "source_tree_sha256": SOURCE_TREE,
            },
            {"reachable_units": 10, "bound_units": 10},
        ),
        "build_binding": _evidence(
            BUILD_BINDING_FORMAT,
            {
                **common,
                "source_manifest_sha256": SOURCE_MANIFEST,
                "source_tree_sha256": SOURCE_TREE,
                "candidate_sha256": CANDIDATE,
            },
            {
                "source_artifacts": 4,
                "bound_source_artifacts": 4,
                "candidate_size": 8192,
            },
        ),
        "trust_assumptions": [
            {
                "id": "pinned-toolchain-correct",
                "scope": "candidate build",
                "statement": "The pinned compiler and linker preserve C semantics.",
            },
            {
                "id": "external-extensionality",
                "scope": "external environment",
                "statement": "Related calls receive related external results.",
            },
        ],
    }


def _final_inputs(qualification):
    return {
        "reconstruction_qualification": qualification,
        "mutation_results": _evidence(
            MUTATION_RESULTS_FORMAT,
            {
                "original_sha256": ORIGINAL,
                "machine_ir_sha256": IR,
                "candidate_sha256": CANDIDATE,
            },
            {"mutations": 12, "detected": 12, "not_detected": 0},
        ),
        "functional_results": {
            **_evidence(
                FUNCTIONAL_RESULTS_FORMAT,
                {"candidate_sha256": CANDIDATE},
                {"cases": 9, "passed": 9, "failed": 0, "original_runtime_executions": 0},
            ),
            "original_runtime_observations": False,
            "execution": {
                "command": ["xvfb-run", "-a", "/nix/store/tool/bin/wine", "candidate.exe"],
                "session": "headless-x",
                "headless": True,
                "environment": {"DISPLAY": ":99"},
            },
        },
        "regional_replacements": _evidence(
            REGIONAL_REPLACEMENTS_FORMAT,
            {"machine_ir_sha256": IR, "candidate_sha256": CANDIDATE},
            {"replacements": 2, "qualified": 2, "incomplete": 0, "violated": 0},
        ),
        "cache_evidence": {
            **_evidence(
                CACHE_EVIDENCE_FORMAT,
                {"machine_ir_sha256": IR, "candidate_sha256": CANDIDATE},
                {
                    "artifacts": 20,
                    "substituted_no_change": 20,
                    "rebuilt_on_region_change": 3,
                    "reused_on_region_change": 17,
                },
            ),
            "no_change_all_substituted": True,
            "region_change_scope_preserved": True,
        },
        "timing_evidence": {
            "format": TIMING_EVIDENCE_FORMAT,
            "status": "qualified",
            "artifact_sha256": "a" * 64,
            "bindings": {"machine_ir_sha256": IR, "candidate_sha256": CANDIDATE},
            "evidence_classes": ["integration"],
            "assumption_ids": [],
            "replacement_iteration_seconds": 20.5,
            "replacement_iteration_limit_seconds": 60,
            "full_runtime_seconds": 90,
            "full_runtime_limit_seconds": 180,
            "issues": [],
        },
    }


class ReconstructionAssuranceTests(unittest.TestCase):
    def test_builds_qualified_static_and_final_artifacts(self):
        qualification = build_reconstruction_qualification(**_inputs())
        self.assertEqual(qualification["format"], RECONSTRUCTION_QUALIFICATION_FORMAT)
        self.assertEqual(qualification["status"], "qualified")
        self.assertNotEqual(qualification["status"], "pass")
        parsed_qualification = parse_reconstruction_qualification(qualification)
        self.assertIs(parsed_qualification.status, AssuranceStatus.QUALIFIED)

        report = build_assurance_report(**_final_inputs(qualification))
        self.assertEqual(report["format"], ASSURANCE_REPORT_FORMAT)
        self.assertEqual(report["status"], "qualified")
        self.assertFalse(report["authority"]["stage_a_pass_authorized"])
        self.assertEqual(report["runtime_policy"]["original_runtime_executions"], 0)
        self.assertIs(parse_assurance_report(report).status, AssuranceStatus.QUALIFIED)
        self.assertNotIn('"status":"pass"', json.dumps(report, separators=(",", ":")))

    def test_static_semantic_gaps_are_incomplete_and_source_mapped(self):
        inputs = _inputs()
        inputs["machine_ir"]["counts"]["unknown_reachable_units"] = 2
        inputs["machine_ir"]["counts"]["closed_indirect_sites"] = 1
        qualification = build_reconstruction_qualification(**inputs)

        self.assertEqual(qualification["status"], "incomplete")
        codes = {issue["code"] for issue in qualification["issues"]}
        self.assertIn("unknown_reachable_units", codes)
        self.assertIn("unclosed_indirect_sites", codes)
        for issue in qualification["issues"]:
            self.assertTrue(issue["id"].startswith("reconstruction."))
            self.assertTrue(issue["location"]["artifact"])
            self.assertTrue(issue["location"]["json_path"])
        parse_reconstruction_qualification(qualification)

    def test_binding_and_count_drift_are_violated(self):
        inputs = _inputs()
        inputs["lowering_evidence"]["bindings"]["machine_ir_sha256"] = "9" * 64
        inputs["source_binding"]["counts"].update(
            reachable_units=11, bound_units=11
        )
        qualification = build_reconstruction_qualification(**inputs)

        self.assertEqual(qualification["status"], "violated")
        self.assertIn("binding_drift", {issue["code"] for issue in qualification["issues"]})
        self.assertIn("count_drift", {issue["code"] for issue in qualification["issues"]})

    def test_assumed_evidence_requires_a_known_assumption(self):
        inputs = _inputs()
        inputs["machine_ir"]["evidence_classes"] = ["assumed", "exhaustive"]
        qualification = build_reconstruction_qualification(**inputs)
        self.assertEqual(qualification["status"], "incomplete")
        self.assertIn(
            "unbound_assumed_evidence",
            {issue["code"] for issue in qualification["issues"]},
        )

        inputs = _inputs()
        inputs["machine_ir"]["assumption_ids"] = ["missing-assumption"]
        qualification = build_reconstruction_qualification(**inputs)
        self.assertEqual(qualification["status"], "violated")
        self.assertIn(
            "unknown_assumption_reference",
            {issue["code"] for issue in qualification["issues"]},
        )

    def test_qualified_evidence_cannot_be_unsupported(self):
        inputs = _inputs()
        inputs["isa_evidence"]["evidence_classes"] = ["unsupported"]
        qualification = build_reconstruction_qualification(**inputs)
        self.assertEqual(qualification["status"], "violated")
        self.assertIn(
            "unsupported_evidence_qualified",
            {issue["code"] for issue in qualification["issues"]},
        )

    def test_malformed_or_tampered_artifacts_are_rejected(self):
        inputs = _inputs()
        inputs["isa_evidence"]["unexpected"] = True
        with self.assertRaisesRegex(ReconstructionAssuranceError, "fields differ"):
            build_reconstruction_qualification(**inputs)

        qualification = build_reconstruction_qualification(**_inputs())
        qualification["evidence"]["machine_ir"]["counts"]["units"] = 13
        with self.assertRaisesRegex(ReconstructionAssuranceError, "content digest mismatch"):
            parse_reconstruction_qualification(qualification)

        qualification = build_reconstruction_qualification(**_inputs())
        report = build_assurance_report(**_final_inputs(qualification))
        report["runtime_policy"]["original_runtime_executions"] = 1
        with self.assertRaisesRegex(ReconstructionAssuranceError, "content digest mismatch"):
            parse_assurance_report(report)

    def test_undetected_mutation_is_a_source_mapped_violation(self):
        qualification = build_reconstruction_qualification(**_inputs())
        inputs = _final_inputs(qualification)
        counts = inputs["mutation_results"]["counts"]
        counts.update(detected=11, not_detected=1)
        report = build_assurance_report(**inputs)

        self.assertEqual(report["status"], "violated")
        issue = next(issue for issue in report["issues"] if issue["code"] == "mutation_not_detected")
        self.assertEqual(issue["location"]["artifact"], "mutations")
        self.assertEqual(issue["location"]["json_path"], "$.counts.not_detected")
        parse_assurance_report(report)

    def test_original_runtime_or_non_headless_wine_is_violated(self):
        qualification = build_reconstruction_qualification(**_inputs())
        inputs = _final_inputs(qualification)
        functional = inputs["functional_results"]
        functional["counts"]["original_runtime_executions"] = 1
        functional["original_runtime_observations"] = True
        functional["execution"]["headless"] = False
        report = build_assurance_report(**inputs)

        self.assertEqual(report["status"], "violated")
        codes = {issue["code"] for issue in report["issues"]}
        self.assertTrue({"original_runtime_executed", "original_runtime_observed", "runtime_not_headless"} <= codes)

    def test_write_is_deterministic(self):
        qualification = build_reconstruction_qualification(**_inputs())
        inputs = _final_inputs(qualification)
        with tempfile.TemporaryDirectory() as temporary:
            first = Path(temporary) / "first.json"
            second = Path(temporary) / "second.json"
            write_assurance_report(first, **inputs)
            write_assurance_report(second, **inputs)
            self.assertEqual(first.read_bytes(), second.read_bytes())

    def test_parser_rejects_stage_a_pass_vocabulary(self):
        qualification = build_reconstruction_qualification(**_inputs())
        qualification["status"] = "pass"
        # Recompute is intentionally impossible through the public builder; the
        # parser rejects the vocabulary even before consistency could authorize it.
        qualification["content_sha256"] = "0" * 64
        with self.assertRaises(ReconstructionAssuranceError):
            parse_reconstruction_qualification(qualification)


if __name__ == "__main__":
    unittest.main()
