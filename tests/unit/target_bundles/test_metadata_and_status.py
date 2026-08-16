from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.target_bundles.metadata import (
    TargetMetadata,
    TargetMetadataError,
)
from spaghetti_extractor.target_bundles.candidate_status import (
    CANDIDATE_STATUS_FORMAT,
    build_candidate_status,
)
from spaghetti_extractor.target_bundles.project_status import (
    PROJECT_STATUS_FORMAT,
    StatusArtifactError,
    build_project_status,
)
from spaghetti_extractor.target_bundles.status_common import canonical_sha256
from spaghetti_extractor.target_bundles.runtime_frontiers import (
    RUNTIME_FRONTIER_REPORT_FORMAT,
    build_runtime_frontier_report,
)


def _metadata() -> dict[str, object]:
    return {
        "format": "spaghetti-extractor-target-bundle-v3",
        "id": "fixture",
        "display_name": "Fixture PE32",
        "input": {"kind": "pe32", "expected_sha256": "1" * 64},
        "paths": {"nix": "default.nix", "components": "intent/components.json"},
        "workflow": {"default_configuration": "default"},
    }


class TargetMetadataTests(unittest.TestCase):
    def test_strict_metadata_parses(self) -> None:
        value = TargetMetadata.parse(_metadata())
        self.assertEqual(value.identity, "fixture")
        self.assertEqual(value.input.expected_sha256, "1" * 64)
        self.assertEqual(value.workflow.default_configuration, "default")

    def test_unknown_fields_bad_hashes_and_escaping_paths_fail(self) -> None:
        for mutate, pattern in (
            (lambda row: row.update({"extra": True}), "invalid fields"),
            (
                lambda row: row["input"].update({"expected_sha256": "bad"}),
                "not canonical",
            ),
            (
                lambda row: row["paths"].update({"nix": "../default.nix"}),
                "strict relative",
            ),
            (
                lambda row: row["paths"].pop("components"),
                "invalid fields",
            ),
        ):
            payload = _metadata()
            mutate(payload)
            with self.subTest(pattern=pattern), self.assertRaisesRegex(
                TargetMetadataError, pattern
            ):
                TargetMetadata.parse(payload)

    def test_analysis_only_metadata_has_no_fake_component_configuration(self) -> None:
        payload = _metadata()
        payload["paths"]["components"] = None
        payload["workflow"]["default_configuration"] = None
        value = TargetMetadata.parse(payload)
        self.assertIsNone(value.workflow.default_configuration)
        self.assertEqual(dict(value.paths), {"nix": Path("default.nix")})

    def test_component_path_and_configuration_are_atomic(self) -> None:
        payload = _metadata()
        payload["paths"]["components"] = None
        with self.assertRaisesRegex(TargetMetadataError, "both be set or both be null"):
            TargetMetadata.parse(payload)


class ProjectStatusTests(unittest.TestCase):
    def _build(self, authority: object) -> dict[str, object]:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            authority_path = root / "authority.json"
            output = root / "status.json"
            payload = (
                {
                    "format": "spaghetti-extractor-authority-diagnostics-v3",
                    **authority,
                }
                if isinstance(authority, dict)
                else authority
            )
            authority_path.write_text(json.dumps(payload), encoding="ascii")
            return build_project_status(
                target_id="fixture",
                authority_diagnostics=authority_path,
                out=output,
            )

    def test_incomplete_authority_is_forwarded_without_candidate_state(self) -> None:
        result = self._build(
            {
                "status": "incomplete",
                "authorizing": False,
                "counts": {
                    "primary_frontiers": 1,
                    "dependent_occurrences": 4,
                },
                "primary_frontiers": [
                    {
                        "status": "incomplete",
                        "family": "roots-v3",
                        "code": "callback_missing",
                        "record_id": "root:1",
                        "dependent_occurrences": 4,
                        "next_action": "describe the callback entry",
                    }
                ],
            }
        )
        self.assertEqual(result["format"], PROJECT_STATUS_FORMAT)
        self.assertEqual(result["status"], "incomplete")
        self.assertFalse(result["authority_ready"])
        self.assertEqual(result["counts"]["dependent_occurrences"], 4)
        self.assertFalse(result["authorizing"])
        self.assertNotIn("configuration_id", result)
        self.assertNotIn("component_configuration", result)
        self.assertNotIn("candidate", result)

    def test_complete_authorizing_authority_is_ready(self) -> None:
        result = self._build(
            {
                "status": "complete",
                "authorizing": True,
                "counts": {
                    "primary_frontiers": 0,
                    "dependent_occurrences": 0,
                },
                "primary_frontiers": [],
            }
        )
        self.assertEqual(result["status"], "ready")
        self.assertTrue(result["authority_ready"])
        self.assertEqual(result["next_action"], "inspect component or candidate status")

    def test_non_authorizing_complete_authority_remains_incomplete(self) -> None:
        result = self._build(
            {
                "status": "complete",
                "authorizing": False,
                "counts": {"primary_frontiers": 0, "dependent_occurrences": 0},
                "primary_frontiers": [],
            }
        )
        self.assertEqual(result["status"], "incomplete")
        self.assertFalse(result["authority_ready"])

    def test_violated_authority_wins_and_malformed_counts_fail(self) -> None:
        violated = self._build(
            {
                "status": "violated",
                "authorizing": False,
                "counts": {"primary_frontiers": 0, "dependent_occurrences": 0},
                "primary_frontiers": [],
            }
        )
        self.assertEqual(violated["status"], "violated")
        with self.assertRaisesRegex(StatusArtifactError, "dependent_occurrences"):
            self._build(
                {
                    "status": "incomplete",
                    "authorizing": False,
                    "counts": {"dependent_occurrences": -1},
                    "primary_frontiers": [],
                }
            )


class RuntimeFrontierReportTests(unittest.TestCase):
    def _build(self, authority: dict[str, object]) -> dict[str, object]:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "authority.json"
            source.write_text(
                json.dumps({
                    "format": "spaghetti-extractor-authority-diagnostics-v3",
                    **authority,
                }),
                encoding="ascii",
            )
            return build_runtime_frontier_report(
                authority_diagnostics=source,
                out=root / "runtime-frontiers.json",
            )

    def test_projection_is_non_authorizing_and_filters_nonruntime_rows(self) -> None:
        result = self._build({
            "status": "incomplete",
            "authorizing": False,
            "primary_frontiers": [
                {
                    "status": "incomplete",
                    "family": "indirect-targets-v3",
                    "code": "target_unknown",
                    "record_id": "unit:1",
                },
                {
                    "status": "incomplete",
                    "family": "documentation",
                    "code": "label_missing",
                    "record_id": "note:1",
                },
            ],
            "dependency_consequences": [],
        })
        self.assertEqual(result["format"], RUNTIME_FRONTIER_REPORT_FORMAT)
        self.assertEqual(result["status"], "incomplete")
        self.assertFalse(result["authorizing"])
        self.assertEqual([row["record_id"] for row in result["frontiers"]], ["unit:1"])
        self.assertFalse(result["policy"]["candidate_generated"])
        self.assertFalse(result["policy"]["runtime_executed"])
        self.assertFalse(result["policy"]["original_binary_executed"])

    def test_runtime_violation_wins_and_complete_projection_is_empty(self) -> None:
        violated = self._build({
            "status": "violated",
            "authorizing": False,
            "primary_frontiers": [{
                "status": "violated",
                "family": "external-sites-v3",
                "code": "abi_contradiction",
                "record_id": "site:1",
            }],
            "dependency_consequences": [],
        })
        self.assertEqual(violated["status"], "violated")
        complete = self._build({
            "status": "complete",
            "authorizing": True,
            "primary_frontiers": [],
            "dependency_consequences": [],
        })
        self.assertEqual(complete["status"], "complete")
        self.assertEqual(complete["frontiers"], [])


class CandidateStatusTests(unittest.TestCase):
    def _build(
        self,
        *,
        structural_status: str = "complete",
        configuration_status: str = "ready",
        blockers: list[dict[str, object]] | None = None,
        suites: dict[str, object] | None = None,
        configuration_binding: str = "default",
    ) -> dict[str, object]:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            structural_path = root / "structural.json"
            configuration_path = root / "configuration.json"
            output = root / "candidate.json"
            structural_core = {
                "format": "spaghetti-extractor-structural-executable-v1",
                "status": structural_status,
                "executable": structural_status == "complete",
                "release_accepted": False,
                "bindings": {},
                "families": [
                    {
                        "id": "semantic_index",
                        "status": structural_status,
                        "input_sha256": "1" * 64,
                        "record_count": 3,
                        "blocker": (
                            None
                            if structural_status == "complete"
                            else "one semantic unit is not executable"
                        ),
                    }
                ],
            }
            structural_path.write_text(
                json.dumps(
                    {
                        **structural_core,
                        "receipt_sha256": canonical_sha256(structural_core),
                    }
                ),
                encoding="ascii",
            )
            configuration_path.write_text(
                json.dumps(
                    {
                        "format": (
                            "spaghetti-extractor-component-configuration-status-v1"
                        ),
                        "configuration_id": configuration_binding,
                        "status": configuration_status,
                        "counts": {"blocked": len(blockers or [])},
                        "blockers": blockers or [],
                    }
                ),
                encoding="ascii",
            )
            return build_candidate_status(
                target_id="fixture",
                configuration_id="default",
                structural_receipt=structural_path,
                configuration_status=configuration_path,
                candidate_test_suites=suites or {},
                out=output,
            )

    def test_ready_candidate_has_explicit_readiness_dimensions(self) -> None:
        result = self._build(
            suites={
                "public": {"configurationId": "default", "caseIds": ["help"]}
            }
        )
        self.assertEqual(result["format"], CANDIDATE_STATUS_FORMAT)
        self.assertEqual(result["status"], "ready")
        self.assertTrue(result["structural_ready"])
        self.assertTrue(result["configuration_ready"])
        self.assertTrue(result["build_ready"])
        self.assertEqual(result["candidate"]["status"], "ready_to_build")
        self.assertEqual(result["counts"]["candidate_test_suites"], 1)

    def test_missing_suite_does_not_block_static_build(self) -> None:
        result = self._build()
        self.assertEqual(result["status"], "ready")
        self.assertTrue(result["build_ready"])
        self.assertEqual(result["counts"]["candidate_test_suites"], 0)
        self.assertFalse(result["policy"]["candidate_tests_authorize"])

    def test_structural_and_configuration_blockers_are_distinct(self) -> None:
        structural = self._build(structural_status="incomplete")
        self.assertEqual(
            structural["candidate"]["status"], "blocked_by_static_closure"
        )
        self.assertEqual(
            structural["primary_frontiers"][0]["code"],
            "semantic_index_incomplete",
        )
        component = self._build(
            configuration_status="incomplete",
            blockers=[{"code": "source_missing", "detail": "write source"}],
        )
        self.assertEqual(
            component["candidate"]["status"],
            "blocked_by_component_configuration",
        )
        self.assertEqual(
            component["primary_frontiers"][0]["code"], "source_missing"
        )

    def test_violation_wins_over_incompleteness(self) -> None:
        result = self._build(
            structural_status="incomplete",
            configuration_status="violated",
            blockers=[{"status": "violated", "code": "evidence_corrupt"}],
        )
        self.assertEqual(result["status"], "violated")
        self.assertEqual(result["candidate"]["status"], "blocked_by_violation")

    def test_suite_for_another_configuration_is_rejected(self) -> None:
        with self.assertRaisesRegex(StatusArtifactError, "another configuration"):
            self._build(
                suites={
                    "other": {
                        "configurationId": "minimal",
                        "caseIds": [],
                    }
                }
            )

    def test_wrong_configuration_binding_is_rejected(self) -> None:
        with self.assertRaisesRegex(StatusArtifactError, "another ID"):
            self._build(configuration_binding="other")

    def test_status_hash_is_deterministic(self) -> None:
        first = self._build()
        second = self._build()
        self.assertEqual(
            first["candidate_status_sha256"], second["candidate_status_sha256"]
        )


if __name__ == "__main__":
    unittest.main()
