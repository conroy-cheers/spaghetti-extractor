from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.target_bundles.metadata import (
    TargetMetadata,
    TargetMetadataError,
)
from spaghetti_extractor.target_bundles.progress import build_project_progress


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


class ProjectProgressTests(unittest.TestCase):
    def _build(
        self, authority: dict[str, object], configuration: dict[str, object]
    ) -> dict[str, object]:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            authority_path = root / "authority.json"
            configuration_path = root / "configuration.json"
            output = root / "progress.json"
            authority_path.write_text(json.dumps(authority), encoding="ascii")
            configuration_path.write_text(json.dumps(configuration), encoding="ascii")
            return build_project_progress(
                target_id="fixture",
                configuration_id="default",
                authority_diagnostics=authority_path,
                configuration_status=configuration_path,
                candidate_test_suites={
                    "public": {
                        "configurationId": "default",
                        "caseIds": ["help"],
                    }
                },
                out=output,
            )

    def test_incomplete_authority_is_the_primary_frontier(self) -> None:
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
            },
            {
                "configuration_id": "default",
                "status": "ready",
                "counts": {"blocked": 0},
                "blockers": [],
            },
        )
        self.assertEqual(result["status"], "incomplete")
        self.assertEqual(result["candidate"]["status"], "blocked_by_authority")
        self.assertEqual(result["counts"]["candidate_test_suites"], 1)
        self.assertEqual(result["counts"]["dependent_occurrences"], 4)
        self.assertFalse(result["authorizing"])

    def test_ready_inputs_report_candidate_build_as_next_step(self) -> None:
        result = self._build(
            {
                "status": "complete",
                "authorizing": True,
                "counts": {
                    "primary_frontiers": 0,
                    "dependent_occurrences": 0,
                },
                "primary_frontiers": [],
            },
            {
                "configuration_id": "default",
                "status": "ready",
                "counts": {"blocked": 0},
                "blockers": [],
            },
        )
        self.assertEqual(result["status"], "ready")
        self.assertTrue(result["static_ready"])
        self.assertEqual(result["candidate"]["status"], "ready_to_build")

    def test_analysis_only_target_reports_component_bootstrap_frontier(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            authority_path = root / "authority.json"
            output = root / "progress.json"
            authority_path.write_text(
                json.dumps(
                    {
                        "status": "complete",
                        "authorizing": True,
                        "counts": {"primary_frontiers": 0, "dependent_occurrences": 0},
                        "primary_frontiers": [],
                    }
                ),
                encoding="ascii",
            )
            result = build_project_progress(
                target_id="fixture",
                configuration_id=None,
                authority_diagnostics=authority_path,
                configuration_status=None,
                candidate_test_suites={},
                out=output,
            )
        self.assertEqual(result["status"], "incomplete")
        self.assertEqual(result["configuration_id"], None)
        self.assertEqual(result["candidate"]["status"], "blocked_by_component_intent")
        self.assertEqual(
            result["primary_frontiers"][0]["code"], "component_intent_required"
        )


if __name__ == "__main__":
    unittest.main()
