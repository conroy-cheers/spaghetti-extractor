from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.analysis_v3.diagnostics import (
    AUTHORITY_DIAGNOSTICS_V3_FORMAT,
    summarize_authority_artifacts_v3,
)
from spaghetti_extractor.artifact_set_v3 import (
    ArtifactBindingV3,
    ArtifactRecordV3,
    ArtifactSetWriterV3,
    write_artifact_bundle_v3,
)


BINDING = ArtifactBindingV3("binary", "pe32", "fixture.exe", "a" * 64)


def _write(
    path: Path, kind: str, records: tuple[ArtifactRecordV3, ...]
) -> Path:
    ArtifactSetWriterV3(
        artifact_kind=kind,
        bindings=(BINDING,),
    ).write(path, records)
    return path


class AuthorityDiagnosticsV3Tests(unittest.TestCase):
    def test_reports_primary_frontier_with_exact_source_location(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            semantic = _write(
                root / "semantic",
                "semantic-index-v3",
                (
                    ArtifactRecordV3.create(
                        "unit:one",
                        {
                            "rva_start": 0x1000,
                            "rva_end": 0x1010,
                            "unit_sha256": "b" * 64,
                        },
                    ),
                ),
            )
            family = _write(
                root / "family",
                "callback-authority-v3",
                (
                    ArtifactRecordV3.create(
                        "unit:one",
                        {
                            "status": "incomplete",
                            "authorizing": False,
                            "primary_blocker": {
                                "status": "incomplete",
                                "code": "callback_evidence_missing",
                                "input": "callback_evidence",
                                "record_id": "callback:one",
                            },
                        },
                    ),
                ),
            )
            family_bundle = root / "family-bundle"
            write_artifact_bundle_v3(
                family_bundle,
                (family,),
                ("unit:one",),
                expected_kind="callback-authority-v3",
            )
            final = _write(
                root / "final",
                "final-authority-v3",
                (
                    ArtifactRecordV3.create(
                        "final:one",
                        {
                            "status": "incomplete",
                            "authorizing": False,
                            "exact_unit_count": 1,
                            "primary_blocker": {
                                "status": "incomplete",
                                "code": "callback_authority_not_complete",
                            },
                        },
                    ),
                ),
            )

            report = summarize_authority_artifacts_v3(
                {
                    "callback-authority-v3": family_bundle,
                    "final-authority-v3": final,
                    "semantic-index-v3": semantic,
                },
                graph_manifest={
                    "phases": [
                        {
                            "phase_id": "callback-authority-v3",
                            "inputs": {
                                "callback_evidence": {
                                    "source": "external",
                                    "id": "callback_evidence",
                                }
                            },
                        },
                        {"phase_id": "final-authority-v3", "inputs": {}},
                    ]
                },
            )

        self.assertEqual(report["format"], AUTHORITY_DIAGNOSTICS_V3_FORMAT)
        self.assertEqual(report["status"], "incomplete")
        self.assertFalse(report["authorizing"])
        self.assertEqual(
            report["binary_bindings"],
            [
                {
                    "name": "binary",
                    "kind": "pe32",
                    "identity": "fixture.exe",
                    "sha256": "a" * 64,
                }
            ],
        )
        self.assertFalse(
            report["trust"]["authorizes_candidate_generation"]
        )
        callback = next(
            row
            for row in report["primary_frontiers"]
            if row["code"] == "callback_evidence_missing"
        )
        self.assertEqual(callback["source_location"]["rva_start"], 0x1000)
        self.assertEqual(callback["family"], "external:callback_evidence")
        self.assertEqual(callback["record_id"], "callback:one")
        self.assertEqual(callback["dependent_occurrences"], 1)
        self.assertIn("checked dependency", callback["next_action"])

    def test_collapses_transitive_blockers_to_one_root_record(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            upstream = _write(
                root / "upstream",
                "upstream-v3",
                (
                    ArtifactRecordV3.create(
                        "unit:one",
                        {
                            "status": "incomplete",
                            "authorizing": False,
                            "primary_blocker": {
                                "status": "incomplete",
                                "code": "evidence_missing",
                                "input": "evidence",
                                "record_id": "evidence:one",
                            },
                        },
                    ),
                ),
            )
            downstream = _write(
                root / "downstream",
                "downstream-v3",
                tuple(
                    ArtifactRecordV3.create(
                        record_id,
                        {
                            "status": "incomplete",
                            "authorizing": False,
                            "primary_blocker": {
                                "status": "incomplete",
                                "code": "upstream_not_complete",
                                "input": "upstream",
                                "record_id": "unit:one",
                            },
                        },
                    )
                    for record_id in ("dependent:a", "dependent:b")
                ),
            )
            report = summarize_authority_artifacts_v3(
                {"upstream": upstream, "downstream": downstream},
                graph_manifest={
                    "phases": [
                        {
                            "phase_id": "upstream",
                            "inputs": {
                                "evidence": {
                                    "source": "external",
                                    "id": "evidence",
                                }
                            },
                        },
                        {
                            "phase_id": "downstream",
                            "inputs": {
                                "upstream": {
                                    "source": "phase",
                                    "id": "upstream",
                                }
                            },
                        },
                    ]
                },
            )

        self.assertEqual(report["counts"]["primary_frontiers"], 1)
        self.assertEqual(report["primary_frontiers"][0]["record_id"], "evidence:one")
        # The upstream authority record and both downstream records all point
        # at the same repair item.
        self.assertEqual(report["primary_frontiers"][0]["dependent_occurrences"], 3)
        self.assertGreaterEqual(report["counts"]["dependent_occurrences"], 2)


if __name__ == "__main__":
    unittest.main()
