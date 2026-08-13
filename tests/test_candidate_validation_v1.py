from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.candidate_validation_v1 import (
    CandidateValidationV1Error,
    build_candidate_validation_v1,
)


def _report(path: Path, *, digest: str, status: str = "pass") -> Path:
    path.write_text(
        json.dumps(
            {
                "format": "stage-b-functional-report-v1",
                "status": status,
                "binary_bindings": {
                    "candidate": {
                        "provided": True,
                        "exists": True,
                        "sha256": digest,
                    }
                },
                "cases": [{"id": "default", "status": status}],
            }
        ),
        encoding="ascii",
    )
    return path


class CandidateValidationV1Tests(unittest.TestCase):
    def test_matching_candidate_only_suites_complete(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            result = build_candidate_validation_v1(
                pe32_report=_report(root / "pe.json", digest="a" * 64),
                non_x86_report=_report(
                    root / "native.json", digest="b" * 64
                ),
            )
            self.assertEqual(result["status"], "complete")
            self.assertFalse(result["authority"]["proves_equivalence"])

    def test_failure_vetoes_and_duplicate_binary_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            result = build_candidate_validation_v1(
                pe32_report=_report(root / "pe.json", digest="a" * 64),
                non_x86_report=_report(
                    root / "native.json", digest="b" * 64, status="fail"
                ),
            )
            self.assertEqual(result["status"], "violated")
            with self.assertRaisesRegex(
                CandidateValidationV1Error, "same binary"
            ):
                build_candidate_validation_v1(
                    pe32_report=root / "pe.json",
                    non_x86_report=_report(
                        root / "same.json", digest="a" * 64
                    ),
                )


if __name__ == "__main__":
    unittest.main()
