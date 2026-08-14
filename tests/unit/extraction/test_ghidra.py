from __future__ import annotations

import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from spaghetti_extractor.extraction.ghidra import (
    GHIDRA_PROPOSAL_FORMAT,
    export_ghidra_proposal,
)
from spaghetti_extractor.stage_binary import StageAInputError
from spaghetti_extractor.util import sha256_file


class GhidraProposalTests(unittest.TestCase):
    def _payload(self, binary: Path) -> dict[str, object]:
        return {
            "schema_version": 1,
            "binary_sha256": sha256_file(binary),
            "program_name": binary.name,
            "image_base": 0x400000,
            "functions": [],
            "basic_blocks": [],
            "cfg_edges": [],
            "call_edges": [],
            "data_refs": [],
            "globals": [],
        }

    def test_complete_proposal_is_exactly_bound_and_non_authorizing(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            binary = root / "program.exe"
            binary.write_bytes(b"MZfixture")

            def run(command: list[str], **_: object) -> subprocess.CompletedProcess[str]:
                Path(command[9]).write_text(
                    json.dumps(self._payload(binary)), encoding="utf-8"
                )
                return subprocess.CompletedProcess(command, 0, "ok", "")

            with patch(
                "spaghetti_extractor.extraction.ghidra.subprocess.run",
                side_effect=run,
            ):
                report = export_ghidra_proposal(
                    binary=binary,
                    out=root / "out",
                    analyze_headless="fake-ghidra",
                )

            self.assertEqual(report["format"], GHIDRA_PROPOSAL_FORMAT)
            self.assertEqual(report["status"], "complete")
            self.assertEqual(report["authority"], "untrusted-proposal")
            self.assertIs(report["executes_original_binary"], False)
            self.assertEqual(report["binary"]["sha256"], sha256_file(binary))

    def test_stale_export_remains_incomplete(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            binary = root / "program.exe"
            binary.write_bytes(b"MZfixture")
            payload = self._payload(binary)
            payload["binary_sha256"] = "0" * 64

            def run(command: list[str], **_: object) -> subprocess.CompletedProcess[str]:
                Path(command[9]).write_text(json.dumps(payload), encoding="utf-8")
                return subprocess.CompletedProcess(command, 0, "", "")

            with patch(
                "spaghetti_extractor.extraction.ghidra.subprocess.run",
                side_effect=run,
            ):
                report = export_ghidra_proposal(
                    binary=binary,
                    out=root / "out",
                    analyze_headless="fake-ghidra",
                )
            self.assertEqual(report["status"], "incomplete")
            self.assertIn("different binary", report["issues"][0]["detail"])

    def test_tool_failure_is_an_incomplete_proposal(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            binary = root / "program.exe"
            binary.write_bytes(b"MZfixture")
            with patch(
                "spaghetti_extractor.extraction.ghidra.subprocess.run",
                return_value=subprocess.CompletedProcess([], 7, "", "failed"),
            ):
                report = export_ghidra_proposal(
                    binary=binary,
                    out=root / "out",
                    analyze_headless="fake-ghidra",
                )
            self.assertEqual(report["status"], "incomplete")
            self.assertEqual(report["returncode"], 7)

    def test_missing_binary_is_rejected_before_launch(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with self.assertRaises(StageAInputError):
                export_ghidra_proposal(
                    binary=root / "missing.exe",
                    out=root / "out",
                )


if __name__ == "__main__":
    unittest.main()
