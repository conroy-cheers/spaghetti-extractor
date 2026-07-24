from __future__ import annotations

import hashlib
import json
import re
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.errors import StageAInputError
from spaghetti_extractor.relational.lean.universal_paired_external_environment import (
    UNIVERSAL_PAIRED_EXTERNAL_ENVIRONMENT_FORMAT,
    UniversalPairedExternalEnvironmentBindings,
    universal_paired_external_environment_source,
    write_universal_paired_external_environment_source,
)


def _bindings() -> UniversalPairedExternalEnvironmentBindings:
    return UniversalPairedExternalEnvironmentBindings(
        original_module="StageA.GeneratedOriginalPE",
        candidate_module="StageA.GeneratedCandidatePE",
        static_import_module="StageA.GeneratedStaticImports",
        original_namespace="StageA.GeneratedOriginal",
        candidate_namespace="StageA.GeneratedCandidate",
        static_import_namespace="StageA.GeneratedStaticImports",
        original_bytes="originalBytes",
        candidate_bytes="candidateBytes",
        original_pe="originalPe",
        candidate_pe="candidatePe",
        original_imports="originalImports",
        candidate_imports="candidateImports",
        original_pe_parsed="originalPeParsed",
        candidate_pe_parsed="candidatePeParsed",
    )


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _machine_import_report(original_sha256: str) -> dict[str, object]:
    return {
        "format": "stage-a-static-machine-import-contracts-v1",
        "status": "ready",
        "inputs": {"original_sha256": original_sha256},
        "counts": {
            "required_reachable_imports": 2,
            "lean_profile_signatures": 2,
            "checked_boundary_proposals": 3,
        },
        "blockers": [],
    }


class StageAUniversalPairedExternalEnvironmentTests(unittest.TestCase):
    def test_emits_universal_response_and_exact_pe_pair_terms(self) -> None:
        source = universal_paired_external_environment_source(
            original_sha256="1" * 64,
            candidate_sha256="2" * 64,
            machine_import_report_sha256="3" * 64,
            bindings=_bindings(),
        )

        for expected in (
            "exactNormalizedImportInventoryChecked",
            "candidateStaticMachineImportProfileChecked",
            "sharedBoundaryMachineContractsChecked",
            "exactPinnedStaticMachineImportPair",
            "ExactPinnedUniversalPairedExternalEnvironmentCertificate",
            "StageA.GeneratedOriginal.originalPeParsed",
            "StageA.GeneratedCandidate.candidatePeParsed",
        ):
            self.assertIn(expected, source)
        self.assertIn(
            "UniversalPairedExternalEnvironmentCertificate", source
        )
        self.assertNotIn("WorldExternalEnvironment :=", source)
        for marker in ("sorry", "axiom", "unsafe"):
            self.assertIsNone(re.search(rf"\b{marker}\b", source), marker)

    def test_writer_is_hash_bound_and_reports_truthful_premises(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            original = root / "original.exe"
            candidate = root / "candidate.exe"
            report = root / "machine-import-report.json"
            original.write_bytes(b"exact original")
            candidate.write_bytes(b"exact candidate")
            report.write_text(
                json.dumps(_machine_import_report(_sha256(original.read_bytes()))),
                encoding="utf-8",
            )

            lean_path, manifest_path = (
                write_universal_paired_external_environment_source(
                    original_pe=original,
                    candidate_pe=candidate,
                    machine_import_report=report,
                    out_dir=root / "out",
                    bindings=_bindings(),
                )
            )

            self.assertTrue(lean_path.is_file())
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            self.assertEqual(
                manifest["format"],
                UNIVERSAL_PAIRED_EXTERNAL_ENVIRONMENT_FORMAT,
            )
            self.assertEqual(manifest["status"], "source-ready")
            self.assertFalse(manifest["proof_authority"])
            self.assertEqual(
                manifest["inputs"]["original_sha256"],
                _sha256(original.read_bytes()),
            )
            self.assertIn(
                "each_returning_site_has_a_universally_sound_response_relation",
                manifest["remaining_premises"],
            )
            self.assertIn(
                "protocol_and_callback_actions_have_separate_nested_frame_refinement",
                manifest["remaining_premises"],
            )

    def test_writer_rejects_stale_or_incomplete_machine_import_reports(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            original = root / "original.exe"
            candidate = root / "candidate.exe"
            report = root / "report.json"
            original.write_bytes(b"original")
            candidate.write_bytes(b"candidate")

            cases = [
                (
                    "stale",
                    _machine_import_report("0" * 64),
                    "does not match the exact original PE",
                ),
                (
                    "incomplete",
                    {
                        **_machine_import_report(
                            _sha256(original.read_bytes())
                        ),
                        "status": "incomplete",
                    },
                    "is not ready",
                ),
                (
                    "blocked",
                    {
                        **_machine_import_report(
                            _sha256(original.read_bytes())
                        ),
                        "blockers": [{"id": "missing"}],
                    },
                    "contains blockers",
                ),
            ]
            for name, payload, message in cases:
                with self.subTest(name=name):
                    report.write_text(json.dumps(payload), encoding="utf-8")
                    with self.assertRaisesRegex(StageAInputError, message):
                        write_universal_paired_external_environment_source(
                            original_pe=original,
                            candidate_pe=candidate,
                            machine_import_report=report,
                            out_dir=root / name,
                            bindings=_bindings(),
                        )

    def test_rejects_lean_name_and_hash_injection(self) -> None:
        with self.assertRaisesRegex(StageAInputError, "must be a Lean name"):
            UniversalPairedExternalEnvironmentBindings(
                **{
                    **_bindings().__dict__,
                    "candidate_pe": "candidatePe; axiom bad : False",
                }
            )
        with self.assertRaisesRegex(StageAInputError, "lowercase SHA-256"):
            universal_paired_external_environment_source(
                original_sha256="not-a-hash",
                candidate_sha256="2" * 64,
                machine_import_report_sha256="3" * 64,
                bindings=_bindings(),
            )


if __name__ == "__main__":
    unittest.main()
