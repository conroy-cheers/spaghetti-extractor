from __future__ import annotations

import copy
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from spaghetti_extractor.relational.lean.source_equivalence_final_report import (
    FINAL_REPORT_FILENAME,
    SourceEquivalenceFinalReportError,
    build_source_equivalence_final_report,
    write_source_equivalence_final_report,
)
from spaghetti_extractor.util import sha256_file


MODULE = (
    "spaghetti_extractor.relational.lean.source_equivalence_final_report"
)
THEOREM = (
    "StageA.GeneratedRelational.SourceAcceptance."
    "generatedSourceWholeProgramEquivalence"
)
TOOLCHAIN_AXIOM = "StageA.GeneratedRelational.Toolchain.pinnedLoweringCorrect"
ORIGINAL_SHA256 = "1" * 64
SOURCE_CLOSURE_SHA256 = "2" * 64
ATTESTATION_CORE_SHA256 = "3" * 64


def _write(path: Path, value: object) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="ascii"
    )
    return path


class _Fixture:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.candidate = root / "candidate.exe"
        self.candidate.write_bytes(b"MZ\x00checked-candidate")
        self.candidate_sha256 = sha256_file(self.candidate)
        self.candidate_size = self.candidate.stat().st_size

        self.proof_bundle = root / "proof"
        self.proof_bundle.mkdir()
        _write(
            self.proof_bundle / "bundle.json",
            {"format": "fixture-checked-lean-bundle-v1", "status": "checked"},
        )

        self.source_payload = {
            "format": "stage-b-native-interpreter-source-bundle-v1",
            "status": "ready",
            "load_image_contract": {
                "bound_original_pe_sha256": ORIGINAL_SHA256,
            },
            "hashes": {
                "algorithm": "sha256",
                "source_bundle_sha256": SOURCE_CLOSURE_SHA256,
            },
            "trust": {
                "acceptance_authority": False,
                "package_manifests_are_proposals": True,
                "original_binary_executed": False,
                "original_binary_consumed_statically": True,
                "lean_whole_program_proof_required": True,
                "compiler_correctness_assumed_by_source_equivalence": True,
            },
        }
        self.source = _write(root / "source-bundle.json", self.source_payload)

        self.attestation_payload = {
            "format": "stage-b-native-interpreter-compilation-attestation-v1",
            "status": "complete",
            "source_bundle": {
                "artifact_sha256": sha256_file(self.source),
                "source_bundle_sha256": SOURCE_CLOSURE_SHA256,
            },
            "candidate": {
                "path": str(self.candidate),
                "sha256": self.candidate_sha256,
                "size": self.candidate_size,
            },
            "hashes": {
                "algorithm": "sha256",
                "attestation_core_sha256": ATTESTATION_CORE_SHA256,
            },
            "trust": {
                "acceptance_authority": False,
                "build_manifest_is_provenance_not_proof": True,
                "nix_metadata_requires_independent_store_validation": True,
                "compiler_assembler_linker_correctness_assumed": True,
                "lean_whole_program_proof_required": True,
            },
        }
        self.attestation = _write(
            root / "compilation-attestation.json", self.attestation_payload
        )

        self.candidate_metadata_payload = {
            "format": "stage-a-native-source-candidate-static-authority-v1",
            "phase": "native-source-candidate-static-authority",
            "status": "source-ready",
            "candidate": {
                "path": str(self.candidate),
                "sha256": self.candidate_sha256,
                "size": self.candidate_size,
            },
            "module": "GeneratedCandidateStaticAuthority",
            "compiled_identity_interface": {},
            "trust": {
                "executes_original_binary": False,
                "executes_candidate_binary": False,
                "exact_candidate_bytes_checked_in_lean": True,
                "imports_parsed_from_candidate_exe": True,
                "relocations_parsed_from_candidate_exe": True,
                "environment_parameterized": True,
                "indirect_target_shape_is_completeness": False,
                "indirect_target_completeness_proved": False,
                "whole_program_acceptance_authority": False,
            },
        }
        self.candidate_metadata = _write(
            root / "candidate-pe-metadata.json", self.candidate_metadata_payload
        )

        self.functional_payload = {
            "format": "stage-b-functional-report-v1",
            "runner": {
                "name": "stage-b-run-functional-suite",
                "report_format": "stage-b-functional-report-v1",
                "strip_stderr_line_regexes": [],
            },
            "status": "pass",
            "target_name": "fixture-program",
            "suite_id": "fixture-public-behavior",
            "oracle": {
                "kind": "expected_output",
                "original_runtime_observations": False,
            },
            "commands": {
                "candidate": [
                    "xvfb-run",
                    "-a",
                    "wine",
                    str(self.candidate),
                ]
            },
            "binary_bindings": {
                "candidate": {
                    "provided": True,
                    "path": str(self.candidate),
                    "exists": True,
                    "command_contains_path": True,
                    "command": [
                        "xvfb-run",
                        "-a",
                        "wine",
                        str(self.candidate),
                    ],
                    "sha256": self.candidate_sha256,
                    "size": self.candidate_size,
                }
            },
            "counts": {"cases": 2, "passed": 2, "failed": 0},
            "cases": [
                {"id": "default", "status": "pass"},
                {"id": "help", "status": "pass"},
            ],
        }
        self.functional = _write(
            root / "functional-report.json", self.functional_payload
        )

        self.audit_payload = {
            "format": "stage-a-checked-detached-axiom-audit-v1",
            "status": "checked",
            "declaration": THEOREM,
            "inventory": ["Quot.sound", TOOLCHAIN_AXIOM],
            "approved_axioms": [
                "propext",
                "Classical.choice",
                "Quot.sound",
                TOOLCHAIN_AXIOM,
            ],
            "required_axioms": [TOOLCHAIN_AXIOM],
            "proof_bundle": str(self.proof_bundle),
        }
        self.audit = _write(root / "audit" / "axiom-audit.json", self.audit_payload)

        self.acceptance_payload = {
            "format": "stage-a-native-source-conditional-acceptance-checked-v1",
            "status": "checked",
            "theorem": THEOREM,
            "approved_toolchain_axiom": TOOLCHAIN_AXIOM,
            "proof_bundle": str(self.proof_bundle),
            "detached_axiom_audit": str(self.audit.parent),
            "runtime_authority": False,
            "execution": {
                "original_binary_executed": False,
                "candidate_binary_executed": False,
            },
            "bindings": {
                "source_bundle_artifact_sha256": sha256_file(self.source),
                "source_bundle_sha256": SOURCE_CLOSURE_SHA256,
                "compilation_attestation_artifact_sha256": sha256_file(
                    self.attestation
                ),
                "attestation_core_sha256": ATTESTATION_CORE_SHA256,
                "original_pe_sha256": ORIGINAL_SHA256,
                "candidate_pe_sha256": self.candidate_sha256,
                "candidate_pe_size": self.candidate_size,
            },
        }
        self.acceptance = _write(
            root / "checked-acceptance.json", self.acceptance_payload
        )

    def build(self) -> dict[str, object]:
        with (
            patch(
                f"{MODULE}.validate_native_source_bundle_manifest",
                return_value=copy.deepcopy(self.source_payload),
            ) as source_validator,
            patch(
                f"{MODULE}.validate_native_source_compilation_attestation",
                return_value=copy.deepcopy(self.attestation_payload),
            ) as attestation_validator,
        ):
            report = build_source_equivalence_final_report(
                checked_acceptance=self.acceptance,
                detached_axiom_audit=self.audit,
                source_bundle=self.source,
                compilation_attestation=self.attestation,
                candidate_pe_metadata=self.candidate_metadata,
                functional_report=self.functional,
                approved_toolchain_axiom=TOOLCHAIN_AXIOM,
            )
        source_validator.assert_called_once_with(self.source.resolve())
        attestation_validator.assert_called_once_with(self.attestation.resolve())
        return report

    def rewrite(self, name: str, payload: object) -> None:
        path = getattr(self, name)
        _write(path, payload)


class StageASourceEquivalenceFinalReportTests(unittest.TestCase):
    def test_emits_conditional_pass_with_reconciled_provenance(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = _Fixture(Path(temporary))
            report = fixture.build()

            self.assertEqual(report["format"], "stage-a-source-equivalence-report-v1")
            self.assertEqual(report["verdict"], "conditional_pass")
            self.assertEqual(report["status"], "conditional_pass")
            self.assertEqual(report["theorem"], THEOREM)
            self.assertEqual(report["original"], {"pe_sha256": ORIGINAL_SHA256})
            self.assertEqual(
                report["candidate"],
                {
                    "pe_sha256": fixture.candidate_sha256,
                    "size": fixture.candidate_size,
                },
            )
            self.assertEqual(
                report["approved_premise"],
                {
                    "kind": "pinned_toolchain_correctness",
                    "lean_axiom": TOOLCHAIN_AXIOM,
                    "conditional": True,
                    "only_nonlogical_axiom": True,
                },
            )
            self.assertEqual(report["runtime_validation"]["cases"], 2)
            self.assertEqual(
                report["runtime_validation"]["original_runtime_executions"], 0
            )
            self.assertFalse(report["runtime_validation"]["runtime_authority"])
            self.assertTrue(report["zero_original_runtime"]["asserted"])
            self.assertFalse(report["acceptance_authority"])
            self.assertFalse(report["proof_authority"])
            self.assertFalse(report["trust"]["generated_json_is_authority"])
            self.assertFalse(report["trust"]["runtime_validation_is_authority"])
            self.assertEqual(
                set(report["input_sha256s"]),
                {
                    "checked_acceptance",
                    "detached_axiom_audit",
                    "source_bundle",
                    "compilation_attestation",
                    "candidate_pe_metadata",
                    "functional_report",
                },
            )

    def test_writer_is_byte_reproducible(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = _Fixture(Path(temporary))
            out = fixture.root / "out"
            with (
                patch(
                    f"{MODULE}.validate_native_source_bundle_manifest",
                    return_value=copy.deepcopy(fixture.source_payload),
                ),
                patch(
                    f"{MODULE}.validate_native_source_compilation_attestation",
                    return_value=copy.deepcopy(fixture.attestation_payload),
                ),
            ):
                first = write_source_equivalence_final_report(
                    out=out,
                    checked_acceptance=fixture.acceptance,
                    detached_axiom_audit=fixture.audit,
                    source_bundle=fixture.source,
                    compilation_attestation=fixture.attestation,
                    candidate_pe_metadata=fixture.candidate_metadata,
                    functional_report=fixture.functional,
                    approved_toolchain_axiom=TOOLCHAIN_AXIOM,
                )
                first_bytes = (out / FINAL_REPORT_FILENAME).read_bytes()
                second = write_source_equivalence_final_report(
                    out=out,
                    checked_acceptance=fixture.acceptance,
                    detached_axiom_audit=fixture.audit,
                    source_bundle=fixture.source,
                    compilation_attestation=fixture.attestation,
                    candidate_pe_metadata=fixture.candidate_metadata,
                    functional_report=fixture.functional,
                    approved_toolchain_axiom=TOOLCHAIN_AXIOM,
                )
            self.assertEqual(first, second)
            self.assertEqual(first_bytes, (out / FINAL_REPORT_FILENAME).read_bytes())

    def test_rejects_unchecked_or_unbound_acceptance(self) -> None:
        mutations = (
            ("status", "incomplete"),
            ("runtime_authority", True),
            ("approved_toolchain_axiom", "StageA.Other.correct"),
        )
        for field, value in mutations:
            with self.subTest(field=field), tempfile.TemporaryDirectory() as temporary:
                fixture = _Fixture(Path(temporary))
                payload = copy.deepcopy(fixture.acceptance_payload)
                payload[field] = value
                fixture.rewrite("acceptance", payload)
                with self.assertRaises(SourceEquivalenceFinalReportError):
                    fixture.build()

        with tempfile.TemporaryDirectory() as temporary:
            fixture = _Fixture(Path(temporary))
            payload = copy.deepcopy(fixture.acceptance_payload)
            payload["bindings"]["candidate_pe_sha256"] = "f" * 64
            fixture.rewrite("acceptance", payload)
            with self.assertRaisesRegex(
                SourceEquivalenceFinalReportError, "provenance"
            ):
                fixture.build()

    def test_rejects_audit_with_wrong_theorem_or_axiom_policy(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = _Fixture(Path(temporary))
            payload = copy.deepcopy(fixture.audit_payload)
            payload["declaration"] = "StageA.Other.theorem"
            fixture.rewrite("audit", payload)
            with self.assertRaisesRegex(
                SourceEquivalenceFinalReportError, "accepted theorem"
            ):
                fixture.build()

        with tempfile.TemporaryDirectory() as temporary:
            fixture = _Fixture(Path(temporary))
            payload = copy.deepcopy(fixture.audit_payload)
            payload["inventory"].append("StageA.Unapproved.assumption")
            payload["approved_axioms"].append("StageA.Unapproved.assumption")
            fixture.rewrite("audit", payload)
            with self.assertRaisesRegex(
                SourceEquivalenceFinalReportError, "approve exactly"
            ):
                fixture.build()

        with tempfile.TemporaryDirectory() as temporary:
            fixture = _Fixture(Path(temporary))
            payload = copy.deepcopy(fixture.audit_payload)
            payload["required_axioms"] = []
            fixture.rewrite("audit", payload)
            with self.assertRaisesRegex(
                SourceEquivalenceFinalReportError, "require exactly"
            ):
                fixture.build()

    def test_rejects_any_original_runtime_observation_or_command(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = _Fixture(Path(temporary))
            payload = copy.deepcopy(fixture.functional_payload)
            payload["oracle"]["original_runtime_observations"] = True
            fixture.rewrite("functional", payload)
            with self.assertRaisesRegex(
                SourceEquivalenceFinalReportError, "zero-original"
            ):
                fixture.build()

        with tempfile.TemporaryDirectory() as temporary:
            fixture = _Fixture(Path(temporary))
            payload = copy.deepcopy(fixture.functional_payload)
            payload["commands"]["original"] = ["wine", "original.exe"]
            fixture.rewrite("functional", payload)
            with self.assertRaisesRegex(
                SourceEquivalenceFinalReportError, "candidate-only"
            ):
                fixture.build()

        with tempfile.TemporaryDirectory() as temporary:
            fixture = _Fixture(Path(temporary))
            source = copy.deepcopy(fixture.source_payload)
            source["trust"]["original_binary_executed"] = True
            with patch(
                f"{MODULE}.validate_native_source_bundle_manifest",
                return_value=source,
            ), patch(
                f"{MODULE}.validate_native_source_compilation_attestation",
                return_value=copy.deepcopy(fixture.attestation_payload),
            ):
                with self.assertRaisesRegex(
                    SourceEquivalenceFinalReportError, "trust boundary"
                ):
                    build_source_equivalence_final_report(
                        checked_acceptance=fixture.acceptance,
                        detached_axiom_audit=fixture.audit,
                        source_bundle=fixture.source,
                        compilation_attestation=fixture.attestation,
                        candidate_pe_metadata=fixture.candidate_metadata,
                        functional_report=fixture.functional,
                        approved_toolchain_axiom=TOOLCHAIN_AXIOM,
                    )

    def test_rejects_failed_or_wrong_candidate_functional_report(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = _Fixture(Path(temporary))
            payload = copy.deepcopy(fixture.functional_payload)
            payload["status"] = "fail"
            payload["counts"] = {"cases": 2, "passed": 1, "failed": 1}
            payload["cases"][1]["status"] = "fail"
            fixture.rewrite("functional", payload)
            with self.assertRaisesRegex(
                SourceEquivalenceFinalReportError, "did not pass"
            ):
                fixture.build()

        with tempfile.TemporaryDirectory() as temporary:
            fixture = _Fixture(Path(temporary))
            payload = copy.deepcopy(fixture.functional_payload)
            payload["binary_bindings"]["candidate"]["sha256"] = "f" * 64
            fixture.rewrite("functional", payload)
            with self.assertRaisesRegex(
                SourceEquivalenceFinalReportError, "checked candidate"
            ):
                fixture.build()

    def test_rejects_stale_candidate_bytes_and_attestation_disagreement(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = _Fixture(Path(temporary))
            fixture.candidate.write_bytes(b"changed")
            with self.assertRaisesRegex(
                SourceEquivalenceFinalReportError, "differ from checked metadata"
            ):
                fixture.build()

        with tempfile.TemporaryDirectory() as temporary:
            fixture = _Fixture(Path(temporary))
            attestation = copy.deepcopy(fixture.attestation_payload)
            attestation["candidate"]["sha256"] = "f" * 64
            with (
                patch(
                    f"{MODULE}.validate_native_source_bundle_manifest",
                    return_value=copy.deepcopy(fixture.source_payload),
                ),
                patch(
                    f"{MODULE}.validate_native_source_compilation_attestation",
                    return_value=attestation,
                ),
            ):
                with self.assertRaisesRegex(
                    SourceEquivalenceFinalReportError, "disagree"
                ):
                    build_source_equivalence_final_report(
                        checked_acceptance=fixture.acceptance,
                        detached_axiom_audit=fixture.audit,
                        source_bundle=fixture.source,
                        compilation_attestation=fixture.attestation,
                        candidate_pe_metadata=fixture.candidate_metadata,
                        functional_report=fixture.functional,
                        approved_toolchain_axiom=TOOLCHAIN_AXIOM,
                    )

    def test_rejects_duplicate_json_fields(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = _Fixture(Path(temporary))
            fixture.functional.write_text(
                '{"format":"stage-b-functional-report-v1",'
                '"status":"pass","status":"fail"}\n',
                encoding="ascii",
            )
            with self.assertRaisesRegex(
                SourceEquivalenceFinalReportError, "duplicate field"
            ):
                fixture.build()


if __name__ == "__main__":
    unittest.main()
