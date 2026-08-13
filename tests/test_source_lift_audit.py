from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.source_lift_audit import (
    audit_source_iteration,
    audit_source_lift,
)
from spaghetti_extractor.util import sha256_file, write_json
from tests.pe_fixtures import pe32_import_image


class SourceLiftAuditTests(unittest.TestCase):
    def test_reports_partial_source_binding_and_withholds_runtime(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            machine = root / "machine-ir-manifest.json"
            authority = root / "authority-diagnostics-v3.json"
            binding = root / "source-project-binding.json"
            evidence = root / "source-component-evidence.json"
            candidate = root / "source-project-build.json"
            candidate_binary = root / "candidate.exe"
            candidate_binary.write_bytes(pe32_import_image(b"\xc3", symbol="WriteFile"))
            write_json(
                machine,
                {
                    "format": "stage-a-machine-ir-v2",
                    "status": "incomplete",
                    "binary": {
                        "sha256": "a" * 64,
                        "imports": [
                            {
                                "dll": "kernel32.dll",
                                "symbol": "WriteFile",
                                "ordinal": None,
                            }
                        ],
                    },
                    "counts": {"units": 4},
                    "issues": [
                        {
                            "id": "issue:one",
                            "category": "indirect_target_deferred",
                            "location": {"rva_start": 0x1000},
                            "next_action": "recover the target",
                        }
                    ],
                },
            )
            write_json(
                authority,
                {
                    "format": "spaghetti-extractor-authority-diagnostics-v3",
                    "status": "incomplete",
                    "authorizing": False,
                    "binary_bindings": [
                        {
                            "name": "binary",
                            "kind": "pe32",
                            "identity": "fixture.exe",
                            "sha256": "a" * 64,
                        }
                    ],
                    "final_authority": {"status": "incomplete"},
                    "primary_frontiers": [{"code": "target_missing"}],
                },
            )
            write_json(
                binding,
                {
                    "format": "stage-b-source-project-binding-v1",
                    "status": "bound",
                    "equivalence_status": "not_proven",
                    "binding_sha256": "b" * 64,
                    "bindings": {
                        "machine_ir_manifest_sha256": sha256_file(machine),
                        "original_binary_sha256": "a" * 64,
                        "specification_sha256": "c" * 64,
                    },
                    "sources": [{"path": "hello.c", "sha256": "d" * 64}],
                    "coverage": {
                        "machine_units": 4,
                        "source_bound_units": 1,
                        "remaining_machine_units": 3,
                        "linked_islands": None,
                    },
                    "authority": {"proves_source_semantics": False},
                },
            )
            write_json(
                evidence,
                {
                    "format": "stage-b-source-component-evidence-plan-v1",
                    "source_project_specification_sha256": "c" * 64,
                    "plan_sha256": "e" * 64,
                    "accepted_assumptions": [
                        "machine_to_source_component_equivalence_not_proven"
                    ],
                },
            )
            write_json(
                candidate,
                {
                    "format": "stage-b-source-project-build-v1",
                    "status": "candidate-generated",
                    "inputs": {
                        "source_project_specification_sha256": "c" * 64,
                        "source_project_binding_sha256": "b" * 64,
                        "source_project_binding_artifact_sha256": sha256_file(
                            binding
                        ),
                        "sources": [
                            {"path": "hello.c", "sha256": "d" * 64}
                        ],
                    },
                    "outputs": {
                        "candidate": {
                            "path": "candidate.exe",
                            "sha256": sha256_file(candidate_binary),
                            "bytes": candidate_binary.stat().st_size,
                        }
                    },
                },
            )

            iteration = audit_source_iteration(
                machine_ir=machine,
                source_binding=binding,
                source_evidence_plan=evidence,
                candidate_build=candidate,
                out=root / "iteration.json",
            )
            report = audit_source_lift(
                machine_ir=machine,
                authority_diagnostics=authority,
                source_binding=binding,
                source_evidence_plan=evidence,
                candidate_build=candidate,
                out=root / "audit.json",
            )

            candidate_binary.write_bytes(
                pe32_import_image(b"\xc3", symbol="ExitProcess")
            )
            candidate_manifest = json.loads(
                candidate.read_text(encoding="utf-8")
            )
            candidate_manifest["outputs"]["candidate"].update(
                {
                    "sha256": sha256_file(candidate_binary),
                    "bytes": candidate_binary.stat().st_size,
                }
            )
            write_json(candidate, candidate_manifest)
            divergent = audit_source_lift(
                machine_ir=machine,
                authority_diagnostics=authority,
                source_binding=binding,
                source_evidence_plan=evidence,
                candidate_build=candidate,
                out=root / "audit-divergent.json",
            )

        self.assertEqual(report["status"], "incomplete")
        self.assertEqual(
            iteration["format"],
            "spaghetti-extractor-source-iteration-audit-v1",
        )
        self.assertEqual(
            iteration["stages"]["final_authority_join"]["status"],
            "not_evaluated",
        )
        self.assertNotIn(
            "static_authority_incomplete",
            {row["code"] for row in iteration["blockers"]},
        )
        self.assertFalse(
            iteration["stages"]["candidate_behavior"]["authorized_to_run"]
        )
        self.assertFalse(report["whole_program_lift_complete"])
        self.assertFalse(
            report["stages"]["candidate_behavior"]["authorized_to_run"]
        )
        self.assertEqual(
            {row["code"] for row in report["blockers"]},
            {
                "linked_island_classification_incomplete",
                "candidate_validation_not_joined",
                "static_authority_incomplete",
            },
        )
        self.assertEqual(report["machine_ir_frontiers"][0]["count"], 1)
        self.assertEqual(
            report["stages"]["candidate_import_surface"]["status"],
            "matching",
        )
        self.assertEqual(
            [row["code"] for row in report["warnings"]],
            ["machine_to_source_semantics_not_proven"],
        )
        self.assertEqual(
            divergent["stages"]["candidate_import_surface"]["status"],
            "different",
        )
        self.assertEqual(
            divergent["warnings"][1]["code"],
            "candidate_static_import_surface_differs",
        )


if __name__ == "__main__":
    unittest.main()
