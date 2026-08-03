from __future__ import annotations

import json
import tempfile
import unittest
from hashlib import sha256
from pathlib import Path

from spaghetti_extractor.source_project import (
    SourceProjectError,
    assess_source_project,
    bind_source_project,
    bind_source_project_specification,
)
from spaghetti_extractor.util import sha256_file, write_json


class SourceProjectTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.machine = self.root / "machine"
        self.machine.mkdir()
        units = [
            _unit(0x1000, 0x1004, [0x1004]),
            _unit(
                0x1004,
                0x1008,
                [],
                events=[
                    {
                        "kind": "internal_call",
                        "target_rva": 0x2000,
                        "return_rva": 0x1008,
                    }
                ],
            ),
            _unit(0x2000, 0x2001, []),
        ]
        ir = self.machine / "machine-ir.jsonl"
        ir.write_text(
            "".join(json.dumps(unit, sort_keys=True) + "\n" for unit in units),
            encoding="utf-8",
        )
        write_json(
            self.machine / "machine-ir-manifest.json",
            {
                "format": "stage-a-machine-ir-v2",
                "binary": {"sha256": "f" * 64},
                "artifacts": {
                    "machine_ir": {
                        "path": "machine-ir.jsonl",
                        "sha256": sha256_file(ir),
                    }
                },
            },
        )
        self.sources = self.root / "sources"
        self.sources.mkdir()
        (self.sources / "main.c").write_text("int main(void) { return 0; }\n", encoding="ascii")
        self.specification = bind_source_project_specification(
            {
                "format": "stage-b-source-project-spec-v1",
                "program_id": "fixture",
                "original_binary_sha256": "f" * 64,
                "sources": [{"path": "main.c"}],
                "coverage_scope": {
                    "kind": "reviewed_machine_ranges",
                    "required_ranges": [
                        {
                            "id": "application-text",
                            "rva_start": 0x1000,
                            "rva_end": 0x1008,
                            "provenance_hint": "fixture application object",
                        }
                    ],
                    "out_of_scope_policy": "linked_runtime_and_library_code",
                },
                "islands": [
                    {
                        "id": "entry",
                        "source_symbol": "main",
                        "entry_rvas": [0x1000],
                        "ranges": [{"rva_start": 0x1000, "rva_end": 0x1008}],
                    }
                ],
            }
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_static_binding_records_exact_units_and_boundary_calls(self) -> None:
        out = self.root / "binding.json"
        payload = bind_source_project(
            machine_ir=self.machine,
            specification=self.specification,
            source_root=self.sources,
            out=out,
        )

        self.assertEqual(payload["status"], "bound")
        self.assertEqual(payload["equivalence_status"], "not_proven")
        self.assertFalse(payload["executes_original_binary"])
        self.assertEqual(payload["coverage"]["source_bound_units"], 2)
        self.assertEqual(payload["coverage"]["remaining_machine_units"], 1)
        scope = payload["coverage"]["reviewed_scope"]
        self.assertTrue(scope["fully_source_bound"])
        self.assertEqual(scope["required_machine_units"], 2)
        self.assertEqual(scope["remaining_machine_units"], 0)
        boundary = payload["islands"][0]["boundary"]
        self.assertEqual(boundary["counts"]["internal_calls"], 1)
        self.assertEqual(boundary["internal_calls"][0]["target_rva"], 0x2000)
        self.assertFalse(payload["authority"]["proves_source_semantics"])

    def test_linked_islands_make_out_of_scope_ownership_explicit(self) -> None:
        linked = self._linked_island_manifest()
        payload = bind_source_project(
            machine_ir=self.machine,
            specification=self.specification,
            source_root=self.sources,
            linked_islands=linked,
            out=self.root / "binding.json",
        )

        scope = payload["coverage"]["linked_islands"]
        self.assertEqual(scope["units_by_kind"]["application"], 2)
        self.assertEqual(scope["units_by_kind"]["linked_dependency"], 1)
        self.assertEqual(scope["remaining_application_units"], 0)
        self.assertTrue(scope["all_source_units_are_reviewed_application"])
        self.assertFalse(
            payload["authority"][
                "linked_dependency_identity_authorizes_source_replacement"
            ]
        )

    def test_source_binding_rejects_non_application_linked_units(self) -> None:
        linked = self._linked_island_manifest()
        linked["islands"][0]["kind"] = "linked_dependency"
        linked["coverage"]["units_by_kind"] = {"linked_dependency": 3}
        linked["manifest_sha256"] = _canonical_sha256(
            {key: value for key, value in linked.items() if key != "manifest_sha256"}
        )
        with self.assertRaisesRegex(SourceProjectError, "reviewed application units"):
            bind_source_project(
                machine_ir=self.machine,
                specification=self.specification,
                source_root=self.sources,
                linked_islands=linked,
                out=self.root / "binding.json",
            )

    def test_range_that_cuts_a_machine_unit_fails_closed(self) -> None:
        spec = json.loads(json.dumps(self.specification))
        spec["islands"][0]["ranges"][0]["rva_end"] = 0x1006
        spec = bind_source_project_specification(spec)
        with self.assertRaisesRegex(SourceProjectError, "cuts machine unit"):
            bind_source_project(
                machine_ir=self.machine,
                specification=spec,
                source_root=self.sources,
                out=self.root / "binding.json",
            )

    def _linked_island_manifest(self) -> dict[str, object]:
        ir = self.machine / "machine-ir.jsonl"
        manifest = self.machine / "machine-ir-manifest.json"
        units = ["unit:00001000", "unit:00001004", "unit:00002000"]
        core: dict[str, object] = {
            "format": "stage-b-linked-island-manifest-v1",
            "status": "classified",
            "executes_original_binary": False,
            "bindings": {
                "original_binary_sha256": "f" * 64,
                "machine_ir_sha256": sha256_file(ir),
                "machine_ir_manifest_sha256": sha256_file(manifest),
            },
            "islands": [
                {
                    "id": "application",
                    "kind": "application",
                    "unit_ids": units[:2],
                    "unit_count": 2,
                    "replacement_authorized": False,
                },
                {
                    "id": "linked-runtime",
                    "kind": "linked_dependency",
                    "unit_ids": units[2:],
                    "unit_count": 1,
                    "replacement_authorized": False,
                },
            ],
            "coverage": {
                "machine_units": len(units),
                "classified_units": len(units),
                "classified_exactly_once": True,
                "units_by_kind": {"application": 2, "linked_dependency": 1},
                "unknown_units": 0,
            },
            "authority": {
                "artifact_recognition_authorizes_replacement": False,
                "semantic_qualification_required": True,
            },
        }
        return {**core, "manifest_sha256": _canonical_sha256(core)}

    def test_reviewed_scope_requires_every_machine_unit_to_be_bound(self) -> None:
        spec = json.loads(json.dumps(self.specification))
        spec["islands"][0]["ranges"][0]["rva_end"] = 0x1004
        spec = bind_source_project_specification(spec)
        with self.assertRaisesRegex(SourceProjectError, "exactly cover"):
            bind_source_project(
                machine_ir=self.machine,
                specification=spec,
                source_root=self.sources,
                out=self.root / "binding.json",
            )

    def test_candidate_only_assurance_never_claims_equivalence(self) -> None:
        binding = self.root / "binding.json"
        bind_source_project(
            machine_ir=self.machine,
            specification=self.specification,
            source_root=self.sources,
            out=binding,
        )
        candidate = self.root / "candidate.exe"
        candidate.write_bytes(b"MZcandidate")
        report = self.root / "functional.json"
        write_json(
            report,
            {
                "format": "stage-b-functional-report-v1",
                "status": "pass",
                "suite_id": "fixture-suite",
                "counts": {"cases": 3, "passed": 3, "failed": 0},
                "oracle": {"original_runtime_observations": False},
                "binary_bindings": {
                    "candidate": {
                        "provided": True,
                        "exists": True,
                        "sha256": sha256_file(candidate),
                    }
                },
            },
        )

        payload = assess_source_project(
            binding=binding,
            candidate_binary=candidate,
            functional_report=report,
            out=self.root / "assurance.json",
        )

        self.assertEqual(payload["status"], "behavior_validated")
        self.assertEqual(payload["equivalence_status"], "not_proven")
        self.assertFalse(payload["authority"]["proves_equivalence"])

        failed_report = json.loads(report.read_text(encoding="utf-8"))
        failed_report["status"] = "fail"
        failed_report["counts"] = {"cases": 3, "passed": 2, "failed": 1}
        write_json(report, failed_report)
        failed = assess_source_project(
            binding=binding,
            candidate_binary=candidate,
            functional_report=report,
            out=self.root / "failed.json",
        )
        self.assertEqual(failed["status"], "violated")

        write_json(
            report,
            {
                **failed_report,
                "status": "pass",
                "counts": {"cases": 3, "passed": 3, "failed": 0},
            },
        )

        stale_candidate = self.root / "stale.exe"
        stale_candidate.write_bytes(b"MZstale")
        with self.assertRaisesRegex(SourceProjectError, "not bound"):
            assess_source_project(
                binding=binding,
                candidate_binary=stale_candidate,
                functional_report=report,
                out=self.root / "stale.json",
            )

        functional = json.loads(report.read_text(encoding="utf-8"))
        functional["oracle"]["original_runtime_observations"] = True
        write_json(report, functional)
        with self.assertRaisesRegex(SourceProjectError, "candidate-only oracle"):
            assess_source_project(
                binding=binding,
                candidate_binary=candidate,
                functional_report=report,
                out=self.root / "rejected.json",
            )


def _unit(start: int, end: int, targets: list[int], *, events: list[dict] | None = None) -> dict:
    return {
        "id": f"unit:{start:08x}",
        "source": {
            "contract_sha256": f"{start:064x}"[-64:],
            "instruction_bytes_sha256": f"{end:064x}"[-64:],
            "original": {"rva_start": start, "rva_end": end},
        },
        "control": {"kind": "fallthrough", "direct_targets": targets},
        "semantics": {"external_events": events or []},
    }


def _canonical_sha256(value: object) -> str:
    return sha256(
        json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("ascii")
    ).hexdigest()


if __name__ == "__main__":
    unittest.main()
