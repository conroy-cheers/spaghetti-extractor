from __future__ import annotations

import json
import tempfile
import unittest
from hashlib import sha256
from pathlib import Path

from spaghetti_extractor.source_project import (
    SourceProjectError,
    assess_source_components,
    assess_source_project,
    bind_source_component_evidence_plan,
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
                "cases": [
                    {"id": "case-1", "status": "pass"},
                    {"id": "case-2", "status": "pass"},
                    {"id": "case-3", "status": "pass"},
                ],
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
        failed_report["cases"][0]["status"] = "fail"
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
                "cases": [
                    {"id": "case-1", "status": "pass"},
                    {"id": "case-2", "status": "pass"},
                    {"id": "case-3", "status": "pass"},
                ],
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

    def test_assurance_can_require_a_full_upstream_shell_suite(self) -> None:
        binding = self.root / "binding.json"
        bind_source_project(
            machine_ir=self.machine,
            specification=self.specification,
            source_root=self.sources,
            out=binding,
        )
        candidate = self.root / "candidate.exe"
        candidate.write_bytes(b"MZcandidate")
        candidate_sha256 = sha256_file(candidate)
        functional = self.root / "functional.json"
        write_json(
            functional,
            {
                "format": "stage-b-functional-report-v1",
                "status": "pass",
                "suite_id": "fixture-extended",
                "counts": {"cases": 1, "passed": 1, "failed": 0},
                "cases": [{"id": "functional-1", "status": "pass"}],
                "oracle": {"original_runtime_observations": False},
                "binary_bindings": {
                    "candidate": {
                        "provided": True,
                        "exists": True,
                        "sha256": candidate_sha256,
                    }
                },
            },
        )
        upstream = self.root / "upstream.json"
        upstream_payload = {
            "format": "stage-b-upstream-shell-suite-report-v1",
            "status": "pass",
            "suite_id": "fixture-upstream",
            "suite_scope": "full",
            "upstream_suite": True,
            "source_revision": "1.0",
            "executes_original_binary": False,
            "oracle": {"original_runtime_observations": False},
            "counts": {"cases": 1, "passed": 1, "failed": 0},
            "cases": [
                {
                    "format": "stage-b-upstream-shell-case-report-v1",
                    "id": "upstream-1",
                    "status": "pass",
                    "executes_original_binary": False,
                    "candidate_binary_sha256": candidate_sha256,
                }
            ],
        }
        write_json(upstream, upstream_payload)

        payload = assess_source_project(
            binding=binding,
            candidate_binary=candidate,
            functional_report=functional,
            upstream_report=upstream,
            out=self.root / "assurance.json",
        )

        self.assertEqual(payload["status"], "behavior_validated")
        self.assertTrue(payload["authority"]["full_upstream_suite_required"])
        self.assertEqual(
            payload["functional"]["upstream_suite"]["counts"],
            {"cases": 1, "passed": 1, "failed": 0},
        )

        upstream_payload["cases"][0]["candidate_binary_sha256"] = "0" * 64
        write_json(upstream, upstream_payload)
        with self.assertRaisesRegex(SourceProjectError, "case binding is stale"):
            assess_source_project(
                binding=binding,
                candidate_binary=candidate,
                functional_report=functional,
                upstream_report=upstream,
                out=self.root / "stale-upstream.json",
            )

    def test_source_component_assurance_accounts_for_every_island(self) -> None:
        binding_path = self.root / "binding.json"
        binding = bind_source_project(
            machine_ir=self.machine,
            specification=self.specification,
            source_root=self.sources,
            out=binding_path,
        )
        inventory_core = {
            "format": "stage-b-source-call-inventory-v1",
            "bindings": {"sources": binding["sources"]},
            "definitions": [{"symbol": "callback"}, {"symbol": "main"}],
            "calls": [
                {
                    "id": "source-call:callback-output",
                    "callee": "puts",
                    "callee_scope": "external",
                    "enclosing_function": "callback",
                }
            ],
            "function_references": [
                {
                    "id": "source-function-reference:main-callback",
                    "kind": "function_value",
                    "enclosing_function": "main",
                    "target_symbol": "callback",
                    "target_scope": "source_local",
                }
            ],
            "counts": {
                "calls": 1,
                "direct": 1,
                "indirect": 0,
                "function_references": 1,
            },
        }
        inventory = {
            **inventory_core,
            "inventory_sha256": _canonical_sha256(inventory_core),
        }
        inventory_path = self.root / "inventory.json"
        write_json(inventory_path, inventory)
        report_core = {
            "format": "stage-b-source-call-binding-report-v1",
            "status": "incomplete",
            "bindings": {
                "source_inventory_sha256": inventory["inventory_sha256"]
            },
            "counts": {
                "source_calls": 1,
                "covered_by_source_component": 1,
                "unbound_source_local": 0,
            },
            "issues": [],
        }
        report_path = self.root / "source-call-report.json"
        write_json(
            report_path,
            {**report_core, "report_sha256": _canonical_sha256(report_core)},
        )
        candidate = self.root / "candidate.exe"
        candidate.write_bytes(b"MZcandidate")
        candidate_sha256 = sha256_file(candidate)
        functional_path = self.root / "functional.json"
        write_json(
            functional_path,
            {
                "format": "stage-b-functional-report-v1",
                "status": "pass",
                "suite_id": "fixture-functional",
                "counts": {"cases": 1, "passed": 1, "failed": 0},
                "cases": [{"id": "functional-1", "status": "pass"}],
                "oracle": {"original_runtime_observations": False},
                "binary_bindings": {
                    "candidate": {
                        "provided": True,
                        "exists": True,
                        "sha256": candidate_sha256,
                    }
                },
            },
        )
        upstream_path = self.root / "upstream.json"
        write_json(
            upstream_path,
            {
                "format": "stage-b-upstream-shell-suite-report-v1",
                "status": "pass",
                "suite_id": "fixture-upstream",
                "suite_scope": "full",
                "upstream_suite": True,
                "source_revision": "1.0",
                "executes_original_binary": False,
                "oracle": {"original_runtime_observations": False},
                "counts": {"cases": 1, "passed": 1, "failed": 0},
                "cases": [
                    {
                        "format": "stage-b-upstream-shell-case-report-v1",
                        "id": "upstream-1",
                        "status": "pass",
                        "executes_original_binary": False,
                        "candidate_binary_sha256": candidate_sha256,
                    }
                ],
            },
        )
        plan = bind_source_component_evidence_plan(
            {
                "format": "stage-b-source-component-evidence-plan-v1",
                "evidence_profile": "high-assurance-source-reconstruction-v1",
                "program_id": binding["program_id"],
                "source_project_specification_sha256": binding["bindings"][
                    "specification_sha256"
                ],
                "accepted_assumptions": [
                    "integration_coverage_is_not_exhaustive",
                    "machine_to_source_component_equivalence_not_proven",
                ],
                "components": [
                    {
                        "island_id": "entry",
                        "source_symbol": "main",
                        "functional_case_ids": ["functional-1"],
                        "upstream_case_ids": ["upstream-1"],
                    }
                ],
            }
        )

        payload = assess_source_components(
            binding=binding_path,
            source_inventory=inventory_path,
            source_call_report=report_path,
            functional_report=functional_path,
            upstream_report=upstream_path,
            evidence_plan=plan,
            out=self.root / "component-assurance.json",
        )

        self.assertEqual(payload["status"], "behavior_validated")
        self.assertEqual(payload["counts"]["behavior_validated"], 1)
        self.assertEqual(payload["issues"], [])
        self.assertEqual(
            payload["components"][0]["source"]["closure_symbols"],
            ["callback", "main"],
        )
        self.assertFalse(payload["authority"]["proves_equivalence"])
        self.assertFalse(payload["authority"]["can_authorize_machine_override"])


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
