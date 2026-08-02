from __future__ import annotations

import copy
import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.artifact_formats import (
    RECONSTRUCTION_PLAN_FORMAT,
    SEMANTIC_COMPONENT_CATALOG_FORMAT,
    SEMANTIC_COMPONENT_DECLARATIONS_FORMAT,
)
from spaghetti_extractor.reconstruction_ir import MACHINE_IR_FORMAT
from spaghetti_extractor.semantic_components import (
    SemanticComponentError,
    build_semantic_component_catalog,
    write_semantic_component_catalog,
)


class SemanticComponentTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.machine = self.root / "machine"
        self.machine.mkdir()
        self.units = [
            _unit(
                "unit:a",
                0x1000,
                0x1004,
                {"kind": "fallthrough", "target_rva": 0x1010},
                reachability="reachable",
                memory_events=[
                    {
                        "kind": "write",
                        "width": 4,
                        "address": {"op": "reg", "name": "eax", "width": 32},
                        "value": {"op": "const", "value": 7, "width": 32},
                    }
                ],
            ),
            _unit(
                "unit:b",
                0x1010,
                0x1011,
                {
                    "kind": "return",
                    "value": {
                        "op": "load",
                        "width": 4,
                        "address": {"op": "reg", "name": "esp", "width": 32},
                    },
                },
                reachability="reachable",
            ),
            _unit(
                "unit:c",
                0x2000,
                0x2004,
                {"kind": "jump", "target_rva": 0x3000},
                reachability="potential",
            ),
        ]
        ir_path = self.machine / "machine-ir.jsonl"
        ir_path.write_text(
            "".join(json.dumps(item, sort_keys=True) + "\n" for item in self.units),
            encoding="utf-8",
        )
        self.machine_ir_sha256 = _file_sha256(ir_path)
        self.manifest = {
            "format": MACHINE_IR_FORMAT,
            "artifacts": {
                "machine_ir": {
                    "path": "machine-ir.jsonl",
                    "sha256": self.machine_ir_sha256,
                }
            },
            "binary": {"sha256": "1" * 64},
            "control": {
                "roots": [{"kind": "pe_entrypoint", "rva": 0x1000, "checked": True}]
            },
        }
        self.manifest_path = self.machine / "machine-ir-manifest.json"
        _write_json(self.manifest_path, self.manifest)
        self.plan = {
            "format": RECONSTRUCTION_PLAN_FORMAT,
            "status": "incomplete",
            "inputs": {
                "machine_ir": {
                    "format": MACHINE_IR_FORMAT,
                    "sha256": self.machine_ir_sha256,
                    "manifest_sha256": _file_sha256(self.manifest_path),
                }
            },
            "clusters": [
                {"id": "cluster:ab", "unit_ids": ["unit:a", "unit:b"]},
                {"id": "cluster:c", "unit_ids": ["unit:c"]},
            ],
        }
        self.plan["plan_sha256"] = _canonical_sha256(self.plan)
        self.plan_path = self.root / "plan.json"
        _write_json(self.plan_path, self.plan)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_hierarchy_derives_noncontiguous_boundary_and_residual_coverage(self) -> None:
        declarations = self._declarations(
            [
                _component(
                    "sample",
                    kind="aggregate",
                    children=["worker"],
                    logical_status="not_applicable",
                    refinement_status="not_applicable",
                    emission="none",
                ),
                _component("worker", cluster_ids=["cluster:ab"]),
            ]
        )
        catalog = build_semantic_component_catalog(
            machine_ir=self.machine,
            reconstruction_plan=self.plan_path,
            declarations=declarations,
        )

        self.assertEqual(catalog["format"], SEMANTIC_COMPONENT_CATALOG_FORMAT)
        self.assertEqual(catalog["status"], "incomplete")
        self.assertEqual(catalog["definition_status"], "valid")
        worker = next(item for item in catalog["components"] if item["id"] == "worker")
        self.assertTrue(worker["membership"]["noncontiguous"])
        self.assertEqual(worker["machine_boundary"]["entries"][0]["unit_id"], "unit:a")
        self.assertEqual(worker["machine_boundary"]["exits"][0]["kind"], "return")
        self.assertEqual(worker["machine_boundary"]["counts"]["memory_events"], 1)
        self.assertEqual(worker["logical_interface"]["authority"], "operator_proposal_not_machine_truth")
        self.assertFalse(worker["refinement"]["machine_to_logical_projection_validated"])
        self.assertEqual(catalog["coverage"]["counts"]["declared_exact_reachable_units"], 2)
        self.assertEqual(catalog["coverage"]["counts"]["unassigned_potential_units"], 1)
        self.assertFalse(catalog["coverage"]["complete"])

    def test_stale_binding_is_a_source_localized_violation(self) -> None:
        declarations = self._declarations([_component("worker", cluster_ids=["cluster:ab"])])
        declarations["bindings"]["machine_ir_sha256"] = "9" * 64

        catalog = build_semantic_component_catalog(
            machine_ir=self.machine,
            reconstruction_plan=self.plan_path,
            declarations=declarations,
        )

        self.assertEqual(catalog["status"], "violated")
        issue = next(item for item in catalog["issues"] if item["code"] == "component_binding_mismatch")
        self.assertEqual(issue["expected"], self.machine_ir_sha256)
        self.assertEqual(issue["observed"], "9" * 64)

    def test_unknown_machine_unit_fails_closed(self) -> None:
        declarations = self._declarations(
            [_component("worker", unit_ids=["unit:missing"])]
        )
        catalog = build_semantic_component_catalog(
            machine_ir=self.machine,
            reconstruction_plan=self.plan_path,
            declarations=declarations,
        )
        self.assertEqual(catalog["status"], "violated")
        self.assertIn(
            "unknown_component_unit", {item["code"] for item in catalog["issues"]}
        )
        self.assertIn("empty_component", {item["code"] for item in catalog["issues"]})

    def test_incomparable_overlap_fails_closed(self) -> None:
        declarations = self._declarations(
            [
                _component("left", cluster_ids=["cluster:ab"]),
                _component("right", unit_ids=["unit:b"]),
            ]
        )
        catalog = build_semantic_component_catalog(
            machine_ir=self.machine,
            reconstruction_plan=self.plan_path,
            declarations=declarations,
        )
        issue = next(
            item
            for item in catalog["issues"]
            if item["code"] == "incomparable_component_overlap"
        )
        self.assertEqual(issue["unit_ids"], ["unit:b"])

    def test_hierarchy_cycle_fails_closed(self) -> None:
        declarations = self._declarations(
            [
                _component("left", unit_ids=["unit:a"], children=["right"]),
                _component("right", unit_ids=["unit:b"], children=["left"]),
            ]
        )
        catalog = build_semantic_component_catalog(
            machine_ir=self.machine,
            reconstruction_plan=self.plan_path,
            declarations=declarations,
        )
        self.assertEqual(catalog["status"], "violated")
        self.assertIn(
            "component_hierarchy_cycle", {item["code"] for item in catalog["issues"]}
        )

    def test_explicit_shared_child_may_have_multiple_parents(self) -> None:
        declarations = self._declarations(
            [
                _component("left", unit_ids=["unit:a"], children=["shared"]),
                _component("right", unit_ids=["unit:c"], children=["shared"]),
                _component("shared", unit_ids=["unit:b"], sharing="shared"),
            ]
        )
        catalog = build_semantic_component_catalog(
            machine_ir=self.machine,
            reconstruction_plan=self.plan_path,
            declarations=declarations,
        )
        self.assertEqual(catalog["definition_status"], "valid")
        self.assertNotIn(
            "incomparable_component_overlap",
            {item["code"] for item in catalog["issues"]},
        )
        self.assertEqual(catalog["coverage"]["unit_owners"]["unit:b"], ["shared"])

    def test_corrupted_indirect_target_id_fails_closed(self) -> None:
        self.manifest["control"]["recovered_indirect_targets"] = [
            {
                "id": "indirect:test",
                "status": "recovered",
                "source_unit_id": "unit:a",
                "source_rva": 0x1000,
                "target_unit_ids": ["unit:missing"],
                "target_rvas": [0x3000],
            }
        ]
        _write_json(self.manifest_path, self.manifest)
        self.plan["inputs"]["machine_ir"]["manifest_sha256"] = _file_sha256(
            self.manifest_path
        )
        self.plan.pop("plan_sha256")
        self.plan["plan_sha256"] = _canonical_sha256(self.plan)
        _write_json(self.plan_path, self.plan)
        declarations = self._declarations(
            [_component("worker", cluster_ids=["cluster:ab"])]
        )

        catalog = build_semantic_component_catalog(
            machine_ir=self.machine,
            reconstruction_plan=self.plan_path,
            declarations=declarations,
        )

        self.assertEqual(catalog["status"], "violated")
        self.assertIn(
            "unknown_indirect_target", {item["code"] for item in catalog["issues"]}
        )

    def test_writer_is_byte_reproducible(self) -> None:
        declarations = self._declarations([_component("worker", cluster_ids=["cluster:ab"])])
        first = self.root / "first.json"
        second = self.root / "second.json"
        write_semantic_component_catalog(
            machine_ir=self.machine,
            reconstruction_plan=self.plan_path,
            declarations=declarations,
            out=first,
        )
        write_semantic_component_catalog(
            machine_ir=self.machine,
            reconstruction_plan=self.plan_path,
            declarations=declarations,
            out=second,
        )
        self.assertEqual(first.read_bytes(), second.read_bytes())

    def test_malformed_declaration_is_rejected_before_validation(self) -> None:
        declarations = self._declarations([_component("worker")])
        declarations["components"][0]["kind"] = "source-function-by-guess"
        with self.assertRaisesRegex(SemanticComponentError, "must be one of"):
            build_semantic_component_catalog(
                machine_ir=self.machine,
                reconstruction_plan=self.plan_path,
                declarations=declarations,
            )

    def test_internal_direct_call_consumes_owned_return_and_records_frame(self) -> None:
        caller = _unit(
            "unit:caller",
            0x4000,
            0x4005,
            {"kind": "fallthrough", "target_rva": 0x4010},
            reachability="reachable",
            external_events=[
                {
                    "kind": "internal_call",
                    "target_rva": 0x5000,
                    "return_rva": 0x4010,
                }
            ],
        )
        helper = _unit(
            "unit:helper",
            0x5000,
            0x5003,
            {
                "kind": "return",
                "value": {
                    "op": "load",
                    "width": 4,
                    "address": {"op": "reg", "name": "esp", "width": 32},
                },
            },
            reachability="reachable",
            memory_events=[
                {
                    "kind": "read",
                    "width": 4,
                    "address": {"op": "reg", "name": "esp", "width": 32},
                }
            ],
        )
        successor = _unit(
            "unit:successor",
            0x4010,
            0x4011,
            {"kind": "return"},
            reachability="reachable",
        )
        self._replace_machine([caller, helper, successor])
        declarations = self._declarations(
            [_component("worker", unit_ids=["unit:caller", "unit:helper"])]
        )

        catalog = build_semantic_component_catalog(
            machine_ir=self.machine,
            reconstruction_plan=self.plan_path,
            declarations=declarations,
        )

        worker = next(item for item in catalog["components"] if item["id"] == "worker")
        boundary = worker["machine_boundary"]
        self.assertEqual(boundary["call_closure"]["status"], "complete")
        self.assertEqual(boundary["counts"]["internal_calls"], 1)
        self.assertEqual(boundary["counts"]["internal_returns"], 1)
        self.assertEqual(boundary["counts"]["internal_frame_effects"], 2)
        self.assertEqual(
            [(item["kind"], item.get("target_rva")) for item in boundary["exits"]],
            [("direct_control", 0x4010)],
        )
        self.assertEqual(
            [item["phase"] for item in boundary["effects"]["internal_call_frames"]],
            ["call_push", "return_target_read"],
        )

    def test_externally_entered_helper_return_remains_a_boundary_exit(self) -> None:
        caller = _unit(
            "unit:caller",
            0x4000,
            0x4005,
            {"kind": "fallthrough", "target_rva": 0x4010},
            reachability="reachable",
            external_events=[
                {
                    "kind": "internal_call",
                    "target_rva": 0x5000,
                    "return_rva": 0x4010,
                }
            ],
        )
        outsider = _unit(
            "unit:outsider",
            0x3000,
            0x3005,
            {"kind": "fallthrough", "target_rva": 0x3005},
            reachability="reachable",
            external_events=[
                {
                    "kind": "internal_call",
                    "target_rva": 0x5000,
                    "return_rva": 0x3005,
                }
            ],
        )
        helper = _unit(
            "unit:helper",
            0x5000,
            0x5003,
            {"kind": "return"},
            reachability="reachable",
        )
        self._replace_machine([caller, outsider, helper])
        declarations = self._declarations(
            [_component("worker", unit_ids=["unit:caller", "unit:helper"])]
        )

        catalog = build_semantic_component_catalog(
            machine_ir=self.machine,
            reconstruction_plan=self.plan_path,
            declarations=declarations,
        )

        worker = next(item for item in catalog["components"] if item["id"] == "worker")
        boundary = worker["machine_boundary"]
        self.assertEqual(boundary["call_closure"]["status"], "incomplete")
        self.assertIn("return", {item["kind"] for item in boundary["exits"]})
        self.assertEqual(
            boundary["internal_calls"][0]["issues"],
            ["callee_has_external_entry"],
        )

    def _replace_machine(self, units: list[dict[str, object]]) -> None:
        self.units = units
        ir_path = self.machine / "machine-ir.jsonl"
        ir_path.write_text(
            "".join(json.dumps(item, sort_keys=True) + "\n" for item in units),
            encoding="utf-8",
        )
        self.machine_ir_sha256 = _file_sha256(ir_path)
        self.manifest["artifacts"]["machine_ir"]["sha256"] = self.machine_ir_sha256
        self.manifest["control"]["roots"] = [
            {"kind": "pe_entrypoint", "rva": min(_unit_start(item) for item in units), "checked": True}
        ]
        _write_json(self.manifest_path, self.manifest)
        self.plan["inputs"]["machine_ir"] = {
            "format": MACHINE_IR_FORMAT,
            "sha256": self.machine_ir_sha256,
            "manifest_sha256": _file_sha256(self.manifest_path),
        }
        self.plan["clusters"] = []
        self.plan.pop("plan_sha256", None)
        self.plan["plan_sha256"] = _canonical_sha256(self.plan)
        _write_json(self.plan_path, self.plan)

    def _declarations(self, components: list[dict[str, object]]) -> dict[str, object]:
        return {
            "format": SEMANTIC_COMPONENT_DECLARATIONS_FORMAT,
            "program_id": "synthetic-pe32",
            "bindings": {
                "machine_ir_sha256": self.machine_ir_sha256,
                "machine_ir_manifest_sha256": _file_sha256(self.manifest_path),
                "reconstruction_plan_sha256": self.plan["plan_sha256"],
                "original_binary_sha256": self.manifest["binary"]["sha256"],
            },
            "components": components,
        }


def _component(
    identity: str,
    *,
    kind: str = "procedure",
    unit_ids: list[str] | None = None,
    cluster_ids: list[str] | None = None,
    children: list[str] | None = None,
    sharing: str = "exclusive",
    logical_status: str = "proposed",
    refinement_status: str = "not_started",
    emission: str = "function",
) -> dict[str, object]:
    return {
        "id": identity,
        "label": identity.replace("-", " "),
        "purpose": "exercise semantic component validation",
        "kind": kind,
        "sharing": sharing,
        "expected_reachability": "any",
        "membership": {
            "unit_ids": unit_ids or [],
            "cluster_ids": cluster_ids or [],
        },
        "children": children or [],
        "logical_interface": {
            "status": logical_status,
            "parameters": [],
            "results": [],
            "objects": [],
            "persistent_state": [],
            "services": [],
            "preconditions": [],
            "postconditions": [],
            "observations": [],
        },
        "refinement": {"status": refinement_status, "stages": []},
        "emission": {"policy": emission},
        "evidence": [],
        "assumptions": [],
    }


def _unit(
    identity: str,
    start: int,
    end: int,
    outcome: dict[str, object],
    *,
    reachability: str,
    memory_events: list[dict[str, object]] | None = None,
    external_events: list[dict[str, object]] | None = None,
) -> dict[str, object]:
    return {
        "id": identity,
        "reachability": reachability,
        "source": {"original": {"rva_start": start, "rva_end": end}},
        "semantics": {
            "outcome": outcome,
            "memory_events": memory_events or [],
            "external_events": external_events or [],
            "faults": [],
            "register_writes": [],
            "flag_writes": [],
        },
    }


def _unit_start(unit: dict[str, object]) -> int:
    return int(unit["source"]["original"]["rva_start"])  # type: ignore[index]


def _write_json(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _file_sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _canonical_sha256(value: object) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()


if __name__ == "__main__":
    unittest.main()
