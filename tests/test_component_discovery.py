from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.component_discovery import (
    MACHINE_IR_FORMAT,
    PROPOSAL_SET_FORMAT,
    RECONSTRUCTION_PLAN_FORMAT,
    ComponentDiscoveryError,
    discover_component_proposals,
    write_component_proposals,
)


class ComponentDiscoveryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.machine = self.root / "machine"
        self.machine.mkdir()
        self.units = [
            _unit(
                "unit:branch",
                0x1000,
                0x1008,
                {
                    "kind": "branch",
                    "condition": {
                        "op": "eq",
                        "args": [
                            {
                                "op": "sub32",
                                "args": [_reg("ebx"), _reg("eax")],
                            },
                            _const(0),
                        ],
                    },
                    "true_target_rva": 0x1030,
                    "false_target_rva": 0x1010,
                },
                flag_writes=[{"flag": "zf", "value": {"op": "flag", "name": "zf"}}],
            ),
            _unit(
                "unit:sleep",
                0x1010,
                0x1020,
                {"kind": "fallthrough", "target_rva": 0x1030},
                external_events=[
                    {
                        "kind": "external_call",
                        "dll": "kernel32.dll",
                        "symbol": "Sleep",
                        "arguments": [_const(1000)],
                        "return_rva": 0x1030,
                    }
                ],
                memory_events=[
                    {
                        "kind": "write",
                        "width": 4,
                        "address": _reg("esp"),
                        "value": _const(1000),
                    }
                ],
            ),
            _unit("unit:join", 0x1030, 0x1031, {"kind": "return"}),
            _unit(
                "unit:caller",
                0x2000,
                0x2005,
                {"kind": "fallthrough", "target_rva": 0x2005},
                external_events=[
                    {
                        "kind": "internal_call",
                        "target_rva": 0x2100,
                        "return_rva": 0x2005,
                        "register_inputs": {"eax": _reg("eax")},
                    }
                ],
                memory_events=[
                    {
                        "kind": "read",
                        "width": 4,
                        "address": _reg("edx"),
                    }
                ],
            ),
            _unit("unit:continuation", 0x2005, 0x2006, {"kind": "return"}),
            _unit(
                "unit:helper",
                0x2100,
                0x2105,
                {"kind": "return"},
                memory_events=[
                    {
                        "kind": "write",
                        "width": 4,
                        "address": _reg("edx"),
                        "value": _reg("eax"),
                    }
                ],
                register_writes=[{"register": "eax", "value": _const(0)}],
            ),
            _unit(
                "unit:indirect",
                0x3000,
                0x3007,
                {"kind": "indirect_jump", "target": _reg("eax")},
                reachability="potential",
            ),
        ]
        self._write_inputs()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_output_is_deterministic_and_self_bound(self) -> None:
        first = self._discover()
        second = self._discover()

        self.assertEqual(first, second)
        self.assertEqual(first["format"], PROPOSAL_SET_FORMAT)
        self.assertFalse(first["executes_original_binary"])
        self.assertFalse(first["authority"]["can_authorize_replacement"])
        core = {key: value for key, value in first.items() if key != "proposal_set_sha256"}
        self.assertEqual(first["proposal_set_sha256"], _canonical_sha256(core))

        output = self.root / "proposals.json"
        written = write_component_proposals(
            machine_ir=self.machine,
            reconstruction_plan=self.plan_path,
            out=output,
        )
        self.assertEqual(written, first)
        self.assertEqual(json.loads(output.read_text(encoding="utf-8")), first)

        required = {
            "id",
            "membership",
            "reachability",
            "interface_hint",
            "score",
            "closure_history",
            "blockers",
            "issues",
        }
        for proposal in first["proposals"]:
            self.assertTrue(required <= set(proposal))
            self.assertIn("unit_ids", proposal["membership"])
            self.assertIn("classification", proposal["reachability"])
            proposal_core = {
                key: value
                for key, value in proposal.items()
                if key != "proposal_sha256"
            }
            self.assertEqual(
                proposal["proposal_sha256"], _canonical_sha256(proposal_core)
            )

    def test_full_exact_and_potential_coverage_ledgers_are_complete(self) -> None:
        payload = self._discover()
        coverage = payload["coverage"]

        self.assertTrue(coverage["exact"]["complete"])
        self.assertTrue(coverage["potential"]["complete"])
        self.assertTrue(coverage["full"]["complete"])
        self.assertEqual(coverage["full"]["counts"]["total"], len(self.units))
        self.assertEqual(coverage["full"]["uncovered_unit_ids"], [])
        self.assertEqual(
            {item["unit_id"] for item in coverage["by_unit"]},
            {item["id"] for item in self.units},
        )
        self.assertTrue(all(item["proposal_ids"] for item in coverage["by_unit"]))

        limited = discover_component_proposals(
            machine_ir=self.machine,
            reconstruction_plan=self.plan_path,
            max_candidates_per_seed=1,
        )
        self.assertTrue(limited["coverage"]["full"]["complete"])
        self.assertTrue(
            all(len(item["proposal_ids"]) == 1 for item in limited["seed_index"])
        )

    def test_external_event_branch_is_preferred_over_machine_singleton(self) -> None:
        payload = self._discover()
        proposals = self._seed_proposals(payload, "unit:unit:branch")
        singleton = next(
            item
            for item in proposals
            if item["membership"]["unit_ids"] == ["unit:branch"]
        )
        coarsened = next(
            item
            for item in proposals
            if "external_event_branch_coarsening" in item["proposal_kinds"]
        )

        self.assertEqual(
            coarsened["membership"]["unit_ids"], ["unit:branch", "unit:sleep"]
        )
        self.assertEqual(
            coarsened["interface_hint"]["control"]["suggested_form"],
            "conditional_external_service",
        )
        self.assertEqual(coarsened["interface_hint"]["services"][0]["symbol"], "Sleep")
        self.assertLess(
            self._seed_rank(coarsened, "unit:unit:branch"),
            self._seed_rank(singleton, "unit:unit:branch"),
        )
        self.assertLess(
            coarsened["score"]["vector"]["raw_machine_exposure"],
            singleton["score"]["vector"]["raw_machine_exposure"],
        )

    def test_direct_call_closure_absorbs_helper(self) -> None:
        payload = self._discover()
        proposal = next(
            item
            for item in self._seed_proposals(payload, "unit:unit:caller")
            if "direct_call_closure" in item["proposal_kinds"]
        )

        self.assertEqual(
            proposal["membership"]["unit_ids"], ["unit:caller", "unit:helper"]
        )
        history = next(
            item
            for item in proposal["closure_history"]
            if item["operation"] == "direct_call_closure"
        )
        self.assertEqual(history["details"]["callee_entry_unit_id"], "unit:helper")
        self.assertEqual(history["details"]["return_rva"], 0x2005)
        self.assertGreaterEqual(proposal["boundary"]["internal_edge_count"], 1)

    def test_unclosed_known_internal_call_is_an_actionable_blocker(self) -> None:
        payload = self._discover()
        singleton = next(
            item
            for item in self._seed_proposals(payload, "unit:unit:caller")
            if item["membership"]["unit_ids"] == ["unit:caller"]
        )
        blocker = next(
            item
            for item in singleton["blockers"]
            if item["category"] == "unclosed_internal_call_dependency"
        )
        self.assertEqual(singleton["status"], "blocked")
        self.assertEqual(blocker["source_location"]["unit_id"], "unit:caller")
        self.assertEqual(blocker["observed"]["target_unit_id"], "unit:helper")
        self.assertIn("call-closure", blocker["remediation"]["details"])
        dependency = singleton["component_call_dependencies"][0]
        self.assertEqual(dependency["target_rva"], 0x2100)
        self.assertEqual(dependency["target_unit_id"], "unit:helper")
        self.assertEqual(dependency["resolution"], "selection_required")
        recommended = dependency["recommended_proposal_id"]
        alternative = next(
            item
            for item in dependency["alternatives"]
            if item["proposal_id"] == recommended
        )
        self.assertEqual(alternative["readiness"], "ready")

    def test_call_target_closure_proposes_standalone_callee(self) -> None:
        payload = self._discover()
        proposal = next(
            item
            for item in self._seed_proposals(payload, "unit:unit:helper")
            if "call_target_return_closure" in item["proposal_kinds"]
        )

        self.assertEqual(proposal["membership"]["unit_ids"], ["unit:helper"])
        history = next(
            item
            for item in proposal["closure_history"]
            if item["operation"] == "call_target_return_closure"
        )
        self.assertEqual(history["details"]["entry_unit_id"], "unit:helper")
        self.assertEqual(history["details"]["caller_unit_ids"], ["unit:caller"])
        self.assertTrue(history["details"]["stops_at_terminal_outcomes"])

    def test_multi_entry_cycle_is_split_into_single_entry_closures(self) -> None:
        self.units.extend(
            [
                _unit(
                    "unit:loop-entry",
                    0x4000,
                    0x4004,
                    {
                        "kind": "branch",
                        "condition": _reg("eax"),
                        "true_target_rva": 0x4010,
                        "false_target_rva": 0x4020,
                    },
                ),
                _unit(
                    "unit:loop-left",
                    0x4010,
                    0x4014,
                    {"kind": "fallthrough", "target_rva": 0x4020},
                ),
                _unit(
                    "unit:loop-alternate-entry",
                    0x4020,
                    0x4024,
                    {"kind": "fallthrough", "target_rva": 0x4030},
                ),
                _unit(
                    "unit:loop-back",
                    0x4030,
                    0x4034,
                    {"kind": "jump", "target_rva": 0x4000},
                ),
                _unit(
                    "unit:outside-caller",
                    0x4100,
                    0x4104,
                    {
                        "kind": "branch",
                        "condition": _reg("ecx"),
                        "true_target_rva": 0x4000,
                        "false_target_rva": 0x4020,
                    },
                ),
            ]
        )
        self._write_inputs()

        payload = self._discover()
        entry = next(
            item
            for item in self._seed_proposals(payload, "unit:unit:loop-entry")
            if "single_entry_control_closure" in item["proposal_kinds"]
        )
        alternate = next(
            item
            for item in self._seed_proposals(
                payload, "unit:unit:loop-alternate-entry"
            )
            if "single_entry_control_closure" in item["proposal_kinds"]
        )

        self.assertEqual(
            entry["membership"]["unit_ids"],
            ["unit:loop-entry", "unit:loop-left"],
        )
        self.assertEqual(
            alternate["membership"]["unit_ids"],
            ["unit:loop-alternate-entry", "unit:loop-back"],
        )
        self.assertEqual(len(entry["boundary"]["entries"]), 1)
        self.assertEqual(len(alternate["boundary"]["entries"]), 1)
        self.assertEqual(entry["boundary"]["exits"][0]["target_rva"], 0x4020)
        self.assertEqual(alternate["boundary"]["exits"][0]["target_rva"], 0x4000)

    def test_object_and_epilogue_closures_are_retained_as_alternatives(self) -> None:
        payload = self._discover()
        kinds = {
            kind
            for proposal in payload["proposals"]
            for kind in proposal["proposal_kinds"]
        }
        self.assertIn("object_footprint_closure", kinds)
        self.assertIn("epilogue_absorption", kinds)

    def test_checked_finite_dispatch_generates_a_dispatch_proposal(self) -> None:
        manifest = json.loads(self.manifest_path.read_text(encoding="utf-8"))
        certificate = manifest["control"]["recovered_indirect_targets"][0]
        certificate.update(
            {
                "status": "recovered",
                "closure": "checked_finite_target_inventory",
                "target_unit_ids": ["unit:join", "unit:helper"],
                "target_rvas": [0x1030, 0x2100],
                "failure": None,
            }
        )
        _write_json(self.manifest_path, manifest)
        plan = json.loads(self.plan_path.read_text(encoding="utf-8"))
        plan["inputs"]["machine_ir"]["manifest_sha256"] = _file_sha256(
            self.manifest_path
        )
        plan.pop("plan_sha256")
        plan["plan_sha256"] = _canonical_sha256(plan)
        _write_json(self.plan_path, plan)

        payload = self._discover()
        proposal = next(
            item
            for item in payload["proposals"]
            if "finite_dispatch_closure" in item["proposal_kinds"]
        )
        self.assertEqual(
            proposal["membership"]["unit_ids"],
            ["unit:join", "unit:helper", "unit:indirect"],
        )
        self.assertFalse(
            any(
                issue["category"] == "unresolved_indirect_control"
                for issue in proposal["issues"]
            )
        )

    def test_unresolved_indirect_control_fails_closed_with_repair_location(self) -> None:
        payload = self._discover()
        self.assertEqual(payload["status"], "incomplete")
        proposal = next(
            item
            for item in payload["proposals"]
            if item["membership"]["unit_ids"] == ["unit:indirect"]
        )
        blocker = next(
            item
            for item in proposal["blockers"]
            if item["category"] == "unresolved_indirect_control"
        )

        self.assertEqual(proposal["status"], "blocked")
        self.assertEqual(blocker["status"], "incomplete")
        self.assertEqual(blocker["source_location"]["unit_id"], "unit:indirect")
        self.assertEqual(blocker["source_location"]["rva_start"], 0x3000)
        self.assertEqual(blocker["source_location"]["field"], "semantics.outcome.target")
        self.assertIn("target", blocker["remediation"]["details"])
        self.assertEqual(blocker["expected"], "checked finite target inventory")
        self.assertTrue(any(item["id"] == blocker["id"] for item in payload["issues"]))

    def test_stale_plan_binding_is_rejected_before_discovery(self) -> None:
        plan = json.loads(self.plan_path.read_text(encoding="utf-8"))
        plan["inputs"]["machine_ir"]["sha256"] = "f" * 64
        plan.pop("plan_sha256")
        plan["plan_sha256"] = _canonical_sha256(plan)
        _write_json(self.plan_path, plan)

        with self.assertRaisesRegex(ComponentDiscoveryError, "binding is stale"):
            self._discover()

    def test_empty_recovered_indirect_inventory_is_not_accepted(self) -> None:
        manifest = json.loads(self.manifest_path.read_text(encoding="utf-8"))
        certificate = manifest["control"]["recovered_indirect_targets"][0]
        certificate.update(
            {
                "status": "recovered",
                "closure": "checked_finite_target_inventory",
                "target_unit_ids": [],
            }
        )
        _write_json(self.manifest_path, manifest)
        plan = json.loads(self.plan_path.read_text(encoding="utf-8"))
        plan["inputs"]["machine_ir"]["manifest_sha256"] = _file_sha256(
            self.manifest_path
        )
        plan.pop("plan_sha256")
        plan["plan_sha256"] = _canonical_sha256(plan)
        _write_json(self.plan_path, plan)

        payload = self._discover()
        proposal = next(
            item
            for item in payload["proposals"]
            if item["membership"]["unit_ids"] == ["unit:indirect"]
        )
        self.assertEqual(payload["status"], "incomplete")
        self.assertTrue(
            any(
                item["category"] == "unresolved_indirect_control"
                for item in proposal["blockers"]
            )
        )

    def _discover(self) -> dict[str, object]:
        return discover_component_proposals(
            machine_ir=self.machine,
            reconstruction_plan=self.plan_path,
        )

    @staticmethod
    def _seed_proposals(payload: dict[str, object], seed_id: str) -> list[dict[str, object]]:
        index = next(
            item
            for item in payload["seed_index"]  # type: ignore[index]
            if item["seed_id"] == seed_id
        )
        by_id = {
            item["id"]: item for item in payload["proposals"]  # type: ignore[index]
        }
        return [by_id[identity] for identity in index["proposal_ids"]]

    @staticmethod
    def _seed_rank(proposal: dict[str, object], seed_id: str) -> int:
        item = next(
            entry
            for entry in proposal["score"]["seed_rankings"]  # type: ignore[index]
            if entry["seed_id"] == seed_id
        )
        return int(item["rank"])

    def _write_inputs(self) -> None:
        ir_path = self.machine / "machine-ir.jsonl"
        ir_path.write_text(
            "".join(json.dumps(item, sort_keys=True) + "\n" for item in self.units),
            encoding="utf-8",
        )
        ir_sha = _file_sha256(ir_path)
        self.manifest = {
            "format": MACHINE_IR_FORMAT,
            "binary": {"sha256": "1" * 64},
            "artifacts": {
                "machine_ir": {
                    "format": MACHINE_IR_FORMAT,
                    "path": "machine-ir.jsonl",
                    "sha256": ir_sha,
                }
            },
            "control": {
                "roots": [
                    {"kind": "pe_entrypoint", "rva": 0x1000, "checked": True},
                    {"kind": "export", "rva": 0x2000, "checked": True},
                    {"kind": "callback", "rva": 0x3000, "checked": True},
                ],
                "recovered_indirect_targets": [
                    {
                        "id": "indirect:unresolved",
                        "status": "incomplete",
                        "closure": "unresolved",
                        "source_unit_id": "unit:indirect",
                        "source_rva": 0x3000,
                        "target_unit_ids": [],
                        "target_rvas": [],
                        "failure": {
                            "code": "unsupported_target_expression",
                            "message": "register target provenance is unresolved",
                        },
                    }
                ],
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
                    "sha256": ir_sha,
                    "manifest_sha256": _file_sha256(self.manifest_path),
                }
            },
            "clusters": [
                {
                    "id": "cluster:branch",
                    "entry_unit_id": "unit:branch",
                    "unit_ids": ["unit:branch", "unit:sleep", "unit:join"],
                },
                {
                    "id": "cluster:call",
                    "entry_unit_id": "unit:caller",
                    "unit_ids": ["unit:caller", "unit:continuation", "unit:helper"],
                },
                {
                    "id": "cluster:indirect",
                    "entry_unit_id": "unit:indirect",
                    "unit_ids": ["unit:indirect"],
                },
            ],
        }
        self.plan["plan_sha256"] = _canonical_sha256(self.plan)
        self.plan_path = self.root / "reconstruction-plan.json"
        _write_json(self.plan_path, self.plan)


def _unit(
    identity: str,
    start: int,
    end: int,
    outcome: dict[str, object],
    *,
    reachability: str = "reachable",
    memory_events: list[dict[str, object]] | None = None,
    external_events: list[dict[str, object]] | None = None,
    register_writes: list[dict[str, object]] | None = None,
    flag_writes: list[dict[str, object]] | None = None,
) -> dict[str, object]:
    return {
        "id": identity,
        "reachability": reachability,
        "source": {
            "contract_sha256": hashlib.sha256(
                f"contract:{identity}".encode("ascii")
            ).hexdigest(),
            "instruction_bytes_sha256": hashlib.sha256(
                f"instructions:{identity}".encode("ascii")
            ).hexdigest(),
            "original": {
                "rva_start": start,
                "rva_end": end,
                "size": end - start,
            }
        },
        "semantics": {
            "outcome": outcome,
            "memory_events": memory_events or [],
            "external_events": external_events or [],
            "faults": [],
            "register_writes": register_writes or [],
            "flag_writes": flag_writes or [],
        },
    }


def _reg(name: str) -> dict[str, object]:
    return {"op": "reg", "name": name, "width": 32}


def _const(value: int) -> dict[str, object]:
    return {"op": "const", "value": value, "width": 32}


def _write_json(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _file_sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _canonical_sha256(value: object) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


if __name__ == "__main__":
    unittest.main()
