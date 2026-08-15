from __future__ import annotations

import json
import tempfile
import unittest
from hashlib import sha256
from pathlib import Path

from spaghetti_extractor.components.formats import (
    COMPONENT_ACTIVATION_PLAN_V3_FORMAT,
    COMPONENT_ADAPTER_PLAN_V1_FORMAT,
    COMPONENT_CONTRACT_PACKAGE_V2_FORMAT,
    COMPONENT_EVIDENCE_V3_FORMAT,
    COMPONENT_QUALIFICATION_V3_FORMAT,
)
from spaghetti_extractor.components.intent import ComponentIntentError
from spaghetti_extractor.components.source import build_component_source_package
from spaghetti_extractor.components.status import (
    build_configuration_status,
    build_lift_unit_status,
)


TESTKIT = {"commands": ("*",)}


def _digest(value: object) -> str:
    return sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode("ascii")
    ).hexdigest()


def _write_hashed(path: Path, core: dict[str, object], field: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps({**core, field: _digest(core)}, sort_keys=True) + "\n",
        encoding="utf-8",
    )


class ComponentStatusTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.contract = self.root / "contract.json"
        self.evidence = self.root / "evidence.json"
        self.qualification = self.root / "qualification.json"
        self.adapter = self.root / "adapter"
        self.adapter.mkdir()
        self.source = self.root / "source"
        self.source_file = self.root / "component.c"
        self.source_file.write_text("unsigned component(unsigned x) { return x; }\n")
        source = build_component_source_package(
            lift_unit_id="fixture",
            files={"component.c": self.source_file},
            shared_inputs={},
            entry={"abi": "logical-c-v1", "symbol": "component"},
            out_dir=self.source,
        )
        contract_core = {
            "format": COMPONENT_CONTRACT_PACKAGE_V2_FORMAT,
            "status": "checked",
            "lift_unit": {
                "kind": "component",
                "id": "fixture",
                "label": "Fixture",
                "unit_ids": ["unit:fixture"],
                "evidence_profile": "bounded-equivalence-v1",
            },
            "blockers": [],
        }
        _write_hashed(self.contract, contract_core, "contract_sha256")
        header = self.adapter / "spaghetti-component-abi.h"
        header.write_text("/* fixture */\n", encoding="ascii")
        adapter_core = {
            "format": COMPONENT_ADAPTER_PLAN_V1_FORMAT,
            "status": "checked",
            "lift_unit_id": "fixture",
            "artifacts": {
                "logical_abi_header": {
                    "path": header.name,
                    "sha256": sha256(header.read_bytes()).hexdigest(),
                }
            },
            "issues": [],
        }
        _write_hashed(
            self.adapter / "adapter-plan.json",
            adapter_core,
            "adapter_plan_sha256",
        )
        evidence_core = {
            "format": COMPONENT_EVIDENCE_V3_FORMAT,
            "status": "satisfied",
            "lift_unit_id": "fixture",
            "issues": [],
        }
        _write_hashed(self.evidence, evidence_core, "evidence_sha256")
        qualification_core = {
            "format": COMPONENT_QUALIFICATION_V3_FORMAT,
            "status": "qualified",
            "lift_unit_id": "fixture",
            "issues": [],
            "bindings": {
                "implementation_sha256": source["implementation_sha256"],
            },
        }
        _write_hashed(
            self.qualification, qualification_core, "qualification_sha256"
        )

    def test_qualified_unit_reports_no_blockers(self) -> None:
        result = build_lift_unit_status(
            contract=self.contract,
            source=self.source,
            adapter_plan=self.adapter,
            evidence=self.evidence,
            qualification=self.qualification,
            out=self.root / "status.json",
        )
        self.assertEqual(result["status"], "qualified")
        self.assertEqual(result["blockers"], [])
        self.assertIsNone(result["next_action"])
        self.assertFalse(result["policy"]["authorizes_runtime"])

    def test_missing_replacement_inputs_are_actionable_incomplete(self) -> None:
        result = build_lift_unit_status(
            contract=self.contract,
            source=None,
            adapter_plan=None,
            evidence=None,
            qualification=None,
            out=self.root / "status.json",
        )
        self.assertEqual(result["status"], "incomplete")
        self.assertEqual(result["next_action"]["code"], "behavioral_evidence_not_available")
        self.assertEqual(
            {row["code"] for row in result["blockers"]},
            {
                "portable_source_not_declared",
                "component_adapter_plan_not_available",
                "behavioral_evidence_not_available",
                "component_qualification_not_available",
            },
        )

    def test_corrupted_qualification_fails_closed(self) -> None:
        payload = json.loads(self.qualification.read_text(encoding="utf-8"))
        payload["status"] = "violated"
        self.qualification.write_text(json.dumps(payload), encoding="utf-8")
        with self.assertRaisesRegex(ComponentIntentError, "self-hash is stale"):
            build_lift_unit_status(
                contract=self.contract,
                source=self.source,
                adapter_plan=self.adapter,
                evidence=self.evidence,
                qualification=self.qualification,
                out=self.root / "status.json",
            )

    def test_configuration_status_tracks_blocked_ownership(self) -> None:
        plan_core = {
            "format": COMPONENT_ACTIVATION_PLAN_V3_FORMAT,
            "status": "incomplete",
            "configuration_id": "default",
            "counts": {
                "structural_units": 2,
                "portable_replacement": 0,
                "machine_ir_fallback": 1,
                "blocked": 1,
                "issues": 1,
            },
            "selections": [],
            "issues": [{
                "status": "incomplete",
                "code": "enabled_component_not_qualified",
                "lift_unit_id": "fixture",
            }],
        }
        plan = self.root / "activation-plan.json"
        _write_hashed(plan, plan_core, "activation_plan_sha256")
        result = build_configuration_status(
            activation_plan=plan,
            out=self.root / "configuration-status.json",
        )
        self.assertEqual(result["status"], "incomplete")
        self.assertEqual(result["counts"]["blocked"], 1)
        self.assertEqual(result["next_action"]["code"], "enabled_component_not_qualified")


if __name__ == "__main__":
    unittest.main()
