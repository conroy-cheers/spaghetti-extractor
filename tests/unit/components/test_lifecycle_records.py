from __future__ import annotations

import copy
import unittest

from spaghetti_extractor.components.lifecycle_records import (
    ComponentActivationPlanRecordV3,
    ComponentLifecycleRecordError,
    ComponentQualificationRecordV3,
)
from spaghetti_extractor.artifacts.artifact_set import canonical_sha256_v3


def _qualification() -> dict[str, object]:
    return ComponentQualificationRecordV3.create(
        status="qualified",
        lift_unit_id="unit",
        evidence_profile="bounded-equivalence-v1",
        bindings={
            "contract_sha256": "1" * 64,
            "implementation_sha256": "2" * 64,
            "machine_ir_sha256": "3" * 64,
            "domain_sha256": "4" * 64,
            "adapter_plan_sha256": "5" * 64,
            "evidence_sha256": "6" * 64,
            "source_entry": {"abi": "logical-c-v1", "symbol": "component"},
            "tool_id": "component-harness",
            "tool_version": "1",
        },
        assurance={
            "kind": "exhaustive_over_declared_finite_domain",
            "universal_equivalence_claimed": False,
            "declared_domain_equivalence": True,
            "declared_cases_satisfied": False,
            "original_binary_executed": False,
        },
        issues=[],
    ).to_payload()


def _activation_plan() -> dict[str, object]:
    core = {
        "format": "spaghetti-extractor-component-activation-plan-v3",
        "status": "checked",
        "configuration_id": "configuration",
        "bindings": {},
        "policy": {},
        "ownership": {},
        "hybrid": {},
        "selections": [],
        "entries": [
            {
                "unit_id": "unit-z",
                "rva": 0x1000,
                "implementation_kind": "machine_ir_fallback",
                "dispatch_lookup": "spx_program_lookup",
                "selected_owner": None,
            },
            {
                "unit_id": "unit-a",
                "rva": 0x2000,
                "implementation_kind": "portable_replacement",
                "dispatch_lookup": "spx_region_override_lookup",
                "selected_owner": {"component_id": "portable"},
            },
        ],
        "counts": {
            "structural_units": 2,
            "portable_replacement": 1,
            "machine_ir_fallback": 1,
            "blocked": 0,
            "issues": 0,
        },
        "issues": [],
    }
    return {**core, "activation_plan_sha256": canonical_sha256_v3(core)}


class ComponentLifecycleRecordTests(unittest.TestCase):
    def test_round_trips_qualified_record(self) -> None:
        payload = _qualification()
        self.assertEqual(
            ComponentQualificationRecordV3.parse(payload).to_payload(), payload
        )

    def test_rejects_authorization_status_contradiction(self) -> None:
        payload = copy.deepcopy(_qualification())
        payload["activation"]["authorized"] = False  # type: ignore[index]
        with self.assertRaisesRegex(ComponentLifecycleRecordError, "contradicts"):
            ComponentQualificationRecordV3.parse(payload)

    def test_rejects_stale_binding(self) -> None:
        payload = copy.deepcopy(_qualification())
        payload["bindings"]["machine_ir_sha256"] = "7" * 64  # type: ignore[index]
        with self.assertRaisesRegex(ComponentLifecycleRecordError, "self-hash"):
            ComponentQualificationRecordV3.parse(payload)

    def test_accepts_activation_entries_ordered_by_rva(self) -> None:
        ComponentActivationPlanRecordV3.parse(_activation_plan())

    def test_rejects_activation_dispatch_inconsistent_with_owner(self) -> None:
        payload = _activation_plan()
        payload["entries"][0]["dispatch_lookup"] = "spx_region_override_lookup"  # type: ignore[index]
        core = dict(payload)
        core.pop("activation_plan_sha256")
        payload["activation_plan_sha256"] = canonical_sha256_v3(core)
        with self.assertRaisesRegex(ComponentLifecycleRecordError, "dispatch lookup"):
            ComponentActivationPlanRecordV3.parse(payload)


if __name__ == "__main__":
    unittest.main()
