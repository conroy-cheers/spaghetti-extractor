from __future__ import annotations

import copy
import unittest

from spaghetti_extractor.authority_bindings_v2 import BinaryBinding
from spaghetti_extractor.machine_ir_authority_v2 import machine_ir_sha256
from spaghetti_extractor.structural_target_proposals_v2 import (
    build_structural_target_proposals_v2,
)
from spaghetti_extractor.transition_inventory_v2 import (
    build_transition_summary_inventory_v2,
)


def _reg(name: str) -> dict[str, object]:
    return {"op": "reg", "name": name, "width": 32}


def _unit(unit_id: str, rva: int, *, indirect: bool = False) -> dict[str, object]:
    outcome = (
        {"kind": "indirect_call", "target": _reg("eax")}
        if indirect
        else {"kind": "return"}
    )
    return {
        "format": "stage-a-machine-ir-v2",
        "record_kind": "unit",
        "id": unit_id,
        "status": "qualified",
        "source": {
            "original": {"rva_start": rva, "rva_end": rva + 8},
            "instruction_bytes_sha256": f"{rva & 0xf:x}" * 64,
        },
        "expression_model": "stage-a-semantic-ir-v1",
        "instructions": [],
        "semantics": {
            "pre_state": {"registers": {"eax": _reg("eax")}, "flags": {}, "memory": {}},
            "register_writes": [], "flag_writes": [], "memory_events": [],
            "external_events": [], "faults": [], "ordered_events": [],
            "edge_conditions": [], "outcome": outcome,
            "stack_delta": {"status": "derived", "net_bytes": 0},
            "counts": {
                "register_writes": 0, "flag_writes": 0, "memory_events": 0,
                "external_events": 0, "faults": 0, "ordered_events": 0,
                "edge_conditions": 0,
            },
        },
        "control": {
            "kind": outcome["kind"],
            "direct_targets": [],
            "has_indirect_target": indirect,
        },
    }


class StructuralTargetProposalsV2Tests(unittest.TestCase):
    def setUp(self) -> None:
        self.units = [_unit("dispatch", 0x1000, indirect=True), _unit("target", 0x1100)]
        self.binary = BinaryBinding("a" * 64, machine_ir_sha256(self.units))
        self.summaries = build_transition_summary_inventory_v2(
            units=self.units,
            binary=self.binary,
        )
        from spaghetti_extractor.control_analysis_v2 import exact_control_inventory_v2

        exact = exact_control_inventory_v2(self.units)["indirect_exits"][0]
        self.recovery = {
            **exact,
            "status": "recovered",
            "target_unit_ids": ["target"],
            "external_targets": [],
            "failure": None,
        }

    def test_recovered_target_is_bound_without_granting_authority(self) -> None:
        result = build_structural_target_proposals_v2(
            units=self.units,
            transition_summaries=self.summaries,
            proposed_recoveries=[self.recovery],
        )

        self.assertEqual(result["status"], "complete")
        self.assertFalse(result["authorizing"])
        self.assertEqual(result["counts"]["recovered_targets"], 1)
        self.assertEqual(result["recovered_targets"][0]["target_unit_ids"], ["target"])

    def test_missing_target_is_incomplete_and_bad_binding_is_violated(self) -> None:
        missing = build_structural_target_proposals_v2(
            units=self.units,
            transition_summaries=self.summaries,
            proposed_recoveries=[],
        )
        self.assertEqual(missing["status"], "incomplete")

        corrupt = copy.deepcopy(self.recovery)
        corrupt["source_rva"] += 1
        violated = build_structural_target_proposals_v2(
            units=self.units,
            transition_summaries=self.summaries,
            proposed_recoveries=[corrupt],
        )
        self.assertEqual(violated["status"], "violated")

    def test_ambiguous_unknown_and_malformed_targets_are_violations(self) -> None:
        ambiguous = build_structural_target_proposals_v2(
            units=self.units,
            transition_summaries=self.summaries,
            proposed_recoveries=[self.recovery, self.recovery],
        )
        self.assertEqual(ambiguous["status"], "violated")

        unknown = copy.deepcopy(self.recovery)
        unknown["target_unit_ids"] = ["absent"]
        contradicted = build_structural_target_proposals_v2(
            units=self.units,
            transition_summaries=self.summaries,
            proposed_recoveries=[unknown, {"not": "a proposal"}],
        )
        self.assertEqual(contradicted["status"], "violated")
        self.assertEqual(
            {row["code"] for row in contradicted["issues"]},
            {
                "structural_target_proposal_malformed",
                "structural_target_proposal_target_unknown",
            },
        )


if __name__ == "__main__":
    unittest.main()
