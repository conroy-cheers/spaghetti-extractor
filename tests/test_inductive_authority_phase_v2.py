from __future__ import annotations

import copy
import unittest

from spaghetti_extractor.authority_bindings_v2 import BinaryBinding
from spaghetti_extractor.inductive_authority_phase_v2 import (
    build_inductive_authority_proposals_v2,
    check_inductive_authority_proposals_v2,
)
from spaghetti_extractor.invariant_certificate_v2 import (
    EntryFactsV2,
    ExportRequirementV2,
    InvariantFactV2,
)
from spaghetti_extractor.machine_ir_authority_v2 import machine_ir_sha256
from spaghetti_extractor.memory_version_graph_v2 import (
    derive_memory_version_graph_v2,
)
from spaghetti_extractor.transition_inventory_v2 import (
    build_transition_summary_inventory_v2,
)


PE_SHA256 = "a" * 64
PROFILE_SHA256 = "b" * 64
SLOT = 0x402000


def _const(value: int) -> dict[str, object]:
    return {"op": "const", "value": value, "width": 32}


def _reg(name: str) -> dict[str, object]:
    return {"op": "reg", "name": name, "width": 32}


def _unit(unit_id: str, rva: int, target: int, value: int) -> dict[str, object]:
    memory_event = {
        "kind": "write",
        "width": 4,
        "instruction_rva": rva + 1,
        "address": _const(SLOT),
        "value": _const(value),
    }
    return {
        "format": "stage-a-machine-ir-v2",
        "record_kind": "unit",
        "id": unit_id,
        "status": "qualified",
        "source": {
            "original": {"rva_start": rva, "rva_end": rva + 8},
            "instruction_bytes_sha256": f"{rva:064x}",
        },
        "expression_model": "stage-a-semantic-ir-v1",
        "instructions": [],
        "semantics": {
            "pre_state": {
                "registers": {"eax": _reg("eax")},
                "flags": {},
                "memory": {
                    "op": "memory",
                    "name": "mem0",
                    "address_width": 32,
                    "value_width": 8,
                },
            },
            "register_writes": [],
            "flag_writes": [],
            "memory_events": [memory_event],
            "external_events": [],
            "faults": [],
            "ordered_events": [],
            "edge_conditions": [],
            "outcome": {"kind": "direct_jump", "target_rva": target},
            "stack_delta": None,
            "counts": {
                "register_writes": 0,
                "flag_writes": 0,
                "memory_events": 1,
                "external_events": 0,
                "faults": 0,
                "ordered_events": 0,
                "edge_conditions": 0,
            },
        },
        "control": {
            "kind": "direct_jump",
            "direct_targets": [target],
            "has_indirect_target": False,
        },
    }


class InductiveAuthorityPhaseV2Tests(unittest.TestCase):
    def setUp(self) -> None:
        self.units = [
            _unit("loop:a", 0x1000, 0x1010, 1),
            _unit("loop:b", 0x1010, 0x1000, 2),
        ]
        self.binary = BinaryBinding(PE_SHA256, machine_ir_sha256(self.units))
        self.summaries = build_transition_summary_inventory_v2(
            units=self.units, binary=self.binary
        )
        self.memory = derive_memory_version_graph_v2(
            units=self.units,
            binary=self.binary,
            transition_summaries=self.summaries.summaries,
        )
        subject = f"memory-range:{SLOT}:{SLOT + 4}"
        self.invariant = (
            InvariantFactV2.finite(subject, (1, 2)),
        )
        self.root = EntryFactsV2(
            "launch:loop",
            "root",
            "loop:a",
            None,
            (InvariantFactV2.exact(subject, 1),),
        )

    def proposal(self) -> dict[str, object]:
        return build_inductive_authority_proposals_v2(
            units=self.units,
            transition_summaries=self.summaries,
            memory_version_graph=self.memory,
            interprocedural_proposal={"recovered_targets": []},
            profile_sha256=PROFILE_SHA256,
            root_unit_ids=("loop:a",),
            root_entry_facts=(self.root,),
            cutpoint_facts={
                "loop:a": self.invariant,
                "loop:b": self.invariant,
            },
        )

    def test_mutable_game_loop_certificate_closes_without_replay(self) -> None:
        proposal = self.proposal()
        report = check_inductive_authority_proposals_v2(
            proposal,
            units=self.units,
            transition_summaries=self.summaries,
            memory_version_graph=self.memory,
            interprocedural_proposal={"recovered_targets": []},
            profile_sha256=PROFILE_SHA256,
            root_unit_ids=("loop:a",),
            root_entry_facts=(self.root,),
        )
        self.assertEqual(report["status"], "complete", report)
        self.assertTrue(report["authorizing"])
        self.assertEqual(report["counts"]["certificates"], 1)

    def test_checked_invariant_export_is_threaded_through_orchestration(self) -> None:
        export = ExportRequirementV2.create("loop:a", self.invariant[0])
        proposal = build_inductive_authority_proposals_v2(
            units=self.units,
            transition_summaries=self.summaries,
            memory_version_graph=self.memory,
            interprocedural_proposal={"recovered_targets": []},
            profile_sha256=PROFILE_SHA256,
            root_unit_ids=("loop:a",),
            root_entry_facts=(self.root,),
            cutpoint_facts={
                "loop:a": self.invariant,
                "loop:b": self.invariant,
            },
            required_exports=(export,),
        )
        report = check_inductive_authority_proposals_v2(
            proposal,
            units=self.units,
            transition_summaries=self.summaries,
            memory_version_graph=self.memory,
            interprocedural_proposal={"recovered_targets": []},
            profile_sha256=PROFILE_SHA256,
            root_unit_ids=("loop:a",),
            root_entry_facts=(self.root,),
            required_exports=(export,),
        )
        self.assertEqual(report["status"], "complete", report)
        self.assertEqual(report["checked_exports"], [export.to_payload()])

        omitted = check_inductive_authority_proposals_v2(
            proposal,
            units=self.units,
            transition_summaries=self.summaries,
            memory_version_graph=self.memory,
            interprocedural_proposal={"recovered_targets": []},
            profile_sha256=PROFILE_SHA256,
            root_unit_ids=("loop:a",),
            root_entry_facts=(self.root,),
        )
        self.assertEqual(omitted["status"], "violated", omitted)
        self.assertIn(
            "export_contradiction",
            {row["code"] for row in omitted["issues"]},
        )

    def test_missing_root_evidence_is_incomplete(self) -> None:
        proposal = build_inductive_authority_proposals_v2(
            units=self.units,
            transition_summaries=self.summaries,
            memory_version_graph=self.memory,
            interprocedural_proposal={"recovered_targets": []},
            profile_sha256=PROFILE_SHA256,
            root_unit_ids=("loop:a",),
            cutpoint_facts={
                "loop:a": self.invariant,
                "loop:b": self.invariant,
            },
        )
        self.assertEqual(proposal["counts"]["certificates"], 1)
        self.assertEqual(proposal["counts"]["reachable_units"], 2)
        report = check_inductive_authority_proposals_v2(
            proposal,
            units=self.units,
            transition_summaries=self.summaries,
            memory_version_graph=self.memory,
            interprocedural_proposal={"recovered_targets": []},
            profile_sha256=PROFILE_SHA256,
            root_unit_ids=("loop:a",),
        )
        self.assertEqual(report["status"], "incomplete")
        self.assertIn(
            "root_entry_facts_missing",
            {row["code"] for row in report["issues"]},
        )

    def test_corrupted_certificate_and_memory_binding_fail_closed(self) -> None:
        proposal = self.proposal()
        corrupted = copy.deepcopy(proposal)
        corrupted["certificates"][0]["member_cutpoints"] = ["loop:a"]
        report = check_inductive_authority_proposals_v2(
            corrupted,
            units=self.units,
            transition_summaries=self.summaries,
            memory_version_graph=self.memory,
            interprocedural_proposal={"recovered_targets": []},
            profile_sha256=PROFILE_SHA256,
            root_unit_ids=("loop:a",),
            root_entry_facts=(self.root,),
        )
        self.assertEqual(report["status"], "violated")

        memory = copy.deepcopy(self.memory.to_payload())
        memory["transition_summary_ids"] = []
        report = check_inductive_authority_proposals_v2(
            proposal,
            units=self.units,
            transition_summaries=self.summaries,
            memory_version_graph=memory,
            interprocedural_proposal={"recovered_targets": []},
            profile_sha256=PROFILE_SHA256,
            root_unit_ids=("loop:a",),
            root_entry_facts=(self.root,),
        )
        self.assertEqual(report["status"], "violated")

    def test_unreachable_indirect_frontier_does_not_block_rooted_induction(self) -> None:
        isolated = _unit("dead:dispatch", 0x2000, 0x2000, 3)
        isolated["semantics"]["outcome"] = {
            "kind": "indirect_jump",
            "target": _reg("eax"),
            "instruction_rva": 0x2001,
        }
        isolated["control"] = {
            "kind": "indirect_jump",
            "direct_targets": [],
            "has_indirect_target": True,
        }
        units = [*self.units, isolated]
        binary = BinaryBinding(PE_SHA256, machine_ir_sha256(units))
        summaries = build_transition_summary_inventory_v2(
            units=units, binary=binary
        )
        memory = derive_memory_version_graph_v2(
            units=units,
            binary=binary,
            transition_summaries=summaries.summaries,
        )
        proposal = build_inductive_authority_proposals_v2(
            units=units,
            transition_summaries=summaries,
            memory_version_graph=memory,
            interprocedural_proposal={"recovered_targets": []},
            profile_sha256=PROFILE_SHA256,
            root_unit_ids=("loop:a",),
            root_entry_facts=(self.root,),
            cutpoint_facts={
                "loop:a": self.invariant,
                "loop:b": self.invariant,
            },
        )
        report = check_inductive_authority_proposals_v2(
            proposal,
            units=units,
            transition_summaries=summaries,
            memory_version_graph=memory,
            interprocedural_proposal={"recovered_targets": []},
            profile_sha256=PROFILE_SHA256,
            root_unit_ids=("loop:a",),
            root_entry_facts=(self.root,),
        )
        self.assertEqual(report["status"], "complete", report)
        self.assertEqual(report["counts"]["structural_units"], 3)
        self.assertEqual(report["counts"]["reachable_units"], 2)
        self.assertEqual(report["counts"]["certificates"], 1)

    def test_compact_inventory_and_dependency_identities_fail_closed(self) -> None:
        proposal = self.proposal()
        for field in ("transition_inventory_id", "dependency_graph_id"):
            corrupted = copy.deepcopy(proposal)
            corrupted[field] = "corrupted"
            report = check_inductive_authority_proposals_v2(
                corrupted,
                units=self.units,
                transition_summaries=self.summaries,
                memory_version_graph=self.memory,
                interprocedural_proposal={"recovered_targets": []},
                profile_sha256=PROFILE_SHA256,
                root_unit_ids=("loop:a",),
                root_entry_facts=(self.root,),
            )
            self.assertEqual(report["status"], "violated", field)

    def test_internal_call_requires_an_owned_call_summary(self) -> None:
        units = copy.deepcopy(self.units)
        units[0]["semantics"]["outcome"] = {
            "kind": "internal_call",
            "target_rva": 0x1010,
        }
        units[0]["control"] = {
            "kind": "internal_call",
            "direct_targets": [0x1010],
            "has_indirect_target": False,
        }
        binary = BinaryBinding(PE_SHA256, machine_ir_sha256(units))
        summaries = build_transition_summary_inventory_v2(
            units=units, binary=binary
        )
        memory = derive_memory_version_graph_v2(
            units=units,
            binary=binary,
            transition_summaries=summaries.summaries,
        )
        proposal = build_inductive_authority_proposals_v2(
            units=units,
            transition_summaries=summaries,
            memory_version_graph=memory,
            interprocedural_proposal={"recovered_targets": []},
            profile_sha256=PROFILE_SHA256,
            root_unit_ids=("loop:a",),
            root_entry_facts=(self.root,),
            cutpoint_facts={
                "loop:a": self.invariant,
                "loop:b": self.invariant,
            },
        )
        self.assertIn(
            "call_summary",
            proposal["counts"]["dependency_nodes_by_kind"],
        )

        report = check_inductive_authority_proposals_v2(
            proposal,
            units=units,
            transition_summaries=summaries,
            memory_version_graph=memory,
            interprocedural_proposal={"recovered_targets": []},
            profile_sha256=PROFILE_SHA256,
            root_unit_ids=("loop:a",),
            root_entry_facts=(self.root,),
        )
        self.assertEqual(report["status"], "incomplete", report)
        self.assertIn(
            "external_dependency_unavailable",
            {row["code"] for row in report["issues"]},
        )

if __name__ == "__main__":
    unittest.main()
