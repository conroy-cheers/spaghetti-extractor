from __future__ import annotations

import copy
import unittest

from spaghetti_extractor.authority_bindings_v2 import BinaryBinding
from spaghetti_extractor.invariant_certificate_v2 import (
    CutpointInvariantV2,
    DependencyDischargeV2,
    DependencyNodeV2,
    EntryFactsV2,
    ExportRequirementV2,
    InvariantBudgetsV2,
    InvariantCertificateV2,
    InvariantFactV2,
    TransitionControlWitnessV2,
    TransitionWitnessInventoryV2,
    canonical_sha256,
    check_invariant_certificate_v2,
    check_transition_witness_inventory_v2,
    derive_typed_dependency_sccs_v2,
    synthesize_invariant_certificate_v2,
)
from spaghetti_extractor.machine_ir_authority_v2 import machine_ir_sha256
from spaghetti_extractor.memory_version_graph_v2 import (
    derive_memory_version_graph_v2,
)
from spaghetti_extractor.transition_summary_v2 import (
    TransitionSummaryV2,
    derive_transition_summary_v2,
)


PE_SHA256 = "a" * 64
PROFILE_SHA256 = "c" * 64
UNIVERSE_SHA256 = "d" * 64


def _const(value: int) -> dict[str, object]:
    return {"op": "const", "value": value, "width": 32}


def _reg(name: str) -> dict[str, object]:
    return {"op": "reg", "name": name, "width": 32}


def _unit(
    unit_id: str,
    rva: int,
    *,
    target_rva: int | None = None,
    write_eax: int | None = None,
    indirect: bool = False,
) -> dict[str, object]:
    outcome: dict[str, object]
    if indirect:
        outcome = {
            "kind": "indirect_jump",
            "target": _reg("eax"),
            "instruction_rva": rva + 1,
        }
    elif target_rva is not None:
        outcome = {"kind": "direct_jump", "target_rva": target_rva}
    else:
        outcome = {"kind": "process_exit"}
    register_writes = (
        []
        if write_eax is None
        else [{"register": "eax", "value": _const(write_eax)}]
    )
    semantics = {
        "pre_state": {
            "registers": {"eax": _reg("eax"), "ecx": _reg("ecx")},
            "flags": {},
        },
        "register_writes": register_writes,
        "flag_writes": [],
        "memory_events": [],
        "external_events": [],
        "faults": [],
        "ordered_events": [],
        "edge_conditions": [],
        "outcome": outcome,
        "stack_delta": None,
        "counts": {
            "register_writes": len(register_writes),
            "flag_writes": 0,
            "memory_events": 0,
            "external_events": 0,
            "faults": 0,
            "ordered_events": 0,
            "edge_conditions": 0,
        },
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
        "semantics": semantics,
        "control": {
            "kind": outcome["kind"],
            "direct_targets": [] if target_rva is None else [target_rva],
            "has_indirect_target": indirect,
        },
    }


def _facts(*facts: InvariantFactV2) -> tuple[InvariantFactV2, ...]:
    return tuple(sorted(facts))


def _certificate_copy(
    certificate: InvariantCertificateV2, **changes: object
) -> InvariantCertificateV2:
    fields = {
        "binary": certificate.binary,
        "profile_sha256": certificate.profile_sha256,
        "transition_inventory_id": certificate.transition_inventory_id,
        "dependency_scc_id": certificate.dependency_scc_id,
        "members": certificate.members,
        "control_inventory": certificate.control_inventory,
        "cutpoint_invariants": certificate.cutpoint_invariants,
        "initiation": certificate.initiation,
        "preservation": certificate.preservation,
        "target_coverage": certificate.target_coverage,
        "exports": certificate.exports,
        "dependencies": certificate.dependencies,
        "budgets": certificate.budgets,
    }
    fields.update(changes)
    return InvariantCertificateV2.create(**fields)


class _LoopFixture:
    def __init__(self) -> None:
        self.units = [
            _unit("unit:a", 0x1000, target_rva=0x1010, write_eax=1),
            _unit("unit:b", 0x1010, target_rva=0x1000, write_eax=2),
        ]
        self.binary = BinaryBinding(
            PE_SHA256, machine_ir_sha256(self.units)
        )
        self.summaries = tuple(
            derive_transition_summary_v2(unit, binary=self.binary)
            for unit in self.units
        )
        by_unit = {summary.unit.unit_id: summary for summary in self.summaries}
        self.witnesses = (
            TransitionControlWitnessV2.create(
                summary=by_unit["unit:a"], target_cutpoints=("unit:b",)
            ),
            TransitionControlWitnessV2.create(
                summary=by_unit["unit:b"], target_cutpoints=("unit:a",)
            ),
        )
        self.inventory = TransitionWitnessInventoryV2.create(
            binary=self.binary,
            structural_universe_sha256=UNIVERSE_SHA256,
            summaries=self.summaries,
            control_witnesses=self.witnesses,
        )
        self.dependency_nodes = (
            DependencyNodeV2(
                "invariant:loop",
                "invariant",
                canonical_sha256({"control_scc": ["unit:a", "unit:b"]}),
            ),
        )
        self.dependency_edges = ()
        self.dependency_members = ("invariant:loop",)
        self.invariant = _facts(
            InvariantFactV2.finite("register:eax", (1, 2)),
            InvariantFactV2.range("register:ecx", 0, 10),
            InvariantFactV2.congruence("register:ecx", 2, 0),
            InvariantFactV2.resource_lifecycle(
                "resource:surface", "surface-1", ("live", "lost")
            ),
        )
        self.entry = EntryFactsV2(
            entry_id="entry:root",
            kind="root",
            target_cutpoint="unit:a",
            transition_id=None,
            facts=_facts(
                InvariantFactV2.exact("register:eax", 1),
                InvariantFactV2.exact("register:ecx", 4),
                InvariantFactV2.resource_lifecycle(
                    "resource:surface", "surface-1", ("live",)
                ),
            ),
        )
        self.export = ExportRequirementV2.create(
            "unit:a", InvariantFactV2.finite("register:eax", (1, 2))
        )

    def synthesize(
        self,
        *,
        facts: dict[str, tuple[InvariantFactV2, ...]] | None = None,
        entries: tuple[EntryFactsV2, ...] | None = None,
        exports: tuple[ExportRequirementV2, ...] | None = None,
        budgets: InvariantBudgetsV2 = InvariantBudgetsV2(),
        inventory: TransitionWitnessInventoryV2 | None = None,
    ) -> InvariantCertificateV2:
        return synthesize_invariant_certificate_v2(
            transition_inventory=self.inventory if inventory is None else inventory,
            dependency_nodes=self.dependency_nodes,
            dependency_edges=self.dependency_edges,
            member_cutpoints=("unit:a", "unit:b"),
            dependency_members=self.dependency_members,
            cutpoint_facts=(
                {"unit:a": self.invariant, "unit:b": self.invariant}
                if facts is None
                else facts
            ),
            entry_facts=(self.entry,) if entries is None else entries,
            required_exports=(self.export,) if exports is None else exports,
            profile_sha256=PROFILE_SHA256,
            budgets=budgets,
        )

    def check(
        self,
        certificate: InvariantCertificateV2 | dict[str, object],
        *,
        budgets: InvariantBudgetsV2 = InvariantBudgetsV2(),
        inventory: TransitionWitnessInventoryV2 | None = None,
        exports: tuple[ExportRequirementV2, ...] | None = None,
        profile_sha256: str = PROFILE_SHA256,
    ) -> dict[str, object]:
        return check_invariant_certificate_v2(
            certificate,
            transition_inventory=self.inventory if inventory is None else inventory,
            canonical_summaries=(
                self.summaries if inventory is None else inventory.summaries
            ),
            dependency_nodes=self.dependency_nodes,
            dependency_edges=self.dependency_edges,
            expected_member_cutpoints=("unit:a", "unit:b"),
            expected_dependency_members=self.dependency_members,
            entry_facts=(self.entry,),
            required_exports=(self.export,) if exports is None else exports,
            profile_sha256=profile_sha256,
            budgets=budgets,
        )


class InvariantCertificateV2Tests(unittest.TestCase):
    def test_finite_loop_certificate_is_complete_and_deterministic(self) -> None:
        fixture = _LoopFixture()
        first = fixture.synthesize()
        second = fixture.synthesize()

        self.assertEqual(first, second)
        self.assertIsInstance(fixture.inventory.summaries[0], TransitionSummaryV2)
        result = fixture.check(first)

        self.assertEqual(result["status"], "complete")
        self.assertTrue(result["authorizing"])
        self.assertEqual(len(result["checked_exports"]), 1)
        self.assertEqual(
            {row["kind"] for row in result["obligations"]},
            {"export", "initiation", "preservation"},
        )

    def test_round_trip_has_strict_bindings_and_rejects_solver_status(self) -> None:
        fixture = _LoopFixture()
        certificate = fixture.synthesize()
        parsed = InvariantCertificateV2.parse(certificate.to_payload())
        self.assertEqual(fixture.check(parsed)["status"], "complete")
        self.assertEqual(
            fixture.check(parsed, profile_sha256="f" * 64)["status"],
            "violated",
        )

        untrusted = copy.deepcopy(certificate.to_payload())
        untrusted["solver_status"] = "unsat"
        result = fixture.check(untrusted)
        self.assertEqual(result["status"], "violated")
        self.assertIn(
            "certificate_malformed", {issue["code"] for issue in result["issues"]}
        )

    def test_witness_inventory_has_a_strict_boundary_rechecker(self) -> None:
        fixture = _LoopFixture()
        payload = fixture.inventory.to_payload()
        checked = check_transition_witness_inventory_v2(
            payload,
            canonical_summaries=fixture.summaries,
            binary=fixture.binary,
            structural_universe_sha256=UNIVERSE_SHA256,
            dependency_nodes=fixture.dependency_nodes,
        )
        self.assertEqual(checked["status"], "complete")

        corrupted = copy.deepcopy(payload)
        corrupted["control_witnesses"][0]["target_cutpoints"] = ["unit:a"]
        result = check_transition_witness_inventory_v2(
            corrupted,
            canonical_summaries=fixture.summaries,
            binary=fixture.binary,
            structural_universe_sha256=UNIVERSE_SHA256,
            dependency_nodes=fixture.dependency_nodes,
        )
        self.assertEqual(result["status"], "violated")
        self.assertIn(
            "witness_inventory_malformed",
            {issue["code"] for issue in result["issues"]},
        )

    def test_control_inventory_is_reconstructed_from_canonical_summaries(self) -> None:
        fixture = _LoopFixture()
        certificate = fixture.synthesize()
        control = certificate.control_inventory.to_value()
        control["internal"] = control["internal"][1:]
        omitted = _certificate_copy(
            certificate,
            control_inventory=type(certificate.control_inventory).of(control),
        )

        result = fixture.check(omitted)
        self.assertEqual(result["status"], "incomplete")
        self.assertIn(
            "control_internal_missing",
            {issue["code"] for issue in result["issues"]},
        )

    def test_incoming_and_outgoing_inventories_are_complete(self) -> None:
        fixture = _LoopFixture()
        dependency = DependencyNodeV2(
            "invariant:unit-a",
            "invariant",
            canonical_sha256({"control_scc": ["unit:a"]}),
        )
        dependency_nodes = (dependency,)
        dependency_members = (dependency.node_id,)
        incoming_witness = next(
            witness
            for witness in fixture.witnesses
            if witness.source_cutpoint == "unit:b"
        )
        incoming = EntryFactsV2(
            entry_id="entry:from-b",
            kind="incoming",
            target_cutpoint="unit:a",
            transition_id=incoming_witness.witness_id,
            facts=fixture.invariant,
            exit_id=incoming_witness.exit_targets[0].exit_id,
        )
        certificate = synthesize_invariant_certificate_v2(
            transition_inventory=fixture.inventory,
            dependency_nodes=dependency_nodes,
            dependency_edges=fixture.dependency_edges,
            member_cutpoints=("unit:a",),
            dependency_members=dependency_members,
            cutpoint_facts={"unit:a": fixture.invariant},
            entry_facts=(incoming,),
            profile_sha256=PROFILE_SHA256,
        )
        complete = check_invariant_certificate_v2(
            certificate,
            transition_inventory=fixture.inventory,
            canonical_summaries=fixture.summaries,
            dependency_nodes=dependency_nodes,
            dependency_edges=fixture.dependency_edges,
            expected_member_cutpoints=("unit:a",),
            expected_dependency_members=dependency_members,
            entry_facts=(incoming,),
            profile_sha256=PROFILE_SHA256,
        )
        self.assertEqual(complete["status"], "complete")

        too_strong = _facts(InvariantFactV2.exact("register:eax", 1))
        failed_entry = EntryFactsV2(
            entry_id="entry:from-b-failed",
            kind="incoming",
            target_cutpoint="unit:a",
            transition_id=incoming_witness.witness_id,
            facts=too_strong,
            exit_id=incoming_witness.exit_targets[0].exit_id,
        )
        failed = synthesize_invariant_certificate_v2(
            transition_inventory=fixture.inventory,
            dependency_nodes=dependency_nodes,
            dependency_edges=fixture.dependency_edges,
            member_cutpoints=("unit:a",),
            dependency_members=dependency_members,
            cutpoint_facts={"unit:a": too_strong},
            entry_facts=(failed_entry,),
            profile_sha256=PROFILE_SHA256,
        )
        failed_result = check_invariant_certificate_v2(
            failed,
            transition_inventory=fixture.inventory,
            canonical_summaries=fixture.summaries,
            dependency_nodes=dependency_nodes,
            dependency_edges=fixture.dependency_edges,
            expected_member_cutpoints=("unit:a",),
            expected_dependency_members=dependency_members,
            entry_facts=(failed_entry,),
            profile_sha256=PROFILE_SHA256,
        )
        self.assertEqual(failed_result["status"], "incomplete")
        self.assertIn(
            "initiation_not_proved",
            {issue["code"] for issue in failed_result["issues"]},
        )

        wrong_exit = EntryFactsV2(
            entry_id="entry:wrong-exit",
            kind="incoming",
            target_cutpoint="unit:a",
            transition_id=incoming_witness.witness_id,
            facts=fixture.invariant,
            exit_id="exit:not-present",
        )
        wrong_exit_certificate = synthesize_invariant_certificate_v2(
            transition_inventory=fixture.inventory,
            dependency_nodes=dependency_nodes,
            dependency_edges=fixture.dependency_edges,
            member_cutpoints=("unit:a",),
            dependency_members=dependency_members,
            cutpoint_facts={"unit:a": fixture.invariant},
            entry_facts=(wrong_exit,),
            profile_sha256=PROFILE_SHA256,
        )
        wrong_exit_result = check_invariant_certificate_v2(
            wrong_exit_certificate,
            transition_inventory=fixture.inventory,
            canonical_summaries=fixture.summaries,
            dependency_nodes=dependency_nodes,
            dependency_edges=fixture.dependency_edges,
            expected_member_cutpoints=("unit:a",),
            expected_dependency_members=dependency_members,
            entry_facts=(wrong_exit,),
            profile_sha256=PROFILE_SHA256,
        )
        self.assertEqual(wrong_exit_result["status"], "violated")
        self.assertIn(
            "incoming_entry_contradiction",
            {issue["code"] for issue in wrong_exit_result["issues"]},
        )

        control = certificate.control_inventory.to_value()
        control["outgoing"] = []
        omitted = _certificate_copy(
            certificate,
            control_inventory=type(certificate.control_inventory).of(control),
        )
        incomplete = check_invariant_certificate_v2(
            omitted,
            transition_inventory=fixture.inventory,
            canonical_summaries=fixture.summaries,
            dependency_nodes=dependency_nodes,
            dependency_edges=fixture.dependency_edges,
            expected_member_cutpoints=("unit:a",),
            expected_dependency_members=dependency_members,
            entry_facts=(incoming,),
            profile_sha256=PROFILE_SHA256,
        )
        self.assertEqual(incomplete["status"], "incomplete")
        self.assertIn(
            "control_outgoing_missing",
            {issue["code"] for issue in incomplete["issues"]},
        )

    def test_direct_target_contradiction_is_violated(self) -> None:
        fixture = _LoopFixture()
        by_unit = {
            summary.unit.unit_id: summary for summary in fixture.summaries
        }
        wrong = TransitionWitnessInventoryV2.create(
            binary=fixture.binary,
            structural_universe_sha256=UNIVERSE_SHA256,
            summaries=fixture.summaries,
            control_witnesses=(
                TransitionControlWitnessV2.create(
                    summary=by_unit["unit:a"], target_cutpoints=("unit:a",)
                ),
                fixture.witnesses[1],
            ),
        )
        certificate = fixture.synthesize(inventory=wrong)

        result = fixture.check(certificate, inventory=wrong)
        self.assertEqual(result["status"], "violated")
        self.assertIn(
            "direct_target_contradiction",
            {issue["code"] for issue in result["issues"]},
        )

    def test_missing_initiation_and_failed_preservation_are_incomplete(self) -> None:
        fixture = _LoopFixture()
        no_entry = fixture.synthesize(entries=())
        no_entry_result = check_invariant_certificate_v2(
            no_entry,
            transition_inventory=fixture.inventory,
            canonical_summaries=fixture.summaries,
            dependency_nodes=fixture.dependency_nodes,
            dependency_edges=fixture.dependency_edges,
            expected_member_cutpoints=("unit:a", "unit:b"),
            expected_dependency_members=fixture.dependency_members,
            entry_facts=(),
            required_exports=(fixture.export,),
            profile_sha256=PROFILE_SHA256,
        )
        self.assertEqual(no_entry_result["status"], "incomplete")
        self.assertIn(
            "root_initiation_missing",
            {issue["code"] for issue in no_entry_result["issues"]},
        )

        impossible = _facts(InvariantFactV2.exact("register:eax", 2))
        failed = fixture.synthesize(
            facts={"unit:a": fixture.invariant, "unit:b": impossible},
            exports=(),
        )
        failed_result = fixture.check(failed, exports=())
        self.assertEqual(failed_result["status"], "incomplete")
        self.assertIn(
            "preservation_not_proved",
            {issue["code"] for issue in failed_result["issues"]},
        )

    def test_stack_delta_does_not_establish_an_exact_esp_value(self) -> None:
        fixture = _LoopFixture()
        units = copy.deepcopy(fixture.units)
        units[0]["semantics"]["stack_delta"] = _const(4)
        binary = BinaryBinding(PE_SHA256, machine_ir_sha256(units))
        summaries = tuple(
            derive_transition_summary_v2(unit, binary=binary) for unit in units
        )
        by_unit = {summary.unit.unit_id: summary for summary in summaries}
        inventory = TransitionWitnessInventoryV2.create(
            binary=binary,
            structural_universe_sha256=UNIVERSE_SHA256,
            summaries=summaries,
            control_witnesses=(
                TransitionControlWitnessV2.create(
                    summary=by_unit["unit:a"], target_cutpoints=("unit:b",)
                ),
                TransitionControlWitnessV2.create(
                    summary=by_unit["unit:b"], target_cutpoints=("unit:a",)
                ),
            ),
        )
        dependency = DependencyNodeV2(
            "invariant:stack",
            "invariant",
            canonical_sha256({"control_scc": ["unit:a", "unit:b"]}),
        )
        esp_is_four = _facts(InvariantFactV2.exact("register:esp", 4))
        entry = EntryFactsV2(
            "entry:stack", "root", "unit:a", None, esp_is_four
        )
        certificate = synthesize_invariant_certificate_v2(
            transition_inventory=inventory,
            dependency_nodes=(dependency,),
            dependency_edges=(),
            member_cutpoints=("unit:a", "unit:b"),
            dependency_members=(dependency.node_id,),
            cutpoint_facts={"unit:a": esp_is_four, "unit:b": esp_is_four},
            entry_facts=(entry,),
            profile_sha256=PROFILE_SHA256,
        )
        result = check_invariant_certificate_v2(
            certificate,
            transition_inventory=inventory,
            canonical_summaries=summaries,
            dependency_nodes=(dependency,),
            dependency_edges=(),
            expected_member_cutpoints=("unit:a", "unit:b"),
            expected_dependency_members=(dependency.node_id,),
            entry_facts=(entry,),
            profile_sha256=PROFILE_SHA256,
        )
        self.assertEqual(result["status"], "incomplete")
        self.assertIn(
            "preservation_not_proved",
            {issue["code"] for issue in result["issues"]},
        )

    def test_mutable_memory_loop_is_closed_by_checked_framed_updates(self) -> None:
        units = [
            _unit("unit:a", 0x1000, target_rva=0x1010),
            _unit("unit:b", 0x1010, target_rva=0x1000),
        ]
        for index, unit in enumerate(units, 1):
            unit["semantics"]["pre_state"]["memory"] = {
                "op": "memory",
                "name": "mem0",
                "address_width": 32,
                "value_width": 8,
            }
            unit["semantics"]["memory_events"] = [{
                "kind": "write",
                "width": 4,
                "instruction_rva": unit["source"]["original"]["rva_start"] + 1,
                "address": _const(0x402000),
                "value": _const(index),
            }]
            unit["semantics"]["counts"]["memory_events"] = 1
        binary = BinaryBinding(PE_SHA256, machine_ir_sha256(units))
        summaries = tuple(
            derive_transition_summary_v2(unit, binary=binary) for unit in units
        )
        memory_graph = derive_memory_version_graph_v2(
            units=units,
            binary=binary,
            transition_summaries=summaries,
        )
        by_unit = {summary.unit.unit_id: summary for summary in summaries}
        memory_dependencies = tuple(
            DependencyNodeV2(
                f"memory-access:{access.access_id}",
                "memory_version",
                canonical_sha256(access.to_payload()),
            )
            for summary in summaries
            for access in summary.memory_accesses
        )
        memory_ids_by_unit = {
            summary.unit.unit_id: tuple(
                f"memory-access:{access.access_id}"
                for access in summary.memory_accesses
            )
            for summary in summaries
        }
        inventory = TransitionWitnessInventoryV2.create(
            binary=binary,
            structural_universe_sha256=UNIVERSE_SHA256,
            summaries=summaries,
            control_witnesses=(
                TransitionControlWitnessV2.create(
                    summary=by_unit["unit:a"],
                    target_cutpoints=("unit:b",),
                    dependency_ids=memory_ids_by_unit["unit:a"],
                ),
                TransitionControlWitnessV2.create(
                    summary=by_unit["unit:b"],
                    target_cutpoints=("unit:a",),
                    dependency_ids=memory_ids_by_unit["unit:b"],
                ),
            ),
        )
        dependency = DependencyNodeV2(
            "invariant:memory-loop",
            "invariant",
            canonical_sha256({"control_scc": ["unit:a", "unit:b"]}),
        )
        dependency_nodes = tuple(sorted((dependency, *memory_dependencies)))
        slot = "memory-range:4202496:4202500"
        invariant = _facts(InvariantFactV2.finite(slot, (1, 2)))
        entry = EntryFactsV2(
            "entry:memory", "root", "unit:a", None,
            _facts(InvariantFactV2.exact(slot, 1)),
        )
        certificate = synthesize_invariant_certificate_v2(
            transition_inventory=inventory,
            dependency_nodes=dependency_nodes,
            dependency_edges=(),
            member_cutpoints=("unit:a", "unit:b"),
            dependency_members=(dependency.node_id,),
            cutpoint_facts={"unit:a": invariant, "unit:b": invariant},
            entry_facts=(entry,),
            profile_sha256=PROFILE_SHA256,
        )
        result = check_invariant_certificate_v2(
            certificate,
            transition_inventory=inventory,
            canonical_summaries=summaries,
            memory_version_graph=memory_graph,
            dependency_nodes=dependency_nodes,
            dependency_edges=(),
            expected_member_cutpoints=("unit:a", "unit:b"),
            expected_dependency_members=(dependency.node_id,),
            entry_facts=(entry,),
            profile_sha256=PROFILE_SHA256,
        )
        self.assertEqual(result["status"], "complete", result)

        without_memory_authority = check_invariant_certificate_v2(
            certificate,
            transition_inventory=inventory,
            canonical_summaries=summaries,
            dependency_nodes=dependency_nodes,
            dependency_edges=(),
            expected_member_cutpoints=("unit:a", "unit:b"),
            expected_dependency_members=(dependency.node_id,),
            entry_facts=(entry,),
            profile_sha256=PROFILE_SHA256,
        )
        self.assertEqual(without_memory_authority["status"], "incomplete")
        self.assertIn(
            "preservation_not_proved",
            {issue["code"] for issue in without_memory_authority["issues"]},
        )

    def test_contradictory_invariant_is_violated(self) -> None:
        fixture = _LoopFixture()
        contradictory = _facts(
            InvariantFactV2.exact("register:eax", 1),
            InvariantFactV2.exact("register:eax", 2),
        )
        certificate = fixture.synthesize(
            facts={"unit:a": contradictory, "unit:b": fixture.invariant},
            exports=(),
        )
        result = fixture.check(certificate, exports=())
        self.assertEqual(result["status"], "violated")
        self.assertIn(
            "cutpoint_invariant_contradictory",
            {issue["code"] for issue in result["issues"]},
        )

    def test_export_must_be_implied_and_budget_overflow_is_incomplete(self) -> None:
        fixture = _LoopFixture()
        exact_export = ExportRequirementV2.create(
            "unit:a", InvariantFactV2.exact("register:eax", 1)
        )
        certificate = fixture.synthesize(exports=(exact_export,))
        result = fixture.check(certificate, exports=(exact_export,))
        self.assertEqual(result["status"], "incomplete")
        self.assertIn(
            "export_not_implied", {issue["code"] for issue in result["issues"]}
        )

        tight = InvariantBudgetsV2(maximum_finite_values=1)
        budgeted = fixture.synthesize(budgets=tight)
        budget_result = fixture.check(budgeted, budgets=tight)
        self.assertEqual(budget_result["status"], "incomplete")
        self.assertIn(
            "finite_value_budget_exceeded",
            {issue["code"] for issue in budget_result["issues"]},
        )

    def test_indirect_target_dependency_and_finite_budget_are_checked(self) -> None:
        units = [_unit("unit:dispatch", 0x2000, indirect=True)]
        binary = BinaryBinding(PE_SHA256, machine_ir_sha256(units))
        summary = derive_transition_summary_v2(units[0], binary=binary)
        outcome = next(row for row in summary.exits if row.source_kind == "outcome")
        target_dependency = DependencyNodeV2(
            "target:dispatch",
            "indirect_target",
            canonical_sha256(outcome.to_payload()),
        )
        invariant_dependency = DependencyNodeV2(
            "invariant:dispatch",
            "invariant",
            canonical_sha256({"control_scc": ["unit:dispatch"]}),
        )
        dependency_nodes = tuple(sorted((invariant_dependency, target_dependency)))
        witness = TransitionControlWitnessV2.create(
            summary=summary,
            target_cutpoints=("unit:dispatch",),
            dependency_ids=(target_dependency.node_id,),
        )
        inventory = TransitionWitnessInventoryV2.create(
            binary=binary,
            structural_universe_sha256=UNIVERSE_SHA256,
            summaries=(summary,),
            control_witnesses=(witness,),
        )
        invariant = _facts(InvariantFactV2.range("register:ecx", 0, 4))
        entry = EntryFactsV2(
            "entry:dispatch",
            "root",
            "unit:dispatch",
            None,
            _facts(InvariantFactV2.exact("register:ecx", 2)),
        )
        tight = InvariantBudgetsV2(maximum_finite_values=1)
        certificate = synthesize_invariant_certificate_v2(
            transition_inventory=inventory,
            dependency_nodes=dependency_nodes,
            dependency_edges=(),
            member_cutpoints=("unit:dispatch",),
            dependency_members=(invariant_dependency.node_id,),
            cutpoint_facts={"unit:dispatch": invariant},
            entry_facts=(entry,),
            profile_sha256=PROFILE_SHA256,
            budgets=tight,
        )
        result = check_invariant_certificate_v2(
            certificate,
            transition_inventory=inventory,
            canonical_summaries=(summary,),
            dependency_nodes=dependency_nodes,
            dependency_edges=(),
            expected_member_cutpoints=("unit:dispatch",),
            expected_dependency_members=(invariant_dependency.node_id,),
            entry_facts=(entry,),
            profile_sha256=PROFILE_SHA256,
            budgets=tight,
        )
        self.assertEqual(result["status"], "incomplete")
        self.assertIn(
            "external_dependency_unavailable",
            {issue["code"] for issue in result["issues"]},
        )

        discharge = DependencyDischargeV2(
            dependency_id=target_dependency.node_id,
            kind="indirect_target",
            binding_sha256=target_dependency.binding_sha256,
            authority_artifact_id="checked-indirect-target:fixture",
            evidence_sha256="e" * 64,
        )
        discharged = check_invariant_certificate_v2(
            certificate,
            transition_inventory=inventory,
            canonical_summaries=(summary,),
            dependency_nodes=dependency_nodes,
            dependency_edges=(),
            dependency_discharges=(discharge,),
            expected_member_cutpoints=("unit:dispatch",),
            expected_dependency_members=(invariant_dependency.node_id,),
            entry_facts=(entry,),
            profile_sha256=PROFILE_SHA256,
            budgets=tight,
        )
        self.assertEqual(discharged["status"], "complete", discharged)

        wrong_discharge = DependencyDischargeV2(
            dependency_id=target_dependency.node_id,
            kind="indirect_target",
            binding_sha256="f" * 64,
            authority_artifact_id="checked-indirect-target:fixture",
            evidence_sha256="e" * 64,
        )
        contradicted = check_invariant_certificate_v2(
            certificate,
            transition_inventory=inventory,
            canonical_summaries=(summary,),
            dependency_nodes=dependency_nodes,
            dependency_edges=(),
            dependency_discharges=(wrong_discharge,),
            expected_member_cutpoints=("unit:dispatch",),
            expected_dependency_members=(invariant_dependency.node_id,),
            entry_facts=(entry,),
            profile_sha256=PROFILE_SHA256,
            budgets=tight,
        )
        self.assertEqual(contradicted["status"], "violated")
        self.assertIn(
            "dependency_discharge_binding_contradiction",
            {issue["code"] for issue in contradicted["issues"]},
        )

        self_justifying = synthesize_invariant_certificate_v2(
            transition_inventory=inventory,
            dependency_nodes=dependency_nodes,
            dependency_edges=(),
            member_cutpoints=("unit:dispatch",),
            dependency_members=(target_dependency.node_id,),
            cutpoint_facts={"unit:dispatch": invariant},
            entry_facts=(entry,),
            profile_sha256=PROFILE_SHA256,
            budgets=tight,
        )
        self_justifying_result = check_invariant_certificate_v2(
            self_justifying,
            transition_inventory=inventory,
            canonical_summaries=(summary,),
            dependency_nodes=dependency_nodes,
            dependency_edges=(),
            expected_member_cutpoints=("unit:dispatch",),
            expected_dependency_members=(target_dependency.node_id,),
            entry_facts=(entry,),
            profile_sha256=PROFILE_SHA256,
            budgets=tight,
        )
        self.assertEqual(self_justifying_result["status"], "violated")
        self.assertIn(
            "invariant_dependency_scc_contradiction",
            {issue["code"] for issue in self_justifying_result["issues"]},
        )

        missing_witness = TransitionControlWitnessV2.create(
            summary=summary,
            target_cutpoints=("unit:dispatch",),
        )
        missing_inventory = TransitionWitnessInventoryV2.create(
            binary=binary,
            structural_universe_sha256=UNIVERSE_SHA256,
            summaries=(summary,),
            control_witnesses=(missing_witness,),
        )
        missing_certificate = synthesize_invariant_certificate_v2(
            transition_inventory=missing_inventory,
            dependency_nodes=dependency_nodes,
            dependency_edges=(),
            member_cutpoints=("unit:dispatch",),
            dependency_members=(invariant_dependency.node_id,),
            cutpoint_facts={"unit:dispatch": invariant},
            entry_facts=(entry,),
            profile_sha256=PROFILE_SHA256,
            budgets=tight,
        )
        missing = check_invariant_certificate_v2(
            missing_certificate,
            transition_inventory=missing_inventory,
            canonical_summaries=(summary,),
            dependency_nodes=dependency_nodes,
            dependency_edges=(),
            expected_member_cutpoints=("unit:dispatch",),
            expected_dependency_members=(invariant_dependency.node_id,),
            entry_facts=(entry,),
            profile_sha256=PROFILE_SHA256,
            budgets=tight,
        )
        self.assertEqual(missing["status"], "incomplete")
        self.assertIn(
            "indirect_target_dependency_missing",
            {issue["code"] for issue in missing["issues"]},
        )

    def test_dependency_sccs_are_reconstructed_not_submitted(self) -> None:
        nodes = (
            DependencyNodeV2("value:a", "value", "1" * 64),
            DependencyNodeV2("value:b", "memory_version", "2" * 64),
        )
        from spaghetti_extractor.invariant_certificate_v2 import DependencyEdgeV2

        edges = (
            DependencyEdgeV2("value:a", "value:b", "consumes"),
            DependencyEdgeV2("value:b", "value:a", "preserves"),
        )
        components = derive_typed_dependency_sccs_v2(nodes, edges)
        self.assertEqual(len(components), 1)
        self.assertEqual(components[0].members, ("value:a", "value:b"))
        self.assertEqual(len(components[0].internal_edges), 2)


if __name__ == "__main__":
    unittest.main()
