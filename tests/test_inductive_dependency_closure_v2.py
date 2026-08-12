from __future__ import annotations

import copy
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.authority_bindings_v2 import BinaryBinding
from spaghetti_extractor.entry_state_analysis_v2 import (
    derive_callback_entry_state_contracts_v2,
)
from spaghetti_extractor.external_profile_authority_v2 import (
    build_external_profile_authority_v2,
)
from spaghetti_extractor.external_site_proposals_v2 import (
    derive_external_site_proposals_v2,
)
from spaghetti_extractor.inductive_authority_phase_v2 import (
    build_inductive_authority_proposals_v2,
    check_inductive_authority_proposals_v2,
)
from spaghetti_extractor.inductive_dependency_closure_v2 import (
    close_inductive_dependencies_v2,
)
from spaghetti_extractor.invariant_certificate_v2 import EntryFactsV2
from spaghetti_extractor.machine_ir_authority_v2 import machine_ir_sha256
from spaghetti_extractor.memory_version_graph_v2 import (
    derive_memory_version_graph_v2,
)
from spaghetti_extractor.transition_inventory_v2 import (
    build_transition_summary_inventory_v2,
)
from tests.test_checked_external_site_contract import _event, _write_profile


PE_SHA256 = "a" * 64
PROFILE_SHA256 = "b" * 64


def _unit(event: dict[str, object]) -> dict[str, object]:
    return {
        "format": "stage-a-machine-ir-v2",
        "record_kind": "unit",
        "id": "unit:entry",
        "status": "qualified",
        "source": {
            "original": {"rva_start": 0x1000, "rva_end": 0x1008},
            "instruction_bytes_sha256": "1" * 64,
        },
        "expression_model": "stage-a-semantic-ir-v1",
        "instructions": [],
        "semantics": {
            "pre_state": {"registers": {}, "flags": {}},
            "register_writes": [],
            "flag_writes": [],
            "memory_events": [],
            "external_events": [event],
            "faults": [],
            "ordered_events": [],
            "edge_conditions": [],
            "outcome": {"kind": "process_exit"},
            "stack_delta": None,
            "counts": {
                "register_writes": 0,
                "flag_writes": 0,
                "memory_events": 0,
                "external_events": 1,
                "faults": 0,
                "ordered_events": 0,
                "edge_conditions": 0,
            },
        },
        "control": {
            "kind": "process_exit",
            "direct_targets": [],
            "has_indirect_target": False,
        },
    }


class InductiveDependencyClosureV2Tests(unittest.TestCase):
    def test_callback_site_requires_external_and_entry_authority(self) -> None:
        event = _event(profile_sha256="c" * 64)
        event["abi_contract"]["callback_source"] = {
            "kind": "stack_argument",
            "offset": 0,
        }
        units = [_unit(event)]
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
            root_unit_ids=("unit:entry",),
            root_entry_facts=(
                EntryFactsV2("launch:entry", "root", "unit:entry", None, ()),
            ),
        )

        kinds = proposal["counts"]["dependency_nodes_by_kind"]
        self.assertEqual(kinds["external_site"], 1)
        self.assertEqual(kinds["callback_entry"], 1)

    def test_exact_external_site_closes_late_dependency(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            profile_path = Path(temporary) / "profile.json"
            _write_profile(profile_path)
            profile_authority = build_external_profile_authority_v2([profile_path])
            unit = _unit(_event(profile_sha256=profile_authority.entries[0].profile_sha256))
            units = [unit]
            binary = BinaryBinding(PE_SHA256, machine_ir_sha256(units))
            summaries = build_transition_summary_inventory_v2(
                units=units, binary=binary
            )
            memory = derive_memory_version_graph_v2(
                units=units,
                binary=binary,
                transition_summaries=summaries.summaries,
            )
            root = EntryFactsV2(
                "launch:entry", "root", "unit:entry", None, ()
            )
            callback_provenance = {
                "format": "stage-a-external-interface-provenance-v1",
                "proof_authority": False,
                "callback_registrations": [],
            }
            interprocedural = {
                "recovered_targets": [],
                "operation_provenance": callback_provenance,
            }
            proposal = build_inductive_authority_proposals_v2(
                units=units,
                transition_summaries=summaries,
                memory_version_graph=memory,
                interprocedural_proposal=interprocedural,
                profile_sha256=PROFILE_SHA256,
                root_unit_ids=("unit:entry",),
                root_entry_facts=(root,),
            )
            local = check_inductive_authority_proposals_v2(
                proposal,
                units=units,
                transition_summaries=summaries,
                memory_version_graph=memory,
                interprocedural_proposal=interprocedural,
                profile_sha256=PROFILE_SHA256,
                root_unit_ids=("unit:entry",),
                root_entry_facts=(root,),
            )
            self.assertEqual(local["status"], "incomplete", local)
            self.assertIn(
                "external_dependency_unavailable",
                {issue["code"] for issue in local["issues"]},
            )

            external_sites = derive_external_site_proposals_v2(
                machine_ir_rows=units,
                interprocedural=interprocedural,
                profile_authority=profile_authority,
                pe_sha256=binary.pe_sha256,
                machine_ir_sha256=binary.machine_ir_sha256,
                reachable_unit_ids=("unit:entry",),
            )
            callback_entries = derive_callback_entry_state_contracts_v2(
                pe_sha256=binary.pe_sha256,
                image_base=0x400000,
                size_of_image=0x10000,
                interface_provenance=callback_provenance,
                units=units,
                machine_ir_sha256=binary.machine_ir_sha256,
            )
            global_slots = {
                "format": "spaghetti-extractor-global-slot-authority-v2",
                "status": "complete",
                "global_slot_invariants": [],
            }
            closed = close_inductive_dependencies_v2(
                proposal,
                local_authority=local,
                units=units,
                transition_summaries=summaries,
                memory_version_graph=memory,
                target_proposals=interprocedural,
                environment_interprocedural_proposal=interprocedural,
                profile_sha256=PROFILE_SHA256,
                root_unit_ids=("unit:entry",),
                root_entry_facts=(root,),
                reachable_unit_ids=("unit:entry",),
                external_site_proposals=external_sites,
                external_profile_authority=profile_authority,
                callback_entry_contracts=callback_entries,
                callback_image_base=0x400000,
                callback_size_of_image=0x10000,
                global_slot_authority=global_slots,
            )
            self.assertEqual(closed["status"], "complete", closed)
            self.assertTrue(closed["authorizing"])
            self.assertEqual(
                [row["kind"] for row in closed["dependency_discharges"]],
                ["external_site"],
            )

            stale = copy.deepcopy(external_sites)
            stale["sites"] = []
            contradicted = close_inductive_dependencies_v2(
                proposal,
                local_authority=local,
                units=units,
                transition_summaries=summaries,
                memory_version_graph=memory,
                target_proposals=interprocedural,
                environment_interprocedural_proposal=interprocedural,
                profile_sha256=PROFILE_SHA256,
                root_unit_ids=("unit:entry",),
                root_entry_facts=(root,),
                reachable_unit_ids=("unit:entry",),
                external_site_proposals=stale,
                external_profile_authority=profile_authority,
                callback_entry_contracts=callback_entries,
                callback_image_base=0x400000,
                callback_size_of_image=0x10000,
                global_slot_authority=global_slots,
            )
            self.assertEqual(contradicted["status"], "violated")
            self.assertIn(
                "external_site_dependency_artifact_contradiction",
                {issue["code"] for issue in contradicted["issues"]},
            )


if __name__ == "__main__":
    unittest.main()
