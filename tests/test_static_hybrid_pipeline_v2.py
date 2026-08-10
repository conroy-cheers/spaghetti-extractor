from __future__ import annotations

import copy
import unittest
from types import SimpleNamespace
from typing import cast

from spaghetti_extractor.behavioral_roots import (
    BEHAVIORAL_ROOTS_FORMAT,
    behavioral_roots_sha256,
)
from spaghetti_extractor.entry_state_analysis_v2 import (
    construct_entry_state_analysis_v2,
)
from spaghetti_extractor.exception_invariants_v2 import (
    synthesize_exception_invariant_certificate_v2,
)
from spaghetti_extractor.hybrid_authority_v2 import GlobalSlotInvariant
from spaghetti_extractor.interprocedural_phase_v2 import (
    _validate_interprocedural_mutable_handoff,
)
from spaghetti_extractor.mutable_slot_candidates_v2 import (
    derive_proposal_slot_dependencies,
)
from spaghetti_extractor.static_hybrid_pipeline_v2 import (
    _exact_indirect_exit_id,
    derive_checked_exception_reports_v2,
    derive_faulting_rooted_sccs_v2,
    derive_iat_facts,
    derive_interprocedural_result_v2,
    derive_mutable_slot_candidates,
    derive_rooted_control_graph_v2,
    promote_complete_global_slot_evidence_v2,
)
from spaghetti_extractor.stage_binary import StageABinary


BINARY_SHA = "1" * 64
MACHINE_IR_SHA = "2" * 64


def _row(unit_id: str, rva: int) -> dict:
    return {
        "id": unit_id,
        "source": {"original": {"rva_start": rva, "rva_end": rva + 1}},
    }


def _reg(name: str) -> dict:
    return {"op": "reg", "name": name, "width": 32}


def _const(value: int) -> dict:
    return {"op": "const", "value": value, "width": 32}


def _analysis_unit(
    unit_id: str,
    rva: int,
    *,
    memory: list[dict] | None = None,
    register_writes: list[dict] | None = None,
) -> dict:
    events = [] if memory is None else copy.deepcopy(memory)
    return {
        "id": unit_id,
        "source": {
            "original": {"rva_start": rva, "rva_end": rva + 1},
            "contract_sha256": f"{rva:064x}"[-64:],
            "instruction_bytes_sha256": f"{rva + 1:064x}"[-64:],
        },
        "instructions": [],
        "semantics": {
            "outcome": {"kind": "fallthrough", "target_rva": rva + 1},
            "register_writes": [] if register_writes is None else register_writes,
            "memory_events": events,
            "external_events": [],
            "ordered_events": events,
        },
    }


def _exception_units(divisor: int) -> list[dict]:
    entry = {
        "id": "unit:entry",
        "status": "qualified",
        "source": {
            "contract_sha256": "3" * 64,
            "instruction_bytes_sha256": "4" * 64,
            "original": {"rva_start": 0x900, "rva_end": 0x902},
        },
        "semantics": {
            "outcome": {"kind": "jump", "target_rva": 0x1000},
            "edge_conditions": [{
                "target_rva": 0x1000,
                "condition": {"op": "true"},
            }],
            "register_writes": [{"register": "ecx", "value": _const(divisor)}],
            "flag_writes": [],
            "faults": [],
        },
    }
    loop = {
        "id": "unit:loop",
        "status": "qualified",
        "source": {
            "contract_sha256": "5" * 64,
            "instruction_bytes_sha256": "6" * 64,
            "original": {"rva_start": 0x1000, "rva_end": 0x1002},
        },
        "semantics": {
            "outcome": {"kind": "jump", "target_rva": 0x1000},
            "edge_conditions": [{
                "target_rva": 0x1000,
                "condition": {"op": "true"},
            }],
            "register_writes": [],
            "flag_writes": [],
            "faults": [{
                "kind": "divide_error",
                "condition": {"op": "eq", "args": [_reg("ecx"), _const(0)]},
            }],
        },
    }
    return [entry, loop]


def _exception_graph() -> dict:
    return {
        "roots": [{"unit_id": "unit:entry", "kind": "pe_entrypoint"}],
        "direct_edges": [
            {"source_unit_id": "unit:entry", "target_unit_id": "unit:loop"},
            {"source_unit_id": "unit:loop", "target_unit_id": "unit:loop"},
        ],
        "indirect_exits": [],
    }


class StaticHybridPipelineV2Tests(unittest.TestCase):
    def test_safe_divide_loop_is_synthesized_and_independently_replayed(self) -> None:
        units = _exception_units(1)

        sccs = derive_faulting_rooted_sccs_v2(
            units=units, graph=_exception_graph()
        )
        proposals, replays, authority = derive_checked_exception_reports_v2(
            units=units,
            graph=_exception_graph(),
            binary_sha256=BINARY_SHA,
            machine_ir_sha256=MACHINE_IR_SHA,
        )

        self.assertEqual([row["members"] for row in sccs], [["unit:loop"]])
        self.assertEqual(len(proposals["proposals"]), 1)
        self.assertFalse(proposals["uses_bounded_paths"])
        self.assertFalse(
            proposals["proposals"][0]["proposal"]["uses_bounded_paths"]
        )
        self.assertEqual(replays["reports"][0]["source"], "synthesized")
        self.assertEqual(replays["reports"][0]["report"]["status"], "complete")
        self.assertFalse(replays["reports"][0]["report"]["uses_bounded_paths"])
        self.assertEqual(authority[0]["status"], "complete")

    def test_feasible_divide_fault_remains_primary_incomplete(self) -> None:
        proposals, replays, authority = derive_checked_exception_reports_v2(
            units=_exception_units(0),
            graph=_exception_graph(),
            binary_sha256=BINARY_SHA,
            machine_ir_sha256=MACHINE_IR_SHA,
        )

        self.assertEqual(
            proposals["proposals"][0]["proposal"]["status"], "incomplete"
        )
        report = replays["reports"][0]["report"]
        self.assertEqual(report["status"], "incomplete")
        self.assertEqual(
            report["faults"][0]["reason_code"], "fault_explicitly_incomplete"
        )
        self.assertEqual(authority, (report,))

    def test_corrupt_submitted_certificate_is_replayed_as_violated(self) -> None:
        units = _exception_units(1)
        proposal = synthesize_exception_invariant_certificate_v2(
            units=units,
            member_ids=["unit:loop"],
            binary_sha256=BINARY_SHA,
            machine_ir_sha256=MACHINE_IR_SHA,
        )
        submitted = copy.deepcopy(proposal)
        submitted["status"] = "complete"
        submitted["certificate"]["bindings"]["units"][0]["unit_sha256"] = (
            "9" * 64
        )

        proposals, replays, authority = derive_checked_exception_reports_v2(
            units=units,
            graph=_exception_graph(),
            binary_sha256=BINARY_SHA,
            machine_ir_sha256=MACHINE_IR_SHA,
            submitted_evidence=[submitted],
        )

        self.assertEqual(proposals["proposals"], [])
        self.assertEqual(replays["reports"][0]["source"], "submitted")
        report = replays["reports"][0]["report"]
        self.assertEqual(report["status"], "violated")
        self.assertIn(
            "exact_binding_contradiction",
            {issue["code"] for issue in report["issues"]},
        )
        self.assertEqual(authority, (report,))

    def test_replay_valid_submission_precedes_synthesis_and_ignores_status(self) -> None:
        units = _exception_units(1)
        submitted = synthesize_exception_invariant_certificate_v2(
            units=units,
            member_ids=["unit:loop"],
            binary_sha256=BINARY_SHA,
            machine_ir_sha256=MACHINE_IR_SHA,
        )
        submitted["status"] = "violated"

        proposals, replays, authority = derive_checked_exception_reports_v2(
            units=units,
            graph=_exception_graph(),
            binary_sha256=BINARY_SHA,
            machine_ir_sha256=MACHINE_IR_SHA,
            submitted_evidence=[submitted],
        )

        self.assertEqual(proposals["proposals"], [])
        self.assertEqual(replays["reports"][0]["source"], "submitted")
        self.assertEqual(replays["reports"][0]["report"]["status"], "complete")
        self.assertEqual(authority[0]["status"], "complete")

    def test_rooted_graph_fails_closed_on_unresolved_indirect_exit(self) -> None:
        rows = [
            {
                **_row("entry", 0x1000),
                "control": {
                    "kind": "indirect_jump",
                    "direct_targets": [],
                    "has_indirect_target": True,
                },
                "semantics": {
                    "outcome": {
                        "kind": "indirect_jump",
                        "target": _reg("eax"),
                    },
                    "external_events": [],
                },
            },
            {
                **_row("next", 0x1001),
                "control": {
                    "kind": "return",
                    "direct_targets": [],
                    "has_indirect_target": False,
                },
                "semantics": {"outcome": {"kind": "return"}, "external_events": []},
            },
        ]
        manifest = {
            "control": {
                "reachability": {
                    "status": "incomplete",
                    "roots": ["entry"],
                    "edges": [{
                        "source_unit_id": "entry",
                        "target_unit_id": "next",
                    }],
                    "frontiers": ["exit:entry"],
                    "potential_units": [],
                },
                "callback_cutpoint_proposals": [],
                "recovered_indirect_targets": [{
                    "id": "exit:entry",
                    "source_unit_id": "entry",
                    "status": "incomplete",
                    "target_unit_ids": [],
                    "external_targets": [],
                    "failure": {"code": "unsupported_target_expression"},
                }],
            }
        }
        roots = {
            "roots": [{"kind": "pe_entrypoint", "rva": 0x1000}],
        }

        graph = derive_rooted_control_graph_v2(
            rows=rows, manifest=manifest, behavioral_roots=roots
        )

        self.assertEqual(graph["status"], "incomplete")
        self.assertEqual(graph["roots"][0]["kind"], "pe_entrypoint")
        self.assertEqual(graph["indirect_exits"][0]["status"], "incomplete")

    def test_only_writable_static_interface_slots_are_replayed(self) -> None:
        binary = SimpleNamespace(
            image_base=0x400000,
            sections=(
                SimpleNamespace(
                    writable=False, rva_start=0x1000, rva_end=0x2000
                ),
                SimpleNamespace(
                    writable=True, rva_start=0x3000, rva_end=0x4000
                ),
            ),
        )
        provenance = {
            "static_interface_slots": [
                {"address": 0x401100},
                {"address": 0x403100},
            ],
            "rejected_tainted_slots": [{"address": 0x403200}],
        }

        self.assertEqual(
            derive_mutable_slot_candidates(cast(StageABinary, binary), provenance),
            [0x403100, 0x403200],
        )

    def test_promotion_drops_unchecked_and_tainted_slot_proposals(self) -> None:
        provenance = {
            "format": "stage-a-external-interface-provenance-v1",
            "proof_authority": False,
            "static_interface_slots": [{"address": 0x403100}],
            "rejected_tainted_slots": [{
                "kind": "static",
                "address": 0x403200,
            }],
            "callback_registrations": [],
        }

        promoted = promote_complete_global_slot_evidence_v2(provenance, [])

        self.assertEqual(promoted["static_interface_slots"], [])
        self.assertEqual(promoted["rejected_tainted_slots"], [])

    def test_rooted_memory_events_add_candidates_without_pooled_provenance(self) -> None:
        binary = SimpleNamespace(
            image_base=0x400000,
            sections=(
                SimpleNamespace(
                    writable=False, rva_start=0x1000, rva_end=0x2000
                ),
                SimpleNamespace(
                    writable=True, rva_start=0x3000, rva_end=0x4000
                ),
            ),
        )
        units = [
            _analysis_unit("root", 0x1000, memory=[{
                "kind": "write",
                "width": 4,
                "address": {
                    "op": "add32",
                    "args": [_const(0x403000), _const(0x20)],
                },
                "value": _const(0x401000),
            }]),
            _analysis_unit("reachable", 0x1010, memory=[{
                "kind": "read",
                "width": 4,
                "address": _const(0x403040),
            }]),
            _analysis_unit("unreachable", 0x1020, memory=[{
                "kind": "write",
                "width": 4,
                "address": _const(0x403060),
                "value": _const(0),
            }]),
        ]
        graph = {
            "roots": [{"unit_id": "root", "kind": "pe_entrypoint"}],
            "direct_edges": [{
                "source_unit_id": "root", "target_unit_id": "reachable"
            }],
            "indirect_exits": [],
        }

        self.assertEqual(
            derive_mutable_slot_candidates(
                cast(StageABinary, binary),
                {"static_interface_slots": [], "rejected_tainted_slots": []},
                units=units,
                graph=graph,
            ),
            [0x403020, 0x403040],
        )

    def test_target_proposals_nominate_writable_slots_for_checked_replay(self) -> None:
        binary = SimpleNamespace(
            image_base=0x400000,
            sections=(
                SimpleNamespace(
                    writable=False, rva_start=0x1000, rva_end=0x2000
                ),
                SimpleNamespace(
                    writable=True, rva_start=0x3000, rva_end=0x4000
                ),
            ),
        )
        recoveries = [
            {
                "id": "indirect-exit:one",
                "status": "recovered",
                "target_origin_witnesses": [{
                    "kind": "static_code",
                    "key": [0x401100, [0x403020, 0x401020]],
                }],
                "proposal_static_read_addresses": [0x403024, 0x401024],
            },
            {
                "id": "indirect-exit:ignored",
                "status": "incomplete",
                "target_origin_witnesses": [{
                    "kind": "static_data",
                    "key": [0x401200, [0x403024]],
                }],
            },
        ]

        self.assertEqual(
            derive_proposal_slot_dependencies(
                cast(StageABinary, binary), recoveries
            ),
            [
                {
                    "slot_rva": 0x3020,
                    "exit_id": "indirect-exit:one",
                    "witness_only": True,
                    "proof_authority": False,
                },
                {
                    "slot_rva": 0x3024,
                    "exit_id": "indirect-exit:one",
                    "witness_only": True,
                    "proof_authority": False,
                }
            ],
        )

    def test_manifest_fixed_point_without_v2_handoff_is_diagnostic_only(self) -> None:
        manifest = {
            "control": {
                "internal_call_preservation": {"summaries": []},
                "indirect_exits": [],
                "recovered_indirect_targets": [{"id": "exit"}],
                "analysis_fixed_point": {
                    "format": "stage-a-interprocedural-analysis-v2",
                    "status": "complete",
                    "cold_replay_validated": True,
                },
            }
        }

        result = derive_interprocedural_result_v2(manifest)

        self.assertEqual(result["fixed_point"]["status"], "incomplete")
        self.assertFalse(result["fixed_point"]["cold_replay_validated"])
        self.assertFalse(result["fixed_point"]["authority_replay_validated"])
        self.assertEqual(
            result["fixed_point"]["mutable_slot_handoff"],
            "missing_exact_replay",
        )
        self.assertIn(
            "machine_ir_units_missing",
            result["fixed_point"]["failure_reasons"],
        )
        self.assertEqual(
            result["manifest_diagnostics"]["fixed_point"]["status"],
            "complete",
        )

    def test_incomplete_slot_frontier_does_not_claim_missing_authority(self) -> None:
        payload = {
            "format": "stage-a-interprocedural-analysis-v2",
            "status": "incomplete",
            "call_summaries": {"summaries": []},
            "recovered_targets": [{
                "id": "indirect-exit:tainted",
                "status": "incomplete",
                "mutable_slot_dependencies": [{
                    "slot_rva": 0x3000,
                    "width_bytes": 4,
                    "read_sites": [{"unit_id": "unit:read", "event_index": 0}],
                }],
                "authority_dependencies": [],
            }],
            "fixed_point": {
                "status": "incomplete",
                "authority_replay_validated": True,
                "mutable_slot_handoff": "point_sensitive_dependency_v2",
                "global_slot_promotion": False,
                "dependencies": [],
                "failure_reasons": ["reachable_indirect_targets_incomplete"],
            },
        }

        result = _validate_interprocedural_mutable_handoff(
            payload,
            global_slot_invariants=(),
        )

        self.assertTrue(result["fixed_point"]["authority_replay_validated"])
        self.assertEqual(
            result["fixed_point"]["handoff_validation"]["status"],
            "complete",
        )
        self.assertNotIn(
            "mutable_slot_dependency_content_id_missing",
            result["fixed_point"]["failure_reasons"],
        )

    def test_complete_slot_evidence_promotes_to_strict_v2_record(self) -> None:
        slot = 0x403000
        alternatives = [
            {"kind": "exact_bits", "value": 0x402000, "width_bits": 32}
        ]
        evidence = {
            "address": slot,
            "width": 4,
            "analysis_status": "complete",
            "reachable_write_inventory": {
                "status": "complete",
                "writes": [{
                    "site": {"unit_id": "init", "event_index": 0},
                    "classification": "initializer",
                    "alternatives": alternatives,
                }],
                "unknown_writes": [],
                "aliasing_writes": [],
            },
            "relevant_reads": [],
            "alternatives": alternatives,
        }
        roots_body = {
            "format": BEHAVIORAL_ROOTS_FORMAT,
            "status": "complete",
            "authority": "independent_exact_pe_metadata",
            "pe": {
                "sha256": BINARY_SHA,
                "file_size": 0x1000,
                "machine": "i386",
                "bitness": 32,
                "image_base": 0x400000,
                "size_of_image": 0x10000,
                "entrypoint_rva": 0x1000,
            },
            "roots": [{
                "kind": "pe_entrypoint",
                "identity": "pe-entrypoint",
                "rva": 0x1000,
            }],
            "counts": {"roots": 1, "pe_entrypoint": 1},
            "constraints": {},
        }
        roots = {
            **roots_body,
            "contract_sha256": behavioral_roots_sha256(roots_body),
        }
        units = [
            _analysis_unit("entry", 0x1000),
            _analysis_unit("init", 0x1100, memory=[{
                "kind": "write",
                "width": 4,
                "address": _const(slot),
                "value": _const(0x402000),
            }]),
            _analysis_unit("dispatch", 0x1200),
            _analysis_unit("after", 0x1201),
            _analysis_unit("target", 0x2000),
        ]
        promoted = promote_complete_global_slot_evidence_v2(
            {
                "format": "stage-a-external-interface-provenance-v1",
                "status": "complete",
                "static_interface_slots": [],
                "rejected_tainted_slots": [],
                "callback_registrations": [],
            },
            [evidence],
        )

        indirect_exit = {
            "source_unit_id": "dispatch",
            "source_event_index": 0,
            "source_rva": 0x1200,
            "kind": "indirect_call",
            "target_expression": {
                "op": "load",
                "width": 4,
                "address": _const(slot),
            },
        }
        indirect_exit["id"] = _exact_indirect_exit_id(indirect_exit)
        units[0]["control"] = {
            "kind": "jump",
            "direct_targets": [0x1100],
            "has_indirect_target": False,
        }
        units[1]["control"] = {
            "kind": "jump",
            "direct_targets": [0x1200],
            "has_indirect_target": False,
        }
        units[2]["control"] = {
            "kind": "fallthrough",
            "direct_targets": [0x1201],
            "has_indirect_target": False,
        }
        indirect_call_event = {
            "kind": "indirect_call",
            "target": copy.deepcopy(indirect_exit["target_expression"]),
        }
        units[2]["semantics"]["external_events"] = [indirect_call_event]
        units[2]["semantics"]["ordered_events"] = [
            copy.deepcopy(indirect_call_event)
        ]
        units[3]["control"] = {
            "kind": "return",
            "direct_targets": [],
            "has_indirect_target": False,
        }
        units[3]["semantics"]["outcome"] = {"kind": "return"}
        units[3]["semantics"]["register_writes"] = [{
            "register": "esp",
            "value": {"op": "add32", "args": [_reg("esp"), _const(4)]},
        }]
        units[3]["semantics"]["stack_delta"] = {
            "status": "derived",
            "net_bytes": 4,
        }
        units[4]["control"] = {
            "kind": "return",
            "direct_targets": [],
            "has_indirect_target": False,
        }
        units[4]["semantics"]["outcome"] = {"kind": "return"}
        units[4]["semantics"]["register_writes"] = [{
            "register": "esp",
            "value": {"op": "add32", "args": [_reg("esp"), _const(4)]},
        }]
        units[4]["semantics"]["stack_delta"] = {
            "status": "derived",
            "net_bytes": 4,
        }
        report = construct_entry_state_analysis_v2(
            behavioral_roots=roots,
            interface_provenance=promoted,
            units=units,
            machine_ir_sha256=MACHINE_IR_SHA,
            global_slot_evidence=[evidence],
            launch_invariants={
                "pe_entrypoint": [{"kind": "fixture", "value": {}}]
            },
            iat_facts=[],
        )

        self.assertEqual(len(report["global_slot_invariants"]), 1, report)
        record = GlobalSlotInvariant.parse(report["global_slot_invariants"][0])
        self.assertEqual(record.status.value, "complete")
        self.assertEqual(record.slot_rva, 0x3000)
        recovery = {
            **indirect_exit,
            "status": "recovered",
            "closure": "checked_finite_fixture",
            "target_rvas": [0x2000],
            "target_unit_ids": ["target"],
            "external_targets": [],
            "failure": None,
        }
        manifest = {
            "control": {
                "direct_targets": [
                    {
                        "kind": "direct_control",
                        "source_unit_id": "entry",
                        "resolved_unit_id": "init",
                    },
                    {
                        "kind": "direct_control",
                        "source_unit_id": "init",
                        "resolved_unit_id": "dispatch",
                    },
                    {
                        "kind": "direct_control",
                        "source_unit_id": "dispatch",
                        "resolved_unit_id": "after",
                    },
                ],
                "indirect_exits": [indirect_exit],
                "recovered_indirect_targets": [recovery],
                "internal_call_preservation": {"summaries": []},
                "analysis_fixed_point": {
                    "format": "stage-a-interprocedural-analysis-v2",
                    "status": "complete",
                    "cold_replay_validated": True,
                },
            }
        }
        graph = {
            "roots": [{"unit_id": "entry", "kind": "pe_entrypoint"}],
            "direct_edges": [
                {"source_unit_id": "entry", "target_unit_id": "init"},
                {"source_unit_id": "init", "target_unit_id": "dispatch"},
                {"source_unit_id": "dispatch", "target_unit_id": "after"},
            ],
            "indirect_exits": [{
                "id": indirect_exit["id"],
                "source_unit_id": "dispatch",
                "status": "complete",
                "target_unit_ids": ["target"],
            }],
        }
        binary = SimpleNamespace(
            sha256=BINARY_SHA,
            image_base=0x400000,
            size_of_image=0x10000,
            imports=(),
            sections=(SimpleNamespace(
                writable=True,
                readable=True,
                rva_start=0x3000,
                rva_end=0x4000,
                raw_size=0x1000,
            ),),
            pe=SimpleNamespace(get_data=lambda _rva, _size: b""),
        )

        replay = derive_interprocedural_result_v2(
            manifest,
            units=units,
            graph=graph,
            binary=cast(StageABinary, binary),
            machine_ir_sha256=MACHINE_IR_SHA,
            global_slot_invariants=report["global_slot_invariants"],
            import_abis={},
            interface_profiles=(),
            operation_profiles=(),
            callable_profiles=(),
            internal_function_contracts={},
            static_recoveries=[recovery],
        )

        self.assertEqual(replay["fixed_point"]["status"], "complete", replay)
        self.assertEqual(
            replay["fixed_point"]["mutable_slot_handoff"],
            "point_sensitive_dependency_v2",
        )
        self.assertEqual(
            replay["fixed_point"]["handoff_validation"]["status"],
            "complete",
        )
        recovered = replay["recovered_targets"][0]
        self.assertEqual(
            recovered["mutable_slot_dependencies"][0]["content_id"],
            record.content_id,
        )
        self.assertEqual(
            recovered["authority_dependencies"],
            [{
                "role": "mutable_slot_invariant",
                "content_id": record.content_id,
            }],
        )

    def test_iat_facts_preserve_import_identity_and_slot(self) -> None:
        binary = SimpleNamespace(imports=(
            SimpleNamespace(
                dll="KERNEL32.dll", symbol="ExitProcess", ordinal=None,
                thunk_rva=0x2000,
            ),
        ))

        result = derive_iat_facts(cast(StageABinary, binary))

        self.assertEqual(result["status"], "complete")
        self.assertEqual(result["entries"][0]["iat_rva"], 0x2000)


if __name__ == "__main__":
    unittest.main()
