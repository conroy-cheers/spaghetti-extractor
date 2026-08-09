from __future__ import annotations

import copy
import hashlib
import struct
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

from spaghetti_extractor.global_slot_authority_v2 import (
    GLOBAL_SLOT_AUTHORITY_V2_FORMAT,
    apply_global_slot_authority_v2,
    build_global_slot_authority_v2,
    replay_global_slot_authority_v2,
)
from spaghetti_extractor.global_slot_analysis_v2 import analyze_global_slots_v2
from spaghetti_extractor.global_slot_contract_v2 import GlobalSlotInvariant
from spaghetti_extractor.authority_bindings_v2 import canonical_json_bytes
from spaghetti_extractor.global_slot_image_v2 import (
    GlobalSlotImageV2Error,
    validate_global_slot_invariant_binding_v2,
)
from spaghetti_extractor.machine_ir_authority_v2 import machine_ir_sha256
from spaghetti_extractor.stage_binary import _parse_stage_a_pe
from spaghetti_extractor.stack_range_analysis_v2 import (
    derive_stack_range_analysis_v2,
)
from tests.pe_fixtures import pe32_image_with_writable_data

from tests.test_global_slot_analysis_v2 import (
    IMAGE_BASE,
    IMAGE_SIZE,
    SLOT,
    _analyze,
    _checked_access_facts,
    _const,
    _graph,
    _read,
    _reg,
    _unit,
    _write,
)


PE_SHA256 = "a" * 64


def _provenance(*, slot: int = SLOT) -> dict:
    return {
        "format": "stage-a-external-interface-provenance-v1",
        "proof_authority": False,
        "static_interface_slots": [{"address": slot}],
        "rejected_tainted_slots": [],
        "callback_registrations": [],
    }


class GlobalSlotAuthorityV2Tests(unittest.TestCase):
    def _replay_fixture(self) -> tuple[dict, dict]:
        temporary, binary = self._writable_data_binary()
        self.addCleanup(temporary.cleanup)
        self.addCleanup(binary.pe.close)
        slot = binary.image_base + 0x2000
        units = [_unit(
            "entry",
            0x1000,
            [
                _write(_const(7), address={
                    "op": "add32",
                    "args": [_reg("esp"), _const(12)],
                }),
                _write(_const(0x401020), address=_const(slot)),
                _read(_const(slot)),
            ],
        )]
        graph = _graph(units)
        launch = {
            "assumptions": {
                "initial_stack": {
                    "contract": "private-non-image-stack-range-v2",
                    "mapped_separately_from_image": True,
                    "minimum_accessible_bytes_below": 0x1000,
                    "minimum_accessible_bytes_above": 0x1000,
                }
            }
        }
        recovery = {
            "id": "indirect-exit:entry",
            "mutable_slot_dependencies": [{
                "slot_rva": 0x2000,
                "width_bytes": 4,
                "read_sites": [{"unit_id": "entry", "event_index": 2}],
                "origin_witnessed": True,
            }],
        }
        machine_sha = machine_ir_sha256(units)
        stack = derive_stack_range_analysis_v2(
            units=units,
            graph=graph,
            launch_assumptions=launch,
            pe_sha256=binary.sha256,
            machine_ir_sha256=machine_sha,
            image_base=binary.image_base,
            size_of_image=binary.size_of_image,
            indirect_recoveries=[recovery],
            finite_offset_budget=32,
        )
        interprocedural = {
            "recovered_targets": [recovery],
            "call_summaries": {},
            "operation_provenance": {"checked_memory_access_facts": []},
        }
        relevant_reads = [{
            "slot_rva": 0x2000,
            "exit_id": recovery["id"],
            "unit_id": "entry",
            "event_index": 2,
            "proof_authority": False,
        }]
        analysis = analyze_global_slots_v2(
            units=units,
            graph=graph,
            candidate_slot_addresses=[slot],
            image_base=binary.image_base,
            size_of_image=binary.size_of_image,
            checked_memory_spatial_facts=stack["checked_spatial_facts"],
            range_authority_binding=stack["binding"],
            relevant_read_dependencies=relevant_reads,
            launch_initial_values={slot: 0x401000},
            checked_memory_access_facts=[],
            memory_range_invariant_analysis=None,
            pe_sha256=binary.sha256,
            machine_ir_sha256=machine_sha,
            interprocedural_authority_sha256=None,
            alternative_budget=32,
        )
        replay_inputs = {
            "provenance": _provenance(slot=slot),
            "units": units,
            "graph": graph,
            "interprocedural": interprocedural,
            "stack_range_analysis": stack,
            "launch_assumptions": launch,
            "memory_range_invariant_analysis": None,
            "original_binary": binary,
            "machine_ir_sha256": machine_sha,
            "finite_value_budget": 32,
        }
        return analysis, replay_inputs

    def test_independent_replay_accepts_exact_submitted_analysis(self) -> None:
        analysis, replay_inputs = self._replay_fixture()

        authority = replay_global_slot_authority_v2(
            submitted_analysis=analysis,
            **replay_inputs,
        )

        self.assertEqual(authority["status"], "complete", authority["issues"])
        self.assertEqual(len(authority["global_slot_invariants"]), 1)

    def test_independent_replay_rejects_removed_spatial_evidence(self) -> None:
        analysis, replay_inputs = self._replay_fixture()
        forged = copy.deepcopy(analysis)
        forged["checked_memory_spatial_facts"] = []
        forged["counts"]["checked_memory_spatial_facts"] = 0
        body = dict(forged)
        body.pop("analysis_sha256")
        forged["analysis_sha256"] = hashlib.sha256(
            canonical_json_bytes(body)
        ).hexdigest()

        authority = replay_global_slot_authority_v2(
            submitted_analysis=forged,
            **replay_inputs,
        )

        self.assertEqual(authority["status"], "violated")
        self.assertEqual(authority["global_slot_invariants"], [])
        self.assertIn(
            "global_slot_analysis_replay_mismatch",
            {row["code"] for row in authority["issues"]},
        )

    def test_independent_replay_rejects_forged_write_alternative(self) -> None:
        analysis, replay_inputs = self._replay_fixture()
        forged = copy.deepcopy(analysis)
        forged_origin = {
            "kind": "exact_bits",
            "value": 0xDEADBEEF,
            "width_bits": 32,
        }
        forged["global_slot_evidence"][0]["reachable_write_inventory"][
            "writes"
        ][0]["alternatives"] = [forged_origin]
        forged["slots"][0]["evidence"]["reachable_write_inventory"][
            "writes"
        ][0]["alternatives"] = [forged_origin]
        body = dict(forged)
        body.pop("analysis_sha256")
        forged["analysis_sha256"] = hashlib.sha256(
            canonical_json_bytes(body)
        ).hexdigest()

        authority = replay_global_slot_authority_v2(
            submitted_analysis=forged,
            **replay_inputs,
        )

        self.assertEqual(authority["status"], "violated")
        self.assertEqual(authority["global_slot_invariants"], [])
        self.assertIn(
            "global_slot_analysis_replay_mismatch",
            {row["code"] for row in authority["issues"]},
        )

    def test_stack_spatial_authority_requires_full_rooted_replay(self) -> None:
        units = [_unit(
            "entry",
            0x1000,
            [
                _write(_const(7), address={
                    "op": "add32",
                    "args": [_reg("esp"), _const(12)],
                }),
                _write(_const(0x401020)),
                _read(),
            ],
        )]
        graph = _graph(units)
        launch = {
            "assumptions": {
                "initial_stack": {
                    "contract": "private-non-image-stack-range-v2",
                    "mapped_separately_from_image": True,
                    "minimum_accessible_bytes_below": 0x1000,
                    "minimum_accessible_bytes_above": 0x1000,
                }
            }
        }
        machine_sha = machine_ir_sha256(units)
        stack = derive_stack_range_analysis_v2(
            units=units,
            graph=graph,
            launch_assumptions=launch,
            pe_sha256=PE_SHA256,
            machine_ir_sha256=machine_sha,
            image_base=IMAGE_BASE,
            size_of_image=IMAGE_SIZE,
        )
        analysis = _analyze(
            units,
            graph,
            checked_spatial_facts=stack["checked_spatial_facts"],
            range_binding=stack["binding"],
        )

        authority = build_global_slot_authority_v2(
            provenance=_provenance(),
            global_slot_analysis=analysis,
            units=units,
            pe_sha256=PE_SHA256,
            machine_ir_sha256=machine_sha,
            image_base=IMAGE_BASE,
            size_of_image=IMAGE_SIZE,
            stack_range_analysis=stack,
            stack_graph=graph,
            stack_launch_assumptions=launch,
        )

        self.assertEqual(authority["status"], "complete", authority["issues"])
        self.assertEqual(len(authority["global_slot_invariants"]), 1)

        corrupted = copy.deepcopy(stack)
        corrupted["entry_offsets"]["entry"] = [-4]
        rejected = build_global_slot_authority_v2(
            provenance=_provenance(),
            global_slot_analysis=analysis,
            units=units,
            pe_sha256=PE_SHA256,
            machine_ir_sha256=machine_sha,
            image_base=IMAGE_BASE,
            size_of_image=IMAGE_SIZE,
            stack_range_analysis=corrupted,
            stack_graph=graph,
            stack_launch_assumptions=launch,
        )
        self.assertEqual(rejected["status"], "violated")
        self.assertIn(
            "checked_memory_spatial_binding_invalid",
            {row["code"] for row in rejected["issues"]},
        )

    def _writable_data_binary(self, *, relocated: bool = False):
        raw = bytearray(pe32_image_with_writable_data(
            b"\xc3",
            relocation_offsets=[0] if relocated else [],
            relocation_page_rva=0x2000,
        ))
        struct.pack_into("<I", raw, 0x400, 0x401000)
        temporary = tempfile.TemporaryDirectory()
        path = Path(temporary.name) / "fixture.exe"
        path.write_bytes(raw)
        return temporary, _parse_stage_a_pe(path)

    def test_complete_replay_promotes_one_typed_invariant(self) -> None:
        units = [_unit("init", 0x1000, [_write(_const(0x401020)), _read()])]
        analysis = _analyze(units, _graph(units))

        authority = build_global_slot_authority_v2(
            provenance=_provenance(),
            global_slot_analysis=analysis,
            units=units,
            pe_sha256=PE_SHA256,
            machine_ir_sha256=analysis["bindings"]["machine_ir_sha256"],
            image_base=IMAGE_BASE,
            size_of_image=IMAGE_SIZE,
        )

        self.assertEqual(authority["format"], GLOBAL_SLOT_AUTHORITY_V2_FORMAT)
        self.assertEqual(authority["status"], "complete", authority["issues"])
        self.assertEqual(len(authority["global_slot_invariants"]), 1)
        self.assertFalse(authority["constraints"]["tainted_slots_exported"])
        fresh = apply_global_slot_authority_v2(
            {
                **_provenance(),
                "callback_registrations": [{"id": "registration"}],
            },
            authority,
        )
        self.assertEqual(fresh["callback_registrations"], [{"id": "registration"}])
        self.assertEqual(len(fresh["static_interface_slots"]), 1)

    def test_incomplete_or_tainted_evidence_is_not_exported(self) -> None:
        units = [_unit(
            "entry",
            0x1000,
            [_write(_reg("eax")), _read()],
        )]
        analysis = _analyze(units, _graph(units))
        provenance = _provenance()
        provenance["rejected_tainted_slots"] = [{
            "kind": "static",
            "address": SLOT,
        }]

        authority = build_global_slot_authority_v2(
            provenance=provenance,
            global_slot_analysis=analysis,
            units=units,
            pe_sha256=PE_SHA256,
            machine_ir_sha256=analysis["bindings"]["machine_ir_sha256"],
            image_base=IMAGE_BASE,
            size_of_image=IMAGE_SIZE,
        )

        self.assertEqual(authority["status"], "complete")
        self.assertEqual(authority["global_slot_invariants"], [])
        self.assertEqual(
            authority["authoritative_provenance"]["rejected_tainted_slots"], []
        )

    def test_corrupted_analysis_hash_is_violated(self) -> None:
        units = [_unit("init", 0x1000, [_write(_const(1)), _read()])]
        analysis = _analyze(units, _graph(units))
        corrupted = copy.deepcopy(analysis)
        corrupted["analysis_sha256"] = "0" * 64

        authority = build_global_slot_authority_v2(
            provenance=_provenance(),
            global_slot_analysis=corrupted,
            units=units,
            pe_sha256=PE_SHA256,
            machine_ir_sha256=analysis["bindings"]["machine_ir_sha256"],
            image_base=IMAGE_BASE,
            size_of_image=IMAGE_SIZE,
        )

        self.assertEqual(authority["status"], "violated")
        self.assertIn(
            "global_slot_analysis_hash_mismatch",
            {row["code"] for row in authority["issues"]},
        )

    def test_recomputed_outer_hash_cannot_hide_stale_memory_event_binding(self) -> None:
        units = [_unit(
            "entry",
            0x1000,
            [_write(_const(7), address=_reg("eax"))],
        )]
        facts = _checked_access_facts(
            units,
            origin={"kind": "stack_location", "key": [12]},
        )
        analysis = _analyze(
            units,
            _graph(units),
            launch_initial_values={SLOT: 0},
            checked_access_facts=facts,
        )
        corrupted = copy.deepcopy(analysis)
        corrupted["checked_memory_access_facts"][0]["binding"][
            "event_sha256"
        ] = "0" * 64
        body = dict(corrupted)
        body.pop("analysis_sha256")
        corrupted["analysis_sha256"] = hashlib.sha256(
            canonical_json_bytes(body)
        ).hexdigest()

        authority = build_global_slot_authority_v2(
            provenance=_provenance(),
            global_slot_analysis=corrupted,
            units=units,
            pe_sha256=PE_SHA256,
            machine_ir_sha256=analysis["bindings"]["machine_ir_sha256"],
            image_base=IMAGE_BASE,
            size_of_image=IMAGE_SIZE,
        )

        self.assertEqual(authority["status"], "violated")
        self.assertIn(
            "checked_memory_access_binding_invalid",
            {row["code"] for row in authority["issues"]},
        )

    def test_launch_initialized_writable_slot_binds_exact_pe_bytes(self) -> None:
        temporary, binary = self._writable_data_binary()
        self.addCleanup(temporary.cleanup)
        self.addCleanup(binary.pe.close)
        slot = binary.image_base + 0x2000
        units = [_unit("read", 0x1000, [_read(_const(slot))])]
        analysis = _analyze(
            units,
            _graph(units),
            launch_initial_values={slot: 0x401000},
            slot=slot,
        )

        authority = build_global_slot_authority_v2(
            provenance=_provenance(slot=slot),
            global_slot_analysis=analysis,
            units=units,
            pe_sha256=binary.sha256,
            machine_ir_sha256=analysis["bindings"]["machine_ir_sha256"],
            image_base=binary.image_base,
            size_of_image=binary.size_of_image,
            original_binary=binary,
        )

        self.assertEqual(authority["status"], "complete", authority["issues"])
        invariant = GlobalSlotInvariant.parse(
            authority["global_slot_invariants"][0]
        )
        self.assertEqual(invariant.binding.to_payload()["kind"], "image_span")
        validate_global_slot_invariant_binding_v2(
            invariant,
            binary=binary,
            machine_ir_sha256=analysis["bindings"]["machine_ir_sha256"],
            units=units,
        )

        corrupted = replace(
            invariant,
            binding=replace(invariant.binding, initial_bytes_sha256="0" * 64),
        )
        with self.assertRaises(GlobalSlotImageV2Error):
            validate_global_slot_invariant_binding_v2(
                corrupted,
                binary=binary,
                machine_ir_sha256=analysis["bindings"]["machine_ir_sha256"],
                units=units,
            )

    def test_launch_slot_records_highlow_relocation(self) -> None:
        temporary, binary = self._writable_data_binary(relocated=True)
        self.addCleanup(temporary.cleanup)
        self.addCleanup(binary.pe.close)
        slot = binary.image_base + 0x2000
        units = [_unit("read", 0x1000, [_read(_const(slot))])]
        analysis = _analyze(
            units,
            _graph(units),
            launch_initial_values={slot: 0x401000},
            slot=slot,
        )

        authority = build_global_slot_authority_v2(
            provenance=_provenance(slot=slot),
            global_slot_analysis=analysis,
            units=units,
            pe_sha256=binary.sha256,
            machine_ir_sha256=analysis["bindings"]["machine_ir_sha256"],
            image_base=binary.image_base,
            size_of_image=binary.size_of_image,
            original_binary=binary,
        )

        self.assertEqual(authority["status"], "complete", authority["issues"])
        self.assertEqual(
            authority["global_slot_invariants"][0]["binding"]["relocation_kind"],
            "pe32_highlow",
        )

    def test_launch_value_contradicting_pe_bytes_is_violated(self) -> None:
        temporary, binary = self._writable_data_binary()
        self.addCleanup(temporary.cleanup)
        self.addCleanup(binary.pe.close)
        slot = binary.image_base + 0x2000
        units = [_unit("read", 0x1000, [_read(_const(slot))])]
        analysis = _analyze(
            units,
            _graph(units),
            launch_initial_values={slot: 0xDEADBEEF},
            slot=slot,
        )

        authority = build_global_slot_authority_v2(
            provenance=_provenance(slot=slot),
            global_slot_analysis=analysis,
            units=units,
            pe_sha256=binary.sha256,
            machine_ir_sha256=analysis["bindings"]["machine_ir_sha256"],
            image_base=binary.image_base,
            size_of_image=binary.size_of_image,
            original_binary=binary,
        )

        self.assertEqual(authority["status"], "violated")
        self.assertIn(
            "global_slot_launch_value_contradiction",
            {row["code"] for row in authority["issues"]},
        )


if __name__ == "__main__":
    unittest.main()
