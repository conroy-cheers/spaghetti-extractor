from __future__ import annotations

import copy
import hashlib
import unittest

from spaghetti_extractor.hybrid_authority_builder_v2 import (
    build_hybrid_authority_v2,
    build_machine_ir_authority_bindings,
    machine_ir_sha256,
    recompute_unit_binding,
)
from spaghetti_extractor.hybrid_authority_v2 import (
    AuthorityStatus,
    BinaryBinding,
    CallFrameSummary,
    EvidenceIssue,
    EvidenceIssueKind,
    EntryStateContract,
    CheckedExternalSite,
    FiniteAlternatives,
    GlobalSlotInvariant,
    IndirectExitBinding,
    IndirectExitCertificate,
    ProfileBinding,
    EventBinding,
    canonical_json_bytes,
)

from tests.test_isa_kernel_selection import BINARY_SHA, _authority


INSTRUCTION_SHA = "5" * 64


def _row(
    *,
    outcome: dict | None = None,
    external_events: list[dict] | None = None,
) -> dict:
    return {
        "format": "stage-a-machine-ir-v2",
        "record_kind": "unit",
        "id": "unit:entry",
        "reachable": True,
        "source": {
            "original": {"rva_start": 0x1000, "rva_end": 0x1001},
            "instruction_bytes_sha256": INSTRUCTION_SHA,
        },
        "instructions": [{
            "rva_start": 0x1000,
            "rva_end": 0x1001,
            "size": 1,
            "instruction_sha256": INSTRUCTION_SHA,
            "mnemonic": "ret",
            "operands": [],
            "groups": ["ret"],
            "registers_read": ["esp"],
            "registers_written": ["esp"],
        }],
        "semantics": {
            "external_events": external_events or [],
            "faults": [],
            "outcome": outcome or {"kind": "return"},
        },
    }


def _manifest(rows: list[dict]) -> dict:
    return {
        "format": "stage-a-machine-ir-v2",
        "inputs": {"original_pe": {"sha256": BINARY_SHA}},
        "binary": {"sha256": BINARY_SHA},
        "artifacts": {"machine_ir": {"sha256": machine_ir_sha256(rows)}},
        "authority_bindings": build_machine_ir_authority_bindings(
            rows, pe_sha256=BINARY_SHA
        ),
    }


def _entry(rows: list[dict]) -> EntryStateContract:
    binary = BinaryBinding(BINARY_SHA, machine_ir_sha256(rows))
    return EntryStateContract(
        entry=recompute_unit_binding(rows[0], binary=binary),
        entry_kind="pe_entry",
        alternatives=FiniteAlternatives.of(
            [{"launch": "pe32-console-launch-v1"}], maximum=1
        ),
    )


def _global_slot(rows: list[dict], *, tainted: bool = False) -> GlobalSlotInvariant:
    binary = BinaryBinding(BINARY_SHA, machine_ir_sha256(rows))
    return GlobalSlotInvariant(
        binding=recompute_unit_binding(rows[0], binary=binary),
        slot_rva=0x30000,
        width_bytes=4,
        invariant_kind="finite_set",
        alternatives=FiniteAlternatives.of([{
            "kind": "exact_bits",
            "value": 0x401000,
            "width_bits": 32,
        }], maximum=1),
        issues=(
            EvidenceIssue(
                EvidenceIssueKind.MISSING,
                "global_slot_unknown_write_taint",
                "reachable overwrite is not classified",
            ),
        )
        if tainted
        else (),
    )


def _interprocedural(*, recoveries: list[dict] | None = None) -> dict:
    return {
        "call_summaries": {"summaries": []},
        "recovered_targets": recoveries or [],
        "fixed_point": {
            "status": "complete",
            "cold_replay_validated": True,
            "authority_replay_validated": True,
            "cold_initial_recoveries_empty": True,
            "static_recovery_authority_seeded": False,
            "global_slot_promotion": False,
        },
    }


def _recovery(rows: list[dict], **values: object) -> dict:
    bindings = build_machine_ir_authority_bindings(rows, pe_sha256=BINARY_SHA)
    exit_binding = IndirectExitBinding.parse(bindings["indirect_exits"][0])
    return {
        **exit_binding.identity_payload(),
        "id": exit_binding.exit_id,
        "status": "recovered",
        "target_unit_ids": [],
        "external_targets": [],
        **values,
    }


def _indirect_row(unit_id: str, rva: int, register: str) -> dict:
    row = _row(outcome={
        "kind": "indirect_jump",
        "instruction_rva": rva,
        "target": {"op": "reg", "name": register, "width": 32},
    })
    row["id"] = unit_id
    row["source"]["original"] = {
        "rva_start": rva,
        "rva_end": rva + 1,
    }
    row["instructions"][0]["rva_start"] = rva
    row["instructions"][0]["rva_end"] = rva + 1
    return row


def _recovery_for(
    rows: list[dict], unit_id: str, **values: object
) -> dict:
    bindings = build_machine_ir_authority_bindings(rows, pe_sha256=BINARY_SHA)
    exit_binding = next(
        binding
        for row in bindings["indirect_exits"]
        for binding in (IndirectExitBinding.parse(row),)
        if binding.unit.unit_id == unit_id
    )
    return {
        **exit_binding.identity_payload(),
        "id": exit_binding.exit_id,
        "status": "recovered",
        "target_unit_ids": [],
        "external_targets": [],
        **values,
    }


class HybridAuthorityBuilderV2Tests(unittest.TestCase):
    def test_indirect_provenance_binds_checked_provider_certificate(self) -> None:
        rows = [
            _indirect_row("unit:entry", 0x1000, "eax"),
            _indirect_row("unit:dependent", 0x1010, "ecx"),
        ]
        provider = _recovery_for(
            rows,
            "unit:entry",
            target_unit_ids=["unit:dependent"],
        )
        dependent = _recovery_for(
            rows,
            "unit:dependent",
            target_unit_ids=["unit:dependent"],
            analysis_dependencies=[provider["id"]],
        )
        _qualification, _selection, isa_authority = _authority()

        bundle = build_hybrid_authority_v2(
            machine_ir_rows=rows,
            machine_ir_manifest=_manifest(rows),
            pe_sha256=BINARY_SHA,
            root_records=[{"kind": "pe_entry", "rva": 0x1000}],
            interprocedural_result=_interprocedural(
                recoveries=[dependent, provider]
            ),
            entry_records=[_entry(rows)],
            validated_isa_authority=isa_authority,
        )

        certificates = {
            record.analysis_fact_id: record
            for record in bundle.records
            if isinstance(record, IndirectExitCertificate)
        }
        self.assertEqual(bundle.status, AuthorityStatus.COMPLETE, bundle.diagnostics)
        self.assertEqual(len(certificates[dependent["id"]].dependencies), 1)
        dependency = certificates[dependent["id"]].dependencies[0]
        self.assertEqual(dependency.role, "indirect_exit_certificate")
        self.assertEqual(
            dependency.content_id,
            certificates[provider["id"]].content_id,
        )

    def test_unknown_indirect_provenance_dependency_fails_closed(self) -> None:
        rows = [_indirect_row("unit:entry", 0x1000, "eax")]
        recovery = _recovery_for(
            rows,
            "unit:entry",
            target_unit_ids=["unit:entry"],
            analysis_dependencies=["indirect-exit:not-present"],
        )
        _qualification, _selection, isa_authority = _authority()

        bundle = build_hybrid_authority_v2(
            machine_ir_rows=rows,
            machine_ir_manifest=_manifest(rows),
            pe_sha256=BINARY_SHA,
            root_records=[{"kind": "pe_entry", "rva": 0x1000}],
            interprocedural_result=_interprocedural(recoveries=[recovery]),
            entry_records=[_entry(rows)],
            validated_isa_authority=isa_authority,
        )

        certificate = next(
            record
            for record in bundle.records
            if isinstance(record, IndirectExitCertificate)
        )
        self.assertEqual(bundle.status, AuthorityStatus.INCOMPLETE)
        self.assertIn(
            "indirect_exit_dependency_missing",
            {issue.code for issue in certificate.issues},
        )
        self.assertNotIn(
            "call_frame_dependency_missing",
            {issue.code for issue in certificate.issues},
        )

    def test_cyclic_indirect_provenance_fails_closed_without_record_cycle(self) -> None:
        rows = [
            _indirect_row("unit:entry", 0x1000, "eax"),
            _indirect_row("unit:other", 0x1010, "ecx"),
        ]
        first = _recovery_for(
            rows,
            "unit:entry",
            target_unit_ids=["unit:other"],
        )
        second = _recovery_for(
            rows,
            "unit:other",
            target_unit_ids=["unit:entry"],
        )
        first["analysis_dependencies"] = [second["id"]]
        second["analysis_dependencies"] = [first["id"]]
        _qualification, _selection, isa_authority = _authority()

        bundle = build_hybrid_authority_v2(
            machine_ir_rows=rows,
            machine_ir_manifest=_manifest(rows),
            pe_sha256=BINARY_SHA,
            root_records=[{"kind": "pe_entry", "rva": 0x1000}],
            interprocedural_result=_interprocedural(
                recoveries=[first, second]
            ),
            entry_records=[_entry(rows)],
            validated_isa_authority=isa_authority,
        )

        certificates = [
            record
            for record in bundle.records
            if isinstance(record, IndirectExitCertificate)
        ]
        self.assertEqual(bundle.status, AuthorityStatus.INCOMPLETE)
        self.assertNotIn("dependency_cycle", bundle.diagnostics)
        self.assertEqual(len(certificates), 2)
        self.assertTrue(all(
            "indirect_exit_dependency_cycle"
            in {issue.code for issue in certificate.issues}
            for certificate in certificates
        ))

    def test_unrelated_incomplete_exit_does_not_taint_complete_call_frame(self) -> None:
        rows = [_row(external_events=[{
            "kind": "internal_call",
            "instruction_rva": 0x1000,
            "target_rva": 0x1000,
        }])]
        interprocedural = _interprocedural()
        interprocedural["fixed_point"].update({
            "status": "incomplete",
            "failure_reasons": ["reachable_indirect_targets_incomplete"],
        })
        interprocedural["call_summaries"] = {"summaries": [{
            "target_unit_id": "unit:entry",
            "status": "complete",
            "preserved_registers": ["ebx", "esi", "edi", "ebp"],
            "register_preservation": {"status": "complete"},
            "stack_cleanup": {"status": "complete"},
            "result_register_origins": {"status": "complete"},
            "return_behavior": {"status": "complete"},
            "memory_effects": {"status": "complete"},
            "callback_effects": {"status": "not_applicable"},
            "world_effects": {"status": "not_applicable"},
        }]}
        _qualification, _selection, isa_authority = _authority()

        bundle = build_hybrid_authority_v2(
            machine_ir_rows=rows,
            machine_ir_manifest=_manifest(rows),
            pe_sha256=BINARY_SHA,
            root_records=[{"kind": "pe_entry", "rva": 0x1000}],
            interprocedural_result=interprocedural,
            entry_records=[_entry(rows)],
            validated_isa_authority=isa_authority,
        )

        frame = next(
            record for record in bundle.records
            if isinstance(record, CallFrameSummary)
        )
        self.assertEqual(frame.status, AuthorityStatus.COMPLETE)

    def test_byte_free_machine_ir_has_exact_v2_bindings(self) -> None:
        rows = [_row()]
        bindings = build_machine_ir_authority_bindings(
            rows, pe_sha256=BINARY_SHA
        )

        self.assertEqual(bindings["binary"]["machine_ir_sha256"], machine_ir_sha256(rows))
        self.assertEqual(
            bindings["units"][0]["instruction_bytes_sha256"], INSTRUCTION_SHA
        )
        self.assertEqual(bindings["events"], [])

    def test_qualified_isa_and_complete_entry_authorize(self) -> None:
        rows = [_row()]
        _qualification, _selection, isa_authority = _authority()
        bundle = build_hybrid_authority_v2(
            machine_ir_rows=rows,
            machine_ir_manifest=_manifest(rows),
            pe_sha256=BINARY_SHA,
            root_records=[{"kind": "pe_entry", "rva": 0x1000}],
            interprocedural_result=_interprocedural(),
            entry_records=[_entry(rows)],
            validated_isa_authority=isa_authority,
        )

        self.assertEqual(bundle.status, AuthorityStatus.COMPLETE, bundle.diagnostics)
        self.assertTrue(bundle.authorizes)

    def test_unused_proposal_record_is_not_inserted_into_rooted_bundle(self) -> None:
        rows = [_row()]
        _qualification, _selection, isa_authority = _authority()

        bundle = build_hybrid_authority_v2(
            machine_ir_rows=rows,
            machine_ir_manifest=_manifest(rows),
            pe_sha256=BINARY_SHA,
            root_records=[{"kind": "pe_entry", "rva": 0x1000}],
            interprocedural_result=_interprocedural(),
            global_slot_records=[_global_slot(rows)],
            entry_records=[_entry(rows)],
            validated_isa_authority=isa_authority,
        )

        self.assertEqual(bundle.status, AuthorityStatus.COMPLETE, bundle.diagnostics)
        self.assertFalse(any(
            isinstance(record, GlobalSlotInvariant) for record in bundle.records
        ))
        self.assertNotIn("unrooted_record", bundle.diagnostics)

    def test_missing_isa_is_one_required_incomplete_record(self) -> None:
        rows = [_row()]
        bundle = build_hybrid_authority_v2(
            machine_ir_rows=rows,
            machine_ir_manifest=_manifest(rows),
            pe_sha256=BINARY_SHA,
            root_records=[{"kind": "pe_entry", "rva": 0x1000}],
            interprocedural_result=_interprocedural(),
            entry_records=[_entry(rows)],
        )

        self.assertEqual(bundle.status, AuthorityStatus.INCOMPLETE)
        isa_rows = [
            record
            for record in bundle.records
            if getattr(record, "location", None) == "isa_kernel_selection"
        ]
        self.assertEqual(len(isa_rows), 1)

    def test_stale_manifest_binding_is_violated(self) -> None:
        rows = [_row()]
        manifest = _manifest(rows)
        manifest["authority_bindings"] = copy.deepcopy(
            manifest["authority_bindings"]
        )
        manifest["authority_bindings"]["units"][0]["unit_sha256"] = "0" * 64
        _qualification, _selection, isa_authority = _authority()

        bundle = build_hybrid_authority_v2(
            machine_ir_rows=rows,
            machine_ir_manifest=manifest,
            pe_sha256=BINARY_SHA,
            root_records=[{"kind": "pe_entry", "rva": 0x1000}],
            interprocedural_result=_interprocedural(),
            entry_records=[_entry(rows)],
            validated_isa_authority=isa_authority,
        )

        self.assertEqual(bundle.status, AuthorityStatus.VIOLATED)

    def test_control_only_indirect_exit_is_inventoried(self) -> None:
        rows = [_row(outcome={
            "kind": "indirect_jump",
            "instruction_rva": 0x1000,
            "target": {"op": "reg", "name": "eax", "width": 32},
        })]
        bindings = build_machine_ir_authority_bindings(
            rows, pe_sha256=BINARY_SHA
        )

        self.assertEqual(len(bindings["events"]), 1)
        self.assertEqual(bindings["events"][0]["event_kind"], "indirect_jump")
        self.assertEqual(len(bindings["indirect_exits"]), 1)
        self.assertIsNone(bindings["indirect_exits"][0]["source_event_index"])

    def test_control_only_recovery_uses_canonical_exit_binding(self) -> None:
        rows = [_row(outcome={
            "kind": "indirect_jump",
            "instruction_rva": 0x1000,
            "target": {"op": "reg", "name": "eax", "width": 32},
        })]
        recovery = _recovery(rows, target_unit_ids=["unit:entry"])
        _qualification, _selection, isa_authority = _authority()

        bundle = build_hybrid_authority_v2(
            machine_ir_rows=rows,
            machine_ir_manifest=_manifest(rows),
            pe_sha256=BINARY_SHA,
            root_records=[{"kind": "pe_entry", "rva": 0x1000}],
            interprocedural_result=_interprocedural(recoveries=[recovery]),
            entry_records=[_entry(rows)],
            validated_isa_authority=isa_authority,
        )

        certificate = next(
            record
            for record in bundle.records
            if isinstance(record, IndirectExitCertificate)
        )
        self.assertEqual(bundle.status, AuthorityStatus.COMPLETE, bundle.diagnostics)
        self.assertEqual(certificate.analysis_fact_id, recovery["id"])
        self.assertEqual(certificate.status, AuthorityStatus.COMPLETE)

    def test_stale_or_ambiguous_indirect_identity_is_violated(self) -> None:
        rows = [_row(outcome={
            "kind": "indirect_jump",
            "instruction_rva": 0x1000,
            "target": {"op": "reg", "name": "eax", "width": 32},
        })]
        recovery = _recovery(rows, target_unit_ids=["unit:entry"])
        stale = {**recovery, "id": "indirect:stale"}
        _qualification, _selection, isa_authority = _authority()

        stale_bundle = build_hybrid_authority_v2(
            machine_ir_rows=rows,
            machine_ir_manifest=_manifest(rows),
            pe_sha256=BINARY_SHA,
            root_records=[{"kind": "pe_entry", "rva": 0x1000}],
            interprocedural_result=_interprocedural(recoveries=[stale]),
            entry_records=[_entry(rows)],
            validated_isa_authority=isa_authority,
        )
        duplicate_bundle = build_hybrid_authority_v2(
            machine_ir_rows=rows,
            machine_ir_manifest=_manifest(rows),
            pe_sha256=BINARY_SHA,
            root_records=[{"kind": "pe_entry", "rva": 0x1000}],
            interprocedural_result=_interprocedural(
                recoveries=[recovery, copy.deepcopy(recovery)]
            ),
            entry_records=[_entry(rows)],
            validated_isa_authority=isa_authority,
        )

        self.assertEqual(stale_bundle.status, AuthorityStatus.VIOLATED)
        self.assertEqual(duplicate_bundle.status, AuthorityStatus.VIOLATED)

    def test_explicit_first_call_event_does_not_alias_outcome_identity(self) -> None:
        target = {"op": "reg", "name": "eax", "width": 32}
        call = {
            "kind": "indirect_call",
            "instruction_rva": 0x1000,
            "target": target,
        }
        rows = [_row(outcome=copy.deepcopy(call), external_events=[call])]

        bindings = build_machine_ir_authority_bindings(
            rows, pe_sha256=BINARY_SHA
        )

        self.assertEqual(len(bindings["indirect_exits"]), 1)
        self.assertEqual(bindings["indirect_exits"][0]["source_event_index"], 0)

    def test_external_only_indirect_call_uses_site_and_target_certificate(self) -> None:
        rows = [_row(outcome={
            "kind": "indirect_call",
            "instruction_rva": 0x1000,
            "target": {"op": "reg", "name": "eax", "width": 32},
        })]
        manifest = _manifest(rows)
        event = EventBinding.parse(manifest["authority_bindings"]["events"][0])
        external_target_row = {"dll": "fixture.dll", "symbol": "Call"}
        external = CheckedExternalSite(
            site=event,
            profile=ProfileBinding("fixture", "6" * 64, "fixture.dll!Call"),
            transfer_kind="call",
            target_alternative_index=0,
            target_alternative_sha256=hashlib.sha256(
                canonical_json_bytes(external_target_row)
            ).hexdigest(),
            alternatives=FiniteAlternatives.of([{
                "abi": "pe32-stdcall-v1",
                "arguments": [],
                "effects": {"memory": "none", "world": "none"},
            }], maximum=1),
        )
        _qualification, _selection, isa_authority = _authority()
        recovery = _recovery(rows, external_targets=[external_target_row])

        bundle = build_hybrid_authority_v2(
            machine_ir_rows=rows,
            machine_ir_manifest=manifest,
            pe_sha256=BINARY_SHA,
            root_records=[{"kind": "pe_entry", "rva": 0x1000}],
            interprocedural_result=_interprocedural(recoveries=[recovery]),
            checked_external_site_rows=[external],
            entry_records=[_entry(rows)],
            validated_isa_authority=isa_authority,
        )

        self.assertEqual(bundle.status, AuthorityStatus.COMPLETE, bundle.diagnostics)
        self.assertEqual(
            sum(record.__class__.__name__ == "CallFrameSummary" for record in bundle.records),
            0,
        )

    def test_indirect_certificate_binds_exact_mutable_slot_content_id(self) -> None:
        rows = [_row(outcome={
            "kind": "indirect_call",
            "instruction_rva": 0x1000,
            "target": {"op": "reg", "name": "eax", "width": 32},
        })]
        manifest = _manifest(rows)
        event = EventBinding.parse(manifest["authority_bindings"]["events"][0])
        external_target_row = {"dll": "fixture.dll", "symbol": "Call"}
        external = CheckedExternalSite(
            site=event,
            profile=ProfileBinding("fixture", "6" * 64, "fixture.dll!Call"),
            transfer_kind="call",
            target_alternative_index=0,
            target_alternative_sha256=hashlib.sha256(
                canonical_json_bytes(external_target_row)
            ).hexdigest(),
            alternatives=FiniteAlternatives.of([{
                "abi": "pe32-stdcall-v1",
                "arguments": [],
                "effects": {"memory": "none", "world": "none"},
            }], maximum=1),
        )
        invariant = _global_slot(rows)
        recovery = _recovery(
            rows,
            external_targets=[external_target_row],
            mutable_slot_dependencies=[{
                "slot_rva": 0x30000,
                "width_bytes": 4,
                "content_id": invariant.content_id,
            }],
            authority_dependencies=[{
                "role": "mutable_slot_invariant",
                "content_id": invariant.content_id,
            }],
            analysis_dependencies=[invariant.content_id],
        )
        _qualification, _selection, isa_authority = _authority()

        bundle = build_hybrid_authority_v2(
            machine_ir_rows=rows,
            machine_ir_manifest=manifest,
            pe_sha256=BINARY_SHA,
            root_records=[{"kind": "pe_entry", "rva": 0x1000}],
            interprocedural_result=_interprocedural(recoveries=[recovery]),
            checked_external_site_rows=[external],
            global_slot_records=[invariant],
            entry_records=[_entry(rows)],
            validated_isa_authority=isa_authority,
        )

        self.assertEqual(bundle.status, AuthorityStatus.COMPLETE, bundle.diagnostics)
        certificate = next(
            record
            for record in bundle.records
            if isinstance(record, IndirectExitCertificate)
        )
        self.assertEqual(
            {dependency.content_id for dependency in certificate.dependencies},
            {external.content_id, invariant.content_id},
        )

    def test_indirect_certificate_requires_every_external_alternative(self) -> None:
        rows = [_row(outcome={
            "kind": "indirect_call",
            "instruction_rva": 0x1000,
            "target": {"op": "reg", "name": "eax", "width": 32},
        })]
        manifest = _manifest(rows)
        event = EventBinding.parse(manifest["authority_bindings"]["events"][0])
        target_rows = [
            {"dll": "fixture.dll", "symbol": "First"},
            {"dll": "fixture.dll", "symbol": "Second"},
        ]
        target_rows.sort(
            key=lambda row: hashlib.sha256(
                canonical_json_bytes(row)
            ).hexdigest()
        )
        external_records = [
            CheckedExternalSite(
                site=event,
                profile=ProfileBinding(
                    "fixture", "6" * 64, f"fixture.dll!{target['symbol']}"
                ),
                transfer_kind="call",
                target_alternative_index=index,
                target_alternative_sha256=hashlib.sha256(
                    canonical_json_bytes(target)
                ).hexdigest(),
                alternatives=FiniteAlternatives.of([{
                    "abi": "pe32-stdcall-v1",
                    "arguments": [],
                    "effects": {"memory": "none", "world": "none"},
                }], maximum=1),
            )
            for index, target in enumerate(target_rows)
        ]
        recovery = _recovery(
            rows, external_targets=list(reversed(target_rows))
        )
        _qualification, _selection, isa_authority = _authority()

        complete = build_hybrid_authority_v2(
            machine_ir_rows=rows,
            machine_ir_manifest=manifest,
            pe_sha256=BINARY_SHA,
            root_records=[{"kind": "pe_entry", "rva": 0x1000}],
            interprocedural_result=_interprocedural(recoveries=[recovery]),
            checked_external_site_rows=external_records,
            entry_records=[_entry(rows)],
            validated_isa_authority=isa_authority,
        )
        missing_one = build_hybrid_authority_v2(
            machine_ir_rows=rows,
            machine_ir_manifest=manifest,
            pe_sha256=BINARY_SHA,
            root_records=[{"kind": "pe_entry", "rva": 0x1000}],
            interprocedural_result=_interprocedural(recoveries=[recovery]),
            checked_external_site_rows=external_records[:1],
            entry_records=[_entry(rows)],
            validated_isa_authority=isa_authority,
        )

        self.assertEqual(complete.status, AuthorityStatus.COMPLETE)
        certificate = next(
            record
            for record in complete.records
            if isinstance(record, IndirectExitCertificate)
        )
        self.assertEqual(len(certificate.alternatives.values), 2)
        self.assertEqual(missing_one.status, AuthorityStatus.INCOMPLETE)

    def test_missing_mutable_slot_record_cannot_authorize(self) -> None:
        rows = [_row(outcome={
            "kind": "indirect_jump",
            "instruction_rva": 0x1000,
            "target": {"op": "reg", "name": "eax", "width": 32},
        })]
        invariant = _global_slot(rows)
        recovery = _recovery(
            rows,
            target_unit_ids=["unit:entry"],
            mutable_slot_dependencies=[{
                "slot_rva": 0x30000,
                "width_bytes": 4,
                "content_id": invariant.content_id,
            }],
            authority_dependencies=[{
                "role": "mutable_slot_invariant",
                "content_id": invariant.content_id,
            }],
        )
        _qualification, _selection, isa_authority = _authority()

        bundle = build_hybrid_authority_v2(
            machine_ir_rows=rows,
            machine_ir_manifest=_manifest(rows),
            pe_sha256=BINARY_SHA,
            root_records=[{"kind": "pe_entry", "rva": 0x1000}],
            interprocedural_result=_interprocedural(recoveries=[recovery]),
            entry_records=[_entry(rows)],
            validated_isa_authority=isa_authority,
        )

        self.assertEqual(bundle.status, AuthorityStatus.INCOMPLETE)
        certificate = next(
            record
            for record in bundle.records
            if isinstance(record, IndirectExitCertificate)
        )
        self.assertIn(
            "mutable_slot_invariant_missing",
            {issue.code for issue in certificate.issues},
        )

    def test_copied_complete_status_cannot_mask_tainted_invariant(self) -> None:
        rows = [_row(outcome={
            "kind": "indirect_jump",
            "instruction_rva": 0x1000,
            "target": {"op": "reg", "name": "eax", "width": 32},
        })]
        invariant = _global_slot(rows, tainted=True)
        recovery = _recovery(
            rows,
            target_unit_ids=["unit:entry"],
            mutable_slot_dependencies=[{
                "slot_rva": 0x30000,
                "width_bytes": 4,
                "content_id": invariant.content_id,
                "status": "complete",
            }],
            authority_dependencies=[{
                "role": "mutable_slot_invariant",
                "content_id": invariant.content_id,
            }],
        )
        _qualification, _selection, isa_authority = _authority()

        bundle = build_hybrid_authority_v2(
            machine_ir_rows=rows,
            machine_ir_manifest=_manifest(rows),
            pe_sha256=BINARY_SHA,
            root_records=[{"kind": "pe_entry", "rva": 0x1000}],
            interprocedural_result=_interprocedural(recoveries=[recovery]),
            global_slot_records=[invariant],
            entry_records=[_entry(rows)],
            validated_isa_authority=isa_authority,
        )

        self.assertEqual(bundle.status, AuthorityStatus.INCOMPLETE)
        certificate = next(
            record
            for record in bundle.records
            if isinstance(record, IndirectExitCertificate)
        )
        self.assertIn(
            "mutable_slot_invariant_incomplete",
            {issue.code for issue in certificate.issues},
        )


if __name__ == "__main__":
    unittest.main()
