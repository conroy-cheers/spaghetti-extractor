from __future__ import annotations

import copy
import hashlib
import unittest
from dataclasses import FrozenInstanceError

from spaghetti_extractor.authority_dependencies_v2 import (
    call_summary_family_node_id,
)
from spaghetti_extractor.hybrid_authority_v2 import (
    AuthorityBundle,
    AuthorityDataError,
    AuthorityDependency,
    AuthorityStatus,
    BinaryBinding,
    CallFrameSummary,
    CanonicalJson,
    CheckedExternalSite,
    EntryStateContract,
    EventBinding,
    EvidenceIssue,
    EvidenceIssueKind,
    FiniteAlternatives,
    GlobalSlotInvariant,
    IndirectExitCertificate,
    ProfileBinding,
    UnitBinding,
    ValueFact,
    external_target,
    internal_target,
    parse_authority_record,
    parse_authority_record_json,
    parse_canonical_json,
)


def _digest(label: str) -> str:
    return hashlib.sha256(label.encode("ascii")).hexdigest()


def _binary(label: str = "fixture") -> BinaryBinding:
    return BinaryBinding(
        pe_sha256=_digest(f"{label}:pe"),
        machine_ir_sha256=_digest(f"{label}:machine-ir"),
    )


def _unit(binary: BinaryBinding, label: str = "entry") -> UnitBinding:
    return UnitBinding(
        binary=binary,
        unit_id=f"unit:{label}",
        rva_start=0x1000,
        rva_end=0x1020,
        unit_sha256=_digest(f"{label}:unit"),
        instruction_bytes_sha256=_digest(f"{label}:bytes"),
    )


def _event(unit: UnitBinding, kind: str, index: int) -> EventBinding:
    return EventBinding(
        unit=unit,
        event_index=index,
        event_kind=kind,
        instruction_rva=unit.rva_start + index,
        event_sha256=_digest(f"{unit.unit_id}:{kind}:{index}"),
    )


def _alternatives(*values: object, maximum: int | None = None) -> FiniteAlternatives:
    return FiniteAlternatives.of(
        values,
        maximum=len(values) if maximum is None else maximum,
    )


def _call_alternative(callee: UnitBinding) -> dict[str, object]:
    return {
        "format": "spaghetti-extractor-call-frame-families-v2",
        "status": "complete",
        "callee": callee.to_payload(),
        "return_behavior": {
            "status": "complete",
            "may_return": True,
            "may_not_return": False,
        },
        "stack_cleanup": {"status": "complete", "stack_delta": 4},
        "register_preservation": {"status": "complete", "registers": []},
        "result_origins": {"status": "complete", "registers": {}},
        "memory_effects": {"status": "complete", "local_sites": []},
        "callback_effects": {"status": "complete", "sites": []},
        "world_effects": {"status": "complete", "external_sites": []},
        "target_dependencies": [],
        "blocker_codes": [],
    }


def _complete_records() -> tuple[
    BinaryBinding,
    tuple[
        EntryStateContract,
        ValueFact,
        GlobalSlotInvariant,
        CallFrameSummary,
        IndirectExitCertificate,
        CheckedExternalSite,
    ],
]:
    binary = _binary()
    unit = _unit(binary)
    value = ValueFact(
        binding=unit,
        location="register:eax",
        width_bits=32,
        alternatives=_alternatives(0, 1),
    )
    entry = EntryStateContract(
        entry=unit,
        entry_kind="pe_entry",
        alternatives=_alternatives(
            {"register_facts": {"eax": value.content_id}, "stack_facts": []}
        ),
        dependencies=(AuthorityDependency("value_fact", value.content_id),),
    )
    global_slot = GlobalSlotInvariant(
        binding=unit,
        slot_rva=0x3000,
        width_bytes=4,
        invariant_kind="finite_set",
        alternatives=_alternatives(0, 0x401000),
    )
    call = CallFrameSummary(
        call_site=_event(unit, "internal_call", 1),
        analysis_fact_id="call-frame:unit:fixture:1",
        callee=unit,
        abi="pe32-stdcall-v1",
        alternatives=_alternatives(_call_alternative(unit)),
        dependencies=(AuthorityDependency("frame_value", value.content_id),),
    )
    external = CheckedExternalSite(
        site=_event(unit, "external_call", 2),
        profile=ProfileBinding(
            profile_id="fixture-profile",
            profile_sha256=_digest("fixture-profile"),
            entry_id="fixture.dll!Exact",
        ),
        transfer_kind="call",
        target_alternative_index=0,
        target_alternative_sha256=_digest("external-target"),
        alternatives=_alternatives(
            {
                "abi": "pe32-stdcall-v1",
                "arguments": [value.content_id],
                "memory_effect": "none",
                "world_effect": "none",
            }
        ),
        dependencies=(AuthorityDependency("argument", value.content_id),),
    )
    targets = tuple(
        sorted((internal_target(unit), external_target(external.content_id)))
    )
    indirect = IndirectExitCertificate(
        exit_site=_event(unit, "indirect_jump", 3),
        analysis_fact_id="indirect-exit:fixture",
        target_expression_sha256=_digest("target-expression"),
        alternatives=FiniteAlternatives(maximum=2, values=targets),
        dependencies=(
            AuthorityDependency("external_target", external.content_id),
        ),
    )
    return binary, (entry, value, global_slot, call, indirect, external)


class HybridAuthorityV2SchemaTests(unittest.TestCase):
    def test_every_schema_round_trips_with_stable_content_ids(self) -> None:
        _binary_binding, records = _complete_records()

        for record in records:
            with self.subTest(record=type(record).__name__):
                self.assertEqual(record.status, AuthorityStatus.COMPLETE)
                self.assertEqual(parse_authority_record(record.to_payload()), record)
                self.assertEqual(parse_authority_record_json(record.to_json()), record)
                self.assertEqual(
                    parse_canonical_json(record.to_json()), record.to_payload()
                )
                self.assertEqual(record.content_id, record.content_id)
                self.assertNotIn(" ", record.to_json())
                self.assertNotIn("\n", record.to_json())

    def test_values_are_deeply_immutable_and_payloads_are_detached(self) -> None:
        binary, records = _complete_records()
        value = next(record for record in records if isinstance(record, ValueFact))
        first_id = value.content_id

        with self.assertRaises(FrozenInstanceError):
            binary.pe_sha256 = _digest("replacement")  # type: ignore[misc]
        with self.assertRaises(FrozenInstanceError):
            value.location = "register:ebx"  # type: ignore[misc]

        payload = value.to_payload()
        payload["alternatives"]["values"][0] = 99
        payload["binding"]["unit_id"] = "changed"
        self.assertEqual(value.content_id, first_id)
        self.assertNotEqual(payload, value.to_payload())

    def test_content_ids_cover_canonical_values_and_exact_event_bindings(self) -> None:
        binary = _binary()
        unit = _unit(binary)
        left = ValueFact(
            binding=_event(unit, "internal_call", 1),
            location="register:eax",
            width_bits=32,
            alternatives=_alternatives({"a": 1, "b": 2}),
        )
        right = ValueFact(
            binding=_event(unit, "internal_call", 1),
            location="register:eax",
            width_bits=32,
            alternatives=_alternatives({"b": 2, "a": 1}),
        )
        changed_event = EventBinding(
            unit=left.binding.unit,
            event_index=left.binding.event_index,
            event_kind=left.binding.event_kind,
            instruction_rva=left.binding.instruction_rva,
            event_sha256=_digest("different-event"),
        )
        rebound = ValueFact(
            binding=changed_event,
            location=left.location,
            width_bits=left.width_bits,
            alternatives=left.alternatives,
        )

        self.assertEqual(left.content_id, right.content_id)
        self.assertNotEqual(left.content_id, rebound.content_id)

    def test_missing_evidence_is_incomplete(self) -> None:
        binary = _binary()
        unit = _unit(binary)
        missing = ValueFact(
            binding=unit,
            location="register:eax",
            width_bits=32,
            alternatives=None,
        )
        declared_missing = ValueFact(
            binding=unit,
            location="register:ebx",
            width_bits=32,
            alternatives=_alternatives(0),
            issues=(
                EvidenceIssue(
                    EvidenceIssueKind.MISSING,
                    "origin_missing",
                    "No exact value origin has been recovered.",
                ),
            ),
        )

        for record in (missing, declared_missing):
            self.assertEqual(record.status, AuthorityStatus.INCOMPLETE)
            self.assertEqual(parse_authority_record(record.to_payload()), record)

        bundle = AuthorityBundle.of(
            binary=binary,
            records=(missing,),
            required_content_ids=(missing.content_id,),
        )
        self.assertEqual(bundle.status, AuthorityStatus.INCOMPLETE)
        self.assertFalse(bundle.authorizes)
        self.assertIn("record_incomplete", bundle.diagnostics)

    def test_contradictory_and_corrupt_evidence_is_violated(self) -> None:
        binary = _binary()
        unit = _unit(binary)
        contradictory = ValueFact(
            binding=unit,
            location="register:eax",
            width_bits=32,
            alternatives=_alternatives(0),
            issues=(
                EvidenceIssue(
                    EvidenceIssueKind.CONTRADICTORY,
                    "source_conflict",
                    "Two exact sources claim different values.",
                ),
            ),
        )
        corrupt_entry = EntryStateContract(
            entry=unit,
            entry_kind="pe_entry",
            alternatives=_alternatives(7),
        )
        corrupt_indirect = IndirectExitCertificate(
            exit_site=_event(unit, "indirect_jump", 3),
            analysis_fact_id="indirect-exit:corrupt",
            target_expression_sha256=_digest("target-expression"),
            alternatives=_alternatives({"kind": "unknown_target"}),
        )
        corrupt_external = CheckedExternalSite(
            site=_event(unit, "external_call", 2),
            profile=ProfileBinding(
                "profile", _digest("profile"), "fixture.dll!Exact"
            ),
            transfer_kind="call",
            target_alternative_index=0,
            target_alternative_sha256=_digest("corrupt-target"),
            alternatives=_alternatives({}),
        )
        mismatched_transfer = CheckedExternalSite(
            site=_event(unit, "external_call", 2),
            profile=ProfileBinding(
                "profile", _digest("profile"), "fixture.dll!Exact"
            ),
            transfer_kind="jump",
            target_alternative_index=0,
            target_alternative_sha256=_digest("mismatched-target"),
            alternatives=_alternatives({"abi": "pe32-stdcall-v1"}),
        )

        for record in (
            contradictory,
            corrupt_entry,
            corrupt_indirect,
            corrupt_external,
            mismatched_transfer,
        ):
            with self.subTest(record=type(record).__name__):
                self.assertEqual(record.status, AuthorityStatus.VIOLATED)
                self.assertEqual(parse_authority_record(record.to_payload()), record)

        other_unit = _unit(_binary("other"))
        contradictory_frame = CallFrameSummary(
            call_site=_event(unit, "internal_call", 1),
            analysis_fact_id="call-frame:contradictory",
            callee=other_unit,
            abi="pe32-cdecl-v1",
            alternatives=_alternatives(_call_alternative(unit)),
        )
        self.assertEqual(contradictory_frame.status, AuthorityStatus.VIOLATED)

    def test_strict_parsing_rejects_tampering_and_noncanonical_json(self) -> None:
        _binary_binding, records = _complete_records()
        payload = records[0].to_payload()

        unknown = copy.deepcopy(payload)
        unknown["unexpected"] = False
        with self.assertRaisesRegex(AuthorityDataError, "noncanonical fields"):
            parse_authority_record(unknown)

        stale_id = copy.deepcopy(payload)
        stale_id["content_id"] = (
            "hybrid-authority-v2:entry_state_contract:" + "0" * 64
        )
        with self.assertRaisesRegex(AuthorityDataError, "content ID"):
            parse_authority_record(stale_id)

        with self.assertRaisesRegex(AuthorityDataError, "not canonical"):
            parse_authority_record_json(records[0].to_json() + "\n")
        with self.assertRaisesRegex(AuthorityDataError, "duplicate key"):
            parse_canonical_json('{"a":1,"a":1}')
        with self.assertRaisesRegex(AuthorityDataError, "floating-point"):
            CanonicalJson.of({"value": 1.5})


class HybridAuthorityV2ClosureTests(unittest.TestCase):
    def test_call_frame_family_is_a_distinct_checked_subject(self) -> None:
        binary = _binary()
        unit = _unit(binary)
        aggregate = CallFrameSummary(
            call_site=_event(unit, "internal_call", 1),
            analysis_fact_id="call-frame:unit:fixture:1",
            callee=unit,
            abi="pe32-cdecl-v1",
            alternatives=_alternatives(_call_alternative(unit)),
        )
        family_value = _call_alternative(unit)
        family_value.update({
            "return_behavior": {"status": "not_applicable"},
            "stack_cleanup": {"status": "complete", "stack_delta": 0},
            "register_preservation": {"status": "not_applicable"},
            "result_origins": {"status": "not_applicable"},
            "memory_effects": {"status": "not_applicable"},
            "callback_effects": {"status": "not_applicable"},
            "world_effects": {"status": "not_applicable"},
        })
        family = CallFrameSummary(
            call_site=aggregate.call_site,
            analysis_fact_id=call_summary_family_node_id(
                unit.unit_id, "stack"
            ),
            callee=unit,
            abi=aggregate.abi,
            alternatives=FiniteAlternatives.of([family_value], maximum=1),
        )
        bundle = AuthorityBundle.of(
            binary=binary,
            records=(aggregate, family),
            required_content_ids=(aggregate.content_id, family.content_id),
        )

        self.assertEqual(family.status, AuthorityStatus.COMPLETE)
        self.assertNotIn("contradictory_subject_claims", bundle.diagnostics)

        malformed = CallFrameSummary(
            call_site=aggregate.call_site,
            analysis_fact_id='call-summary-family:["other","stack",null]',
            callee=unit,
            abi=aggregate.abi,
            alternatives=family.alternatives,
        )
        self.assertEqual(malformed.status, AuthorityStatus.VIOLATED)

    def test_complete_dependency_closure_is_the_only_authorizing_state(self) -> None:
        binary, records = _complete_records()
        roots = tuple(
            record.content_id
            for record in records
            if isinstance(
                record,
                (
                    EntryStateContract,
                    GlobalSlotInvariant,
                    CallFrameSummary,
                    IndirectExitCertificate,
                ),
            )
        )
        bundle = AuthorityBundle.of(
            binary=binary,
            records=records,
            required_content_ids=roots,
        )

        self.assertEqual(bundle.status, AuthorityStatus.COMPLETE)
        self.assertEqual(bundle.diagnostics, ())
        self.assertTrue(bundle.authorizes)
        self.assertEqual(AuthorityBundle.parse(bundle.to_payload()), bundle)
        self.assertEqual(AuthorityBundle.from_json(bundle.to_json()), bundle)
        self.assertEqual(bundle.content_id, bundle.content_id)

    def test_dangling_dependencies_are_incomplete(self) -> None:
        binary = _binary()
        unit = _unit(binary)
        missing_id = "hybrid-authority-v2:value_fact:" + _digest("missing")
        record = ValueFact(
            binding=unit,
            location="register:eax",
            width_bits=32,
            alternatives=_alternatives(0),
            dependencies=(AuthorityDependency("origin", missing_id),),
        )
        bundle = AuthorityBundle.of(
            binary=binary,
            records=(record,),
            required_content_ids=(record.content_id,),
        )

        self.assertEqual(bundle.status, AuthorityStatus.INCOMPLETE)
        self.assertFalse(bundle.authorizes)
        self.assertIn("dependency_missing", bundle.diagnostics)

    def test_embedded_content_ids_require_declared_dependencies(self) -> None:
        binary = _binary()
        unit = _unit(binary)
        referenced_id = "hybrid-authority-v2:value_fact:" + _digest("referenced")
        record = EntryStateContract(
            entry=unit,
            entry_kind="pe_entry",
            alternatives=_alternatives({"value_fact": referenced_id}),
        )

        self.assertEqual(record.status, AuthorityStatus.INCOMPLETE)
        declared = EntryStateContract(
            entry=unit,
            entry_kind="pe_entry",
            alternatives=record.alternatives,
            dependencies=(AuthorityDependency("value_fact", referenced_id),),
        )
        self.assertEqual(declared.status, AuthorityStatus.COMPLETE)

    def test_cross_record_binding_and_subject_conflicts_are_violations(self) -> None:
        binary = _binary()
        unit = _unit(binary)
        first = ValueFact(
            binding=unit,
            location="register:eax",
            width_bits=32,
            alternatives=_alternatives(0),
        )
        second = ValueFact(
            binding=unit,
            location="register:eax",
            width_bits=32,
            alternatives=_alternatives(1),
        )
        conflict = AuthorityBundle.of(
            binary=binary,
            records=(first, second),
            required_content_ids=(first.content_id, second.content_id),
        )
        self.assertEqual(conflict.status, AuthorityStatus.VIOLATED)
        self.assertIn("contradictory_subject_claims", conflict.diagnostics)

        foreign = ValueFact(
            binding=_unit(_binary("foreign")),
            location="register:ebx",
            width_bits=32,
            alternatives=_alternatives(0),
        )
        mismatched = AuthorityBundle.of(
            binary=binary,
            records=(foreign,),
            required_content_ids=(foreign.content_id,),
        )
        self.assertEqual(mismatched.status, AuthorityStatus.VIOLATED)
        self.assertIn("binary_binding_conflict", mismatched.diagnostics)

    def test_callback_entry_subject_is_bound_to_registration_event(self) -> None:
        binary = _binary()
        callback = _unit(binary, "callback")
        registrar = _unit(binary, "registrar")
        first = EntryStateContract(
            entry=callback,
            entry_kind="registered_callback",
            entry_event=_event(registrar, "callback_registration", 0),
            alternatives=_alternatives({"registration": 0}),
        )
        second = EntryStateContract(
            entry=callback,
            entry_kind="registered_callback",
            entry_event=_event(registrar, "callback_registration", 1),
            alternatives=_alternatives({"registration": 1}),
        )

        bundle = AuthorityBundle.of(
            binary=binary,
            records=(first, second),
            required_content_ids=(first.content_id, second.content_id),
        )

        self.assertEqual(bundle.status, AuthorityStatus.COMPLETE)
        self.assertNotIn("contradictory_subject_claims", bundle.diagnostics)

    def test_finite_sets_and_exact_bindings_are_fail_closed(self) -> None:
        with self.assertRaisesRegex(AuthorityDataError, "nonempty"):
            FiniteAlternatives.of([], maximum=1)
        with self.assertRaisesRegex(AuthorityDataError, "exceed"):
            FiniteAlternatives.of([0, 1], maximum=1)
        with self.assertRaisesRegex(AuthorityDataError, "sorted and unique"):
            FiniteAlternatives(
                maximum=2,
                values=(CanonicalJson.of(1), CanonicalJson.of(0)),
            )

        unit = _unit(_binary())
        targets = FiniteAlternatives.of([internal_target(unit)], maximum=1)
        self.assertEqual(targets.values, (internal_target(unit),))
        with self.assertRaisesRegex(AuthorityDataError, "checked external-site"):
            external_target(
                "hybrid-authority-v2:value_fact:" + _digest("not-external")
            )

        with self.assertRaisesRegex(AuthorityDataError, "outside"):
            EventBinding(
                unit=unit,
                event_index=0,
                event_kind="internal_call",
                instruction_rva=unit.rva_end,
                event_sha256=_digest("outside"),
            )

    def test_v1_data_never_authorizes(self) -> None:
        binary, records = _complete_records()
        bundle = AuthorityBundle.of(
            binary=binary,
            records=(records[1],),
            required_content_ids=(records[1].content_id,),
        )
        self.assertTrue(bundle.authorizes)

        legacy_record = {"format": "spaghetti-extractor-value-fact-v1"}
        with self.assertRaisesRegex(AuthorityDataError, "v1"):
            parse_authority_record(legacy_record)

        legacy_bundle = bundle.to_payload()
        legacy_bundle["format"] = "spaghetti-extractor-hybrid-authority-bundle-v1"
        with self.assertRaisesRegex(AuthorityDataError, "v1"):
            AuthorityBundle.parse(legacy_bundle)

        escalated = bundle.to_payload()
        escalated["v1_authorizes"] = True
        with self.assertRaisesRegex(AuthorityDataError, "v1"):
            AuthorityBundle.parse(escalated)


if __name__ == "__main__":
    unittest.main()
