from __future__ import annotations

import copy
import unittest
from typing import Any

from spaghetti_extractor.behavioral_roots import (
    BEHAVIORAL_ROOTS_FORMAT,
    behavioral_roots_sha256,
)
from spaghetti_extractor.entry_state_analysis_v2 import (
    CALLBACK_ENTRY_STATE_ANALYSIS_V2_FORMAT,
    ENTRY_STATE_ANALYSIS_V2_FORMAT,
    construct_entry_state_analysis_v2,
    derive_callback_entry_state_contracts_v2,
    parse_callback_entry_state_contracts_v2,
    propose_global_slot_invariant,
    validate_callback_entry_state_contracts_v2,
)
from spaghetti_extractor.hybrid_authority_v2 import (
    BinaryBinding,
    UnitBinding,
    parse_authority_record,
)
from spaghetti_extractor.machine_ir_authority_v2 import recompute_unit_binding


IMAGE_BASE = 0x400000
SLOT = IMAGE_BASE + 0x5000
MACHINE_IR_SHA256 = "c" * 64


def _behavioral_roots() -> dict[str, object]:
    roots = [
        {"kind": "pe_entrypoint", "identity": "pe-entrypoint", "rva": 0x1000},
        {
            "kind": "pe_export",
            "identity": "pe-export:ordinal:1:name:Exported",
            "rva": 0x1100,
            "ordinal": 1,
            "name": "Exported",
        },
        {
            "kind": "pe_tls_callback",
            "identity": "pe-tls-callback:index:0",
            "rva": 0x1200,
            "callback_index": 0,
        },
    ]
    body: dict[str, object] = {
        "format": BEHAVIORAL_ROOTS_FORMAT,
        "status": "complete",
        "authority": "independent_exact_pe_metadata",
        "pe": {
            "sha256": "a" * 64,
            "file_size": 0x9000,
            "machine": "i386",
            "bitness": 32,
            "image_base": IMAGE_BASE,
            "size_of_image": 0xA000,
            "entrypoint_rva": 0x1000,
        },
        "roots": roots,
        "counts": {
            "roots": 3,
            "pe_entrypoint": 1,
            "pe_export": 1,
            "pe_tls_callback": 1,
        },
        "constraints": {
            "original_binary_executed": False,
            "strict_export_parsing_required": True,
            "strict_tls_parsing_required": True,
            "tls_callback_inventory_immutable": True,
            "roots_in_exactly_one_executable_section": True,
        },
    }
    return {**body, "contract_sha256": behavioral_roots_sha256(body)}


def _interface_provenance(
    *,
    slots: list[dict[str, object]] | None = None,
    registrations: list[dict[str, object]] | None = None,
    rejected: list[dict[str, object]] | None = None,
) -> dict[str, object]:
    return {
        "format": "stage-a-external-interface-provenance-v1",
        "status": "complete",
        "proof_authority": False,
        "static_interface_slots": [] if slots is None else slots,
        "rejected_tainted_slots": [] if rejected is None else rejected,
        "callback_registrations": [] if registrations is None else registrations,
    }


def _launch_invariants() -> dict[str, list[dict[str, object]]]:
    return {
        "pe_entrypoint": [
            {"kind": "pe32_process_launch", "value": {"stack": "loader"}}
        ],
        "pe_export": [
            {"kind": "pe32_export_call", "value": {"caller": "external"}}
        ],
        "pe_tls_callback": [
            {"kind": "pe32_tls_callback", "value": {"reason": "loader"}}
        ],
    }


def _origin(value: int) -> dict[str, object]:
    return {"kind": "exact", "key": [value]}


def _site(unit_id: str, event_index: int) -> dict[str, object]:
    return {"unit_id": unit_id, "event_index": event_index}


def _unit(identifier: str, rva: int, digest: str) -> dict[str, object]:
    return {
        "id": identifier,
        "source": {
            "original": {"rva_start": rva, "rva_end": rva + 0x20},
            "contract_sha256": digest * 64,
            "instruction_bytes_sha256": digest * 64,
        },
    }


def _units() -> list[dict[str, object]]:
    return [
        _unit("unit:entry", 0x1000, "1"),
        _unit("unit:export", 0x1100, "2"),
        _unit("unit:tls", 0x1200, "3"),
        _unit("unit:register", 0x1800, "6"),
        _unit("unit:init", 0x1900, "4"),
        _unit("unit:callback", 0x2200, "5"),
    ]


def _initializer_binding() -> UnitBinding:
    return recompute_unit_binding(
        _units()[4],
        binary=BinaryBinding(
            pe_sha256="a" * 64,
            machine_ir_sha256=MACHINE_IR_SHA256,
        ),
    )


def _slot_evidence(
    alternatives: list[dict[str, object]],
    *,
    relevant_reads: list[dict[str, object]] | None = None,
    unknown_writes: list[dict[str, object]] | None = None,
    aliasing_writes: list[dict[str, object]] | None = None,
) -> dict[str, object]:
    initializer = _site("unit:init", 0)
    return {
        "address": SLOT,
        "width": 4,
        "reachable_write_inventory": {
            "status": "complete",
            "writes": [
                {
                    "site": initializer,
                    "classification": "initializer",
                    "alternatives": copy.deepcopy(alternatives),
                }
            ],
            "unknown_writes": [] if unknown_writes is None else unknown_writes,
            "aliasing_writes": [] if aliasing_writes is None else aliasing_writes,
        },
        "relevant_reads": (
            [
                {
                    "site": _site("unit:callback", 1),
                    "dominated_by": initializer,
                }
            ]
            if relevant_reads is None
            else relevant_reads
        ),
    }


def _nested_registration(
    target_rva: int = 0x2200,
    *,
    global_slot_invariant_ids: list[str] | None = None,
) -> dict[str, object]:
    behavior = {
        "kind": "nested_native_callback_v1",
        "provider_relation": "same_pinned_native_provider_v1",
        "delivery": "during_call_or_until_lifetime_end",
        "activation": {
            "kind": "masked_argument_equals",
            "argument": 1,
            "mask": 0xF0,
            "value": 0x20,
        },
        "message_argument": 0,
        "message_values": [1, 2],
        "resource_argument": 1,
        "instance_binding": {
            "callback_argument": 2,
            "registration_argument": 0,
        },
        "payload_arguments": [3],
    }
    return {
        "format": "stage-a-callback-registration-provenance-v1",
        "record_kind": "callback_registration",
        "proof_authority": False,
        "status": "complete",
        "failure": None,
        "unit_id": "unit:register",
        "event_index": 3,
        "instruction_rva": 0x1800,
        "import": {
            "dll": "fixture.dll",
            "symbol": "Register",
            "ordinal": None,
        },
        "contract_id": "fixture.dll!Register",
        "profile_binding": {"profile_id": "fixture", "profile_sha256": "b" * 64},
        "callback_source": {"kind": "argument_word", "argument": 2},
        "callback_abi": {
            "kind": "generic_callback",
            "argument_words": 4,
            "stack_cleanup_bytes": 16,
            "nullable": False,
        },
        "callback_lifetime": "until_release",
        "global_slot_invariant_ids": (
            []
            if global_slot_invariant_ids is None
            else global_slot_invariant_ids
        ),
        "callback_behavior": behavior,
        "callback_activation": {
            "kind": "masked_argument_equals",
            "argument_index": 1,
            "mask": 0xF0,
            "expected_value": 0x20,
            "origins": [_origin(0x20)],
            "exact_value": 0x20,
            "masked_value": 0x20,
            "status": "complete",
            "failure": None,
        },
        "callback_instance": {
            "kind": "registration_argument_origins_v1",
            "registration_argument": 0,
            "callback_argument": 2,
            "origins": [_origin(0x7777)],
        },
        "origins": [_origin(IMAGE_BASE + target_rva)],
        "source_locations": [],
        "target_rvas": [target_rva],
        "target_unit_ids": ["unit:callback"],
    }


def _interface_registration() -> dict[str, object]:
    registration = _nested_registration()
    registration.update({
        "contract_id": "interface-method-callback",
        "profile_binding": {
            "interface_protocols": [{
                "profile_sha256": "b" * 64,
                "interface_id": "IThing",
                "method": "Enumerate",
                "slot": 4,
                "callback_arguments": [{
                    "argument_index": 0,
                    "kind": "interface_object",
                    "interface_id": "IThing",
                }],
            }],
        },
        "callback_abi": {
            "kind": "generic_callback",
            "argument_words": 1,
            "stack_cleanup_bytes": 4,
            "nullable": False,
        },
        "callback_behavior": None,
        "callback_activation": None,
        "callback_instance": None,
        "callback_entry_arguments": [{
            "argument_index": 0,
            "origins": [{
                "kind": "interface_object",
                "key": ["b" * 64, "IThing"],
            }],
        }],
    })
    return registration


def _callback_entry_artifact(
    *,
    provenance: dict[str, object] | None = None,
    global_slot_invariants: list[dict[str, object]] | None = None,
) -> dict[str, Any]:
    return derive_callback_entry_state_contracts_v2(
        pe_sha256="a" * 64,
        image_base=IMAGE_BASE,
        size_of_image=0xA000,
        interface_provenance=(
            _interface_provenance() if provenance is None else provenance
        ),
        units=_units(),
        machine_ir_sha256=MACHINE_IR_SHA256,
        global_slot_invariants=(
            [] if global_slot_invariants is None else global_slot_invariants
        ),
    )


class EntryStateAnalysisV2Tests(unittest.TestCase):
    def test_pe_root_contracts_contain_only_immutable_and_launch_facts(self) -> None:
        report = construct_entry_state_analysis_v2(
            behavioral_roots=_behavioral_roots(),
            interface_provenance=_interface_provenance(),
            units=_units(),
            machine_ir_sha256=MACHINE_IR_SHA256,
            callback_entry_state=_callback_entry_artifact(),
            launch_invariants=_launch_invariants(),
            iat_facts=[
                {
                    "dll": "kernel32.dll",
                    "symbol": "ExitProcess",
                    "ordinal": None,
                    "iat_rva": 0x6000,
                    "iat_va": IMAGE_BASE + 0x6000,
                }
            ],
        )

        self.assertEqual(report["format"], ENTRY_STATE_ANALYSIS_V2_FORMAT)
        self.assertEqual(report["status"], "complete")
        self.assertEqual(len(report["root_contracts"]), 3)
        for contract in report["root_contracts"]:
            facts = contract["alternatives"]["values"][0]
            self.assertEqual(
                set(facts),
                {
                    "root",
                    "authority",
                    "immutable_pe",
                    "immutable_iat",
                    "launch_invariants",
                },
            )
            self.assertNotIn("global_slot_invariants", facts)

    def test_callback_contract_binds_registration_abi_capture_and_globals(self) -> None:
        alternatives = [{"kind": "resource", "key": ["fixture", "device"]}]
        invariant_check = propose_global_slot_invariant(
            _slot_evidence(alternatives),
            interface_slot={
                "address": SLOT,
                "origins": alternatives,
                "tainted": False,
            },
            unit_bindings={"unit:init": _initializer_binding()},
            image_base=IMAGE_BASE,
            size_of_image=0xA000,
        )
        invariant = invariant_check["proposal"]
        assert isinstance(invariant, dict)
        provenance = _interface_provenance(
            slots=[{"address": SLOT, "origins": alternatives, "tainted": False}],
            registrations=[_nested_registration(
                global_slot_invariant_ids=[invariant["content_id"]]
            )],
        )
        report = construct_entry_state_analysis_v2(
            behavioral_roots=_behavioral_roots(),
            interface_provenance=provenance,
            units=_units(),
            machine_ir_sha256=MACHINE_IR_SHA256,
            global_slot_evidence=[_slot_evidence(alternatives)],
            callback_entry_state=_callback_entry_artifact(
                provenance=provenance,
                global_slot_invariants=[invariant],
            ),
            launch_invariants=_launch_invariants(),
            iat_facts=[],
        )

        self.assertEqual(report["status"], "complete")
        self.assertEqual(len(report["global_slot_invariants"]), 1)
        for record in report["authority_records"]:
            self.assertEqual(
                parse_authority_record(record).to_payload(), record
            )
        callback = next(
            contract
            for contract in report["root_contracts"]
            if contract["entry_kind"] == "registered_callback"
        )
        facts = callback["alternatives"]["values"][0]
        self.assertEqual(facts["registration"]["unit_id"], "unit:register")
        self.assertEqual(facts["callback_abi"]["argument_words"], 4)
        self.assertEqual(
            [argument["stack_offset"] for argument in facts["callback_arguments"]],
            [4, 8, 12, 16],
        )
        self.assertEqual(
            [argument["role"] for argument in facts["callback_arguments"]],
            ["message", "provider_resource", "registered_instance", "payload"],
        )
        self.assertEqual(
            facts["captured_resources"][0]["origins"], [_origin(0x7777)]
        )
        self.assertEqual(
            facts["global_slot_invariants"][0]["slot_rva"], 0x5000
        )

    def test_strict_artifact_is_the_only_callback_authority(self) -> None:
        provenance = _interface_provenance(
            registrations=[_nested_registration()]
        )
        callback_artifact = _callback_entry_artifact(provenance=provenance)
        report = construct_entry_state_analysis_v2(
            behavioral_roots=_behavioral_roots(),
            interface_provenance=provenance,
            units=_units(),
            machine_ir_sha256=MACHINE_IR_SHA256,
            callback_entry_state=callback_artifact,
            launch_invariants=_launch_invariants(),
            iat_facts=[],
        )

        authoritative_callbacks = [
            contract
            for contract in report["root_contracts"]
            if contract["entry_kind"] == "registered_callback"
        ]
        authority_record_callbacks = [
            record
            for record in report["authority_records"]
            if record.get("format") == "spaghetti-extractor-entry-state-contract-v2"
            and record.get("entry_kind") == "registered_callback"
        ]
        self.assertEqual(report["status"], "complete")
        self.assertEqual(report["callback_authority"]["status"], "complete")
        self.assertEqual(len(authoritative_callbacks), 1)
        self.assertEqual(len(authority_record_callbacks), 1)
        self.assertEqual(
            authoritative_callbacks[0]["content_id"],
            callback_artifact["contracts"][0]["content_id"],
        )
        self.assertEqual(
            report["legacy_callback_diagnostics"]["counts"]["callback_roots"],
            1,
        )
        self.assertFalse(report["legacy_callback_diagnostics"]["proof_authority"])
        legacy = report["legacy_callback_diagnostics"]["root_checks"][0]
        self.assertFalse(legacy["proof_authority"])
        self.assertNotIn("proposal", legacy)
        self.assertNotIn("format", legacy)

    def test_missing_callback_artifact_fails_closed(self) -> None:
        report = construct_entry_state_analysis_v2(
            behavioral_roots=_behavioral_roots(),
            interface_provenance=_interface_provenance(
                registrations=[_nested_registration()]
            ),
            units=_units(),
            machine_ir_sha256=MACHINE_IR_SHA256,
            launch_invariants=_launch_invariants(),
            iat_facts=[],
        )

        self.assertEqual(report["status"], "incomplete")
        self.assertEqual(report["callback_authority"]["source"], "missing")
        self.assertIn(
            "callback_entry_state_artifact_missing",
            {issue["code"] for issue in report["issues"]},
        )

    def test_corrupt_callback_artifact_is_violated(self) -> None:
        report = construct_entry_state_analysis_v2(
            behavioral_roots=_behavioral_roots(),
            interface_provenance=_interface_provenance(
                registrations=[_nested_registration()]
            ),
            units=_units(),
            machine_ir_sha256=MACHINE_IR_SHA256,
            callback_entry_state={"format": CALLBACK_ENTRY_STATE_ANALYSIS_V2_FORMAT},
            launch_invariants=_launch_invariants(),
            iat_facts=[],
        )

        self.assertEqual(report["status"], "violated")
        self.assertFalse(any(
            contract["entry_kind"] == "registered_callback"
            for contract in report["root_contracts"]
        ))
        self.assertIn(
            "callback_entry_state_artifact_corrupt",
            {issue["code"] for issue in report["issues"]},
        )

    def test_callback_contracts_are_derived_before_launch_finalization(self) -> None:
        report = derive_callback_entry_state_contracts_v2(
            pe_sha256="a" * 64,
            image_base=IMAGE_BASE,
            size_of_image=0xA000,
            interface_provenance=_interface_provenance(
                registrations=[_nested_registration()]
            ),
            units=_units(),
            machine_ir_sha256=MACHINE_IR_SHA256,
        )

        self.assertEqual(report["format"], CALLBACK_ENTRY_STATE_ANALYSIS_V2_FORMAT)
        self.assertEqual(report["status"], "complete")
        self.assertEqual(len(report["contracts"]), 1)
        self.assertEqual(
            report["callback_roots"][0]["entry_contract_content_id"],
            report["contracts"][0]["content_id"],
        )
        self.assertEqual(parse_callback_entry_state_contracts_v2(report), report)
        replay = validate_callback_entry_state_contracts_v2(
            report,
            pe_sha256="a" * 64,
            image_base=IMAGE_BASE,
            size_of_image=0xA000,
            interface_provenance=_interface_provenance(
                registrations=[_nested_registration()]
            ),
            units=_units(),
            machine_ir_sha256=MACHINE_IR_SHA256,
        )
        self.assertEqual(replay["status"], "complete")
        self.assertTrue(replay["usable"])

    def test_profile_callback_argument_origins_are_checked_and_exported(self) -> None:
        registration = _interface_registration()
        report = derive_callback_entry_state_contracts_v2(
            pe_sha256="a" * 64,
            image_base=IMAGE_BASE,
            size_of_image=0xA000,
            interface_provenance=_interface_provenance(
                registrations=[registration]
            ),
            units=_units(),
            machine_ir_sha256=MACHINE_IR_SHA256,
        )

        self.assertEqual(report["status"], "complete", report["issues"])
        arguments = report["contracts"][0]["alternatives"]["values"][0][
            "callback_arguments"
        ]
        self.assertEqual(arguments[0]["role"], "profile_value_origin")
        self.assertEqual(
            arguments[0]["constraints"]["origins"],
            registration["callback_entry_arguments"][0]["origins"],
        )

        registration["callback_entry_arguments"][0]["origins"][0]["key"][0] = (
            "d" * 64
        )
        corrupted = derive_callback_entry_state_contracts_v2(
            pe_sha256="a" * 64,
            image_base=IMAGE_BASE,
            size_of_image=0xA000,
            interface_provenance=_interface_provenance(
                registrations=[registration]
            ),
            units=_units(),
            machine_ir_sha256=MACHINE_IR_SHA256,
        )
        self.assertEqual(corrupted["status"], "violated")
        self.assertIn(
            "callback_entry_argument_origin_corrupt",
            {issue["code"] for issue in corrupted["issues"]},
        )

        registration = _interface_registration()
        registration["callback_entry_arguments"][0]["origins"][0]["key"][0] = []
        corrupted = derive_callback_entry_state_contracts_v2(
            pe_sha256="a" * 64,
            image_base=IMAGE_BASE,
            size_of_image=0xA000,
            interface_provenance=_interface_provenance(
                registrations=[registration]
            ),
            units=_units(),
            machine_ir_sha256=MACHINE_IR_SHA256,
        )
        self.assertEqual(corrupted["status"], "violated")
        self.assertIn(
            "callback_entry_argument_origin_corrupt",
            {issue["code"] for issue in corrupted["issues"]},
        )

        registration = _interface_registration()
        registration["callback_entry_arguments"][0]["origins"][0]["key"][1] = (
            "IUnrelated"
        )
        corrupted = derive_callback_entry_state_contracts_v2(
            pe_sha256="a" * 64,
            image_base=IMAGE_BASE,
            size_of_image=0xA000,
            interface_provenance=_interface_provenance(
                registrations=[registration]
            ),
            units=_units(),
            machine_ir_sha256=MACHINE_IR_SHA256,
        )
        self.assertEqual(corrupted["status"], "violated")
        self.assertIn(
            "callback_entry_argument_origin_corrupt",
            {issue["code"] for issue in corrupted["issues"]},
        )

    def test_callback_missing_named_global_invariant_is_incomplete(self) -> None:
        report = derive_callback_entry_state_contracts_v2(
            pe_sha256="a" * 64,
            image_base=IMAGE_BASE,
            size_of_image=0xA000,
            interface_provenance=_interface_provenance(
                registrations=[_nested_registration(
                    global_slot_invariant_ids=[
                        "hybrid-authority-v2:global_slot_invariant:" + "d" * 64
                    ]
                )]
            ),
            units=_units(),
            machine_ir_sha256=MACHINE_IR_SHA256,
        )

        self.assertEqual(report["status"], "incomplete")
        self.assertIn(
            "callback_global_invariant_missing",
            {issue["code"] for issue in report["issues"]},
        )

    def test_callback_does_not_receive_unreferenced_mutable_invariants(self) -> None:
        alternatives = [_origin(0x1234)]
        invariant_check = propose_global_slot_invariant(
            _slot_evidence(alternatives),
            interface_slot={
                "address": SLOT,
                "origins": alternatives,
                "tainted": False,
            },
            unit_bindings={"unit:init": _initializer_binding()},
            image_base=IMAGE_BASE,
            size_of_image=0xA000,
        )
        invariant = invariant_check["proposal"]
        assert isinstance(invariant, dict)
        report = derive_callback_entry_state_contracts_v2(
            pe_sha256="a" * 64,
            image_base=IMAGE_BASE,
            size_of_image=0xA000,
            interface_provenance=_interface_provenance(
                registrations=[_nested_registration()]
            ),
            units=_units(),
            machine_ir_sha256=MACHINE_IR_SHA256,
            global_slot_invariants=[invariant],
        )

        facts = report["contracts"][0]["alternatives"]["values"][0]
        self.assertEqual(report["status"], "complete")
        self.assertEqual(facts["global_slot_invariants"], [])
        self.assertEqual(report["contracts"][0]["dependencies"], [])
        self.assertEqual(report["global_slot_invariants"], [])
        self.assertEqual(report["global_slot_invariant_ids"], [])
        self.assertEqual(report["counts"]["global_slot_invariants"], 0)

    def test_unknown_and_aliasing_writes_taint_and_prevent_export(self) -> None:
        alternatives = [_origin(0x1234)]
        for field in ("unknown_writes", "aliasing_writes"):
            with self.subTest(field=field):
                evidence = _slot_evidence(
                    alternatives,
                    **{field: [_site("unit:opaque", 7)]},
                )
                check = propose_global_slot_invariant(
                    evidence,
                    interface_slot={
                        "address": SLOT,
                        "origins": alternatives,
                        "tainted": False,
                    },
                    unit_bindings={"unit:init": _initializer_binding()},
                    image_base=IMAGE_BASE,
                    size_of_image=0xA000,
                )

                self.assertEqual(check["status"], "incomplete")
                self.assertTrue(check["tainted"])
                self.assertIsNone(check["proposal"])

    def test_missing_dominance_and_unbounded_alternatives_are_incomplete(self) -> None:
        alternatives = [_origin(1), _origin(2)]
        wrong_dominator = _slot_evidence(
            alternatives,
            relevant_reads=[
                {
                    "site": _site("unit:callback", 1),
                    "dominated_by": _site("unit:other", 0),
                }
            ],
        )
        dominance = propose_global_slot_invariant(
            wrong_dominator,
            interface_slot={"address": SLOT, "origins": alternatives, "tainted": False},
            unit_bindings={"unit:init": _initializer_binding()},
            image_base=IMAGE_BASE,
            size_of_image=0xA000,
        )
        bounded = propose_global_slot_invariant(
            _slot_evidence(alternatives),
            interface_slot={"address": SLOT, "origins": alternatives, "tainted": False},
            unit_bindings={"unit:init": _initializer_binding()},
            image_base=IMAGE_BASE,
            size_of_image=0xA000,
            alternative_budget=1,
        )

        self.assertEqual(dominance["status"], "incomplete")
        self.assertIsNone(dominance["proposal"])
        self.assertEqual(bounded["status"], "incomplete")
        self.assertIsNone(bounded["proposal"])

    def test_replay_and_provenance_disagreement_is_violated(self) -> None:
        check = propose_global_slot_invariant(
            _slot_evidence([_origin(1)]),
            interface_slot={
                "address": SLOT,
                "origins": [_origin(2)],
                "tainted": False,
            },
            unit_bindings={"unit:init": _initializer_binding()},
            image_base=IMAGE_BASE,
            size_of_image=0xA000,
        )

        self.assertEqual(check["status"], "violated")
        self.assertIsNone(check["proposal"])
        self.assertIn(
            "global_slot_replay_provenance_contradiction",
            {issue["code"] for issue in check["issues"]},
        )

    def test_each_checked_registration_gets_its_own_callback_entry(self) -> None:
        first = _nested_registration()
        second = copy.deepcopy(first)
        second.update(
            unit_id="unit:init",
            event_index=0,
            instruction_rva=0x1900,
        )
        report = derive_callback_entry_state_contracts_v2(
            pe_sha256="a" * 64,
            image_base=IMAGE_BASE,
            size_of_image=0xA000,
            interface_provenance=_interface_provenance(
                registrations=[first, second]
            ),
            units=_units(),
            machine_ir_sha256=MACHINE_IR_SHA256,
        )

        callbacks = [
            check
            for check in report["checks"]
            if check["root"]["kind"] == "registered_callback"
        ]
        contracts = report["contracts"]
        self.assertEqual(report["status"], "complete")
        self.assertEqual(len(callbacks), 2)
        self.assertEqual(len(contracts), 2)
        self.assertTrue(all(callback["status"] == "complete" for callback in callbacks))
        self.assertEqual(
            {
                callback["proposal"]["alternatives"]["values"][0]
                ["registration_event"]["unit"]["unit_id"]
                for callback in callbacks
            },
            {"unit:register", "unit:init"},
        )

    def test_missing_evidence_is_incomplete_but_corruption_is_violated(self) -> None:
        missing = construct_entry_state_analysis_v2(
            behavioral_roots=_behavioral_roots(),
            interface_provenance=_interface_provenance(
                slots=[{"address": SLOT, "origins": [_origin(1)], "tainted": False}]
            ),
            units=_units(),
            machine_ir_sha256=MACHINE_IR_SHA256,
            launch_invariants=_launch_invariants(),
            iat_facts=[],
        )
        corrupted_roots = _behavioral_roots()
        corrupted_roots["contract_sha256"] = "0" * 64
        corrupted = construct_entry_state_analysis_v2(
            behavioral_roots=corrupted_roots,
            interface_provenance=_interface_provenance(),
            units=_units(),
            machine_ir_sha256=MACHINE_IR_SHA256,
            callback_entry_state=_callback_entry_artifact(),
            launch_invariants=_launch_invariants(),
            iat_facts=[],
        )

        self.assertEqual(missing["status"], "incomplete")
        self.assertEqual(corrupted["status"], "violated")

    def test_unreferenced_slot_evidence_is_diagnostic_only(self) -> None:
        report = construct_entry_state_analysis_v2(
            behavioral_roots=_behavioral_roots(),
            interface_provenance=_interface_provenance(),
            units=_units(),
            machine_ir_sha256=MACHINE_IR_SHA256,
            global_slot_evidence=[_slot_evidence([_origin(1)])],
            callback_entry_state=_callback_entry_artifact(),
            launch_invariants=_launch_invariants(),
            iat_facts=[],
        )

        self.assertEqual(report["status"], "complete")
        self.assertEqual(report["global_slot_checks"], [])
        self.assertEqual(report["global_slot_invariants"], [])


if __name__ == "__main__":
    unittest.main()
