from __future__ import annotations

import copy
import hashlib
import json
import unittest
from dataclasses import FrozenInstanceError
from typing import Any

from spaghetti_extractor.behavioral_roots import (
    BEHAVIORAL_ROOTS_FORMAT,
    behavioral_roots_sha256,
)
from spaghetti_extractor.hybrid_authority_v2 import (
    BinaryBinding,
    EventBinding,
    UnitBinding,
)
from spaghetti_extractor.entry_state_analysis_v2 import (
    construct_entry_state_analysis_v2,
    derive_callback_entry_state_contracts_v2,
)
from spaghetti_extractor.launch_profile_v2 import (
    LAUNCH_ASSUMPTION_TEMPLATE_V1_FORMAT,
    LAUNCH_PROFILE_V2_FORMAT,
    LaunchProfileV2Error,
    LaunchProfileStatus,
    build_launch_profile_v2,
    finalize_launch_profile_v2,
    launch_invariants_for_entry_state,
    parse_launch_assumption_template_v1,
    parse_launch_profile_v2,
    validate_launch_profile_v2,
)


PE_SHA = "a" * 64
OTHER_PE_SHA = "b" * 64
MACHINE_IR_SHA = "c" * 64
IMAGE_BASE = 0x400000
SIZE_OF_IMAGE = 0xA000


def _digest(label: str) -> str:
    return hashlib.sha256(label.encode("ascii")).hexdigest()


def _behavioral_roots() -> dict[str, object]:
    roots: list[dict[str, object]] = [
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
            "sha256": PE_SHA,
            "file_size": 0x9000,
            "machine": "i386",
            "bitness": 32,
            "image_base": IMAGE_BASE,
            "size_of_image": SIZE_OF_IMAGE,
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


def _assumptions() -> dict[str, dict[str, object]]:
    return {
        "initial_stack": {
            "model": "pe32-loader-stack-v1",
            "alignment": 4,
            "return_target": "process_exit",
        },
        "argv": {
            "model": "pe32-command-line-argv-v1",
            "encoding": "active-code-page",
        },
        "environment": {
            "model": "pe32-environment-block-v1",
            "encoding": "active-code-page",
        },
        "fs": {
            "model": "pe32-tib-v1",
            "selector": "loader-selected",
        },
        "iat": {
            "model": "pe32-loader-bound-iat-v1",
            "imports": "exact-pe-import-inventory",
        },
        "relocations": {
            "model": "pe32-base-relocations-v1",
            "preferred_image_base": IMAGE_BASE,
        },
    }


def _feature_inventory() -> dict[str, list[dict[str, object]]]:
    return {
        "threads": [],
        "unmodelled_seh": [],
        "direct_syscalls": [],
        "executable_writes": [],
        "unknown_async_callbacks": [],
    }


def _registration_event(*, pe_sha256: str = PE_SHA) -> EventBinding:
    binary = BinaryBinding(
        pe_sha256=pe_sha256,
        machine_ir_sha256=MACHINE_IR_SHA,
    )
    unit = UnitBinding(
        binary=binary,
        unit_id="unit:callback-registration",
        rva_start=0x1800,
        rva_end=0x1820,
        unit_sha256=_digest("registration-unit"),
        instruction_bytes_sha256=_digest("registration-bytes"),
    )
    return EventBinding(
        unit=unit,
        event_index=2,
        event_kind="external_call",
        instruction_rva=0x1808,
        event_sha256=_digest("registration-event"),
    )


def _callback(*, pe_sha256: str = PE_SHA) -> dict[str, object]:
    return {
        "rva": 0x1400,
        "registration_event": _registration_event(
            pe_sha256=pe_sha256
        ).to_payload(),
        "entry_contract_content_id": (
            "hybrid-authority-v2:entry_state_contract:" + "d" * 64
        ),
    }


def _callback_entry_state() -> dict[str, object]:
    registration = {
        "format": "stage-a-callback-registration-provenance-v1",
        "record_kind": "callback_registration",
        "proof_authority": False,
        "status": "complete",
        "failure": None,
        "unit_id": "unit:callback-registration",
        "event_index": 2,
        "instruction_rva": 0x1808,
        "import": {"dll": "fixture.dll", "symbol": "Register", "ordinal": None},
        "contract_id": "fixture.dll!Register",
        "profile_binding": {"profile_id": "fixture", "profile_sha256": "e" * 64},
        "callback_source": {"kind": "argument_word", "argument": 0},
        "callback_abi": {
            "kind": "generic_callback",
            "argument_words": 2,
            "stack_cleanup_bytes": 8,
            "nullable": False,
        },
        "callback_lifetime": "until_release",
        "callback_behavior": "registration",
        "global_slot_invariant_ids": [],
        "origins": [{"kind": "exact", "key": [IMAGE_BASE + 0x1400]}],
        "source_locations": [],
        "target_rvas": [0x1400],
        "target_unit_ids": ["unit:callback"],
    }
    units = [
        {
            "id": "unit:callback-registration",
            "source": {
                "original": {"rva_start": 0x1800, "rva_end": 0x1820},
                "contract_sha256": _digest("registration-unit"),
                "instruction_bytes_sha256": _digest("registration-bytes"),
            },
        },
        {
            "id": "unit:callback",
            "source": {
                "original": {"rva_start": 0x1400, "rva_end": 0x1420},
                "contract_sha256": _digest("callback-unit"),
                "instruction_bytes_sha256": _digest("callback-bytes"),
            },
        },
    ]
    return derive_callback_entry_state_contracts_v2(
        pe_sha256=PE_SHA,
        image_base=IMAGE_BASE,
        size_of_image=SIZE_OF_IMAGE,
        interface_provenance={
            "format": "stage-a-external-interface-provenance-v1",
            "status": "complete",
            "proof_authority": False,
            "static_interface_slots": [],
            "rejected_tainted_slots": [],
            "callback_registrations": [registration],
        },
        units=units,
        machine_ir_sha256=MACHINE_IR_SHA,
    )


def _rehash_callback_entry_state(value: dict[str, object]) -> None:
    core = copy.deepcopy(value)
    core.pop("analysis_sha256")
    encoded = json.dumps(
        core, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("ascii")
    value["analysis_sha256"] = hashlib.sha256(encoded).hexdigest()


def _profile(**overrides: object):
    inputs: dict[str, Any] = {
        "pe_sha256": PE_SHA,
        "image_base": IMAGE_BASE,
        "size_of_image": SIZE_OF_IMAGE,
        "behavioral_roots": _behavioral_roots(),
        "assumptions": _assumptions(),
        "callback_entry_state": _callback_entry_state(),
        "feature_inventory": _feature_inventory(),
    }
    inputs.update(overrides)
    if "callback_roots" in overrides:
        callback_roots = inputs.pop("callback_roots")
        inputs.pop("callback_entry_state")
        return build_launch_profile_v2(  # type: ignore[arg-type]
            **inputs,
            callback_roots=callback_roots,
        )
    return finalize_launch_profile_v2(**inputs)  # type: ignore[arg-type]


def _codes(profile) -> set[str]:
    return {issue.code for issue in profile.issues}


class PE32LaunchProfileV2Tests(unittest.TestCase):
    def test_authored_assumption_template_is_strict_and_non_authorizing(self) -> None:
        template = {
            "format": LAUNCH_ASSUMPTION_TEMPLATE_V1_FORMAT,
            "schema_version": 1,
            "assumptions": _assumptions(),
            "feature_inventory": _feature_inventory(),
        }

        parsed = parse_launch_assumption_template_v1(template)

        self.assertEqual(parsed.to_payload(), template)
        self.assertEqual(set(parsed.assumption_map), {
            "initial_stack", "argv", "environment", "fs", "iat", "relocations"
        })
        self.assertNotIn("pe_sha256", parsed.to_payload())
        with self.assertRaises(FrozenInstanceError):
            parsed.assumptions = ()  # type: ignore[misc]

    def test_assumption_template_rejects_missing_or_unknown_fields(self) -> None:
        template = {
            "format": LAUNCH_ASSUMPTION_TEMPLATE_V1_FORMAT,
            "schema_version": 1,
            "assumptions": _assumptions(),
            "feature_inventory": _feature_inventory(),
        }
        missing = copy.deepcopy(template)
        del missing["assumptions"]["initial_stack"]
        with self.assertRaises(LaunchProfileV2Error):
            parse_launch_assumption_template_v1(missing)

        extra = copy.deepcopy(template)
        extra["authority"] = "self_asserted"
        with self.assertRaises(LaunchProfileV2Error):
            parse_launch_assumption_template_v1(extra)

    def test_raw_callback_root_builder_is_diagnostic_only(self) -> None:
        profile = build_launch_profile_v2(
            pe_sha256=PE_SHA,
            image_base=IMAGE_BASE,
            size_of_image=SIZE_OF_IMAGE,
            behavioral_roots=_behavioral_roots(),
            assumptions=_assumptions(),
            callback_roots=[_callback()],
            feature_inventory=_feature_inventory(),
        )

        self.assertEqual(profile.status, LaunchProfileStatus.INCOMPLETE)
        self.assertIn("callback_entry_state_unchecked", _codes(profile))

    def test_callback_contracts_finalize_launch_profile(self) -> None:
        callback_entry = _callback_entry_state()
        profile = finalize_launch_profile_v2(
            pe_sha256=PE_SHA,
            image_base=IMAGE_BASE,
            size_of_image=SIZE_OF_IMAGE,
            behavioral_roots=_behavioral_roots(),
            assumptions=_assumptions(),
            callback_entry_state=callback_entry,
            feature_inventory=_feature_inventory(),
        )

        self.assertEqual(profile.status, LaunchProfileStatus.COMPLETE)
        self.assertEqual(len(profile.callback_roots), 1)
        self.assertEqual(
            profile.callback_roots[0].entry_contract_content_id,
            callback_entry["contracts"][0]["content_id"],  # type: ignore[index]
        )
        validation = validate_launch_profile_v2(
            profile.to_payload(), callback_entry_state=callback_entry
        )
        self.assertEqual(validation.status, LaunchProfileStatus.COMPLETE)

    def test_mismatched_callback_registration_event_is_violated(self) -> None:
        callback_entry = _callback_entry_state()
        callback_entry["callback_roots"][0]["registration_event"][  # type: ignore[index]
            "event_index"
        ] = 3
        _rehash_callback_entry_state(callback_entry)

        profile = finalize_launch_profile_v2(
            pe_sha256=PE_SHA,
            image_base=IMAGE_BASE,
            size_of_image=SIZE_OF_IMAGE,
            behavioral_roots=_behavioral_roots(),
            assumptions=_assumptions(),
            callback_entry_state=callback_entry,
            feature_inventory=_feature_inventory(),
        )

        self.assertEqual(profile.status, LaunchProfileStatus.VIOLATED)
        self.assertIn("callback_entry_state_corrupt", _codes(profile))

    def test_finalized_callbacks_do_not_create_unknown_async_roots(self) -> None:
        profile = finalize_launch_profile_v2(
            pe_sha256=PE_SHA,
            image_base=IMAGE_BASE,
            size_of_image=SIZE_OF_IMAGE,
            behavioral_roots=_behavioral_roots(),
            assumptions=_assumptions(),
            callback_entry_state=_callback_entry_state(),
            feature_inventory=_feature_inventory(),
        )

        self.assertEqual(profile.status, LaunchProfileStatus.COMPLETE)
        self.assertNotIn("unsupported_unknown_async_callbacks", _codes(profile))
        self.assertEqual(
            dict(profile.feature_inventory)["unknown_async_callbacks"], ()
        )

    def test_complete_profile_binds_static_and_event_roots(self) -> None:
        profile = _profile()

        self.assertEqual(profile.format, LAUNCH_PROFILE_V2_FORMAT)
        self.assertEqual(profile.status, LaunchProfileStatus.COMPLETE)
        self.assertTrue(profile.usable)
        self.assertEqual(
            [root.kind for root in profile.static_roots],
            ["pe_entrypoint", "pe_export", "pe_tls_callback"],
        )
        self.assertEqual(len(profile.callback_roots), 1)
        callback = profile.callback_roots[0]
        self.assertEqual(callback.rva, 0x1400)
        self.assertEqual(
            callback.registration_event.unit.binary.pe_sha256, PE_SHA
        )
        self.assertTrue(
            callback.entry_contract_content_id.startswith(
                "hybrid-authority-v2:entry_state_contract:"
            )
        )
        self.assertEqual(parse_launch_profile_v2(profile.to_payload()), profile)

    def test_entry_state_invariants_are_explicit_and_detached(self) -> None:
        profile = _profile()

        invariants = launch_invariants_for_entry_state(profile)
        self.assertEqual(
            set(invariants),
            {
                "pe-entrypoint",
                "pe-export:ordinal:1:name:Exported",
                "pe-tls-callback:index:0",
                "event-callback:rva:5120:source:unit:callback-registration:2",
            },
        )
        entry = invariants["pe-entrypoint"]
        self.assertEqual(len(entry), 6)
        self.assertTrue(all(row["source"] == "explicit" for row in entry))
        self.assertEqual(
            {row["kind"] for row in entry},
            {
                "pe32_initial_stack",
                "pe32_argv",
                "pe32_environment",
                "pe32_fs",
                "pe32_iat",
                "pe32_relocations",
            },
        )
        callback = invariants[
            "event-callback:rva:5120:source:unit:callback-registration:2"
        ][0]
        self.assertEqual(callback["kind"], "pe32_event_callback_entry")
        self.assertEqual(
            callback["value"]["entry_contract_content_id"],
            profile.callback_roots[0].entry_contract_content_id,
        )

        invariants["pe-entrypoint"][0]["value"]["pe_sha256"] = OTHER_PE_SHA
        fresh = launch_invariants_for_entry_state(profile)
        self.assertEqual(fresh["pe-entrypoint"][0]["value"]["pe_sha256"], PE_SHA)

    def test_invariants_close_real_pe_root_entry_state_checks(self) -> None:
        roots = _behavioral_roots()
        raw_roots = roots["roots"]
        assert isinstance(raw_roots, list)
        units = [
            {
                "id": f"unit:{index}",
                "source": {
                    "original": {
                        "rva_start": root["rva"],
                        "rva_end": root["rva"] + 0x20,
                    },
                    "contract_sha256": f"{index + 1}" * 64,
                    "instruction_bytes_sha256": f"{index + 4}" * 64,
                },
            }
            for index, root in enumerate(raw_roots)
        ]
        analysis = construct_entry_state_analysis_v2(
            behavioral_roots=roots,
            interface_provenance={
                "format": "stage-a-external-interface-provenance-v1",
                "status": "complete",
                "proof_authority": False,
                "static_interface_slots": [],
                "rejected_tainted_slots": [],
                "callback_registrations": [],
            },
            units=units,
            machine_ir_sha256=MACHINE_IR_SHA,
            launch_invariants=launch_invariants_for_entry_state(_profile()),
            iat_facts=[],
        )

        self.assertEqual(analysis["status"], "complete")
        self.assertEqual(
            [(row["root"]["kind"], row["status"]) for row in analysis["root_checks"]],
            [
                ("pe_entrypoint", "complete"),
                ("pe_export", "complete"),
                ("pe_tls_callback", "complete"),
            ],
        )

    def test_missing_assumptions_are_incomplete(self) -> None:
        assumptions = _assumptions()
        assumptions.pop("fs")

        profile = _profile(assumptions=assumptions)

        self.assertEqual(profile.status, LaunchProfileStatus.INCOMPLETE)
        self.assertIn("launch_assumption_missing", _codes(profile))
        missing = [issue for issue in profile.issues if issue.code == "launch_assumption_missing"]
        self.assertEqual([issue.subject for issue in missing], ["fs"])

    def test_corrupt_assumption_is_violated(self) -> None:
        assumptions = _assumptions()
        assumptions["iat"] = {}  # Explicit, but not a meaningful assumption object.

        profile = _profile(assumptions=assumptions)

        self.assertEqual(profile.status, LaunchProfileStatus.VIOLATED)
        self.assertIn("launch_assumption_corrupt", _codes(profile))

    def test_missing_callback_inventory_is_incomplete(self) -> None:
        profile = _profile(callback_roots=None)

        self.assertEqual(profile.status, LaunchProfileStatus.INCOMPLETE)
        self.assertIn("callback_root_inventory_missing", _codes(profile))

    def test_callback_event_must_bind_the_same_pe(self) -> None:
        profile = _profile(callback_roots=[_callback(pe_sha256=OTHER_PE_SHA)])

        self.assertEqual(profile.status, LaunchProfileStatus.VIOLATED)
        self.assertIn("callback_root_corrupt", _codes(profile))
        self.assertEqual(profile.callback_roots, ())

    def test_callback_requires_v2_entry_contract_reference(self) -> None:
        callback = _callback()
        callback["entry_contract_content_id"] = "legacy-entry-contract-v1"

        profile = _profile(callback_roots=[callback])

        self.assertEqual(profile.status, LaunchProfileStatus.VIOLATED)
        self.assertIn("callback_root_corrupt", _codes(profile))

    def test_behavioral_roots_must_match_exact_pe_binding(self) -> None:
        roots = _behavioral_roots()
        roots["pe"]["sha256"] = OTHER_PE_SHA  # type: ignore[index]
        body = copy.deepcopy(roots)
        body.pop("contract_sha256")
        roots["contract_sha256"] = behavioral_roots_sha256(body)

        profile = _profile(behavioral_roots=roots)

        self.assertEqual(profile.status, LaunchProfileStatus.VIOLATED)
        self.assertIn("behavioral_roots_corrupt", _codes(profile))
        self.assertEqual(profile.static_roots, ())

    def test_stale_behavioral_root_hash_is_violated(self) -> None:
        roots = _behavioral_roots()
        roots["contract_sha256"] = "0" * 64

        profile = _profile(behavioral_roots=roots)

        self.assertEqual(profile.status, LaunchProfileStatus.VIOLATED)
        self.assertIn("behavioral_roots_corrupt", _codes(profile))

    def test_each_unsupported_platform_feature_is_an_explicit_frontier(self) -> None:
        for feature in _feature_inventory():
            with self.subTest(feature=feature):
                inventory = _feature_inventory()
                inventory[feature] = [{"unit_id": "unit:frontier", "event_index": 4}]

                profile = _profile(feature_inventory=inventory)

                self.assertEqual(profile.status, LaunchProfileStatus.INCOMPLETE)
                issue = next(
                    item for item in profile.issues
                    if item.code == f"unsupported_{feature}"
                )
                self.assertEqual(issue.subject, feature)

    def test_missing_feature_category_is_incomplete(self) -> None:
        inventory = _feature_inventory()
        inventory.pop("direct_syscalls")

        profile = _profile(feature_inventory=inventory)

        self.assertEqual(profile.status, LaunchProfileStatus.INCOMPLETE)
        self.assertTrue(any(
            issue.code == "feature_inventory_missing"
            and issue.subject == "direct_syscalls"
            for issue in profile.issues
        ))

    def test_wrong_expected_binding_is_a_validation_violation(self) -> None:
        profile = _profile()

        check = validate_launch_profile_v2(
            profile.to_payload(), pe_sha256=OTHER_PE_SHA
        )

        self.assertEqual(check.status, LaunchProfileStatus.VIOLATED)
        self.assertFalse(check.usable)
        self.assertIn("exact_pe_binding_mismatch", _codes(check))

    def test_corrupted_content_is_reported_as_violated(self) -> None:
        payload = _profile().to_payload()
        payload["launch_invariants"]["pe-entrypoint"][0]["value"][
            "image_base"
        ] ^= 0x10000

        check = validate_launch_profile_v2(payload)

        self.assertEqual(check.status, LaunchProfileStatus.VIOLATED)
        self.assertIsNone(check.profile)
        self.assertEqual(check.issues[0].code, "launch_profile_corrupt")

    def test_profile_is_immutable_and_deterministic(self) -> None:
        first = _profile()
        second = _profile()

        self.assertEqual(first, second)
        self.assertEqual(first.profile_sha256, second.profile_sha256)
        self.assertEqual(first.content_sha256, second.content_sha256)
        with self.assertRaises(FrozenInstanceError):
            first.profile_sha256 = "0" * 64  # type: ignore[misc]

    def test_validation_rechecks_behavioral_root_identity(self) -> None:
        profile = _profile()
        different = _behavioral_roots()
        different["roots"][1]["rva"] = 0x1180  # type: ignore[index]
        body = copy.deepcopy(different)
        body.pop("contract_sha256")
        different["contract_sha256"] = behavioral_roots_sha256(body)

        check = validate_launch_profile_v2(
            profile.to_payload(), behavioral_roots=different
        )

        self.assertEqual(check.status, LaunchProfileStatus.VIOLATED)
        self.assertIn("behavioral_roots_binding_mismatch", _codes(check))


if __name__ == "__main__":
    unittest.main()
