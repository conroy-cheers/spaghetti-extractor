from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.machine_import_profiles import (
    MachineImportProfileError,
    load_machine_import_profile_set,
)
from spaghetti_extractor.stage_b_state_machine import (
    _annotate_machine_import_arguments,
    _machine_import_contracts,
)


def _write(path: Path, payload: dict[str, object]) -> Path:
    path.write_text(json.dumps(payload, sort_keys=True), encoding="utf-8")
    return path


def _contract(
    symbol: str,
    *,
    abi: str = "pe32-cdecl-v1",
    words: int = 1,
    override: bool = False,
) -> dict[str, object]:
    return {
        "id": symbol,
        "import": {"dll": "fixture.dll", "symbol": symbol},
        "abi_template": abi,
        "argument_words": words,
        "memory_effect": "none",
        "memory_footprints": [],
        "world_effect": "none",
        **({"override": True} if override else {}),
    }


def _digest_payload(payload: dict[str, object], field: str) -> str:
    body = {key: value for key, value in payload.items() if key != field}
    encoded = json.dumps(
        body, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _scheduled_call_row() -> dict[str, object]:
    event = {
        "kind": "external_call",
        "dll": "fixture.dll",
        "symbol": "Call",
        "ordinal": None,
        "instruction_rva": 0x1010,
        "return_rva": 0x1015,
        "arguments": [],
        "stack_inputs": [],
    }
    call_effect = {
        key: value for key, value in event.items() if key != "instruction_rva"
    }
    record: dict[str, object] = {
        "index": 0,
        "rva_start": 0x1010,
        "rva_end": 0x1015,
        "effects": {
            "call_effects": [call_effect],
            "ordered_events": [{"family": "external", **event}],
        },
    }
    record["record_sha256"] = _digest_payload(record, "record_sha256")
    schedule: dict[str, object] = {"records": [record]}
    schedule["schedule_sha256"] = _digest_payload(schedule, "schedule_sha256")
    return {
        "outcome": {"kind": "fallthrough", "target_rva": 0x1015},
        "external_events": [event],
        "ordered_events": [{"family": "external", **event}],
        "instruction_effect_schedule": schedule,
    }


class MachineImportProfileTests(unittest.TestCase):
    def test_includes_are_loaded_first_and_explicit_override_wins(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _write(root / "base.json", {
                "format": "stage-a-external-environment-profile-v1",
                "id": "base",
                "machine_import_call_contracts": [_contract("Call", words=1)],
            })
            top = _write(root / "top.json", {
                "format": "stage-a-static-machine-import-profile-v1",
                "id": "top",
                "includes": ["base.json"],
                "machine_import_signatures": [{
                    **_contract("Call", words=3, override=True),
                    "arity": {"kind": "fixed", "words": 3},
                }],
            })

            profile_set = load_machine_import_profile_set([top])
            self.assertEqual(
                [profile.profile_id for profile in profile_set.profiles],
                ["base", "top"],
            )
            self.assertEqual(len(profile_set.contracts), 1)
            self.assertEqual(profile_set.contracts[0].profile_id, "top")
            self.assertEqual(profile_set.contracts[0].argument_words, 3)

    def test_duplicate_identity_without_override_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _write(root / "base.json", {
                "format": "stage-a-external-environment-profile-v1",
                "id": "base",
                "machine_import_call_contracts": [_contract("Call")],
            })
            top = _write(root / "top.json", {
                "format": "stage-a-static-machine-import-profile-v1",
                "id": "top",
                "includes": ["base.json"],
                "machine_import_signatures": [_contract("Call")],
            })
            with self.assertRaisesRegex(
                MachineImportProfileError, "ambiguous machine import"
            ):
                load_machine_import_profile_set([top])

    def test_include_cycle_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            first = _write(root / "first.json", {
                "format": "stage-a-static-machine-import-profile-v1",
                "id": "first",
                "includes": ["second.json"],
                "machine_import_signatures": [],
            })
            _write(root / "second.json", {
                "format": "stage-a-static-machine-import-profile-v1",
                "id": "second",
                "includes": ["first.json"],
                "machine_import_signatures": [],
            })
            with self.assertRaisesRegex(MachineImportProfileError, "include cycle"):
                load_machine_import_profile_set([first])

    def test_variadic_minimum_is_not_materialized_as_exact_arguments(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            profile = _write(Path(temporary) / "profile.json", {
                "format": "stage-a-static-machine-import-profile-v1",
                "id": "variadic",
                "machine_import_signatures": [{
                    "import": {"dll": "fixture.dll", "symbol": "Printf"},
                    "abi_template": "pe32-cdecl-v1",
                    "arity": {"kind": "variadic", "minimum_words": 1},
                    "memory_effect": "none",
                    "memory_footprints": [],
                    "world_effect": "none",
                }],
            })
            selected = load_machine_import_profile_set([profile]).contracts[0]
            self.assertEqual(selected.arity_kind, "variadic")
            self.assertIsNone(selected.argument_words)
            self.assertEqual(selected.contract["minimum_argument_words"], 1)
            self.assertNotIn(
                selected.identity.state_machine_key(),
                _machine_import_contracts(profile),
            )

    def test_stdcall_callback_thunk_uses_return_address_offset(self) -> None:
        contract = _contract(
            "RegisterCallback", abi="pe32-stdcall-v1", words=1
        )
        contract.update({
            "world_effect": "callbackRegistration",
            "world_effect_argument": 0,
            "callback_lifetime": "until_replaced_or_process_exit",
            "callback_abi": {
                "kind": "generic_callback",
                "argument_words": 1,
                "stack_cleanup_bytes": 4,
                "nullable": True,
            },
        })
        contracts = {
            ("fixture.dll", "RegisterCallback", None): contract,
        }
        event = {
            "kind": "external_call",
            "dll": "fixture.dll",
            "symbol": "RegisterCallback",
            "ordinal": None,
            "arguments": [],
            "stack_inputs": [],
        }
        row = {
            "outcome": {"kind": "external_jump"},
            "external_events": [event],
            "ordered_events": [event],
        }
        annotated = _annotate_machine_import_arguments(row, contracts)
        actual = annotated["ordered_events"][0]
        self.assertEqual(actual["abi_contract"]["template"], "pe32-stdcall-v1")
        self.assertEqual(actual["abi_contract"]["argument_base_offset"], 4)
        self.assertEqual(
            actual["abi_contract"]["callback_lifetime"],
            "until_replaced_or_process_exit",
        )
        self.assertEqual(actual["stack_inputs"][0]["offset"], 4)

    def test_selected_profile_evidence_survives_callsite_annotation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            profile = _write(Path(temporary) / "profile.json", {
                "format": "stage-a-external-environment-profile-v1",
                "id": "stateful-api",
                "machine_import_call_contracts": [{
                    **_contract("Update", words=2),
                    "result_register_relations": [
                        {"register": "eax", "relation": "exact"}
                    ],
                    "memory_effect": "argumentRanges",
                    "memory_footprints": [{
                        "access": "write", "base_argument": 0, "offset": 4,
                        "size": {"kind": "fixed", "bytes": 4},
                        "nullable": False,
                    }],
                    "world_effect": "opaqueResources",
                }],
            })
            contracts = _machine_import_contracts(profile)
            event = {
                "kind": "external_call", "dll": "fixture.dll",
                "symbol": "Update", "ordinal": None,
                "arguments": [], "stack_inputs": [],
            }
            row = {
                "outcome": {"kind": "fallthrough", "target_rva": 0x1010},
                "external_events": [event], "ordered_events": [event],
            }

            actual = _annotate_machine_import_arguments(
                row, contracts
            )["external_events"][0]["abi_contract"]

            self.assertEqual(actual["profile_binding"]["profile_id"], "stateful-api")
            self.assertEqual(len(actual["profile_binding"]["profile_sha256"]), 64)
            self.assertEqual(actual["memory_effect"], "argumentRanges")
            self.assertEqual(actual["memory_footprints"][0]["offset"], 4)
            self.assertEqual(
                actual["memory_footprints"][0]["size"],
                {"kind": "fixed", "byte_count": 4},
            )
            self.assertEqual(
                actual["result_register_relations"],
                [{"register": "eax", "relation": "exact"}],
            )
            self.assertEqual(actual["world_effect"], "opaqueResources")

    def test_instruction_schedule_receives_the_same_machine_call_contract(self) -> None:
        contracts = {
            ("fixture.dll", "Call", None): _contract("Call", words=3),
        }

        annotated = _annotate_machine_import_arguments(
            _scheduled_call_row(), contracts
        )

        schedule = annotated["instruction_effect_schedule"]
        record = schedule["records"][0]
        effects = record["effects"]
        ordered = effects["ordered_events"][0]
        call_effect = effects["call_effects"][0]
        self.assertEqual(len(ordered["arguments"]), 3)
        self.assertEqual(len(call_effect["arguments"]), 3)
        self.assertEqual(ordered["abi_contract"], call_effect["abi_contract"])
        self.assertEqual(
            record["record_sha256"], _digest_payload(record, "record_sha256")
        )
        self.assertEqual(
            schedule["schedule_sha256"],
            _digest_payload(schedule, "schedule_sha256"),
        )

    def test_instruction_schedule_call_must_match_aggregate_call(self) -> None:
        row = _scheduled_call_row()
        row["ordered_events"][0]["instruction_rva"] = 0x1020
        contracts = {
            ("fixture.dll", "Call", None): _contract("Call", words=3),
        }

        with self.assertRaisesRegex(
            Exception, "schedule and aggregate machine-import calls differ"
        ):
            _annotate_machine_import_arguments(row, contracts)

    def test_instruction_schedule_digest_drift_fails_closed(self) -> None:
        row = _scheduled_call_row()
        row["instruction_effect_schedule"]["records"][0]["rva_end"] = 0x1016
        contracts = {
            ("fixture.dll", "Call", None): _contract("Call", words=3),
        }

        with self.assertRaisesRegex(Exception, "schedule digest"):
            _annotate_machine_import_arguments(row, contracts)


if __name__ == "__main__":
    unittest.main()
