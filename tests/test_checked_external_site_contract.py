from __future__ import annotations

import copy
import json
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.checked_external_site_contract import (
    CheckedExternalSiteContractError,
    ExternalSiteIdentity,
    checked_external_site_contract_from_event,
    parse_checked_external_site_contract,
    require_profile_match,
)
from spaghetti_extractor.machine_import_profiles import (
    load_machine_import_profile_set,
)
from spaghetti_extractor.stage_b_native_runtime import (
    StageBNativeRuntimeError,
    _external_range_rules,
)
from spaghetti_extractor.util import sha256_file


def _expression(index: int) -> dict[str, object]:
    return {"op": "input", "name": f"argument-{index}", "width": 32}


def _profile_entry() -> dict[str, object]:
    return {
        "id": "fixture.dll!Exact",
        "import": {"dll": "fixture.dll", "symbol": "Exact"},
        "abi_template": "pe32-stdcall-v1",
        "arity": {"kind": "fixed", "words": 2},
        "disposition": "returns",
        "result_register_relations": [
            {"register": "eax", "relation": "exact"}
        ],
        "memory_effect": "none",
        "memory_footprints": [],
        "world_effect": "none",
        "callback_effect": "none",
        "out_pointer_relations": [],
        "out_interface_relations": [],
    }


def _write_profile(path: Path, entry: dict[str, object] | None = None) -> dict[str, object]:
    payload: dict[str, object] = {
        "format": "stage-a-static-machine-import-profile-v1",
        "id": "fixture-profile",
        "machine_import_signatures": [entry or _profile_entry()],
    }
    path.write_text(json.dumps(payload, sort_keys=True), encoding="utf-8")
    return payload


def _event(*, profile_sha256: str) -> dict[str, object]:
    arguments = [_expression(0), _expression(1)]
    return {
        "kind": "external_call",
        "dll": "fixture.dll",
        "symbol": "Exact",
        "ordinal": None,
        "arguments": arguments,
        "stack_inputs": [
            {"offset": index * 4, "width": 4, "value": value}
            for index, value in enumerate(arguments)
        ],
        "abi_contract": {
            "template": "pe32-stdcall-v1",
            "argument_words": 2,
            "argument_base_offset": 0,
            "contract_id": "fixture.dll!Exact",
            "profile_binding": {
                "profile_id": "fixture-profile",
                "profile_sha256": profile_sha256,
                "entry_key": "machine_import_signatures",
                "entry_index": 0,
            },
            "disposition": "returns",
            "result_register_relations": [
                {"register": "eax", "relation": "exact"}
            ],
            "memory_effect": "none",
            "memory_footprints": [],
            "world_effect": "none",
            "callback_effect": "none",
            "out_pointer_relations": [],
            "out_interface_relations": [],
        },
    }


def _callback_evidence(
    *,
    source: dict[str, object],
    abi: dict[str, object],
    lifetime: object,
    target_rvas: list[int] | None = None,
    behavior: object = None,
    activation: object = None,
    instance: object = None,
) -> dict[str, object]:
    return {
        "format": "stage-a-callback-registration-provenance-v1",
        "record_kind": "callback_registration",
        "status": "complete",
        "failure": None,
        "callback_source": copy.deepcopy(source),
        "callback_abi": copy.deepcopy(abi),
        "callback_lifetime": copy.deepcopy(lifetime),
        "callback_behavior": copy.deepcopy(behavior),
        "callback_activation": copy.deepcopy(activation),
        "callback_instance": copy.deepcopy(instance),
        "target_rvas": [0x1234] if target_rvas is None else target_rvas,
    }


def _checked(profile: Path):
    return checked_external_site_contract_from_event(
        event=_event(profile_sha256=sha256_file(profile)),
        identity=ExternalSiteIdentity.imported(
            {"dll": "fixture.dll", "symbol": "Exact", "ordinal": None},
            context="fixture",
        ),
        transfer_kind="call",
        disposition="returns_here",
        context="fixture external site",
    )


class CheckedExternalSiteContractTests(unittest.TestCase):
    def test_resolved_contract_derives_exact_stack_arguments(self) -> None:
        contract = _profile_entry()
        contract["profile_binding"] = {
            "profile_id": "fixture-profile",
            "profile_sha256": "0" * 64,
            "entry_key": "machine_import_signatures",
            "entry_index": 0,
        }
        event = {
            "kind": "indirect_call",
            "arguments": [],
            "register_inputs": {
                "esp": {"op": "reg", "name": "esp", "width": 32}
            },
        }

        checked = checked_external_site_contract_from_event(
            event=event,
            identity=ExternalSiteIdentity.imported(
                {"dll": "fixture.dll", "symbol": "Exact"},
                context="fixture",
            ),
            transfer_kind="call",
            disposition="returns_here",
            resolved_machine_contract=contract,
            context="resolved fixture",
        )

        self.assertEqual(checked.argument_words, 2)
        self.assertEqual(checked.stack_arguments[0].offset, 0)
        self.assertEqual(checked.stack_arguments[1].offset, 4)
        self.assertEqual(
            checked.arguments[1],
            {
                "op": "load",
                "width": 4,
                "address": {
                    "op": "add32",
                    "args": [
                        {"op": "reg", "name": "esp", "width": 32},
                        {"op": "const", "value": 4, "width": 32},
                    ],
                },
            },
        )

    def test_nonempty_wrong_sized_argument_inventory_remains_invalid(self) -> None:
        contract = _profile_entry()
        contract["profile_binding"] = {
            "profile_id": "fixture-profile",
            "profile_sha256": "0" * 64,
            "entry_key": "machine_import_signatures",
            "entry_index": 0,
        }
        event = {
            "kind": "indirect_call",
            "arguments": [{"op": "const", "value": 1, "width": 32}],
            "register_inputs": {
                "esp": {"op": "reg", "name": "esp", "width": 32}
            },
        }

        with self.assertRaisesRegex(
            CheckedExternalSiteContractError, "argument inventory is not exact"
        ):
            checked_external_site_contract_from_event(
                event=event,
                identity=ExternalSiteIdentity.imported(
                    {"dll": "fixture.dll", "symbol": "Exact"},
                    context="fixture",
                ),
                transfer_kind="call",
                disposition="returns_here",
                resolved_machine_contract=contract,
                context="resolved fixture",
            )

    def test_missing_event_and_resolved_contract_fails_closed(self) -> None:
        with self.assertRaisesRegex(
            CheckedExternalSiteContractError, "no machine ABI contract"
        ):
            checked_external_site_contract_from_event(
                event={"kind": "indirect_call"},
                identity=ExternalSiteIdentity.imported(
                    {"dll": "fixture.dll", "symbol": "Exact"},
                    context="fixture",
                ),
                transfer_kind="call",
                disposition="returns_here",
                context="missing fixture",
            )

    def test_round_trips_and_matches_the_exact_selected_profile(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            profile = Path(temporary) / "profile.json"
            _write_profile(profile)
            checked = _checked(profile)
            self.assertEqual(
                parse_checked_external_site_contract(checked.payload()), checked
            )
            selected = load_machine_import_profile_set([profile]).contracts[0]
            require_profile_match(
                checked,
                profile_contract=selected.contract,
                profile_id=selected.profile_id,
                profile_sha256=selected.profile_sha256,
                entry_key=selected.entry_key,
                entry_index=selected.entry_index,
                context="fixture",
            )

    def test_rejects_variadic_and_inexact_stack_inventories(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            profile = Path(temporary) / "profile.json"
            _write_profile(profile)
            event = _event(profile_sha256=sha256_file(profile))
            event["abi_contract"]["arity"] = {
                "kind": "variadic", "minimum_words": 2
            }
            with self.assertRaisesRegex(
                CheckedExternalSiteContractError, "variadic"
            ):
                checked_external_site_contract_from_event(
                    event=event,
                    identity=ExternalSiteIdentity.imported(
                        {"dll": "fixture.dll", "symbol": "Exact"},
                        context="fixture",
                    ),
                    transfer_kind="call",
                    disposition="returns_here",
                    context="fixture",
                )

            checked = _checked(profile)
            malformed = checked.payload()
            malformed["stack_arguments"][1]["offset"] = 12
            with self.assertRaisesRegex(
                CheckedExternalSiteContractError, "stack argument 1"
            ):
                parse_checked_external_site_contract(malformed, context="fixture")

    def test_unrelated_stack_memory_inputs_do_not_change_abi_arguments(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            profile = Path(temporary) / "profile.json"
            _write_profile(profile)
            event = _event(profile_sha256=sha256_file(profile))
            event["stack_inputs"] = [{
                "offset": 44,
                "width": 4,
                "value": _expression(11),
            }]

            checked = checked_external_site_contract_from_event(
                event=event,
                identity=ExternalSiteIdentity.imported(
                    {"dll": "fixture.dll", "symbol": "Exact"},
                    context="fixture",
                ),
                transfer_kind="call",
                disposition="returns_here",
                context="fixture",
            )

            self.assertEqual(
                [item.offset for item in checked.stack_arguments], [0, 4]
            )
            self.assertEqual(
                [item.value for item in checked.stack_arguments], event["arguments"]
            )

    def test_profile_effect_disagreement_is_not_silently_accepted(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            profile = Path(temporary) / "profile.json"
            _write_profile(profile)
            checked = _checked(profile)
            selected = load_machine_import_profile_set([profile]).contracts[0]
            changed = dict(selected.contract)
            changed["world_effect"] = "opaqueResources"
            with self.assertRaisesRegex(
                CheckedExternalSiteContractError, "world_effect"
            ):
                require_profile_match(
                    checked,
                    profile_contract=changed,
                    profile_id=selected.profile_id,
                    profile_sha256=selected.profile_sha256,
                    entry_key=selected.entry_key,
                    entry_index=selected.entry_index,
                    context="fixture",
                )

    def test_interface_callback_requires_complete_protocol_and_finite_targets(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            profile = Path(temporary) / "interface.json"
            _write_profile(profile)
            event = _event(profile_sha256=sha256_file(profile))
            event["abi_contract"]["callback_effect"] = "explicit"
            event["abi_contract"].update({
                "callback_source": {"kind": "argument_word", "argument": 0},
                "callback_abi": {
                    "kind": "generic_callback",
                    "argument_words": 1,
                    "stack_cleanup_bytes": 4,
                    "nullable": False,
                },
                "callback_lifetime": "during_native_call",
            })
            target = {
                "external_protocol": {
                    "kind": "pe32-interface-method",
                    "profile_id": "interfaces",
                    "profile_sha256": "1" * 64,
                    "interface_id": "IThing",
                    "method": "Invoke",
                },
                "abi": {"template": "pe32-stdcall-v1"},
                "argument_words": 2,
                "callback_effect": "explicit",
                "callback_source": {"kind": "argument_word", "argument": 0},
                "callback_abi": {
                    "kind": "generic_callback",
                    "argument_words": 1,
                    "stack_cleanup_bytes": 4,
                    "nullable": False,
                },
                "callback_lifetime": "during_native_call",
                "callback_contract_status": "complete",
                "callback_contract_blockers": [],
            }
            checked = checked_external_site_contract_from_event(
                event=event,
                identity=ExternalSiteIdentity.interface(
                    target["external_protocol"], context="fixture interface"
                ),
                transfer_kind="call",
                disposition="returns_here",
                protocol_target=target,
                callback_evidence=_callback_evidence(
                    source=target["callback_source"],
                    abi=target["callback_abi"],
                    lifetime=target["callback_lifetime"],
                ),
                context="fixture interface",
            )
            self.assertEqual(checked.callback_effect, "explicit")
            self.assertEqual(checked.callback_adapter.target_rvas, (0x1234,))

            with self.assertRaisesRegex(
                CheckedExternalSiteContractError, "complete callback provenance"
            ):
                checked_external_site_contract_from_event(
                    event=event,
                    identity=ExternalSiteIdentity.interface(
                        target["external_protocol"], context="fixture interface"
                    ),
                    transfer_kind="call",
                    disposition="returns_here",
                    protocol_target=target,
                    context="fixture interface",
                )

            target["callback_contract_status"] = "incomplete"
            target["callback_contract_blockers"] = ["lifetime_unknown"]
            with self.assertRaisesRegex(
                CheckedExternalSiteContractError, "contract is incomplete"
            ):
                checked_external_site_contract_from_event(
                    event=event,
                    identity=ExternalSiteIdentity.interface(
                        target["external_protocol"], context="fixture interface"
                    ),
                    transfer_kind="call",
                    disposition="returns_here",
                    protocol_target=target,
                    callback_evidence=_callback_evidence(
                        source=target["callback_source"],
                        abi=target["callback_abi"],
                        lifetime=target["callback_lifetime"],
                    ),
                    context="fixture interface",
                )

    def test_callback_site_requires_finite_adapter_targets(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            profile = Path(temporary) / "profile.json"
            _write_profile(profile)
            event = _event(profile_sha256=sha256_file(profile))
            event["abi_contract"].update({
                "callback_effect": "explicit",
                "world_effect": "callbackRegistration",
                "callback_source": {"kind": "argument_word", "argument": 0},
                "callback_abi": {
                    "kind": "generic_callback",
                    "argument_words": 1,
                    "stack_cleanup_bytes": 4,
                    "nullable": False,
                },
                "callback_lifetime": "during_native_call",
            })
            with self.assertRaisesRegex(
                CheckedExternalSiteContractError, "nonempty finite target"
            ):
                checked_external_site_contract_from_event(
                    event=event,
                    identity=ExternalSiteIdentity.imported(
                        {"dll": "fixture.dll", "symbol": "Exact"},
                        context="fixture",
                    ),
                    transfer_kind="call",
                    disposition="returns_here",
                    callback_evidence=_callback_evidence(
                        source=event["abi_contract"]["callback_source"],
                        abi=event["abi_contract"]["callback_abi"],
                        lifetime=event["abi_contract"]["callback_lifetime"],
                        target_rvas=[],
                    ),
                    context="fixture callback",
                )

    def test_nested_callback_adapter_binds_activation_resource_and_instance(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            profile = Path(temporary) / "profile.json"
            _write_profile(profile)
            event = _event(profile_sha256=sha256_file(profile))
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
                "message_values": [1],
                "resource_argument": 1,
                "instance_binding": {
                    "callback_argument": 2,
                    "registration_argument": 0,
                },
                "payload_arguments": [3],
            }
            source = {"kind": "argument_word", "argument": 0}
            abi = {
                "kind": "generic_callback",
                "argument_words": 4,
                "stack_cleanup_bytes": 16,
                "nullable": False,
            }
            event["abi_contract"].update({
                "callback_effect": "explicit",
                "world_effect": "callbackRegistration",
                "callback_source": source,
                "callback_abi": abi,
                "callback_lifetime": "until_release",
                "callback_behavior": behavior,
            })
            activation = {
                "kind": "masked_argument_equals",
                "argument_index": 1,
                "mask": 0xF0,
                "expected_value": 0x20,
                "origins": [{"kind": "exact", "value": 0x20}],
                "exact_value": 0x20,
                "masked_value": 0x20,
                "status": "complete",
                "failure": None,
            }
            instance = {
                "kind": "registration_argument_origins_v1",
                "registration_argument": 0,
                "callback_argument": 2,
                "origins": [{"kind": "exact", "value": 0x4444}],
            }
            checked = checked_external_site_contract_from_event(
                event=event,
                identity=ExternalSiteIdentity.imported(
                    {"dll": "fixture.dll", "symbol": "Exact"}, context="fixture"
                ),
                transfer_kind="call",
                disposition="returns_here",
                callback_evidence=_callback_evidence(
                    source=source,
                    abi=abi,
                    lifetime="until_release",
                    behavior=behavior,
                    activation=activation,
                    instance=instance,
                ),
                context="fixture nested callback",
            )
            adapter = checked.callback_adapter
            self.assertIsNotNone(adapter)
            assert adapter is not None
            self.assertEqual(adapter.activation, activation)
            self.assertEqual(adapter.resource_binding["callback_argument"], 1)
            self.assertEqual(adapter.instance_binding["registration_origins"], instance["origins"])

            for field in ("callback_activation", "callback_instance"):
                with self.subTest(missing=field):
                    evidence = _callback_evidence(
                        source=source,
                        abi=abi,
                        lifetime="until_release",
                        behavior=behavior,
                        activation=activation,
                        instance=instance,
                    )
                    evidence[field] = None
                    with self.assertRaises(CheckedExternalSiteContractError):
                        checked_external_site_contract_from_event(
                            event=event,
                            identity=ExternalSiteIdentity.imported(
                                {"dll": "fixture.dll", "symbol": "Exact"},
                                context="fixture",
                            ),
                            transfer_kind="call",
                            disposition="returns_here",
                            callback_evidence=evidence,
                            context="fixture nested callback",
                        )

    def test_runtime_requires_contract_and_exact_profile_join(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            profile = Path(temporary) / "profile.json"
            _write_profile(profile)
            checked = _checked(profile)
            site = {
                "instruction_rva": 0x1000,
                "site_kind": "direct_import",
                "disposition": "returns_here",
                "import": {"dll": "fixture.dll", "symbol": "Exact", "ordinal": None},
                "checked_external_contract": checked.payload(),
            }
            native_plan = {
                "implementation_dispatch_receipt": {
                    "reachability": {"status": "complete"}
                },
                "import_bindings": [{
                    "dll": "fixture.dll",
                    "symbol": "Exact",
                    "ordinal": None,
                    "iat_va": 0x401000,
                    "iat_rva": 0x1000,
                }],
                "external_sites": [site],
            }
            self.assertEqual(
                _external_range_rules(
                    native_plan, profile, candidate_mode="static-closed"
                ),
                ((), (0x1000,), ()),
            )

            missing = copy.deepcopy(native_plan)
            del missing["external_sites"][0]["checked_external_contract"]
            missing["external_sites"][0][
                "checked_external_contract_required"
            ] = True
            with self.assertRaisesRegex(
                StageBNativeRuntimeError, "no checked external contract"
            ):
                _external_range_rules(
                    missing, profile, candidate_mode="static-closed"
                )

            deferred = _external_range_rules(
                    {
                        "implementation_dispatch_receipt": {
                            "reachability": {"status": "incomplete"}
                        },
                        "import_bindings": [], "external_sites": [{
                        "instruction_rva": 0x2000,
                        "site_kind": "dynamic_target",
                        "disposition": "returns_here",
                        "import": None,
                        "external_protocol": None,
                    }]},
                    profile,
                    candidate_mode="structural-diagnostic",
                )
            self.assertEqual(deferred[0], ())
            self.assertEqual(deferred[1], ())
            self.assertEqual(
                deferred[2][0]["category"],
                "uncontracted_dynamic_external_target",
            )


if __name__ == "__main__":
    unittest.main()
