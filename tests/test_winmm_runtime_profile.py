from __future__ import annotations

import copy
import json
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.callback_contracts import (
    parse_callback_abi,
    parse_callback_source,
    parse_nested_native_callback_behavior,
)
from spaghetti_extractor.machine_import_profiles import (
    NATIVE_DLL_CALLTHROUGH_EFFECT_MODEL,
    NATIVE_DLL_CALLTHROUGH_PREREQUISITES,
    load_machine_import_profile_set,
)
from spaghetti_extractor.stage_b_state_machine import (
    _machine_import_contracts,
)
from spaghetti_extractor.stage_binary import StageAInputError


_REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
_PROFILE = _REPOSITORY_ROOT / "profiles/pe32-winmm-runtime-v1.json"
_ADDED_ARITIES = {
    "midiOutPrepareHeader": 3,
    "midiOutUnprepareHeader": 3,
    "midiOutReset": 1,
    "midiStreamOpen": 6,
    "midiStreamOut": 3,
    "midiStreamProperty": 3,
    "midiStreamRestart": 1,
}
_PINNED_CALLTHROUGH = set(_ADDED_ARITIES) - {"midiStreamOpen"}


def _profile_payload() -> dict[str, object]:
    return json.loads(_PROFILE.read_text(encoding="utf-8"))


def _entry(payload: dict[str, object], symbol: str) -> dict[str, object]:
    entries = payload["machine_import_signatures"]
    assert isinstance(entries, list)
    return next(
        row
        for row in entries
        if isinstance(row, dict)
        and isinstance(row.get("import"), dict)
        and row["import"].get("symbol") == symbol
    )


def _load_mutated(payload: dict[str, object]) -> None:
    with tempfile.TemporaryDirectory() as temporary:
        path = Path(temporary) / "winmm-profile.json"
        path.write_text(json.dumps(payload, sort_keys=True), encoding="utf-8")
        _machine_import_contracts([path])


class WinmmRuntimeProfileTests(unittest.TestCase):
    def test_profile_covers_reviewed_pe32_sdk_imports(self) -> None:
        contracts = {
            str(contract.identity.value): contract
            for contract in load_machine_import_profile_set([_PROFILE]).contracts
        }

        self.assertTrue(set(_ADDED_ARITIES) <= set(contracts))
        for symbol, argument_words in _ADDED_ARITIES.items():
            with self.subTest(symbol=symbol):
                contract = contracts[symbol]
                self.assertEqual(contract.identity.dll, "winmm.dll")
                self.assertEqual(contract.argument_words, argument_words)
                self.assertEqual(
                    contract.contract["abi_template"], "pe32-stdcall-v1"
                )
                self.assertEqual(contract.contract["disposition"], "returns")
                self.assertEqual(
                    contract.contract["result_register_relations"],
                    [{"register": "eax", "relation": "exact"}],
                )

    def test_pointer_bearing_operations_require_exact_native_callthrough(self) -> None:
        contracts = {
            str(contract.identity.value): contract.contract
            for contract in load_machine_import_profile_set([_PROFILE]).contracts
        }
        expected_effect = {
            "kind": NATIVE_DLL_CALLTHROUGH_EFFECT_MODEL,
            "prerequisites": {
                prerequisite: True
                for prerequisite in NATIVE_DLL_CALLTHROUGH_PREREQUISITES
            },
        }

        for symbol in sorted(_PINNED_CALLTHROUGH):
            with self.subTest(symbol=symbol):
                row = contracts[symbol]
                self.assertEqual(row["effect_model"], expected_effect)
                self.assertEqual(row["memory_effect"], "nativeCallthrough")
                self.assertEqual(row["memory_footprints"], [])
                self.assertEqual(row["world_effect"], "nativeCallthrough")
                self.assertEqual(row["callback_effect"], "none")

    def test_midi_stream_open_models_the_pe32_sdk_callback_protocol(self) -> None:
        row = _entry(_profile_payload(), "midiStreamOpen")
        source = parse_callback_source(
            row,
            argument_words=6,
            context="midiStreamOpen",
        )
        abi = parse_callback_abi(row, context="midiStreamOpen")
        behavior = parse_nested_native_callback_behavior(
            row,
            registration_argument_words=6,
            context="midiStreamOpen",
        )

        self.assertEqual(source.argument_index, 3)
        self.assertEqual(abi.argument_words, 5)
        self.assertEqual(abi.stack_cleanup_bytes, 20)
        self.assertFalse(abi.nullable)
        self.assertIsNotNone(behavior)
        assert behavior is not None
        self.assertEqual(behavior.activation.argument_index, 5)
        self.assertEqual(behavior.activation.mask, 0x00070000)
        self.assertEqual(behavior.activation.value, 0x00030000)
        self.assertEqual(behavior.message_argument, 1)
        self.assertEqual(behavior.message_values, (0x3C7, 0x3C8, 0x3C9, 0x3CA))
        self.assertEqual(behavior.resource_argument, 0)
        self.assertEqual(behavior.instance_callback_argument, 2)
        self.assertEqual(behavior.instance_registration_argument, 4)
        self.assertEqual(behavior.payload_arguments, (3, 4))
        self.assertEqual(
            row["callback_lifetime"],
            "until_midi_stream_closed_or_process_exit",
        )

        contracts = _machine_import_contracts([_PROFILE])
        loaded = contracts[("winmm.dll", "midiStreamOpen", None)]
        self.assertEqual(loaded["callback_behavior"], row["callback_behavior"])

    def test_midi_stream_open_callback_protocol_fails_closed(self) -> None:
        mutations = {
            "wrong provider": ("provider_relation", "same_named_dll"),
            "wrong delivery": ("delivery", "eventually"),
            "bad mode": (
                "activation",
                {
                    "kind": "masked_argument_equals",
                    "argument": 5,
                    "mask": 0x00070000,
                    "value": 0x80000000,
                },
            ),
            "duplicate message": (
                "message_values",
                [0x3C7, 0x3C7],
            ),
            "missing callback word": ("payload_arguments", [3]),
        }
        for label, (field, value) in mutations.items():
            with self.subTest(mutation=label):
                payload = _profile_payload()
                row = _entry(payload, "midiStreamOpen")
                behavior = copy.deepcopy(row["callback_behavior"])
                assert isinstance(behavior, dict)
                behavior[field] = value
                row["callback_behavior"] = behavior
                with self.assertRaises(StageAInputError):
                    _load_mutated(payload)


if __name__ == "__main__":
    unittest.main()
