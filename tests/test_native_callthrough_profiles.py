from __future__ import annotations

import copy
import json
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.machine_import_profiles import (
    NATIVE_DLL_CALLTHROUGH_EFFECT_MODEL,
    NATIVE_DLL_CALLTHROUGH_PREREQUISITES,
    MachineImportIdentity,
    MachineImportProfileError,
    load_machine_import_profile_set,
)


_REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
_PROFILE = (
    _REPOSITORY_ROOT / "profiles/pe32-native-callthrough-runtime-v1.json"
)
_EXPECTED_ARITIES = {
    ("kernel32.dll", "CreateFileA"): 7,
    ("kernel32.dll", "CreateFileMappingA"): 6,
    ("kernel32.dll", "CreateSemaphoreA"): 4,
    ("kernel32.dll", "FlushFileBuffers"): 1,
    ("kernel32.dll", "GetVersionExA"): 1,
    ("kernel32.dll", "GlobalAlloc"): 2,
    ("kernel32.dll", "GlobalHandle"): 1,
    ("kernel32.dll", "GlobalLock"): 1,
    ("kernel32.dll", "LocalAlloc"): 2,
    ("kernel32.dll", "MapViewOfFile"): 5,
    ("user32.dll", "CreateWindowExA"): 12,
    ("user32.dll", "DefWindowProcA"): 4,
    ("user32.dll", "DestroyWindow"): 1,
    ("user32.dll", "MessageBoxA"): 4,
    ("user32.dll", "PostMessageA"): 4,
    ("user32.dll", "ReleaseCapture"): 0,
    ("user32.dll", "SetCapture"): 1,
    ("user32.dll", "SetFocus"): 1,
    ("user32.dll", "ShowWindow"): 2,
    ("user32.dll", "UpdateWindow"): 1,
}
_EXCLUDED_MIDI_CALLBACK_APIS = {
    "midiOutPrepareHeader",
    "midiOutReset",
    "midiOutUnprepareHeader",
    "midiStreamOpen",
    "midiStreamOut",
    "midiStreamProperty",
    "midiStreamRestart",
}


def _profile_payload(entry: dict[str, object]) -> dict[str, object]:
    return {
        "format": "stage-a-static-machine-import-profile-v1",
        "id": "fixture-native-callthrough-v1",
        "machine_import_signatures": [entry],
    }


def _callthrough_entry() -> dict[str, object]:
    return {
        "id": "fixture.dll!Call",
        "import": {"dll": "fixture.dll", "symbol": "Call"},
        "abi_template": "pe32-stdcall-v1",
        "arity": {"kind": "fixed", "words": 1},
        "disposition": "returns",
        "result_register_relations": [
            {"register": "eax", "relation": "exact"}
        ],
        "effect_model": {
            "kind": NATIVE_DLL_CALLTHROUGH_EFFECT_MODEL,
            "prerequisites": {
                prerequisite: True
                for prerequisite in NATIVE_DLL_CALLTHROUGH_PREREQUISITES
            },
        },
        "memory_effect": "nativeCallthrough",
        "memory_footprints": [],
        "world_effect": "nativeCallthrough",
        "callback_effect": "none",
    }


def _read_only_caller_memory_frame() -> dict[str, object]:
    return {
        "status": "complete",
        "model": "pe32-declared-pointer-arguments-v1",
        "arguments": [{
            "argument_index": 0,
            "role": "caller_memory",
            "access": "read",
            "extent": "enclosing_object",
            "retention": "during_call",
        }],
        "assumptions": [
            "caller memory is accessed only through declared pointer arguments",
            "non-callback pointer arguments are retained only during the call",
            "opaque interface resources are disjoint from caller image and stack memory",
        ],
    }


def _load_fixture(entry: dict[str, object]) -> None:
    with tempfile.TemporaryDirectory() as temporary:
        path = Path(temporary) / "profile.json"
        path.write_text(
            json.dumps(_profile_payload(entry), sort_keys=True),
            encoding="utf-8",
        )
        load_machine_import_profile_set([path])


class NativeCallthroughProfileTests(unittest.TestCase):
    def test_profile_covers_reviewed_non_callback_win32_imports(self) -> None:
        selected = load_machine_import_profile_set([_PROFILE]).contracts
        actual = {
            (contract.identity.dll, str(contract.identity.value)): contract
            for contract in selected
        }

        self.assertEqual(set(actual), set(_EXPECTED_ARITIES))
        for identity, argument_words in _EXPECTED_ARITIES.items():
            with self.subTest(import_identity=identity):
                contract = actual[identity]
                row = contract.contract
                self.assertEqual(contract.arity_kind, "fixed")
                self.assertEqual(contract.argument_words, argument_words)
                self.assertEqual(row["abi_template"], "pe32-stdcall-v1")
                self.assertEqual(row["disposition"], "returns")
                self.assertIsInstance(row["result_register_relations"], list)
                self.assertEqual(
                    row["effect_model"],
                    {
                        "kind": NATIVE_DLL_CALLTHROUGH_EFFECT_MODEL,
                        "prerequisites": {
                            prerequisite: True
                            for prerequisite
                            in NATIVE_DLL_CALLTHROUGH_PREREQUISITES
                        },
                    },
                )
                self.assertEqual(row["memory_effect"], "nativeCallthrough")
                self.assertIsInstance(row["memory_footprints"], list)
                self.assertEqual(row["world_effect"], "nativeCallthrough")
                self.assertEqual(row["callback_effect"], "none")

    def test_profile_omits_midi_callback_apis(self) -> None:
        selected_symbols = {
            str(contract.identity.value)
            for contract in load_machine_import_profile_set([_PROFILE]).contracts
        }

        self.assertFalse(_EXCLUDED_MIDI_CALLBACK_APIS & selected_symbols)
        self.assertFalse(any(symbol.startswith("midi") for symbol in selected_symbols))

    def test_profile_declares_create_file_caller_memory_reads(self) -> None:
        contracts = load_machine_import_profile_set([_PROFILE]).by_identity()
        selected = contracts[
            MachineImportIdentity("kernel32.dll", "symbol", "CreateFileA")
        ]

        self.assertEqual(
            selected.contract["caller_memory_frame"]["arguments"],
            [
                {
                    "argument_index": 0,
                    "role": "caller_memory",
                    "access": "read",
                    "extent": "enclosing_object",
                    "retention": "during_call",
                },
                {
                    "argument_index": 6,
                    "role": "caller_memory",
                    "access": "read",
                    "extent": "enclosing_object",
                    "retention": "during_call",
                },
            ],
        )

    def test_loader_accepts_checked_native_caller_memory_frame(self) -> None:
        entry = _callthrough_entry()
        entry["caller_memory_frame"] = _read_only_caller_memory_frame()

        _load_fixture(entry)

    def test_loader_rejects_malformed_native_caller_memory_frame(self) -> None:
        entry = _callthrough_entry()
        frame = _read_only_caller_memory_frame()
        frame["arguments"][0]["argument_index"] = 1
        entry["caller_memory_frame"] = frame

        with self.assertRaisesRegex(
            MachineImportProfileError,
            "caller-memory frame argument 0 is invalid",
        ):
            _load_fixture(entry)

    def test_loader_rejects_vague_effect_model_label(self) -> None:
        entry = _callthrough_entry()
        entry["effect_model"] = "native callthrough"

        with self.assertRaisesRegex(
            MachineImportProfileError, "exact versioned object"
        ):
            _load_fixture(entry)

    def test_loader_rejects_each_missing_callthrough_prerequisite(self) -> None:
        for prerequisite in sorted(NATIVE_DLL_CALLTHROUGH_PREREQUISITES):
            with self.subTest(prerequisite=prerequisite):
                entry = _callthrough_entry()
                effect_model = copy.deepcopy(entry["effect_model"])
                self.assertIsInstance(effect_model, dict)
                del effect_model["prerequisites"][prerequisite]
                entry["effect_model"] = effect_model

                with self.assertRaisesRegex(
                    MachineImportProfileError, "same pinned DLL implementation"
                ):
                    _load_fixture(entry)

    def test_loader_requires_exact_abi_arity_return_and_categories(self) -> None:
        mutations = {
            "abi": ("abi_template", "pe32-unknown-v1"),
            "disposition": ("disposition", None),
            "memory": ("memory_effect", "unknown"),
            "world": ("world_effect", "unknown"),
            "callback": ("callback_effect", "unknown"),
            "return": ("result_register_relations", None),
        }
        for label, (field, value) in mutations.items():
            with self.subTest(field=label):
                entry = _callthrough_entry()
                entry[field] = value
                with self.assertRaises(MachineImportProfileError):
                    _load_fixture(entry)

        entry = _callthrough_entry()
        entry["arity"] = {"kind": "variadic", "minimum_words": 1}
        with self.assertRaisesRegex(MachineImportProfileError, "fixed arity"):
            _load_fixture(entry)

        entry = _callthrough_entry()
        entry["memory_footprints"] = [{"access": "write"}]
        with self.assertRaisesRegex(MachineImportProfileError, "memory category"):
            _load_fixture(entry)

        entry = _callthrough_entry()
        imported = copy.deepcopy(entry["import"])
        self.assertIsInstance(imported, dict)
        imported["lookup_hint"] = "Call"
        entry["import"] = imported
        with self.assertRaisesRegex(MachineImportProfileError, "exact import identity"):
            _load_fixture(entry)

    def test_loader_requires_full_metadata_for_callback_bearing_api(self) -> None:
        entry = _callthrough_entry()
        entry["callback_effect"] = "explicit"
        with self.assertRaisesRegex(
            MachineImportProfileError, "requires source, ABI, and lifetime"
        ):
            _load_fixture(entry)

        entry.update({
            "callback_source": {"kind": "argument_word", "argument": 0},
            "callback_abi": {
                "kind": "generic_callback",
                "argument_words": 2,
                "stack_cleanup_bytes": 8,
                "nullable": False,
            },
            "callback_lifetime": "during_native_call",
        })
        _load_fixture(entry)


if __name__ == "__main__":
    unittest.main()
