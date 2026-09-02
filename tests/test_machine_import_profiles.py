from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from tests.pe_fixtures import pe32_import_image
from spaghetti_extractor.external.import_abi import (
    expand_import_abi_policy,
    load_selected_import_abis,
)
from spaghetti_extractor.external.machine_import_profiles import (
    MachineImportIdentity,
    MachineImportProfileError,
    load_machine_import_profile_set,
    materialize_v2_profile_contract,
)
from spaghetti_extractor.external.control_disposition import (
    build_control_disposition_profile,
)
from spaghetti_extractor.reconstruction.state_machine import (
    _annotate_machine_import_arguments,
    _machine_import_contracts,
)


_REPOSITORY_ROOT = Path(__file__).resolve().parents[1]

_RUNTIME_PROFILE_ARITIES = {
    ("kernel32.dll", "AreFileApisANSI"): 0,
    ("kernel32.dll", "CloseHandle"): 1,
    ("kernel32.dll", "GetACP"): 0,
    ("kernel32.dll", "GetConsoleMode"): 2,
    ("kernel32.dll", "GetCPInfo"): 2,
    ("kernel32.dll", "GetCurrentProcess"): 0,
    ("kernel32.dll", "GetFileAttributesA"): 1,
    ("kernel32.dll", "GetFileSize"): 2,
    ("kernel32.dll", "GetFileType"): 1,
    ("kernel32.dll", "GetModuleFileNameA"): 3,
    ("kernel32.dll", "GetOEMCP"): 0,
    ("kernel32.dll", "GetStartupInfoA"): 1,
    ("kernel32.dll", "GetStdHandle"): 1,
    ("kernel32.dll", "GetStringTypeA"): 5,
    ("kernel32.dll", "GetStringTypeW"): 4,
    ("kernel32.dll", "GetVersion"): 0,
    ("kernel32.dll", "TlsAlloc"): 0,
    ("kernel32.dll", "TlsFree"): 1,
    ("kernel32.dll", "TlsSetValue"): 2,
    ("kernel32.dll", "GlobalFree"): 1,
    ("kernel32.dll", "GlobalUnlock"): 1,
    ("kernel32.dll", "HeapCreate"): 3,
    ("kernel32.dll", "HeapDestroy"): 1,
    ("kernel32.dll", "IsBadCodePtr"): 1,
    ("kernel32.dll", "LCMapStringA"): 6,
    ("kernel32.dll", "LCMapStringW"): 6,
    ("kernel32.dll", "LoadLibraryA"): 1,
    ("kernel32.dll", "LocalFree"): 1,
    ("kernel32.dll", "OpenSemaphoreA"): 3,
    ("kernel32.dll", "QueryPerformanceCounter"): 1,
    ("kernel32.dll", "QueryPerformanceFrequency"): 1,
    ("kernel32.dll", "ReadFile"): 5,
    ("kernel32.dll", "RtlUnwind"): 4,
    ("kernel32.dll", "SetEndOfFile"): 1,
    ("kernel32.dll", "SetConsoleMode"): 2,
    ("kernel32.dll", "SetFilePointer"): 4,
    ("kernel32.dll", "SetHandleCount"): 1,
    ("kernel32.dll", "SetUnhandledExceptionFilter"): 1,
    ("kernel32.dll", "SetStdHandle"): 2,
    ("kernel32.dll", "TerminateProcess"): 2,
    ("kernel32.dll", "UnmapViewOfFile"): 1,
    ("kernel32.dll", "UnhandledExceptionFilter"): 1,
    ("kernel32.dll", "WriteFile"): 5,
    ("user32.dll", "GetCursorPos"): 1,
    ("user32.dll", "PostQuitMessage"): 1,
    ("user32.dll", "SetCursor"): 1,
    ("user32.dll", "SetCursorPos"): 2,
    ("user32.dll", "WaitMessage"): 0,
    ("winmm.dll", "midiOutPrepareHeader"): 3,
    ("winmm.dll", "midiOutReset"): 1,
    ("winmm.dll", "midiOutUnprepareHeader"): 3,
    ("winmm.dll", "midiStreamClose"): 1,
    ("winmm.dll", "midiStreamOpen"): 6,
    ("winmm.dll", "midiStreamOut"): 3,
    ("winmm.dll", "midiStreamPause"): 1,
    ("winmm.dll", "midiStreamProperty"): 3,
    ("winmm.dll", "midiStreamRestart"): 1,
    ("winmm.dll", "timeGetTime"): 0,
}

_ABI_ONLY_PROFILE_ARITIES = {
    ("user32.dll", "DispatchMessageA"): 1,
    ("user32.dll", "GetMessageA"): 4,
    ("user32.dll", "PeekMessageA"): 5,
    ("user32.dll", "TranslateMessage"): 1,
}


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
    def test_msvcrt_predicate_family_includes_reachable_isspace(self) -> None:
        source = _REPOSITORY_ROOT / "profiles/pe32-msvcrt-lockstep-v1.json"
        selected = load_machine_import_profile_set([source])
        contracts = {
            str(contract.identity.value): contract.contract
            for contract in selected.contracts
            if contract.identity.kind == "symbol"
        }

        self.assertIn("isspace", contracts)
        self.assertEqual(
            {
                key: contracts["isspace"][key]
                for key in (
                    "abi_template",
                    "argument_words",
                    "result_register_relations",
                    "memory_effect",
                    "memory_footprints",
                    "world_effect",
                )
            },
            {
                key: contracts["isalnum"][key]
                for key in (
                    "abi_template",
                    "argument_words",
                    "result_register_relations",
                    "memory_effect",
                    "memory_footprints",
                    "world_effect",
                )
            },
        )

    def test_v2_selected_contracts_round_trip_through_aggregate_profile(self) -> None:
        source = _REPOSITORY_ROOT / "profiles/pe32-msvcrt-lockstep-v1.json"
        selected = load_machine_import_profile_set([source])
        callback = next(
            contract
            for contract in selected.contracts
            if contract.contract.get("callback_protocol") is not None
        )
        self.assertEqual(callback.contract["callback_effect"], "explicit")

        with tempfile.TemporaryDirectory() as temporary:
            bundle = Path(temporary) / "profile.json"
            bundle.write_text(json.dumps({
                "format": "spaghetti-extractor-static-machine-import-profile-v2",
                "id": "fixture-aggregate",
                "provenance": {
                    "kind": "resolved_machine_import_profile_graph_v1",
                    "source_profiles": [{
                        "id": profile.profile_id,
                        "sha256": profile.sha256,
                    } for profile in selected.profiles],
                },
                "machine_import_call_contracts": [
                    materialize_v2_profile_contract(contract)
                    for contract in selected.contracts
                ],
            }), encoding="utf-8")
            reloaded = load_machine_import_profile_set([bundle])

        reloaded_callback = next(
            contract
            for contract in reloaded.contracts
            if contract.contract.get("callback_protocol") is not None
        )
        self.assertEqual(reloaded_callback.contract["callback_effect"], "explicit")
        self.assertEqual(reloaded_callback.profile_id, callback.profile_id)
        self.assertEqual(reloaded_callback.profile_sha256, callback.profile_sha256)
        self.assertNotIn(
            "callback_effect", materialize_v2_profile_contract(callback)
        )

    def test_aggregate_profile_rejects_unbound_selected_source(self) -> None:
        source = _REPOSITORY_ROOT / "profiles/pe32-msvcrt-lockstep-v1.json"
        selected = load_machine_import_profile_set([source])
        row = materialize_v2_profile_contract(selected.contracts[0])
        row["source_profile_binding"]["profile_sha256"] = "0" * 64
        with tempfile.TemporaryDirectory() as temporary:
            bundle = Path(temporary) / "profile.json"
            bundle.write_text(json.dumps({
                "format": "spaghetti-extractor-static-machine-import-profile-v2",
                "id": "fixture-aggregate",
                "provenance": {
                    "kind": "resolved_machine_import_profile_graph_v1",
                    "source_profiles": [{
                        "id": profile.profile_id,
                        "sha256": profile.sha256,
                    } for profile in selected.profiles],
                },
                "machine_import_call_contracts": [row],
            }), encoding="utf-8")
            with self.assertRaisesRegex(
                MachineImportProfileError,
                "absent from resolved provenance",
            ):
                load_machine_import_profile_set([bundle])

    def test_control_disposition_projection_ignores_returning_contracts(self) -> None:
        terminating = {
            "id": "exit",
            "import": {"dll": "fixture.dll", "symbol": "Exit"},
            "abi_template": "pe32-stdcall-v1",
            "argument_words": 1,
            "disposition": "terminates",
        }
        base = {
            "format": "spaghetti-extractor-static-machine-import-profile-v1",
            "id": "base",
            "default_callback_effect": "none",
            "machine_import_signatures": [terminating],
        }
        extended = {
            **base,
            "id": "extended",
            "machine_import_signatures": [
                {
                    "id": "ordinary",
                    "import": {"dll": "fixture.dll", "symbol": "Ordinary"},
                    "abi_template": "pe32-stdcall-v1",
                    "argument_words": 3,
                    "disposition": "returns",
                },
                terminating,
            ],
        }
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            base_path = directory / "base.json"
            extended_path = directory / "extended.json"
            base_path.write_text(json.dumps(base), encoding="utf-8")
            extended_path.write_text(json.dumps(extended), encoding="utf-8")

            base_projection = build_control_disposition_profile([base_path])
            extended_projection = build_control_disposition_profile(
                [extended_path]
            )

        self.assertEqual(base_projection, extended_projection)
        self.assertEqual(
            base_projection["machine_import_signatures"],
            [{
                "id": "control-disposition:fixture.dll!Exit",
                "import": {"dll": "fixture.dll", "symbol": "Exit"},
                "abi_template": "pe32-stdcall-v1",
                "argument_words": 1,
                "disposition": "terminates",
            }],
        )

    def test_control_disposition_projection_tracks_control_changes(self) -> None:
        def profile(words: int) -> dict:
            return {
                "format": "spaghetti-extractor-static-machine-import-profile-v1",
                "id": f"fixture-{words}",
                "machine_import_signatures": [{
                    "id": "exit",
                    "import": {"dll": "fixture.dll", "ordinal": 7},
                    "abi_template": "pe32-cdecl-v1",
                    "argument_words": words,
                    "disposition": "terminates",
                }],
            }

        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            first = directory / "first.json"
            second = directory / "second.json"
            first.write_text(json.dumps(profile(1)), encoding="utf-8")
            second.write_text(json.dumps(profile(2)), encoding="utf-8")

            first_projection = build_control_disposition_profile([first])
            second_projection = build_control_disposition_profile([second])

        self.assertNotEqual(first_projection, second_projection)
        self.assertEqual(
            first_projection["machine_import_signatures"][0]["id"],
            "control-disposition:fixture.dll!ordinal-7",
        )

    def test_runtime_profiles_pin_reviewed_pe32_abi_and_effects(self) -> None:
        profile_set = load_machine_import_profile_set([
            _REPOSITORY_ROOT / "profiles/pe32-msvcrt-machine-runtime-v1.json"
        ])
        selected = {
            (contract.identity.dll, str(contract.identity.value)): contract
            for contract in profile_set.contracts
        }

        for identity, argument_words in _RUNTIME_PROFILE_ARITIES.items():
            with self.subTest(import_identity=identity):
                contract = selected[identity]
                self.assertEqual(contract.arity_kind, "fixed")
                self.assertEqual(contract.argument_words, argument_words)
                self.assertEqual(
                    contract.contract["abi_template"], "pe32-stdcall-v1"
                )
                self.assertEqual(
                    contract.contract["disposition"],
                    "nonlocal" if identity == (
                        "kernel32.dll", "RtlUnwind"
                    ) else "returns",
                )
                self.assertIsInstance(
                    contract.contract["result_register_relations"], list
                )
                self.assertIsInstance(contract.contract["memory_effect"], str)
                self.assertIsInstance(
                    contract.contract["memory_footprints"], list
                )
                self.assertIsInstance(contract.contract["world_effect"], str)

    def test_runtime_profiles_preserve_argument_bounded_footprints(self) -> None:
        selected = load_machine_import_profile_set([
            _REPOSITORY_ROOT / "profiles/pe32-msvcrt-machine-runtime-v1.json"
        ]).by_identity()

        read_file = next(
            contract.contract
            for identity, contract in selected.items()
            if identity.dll == "kernel32.dll" and identity.value == "ReadFile"
        )
        self.assertEqual(
            read_file["memory_footprints"][0]["size"],
            {"kind": "argument", "argument": 2, "scale": 1},
        )
        self.assertEqual(
            read_file["memory_footprints"][2]["size"],
            {"kind": "fixed", "bytes": 20},
        )

        string_type_a = next(
            contract.contract
            for identity, contract in selected.items()
            if identity.dll == "kernel32.dll"
            and identity.value == "GetStringTypeA"
        )
        self.assertEqual(
            string_type_a["memory_footprints"][0],
            {
                "access": "read",
                "base_argument": 2,
                "offset": 0,
                "size": {
                    "kind": "argument_or_bounded_terminated",
                    "length_argument": 3,
                    "terminated_value": 4294967295,
                    "source_argument": 2,
                    "source_offset": 0,
                    "unit_bytes": 1,
                    "sentinel": [0],
                    "max_units": 1048576,
                },
                "nullable": False,
            },
        )
        self.assertEqual(
            string_type_a["memory_footprints"][1],
            {
                "access": "write",
                "base_argument": 4,
                "offset": 0,
                "size": {"kind": "argument", "argument": 3, "scale": 2},
                "nullable": False,
            },
        )

        string_type_w = next(
            contract.contract
            for identity, contract in selected.items()
            if identity.dll == "kernel32.dll"
            and identity.value == "GetStringTypeW"
        )
        self.assertEqual(
            string_type_w["memory_footprints"][0]["size"]["kind"],
            "argument_or_bounded_terminated",
        )
        self.assertEqual(
            string_type_w["memory_footprints"][1]["size"]["unit_bytes"], 2
        )

    def test_jq_host_dependencies_have_reusable_reviewed_contracts(self) -> None:
        profile_set = load_machine_import_profile_set([
            _REPOSITORY_ROOT / "profiles/pe32-msvcrt-machine-runtime-v1.json",
            _REPOSITORY_ROOT / "profiles/pe32-oniguruma-runtime-v1.json",
        ])
        selected = {
            (contract.identity.dll, str(contract.identity.value)): contract
            for contract in profile_set.contracts
        }
        expected_arities = {
            ("msvcrt.dll", "__wgetmainargs"): 5,
            ("msvcrt.dll", "_isatty"): 1,
            ("msvcrt.dll", "_setmode"): 2,
            ("msvcrt.dll", "_strdup"): 1,
            ("msvcrt.dll", "fputs"): 2,
            ("msvcrt.dll", "isalpha"): 1,
            ("msvcrt.dll", "perror"): 1,
            ("msvcrt.dll", "putchar"): 1,
            ("msvcrt.dll", "puts"): 1,
            ("msvcrt.dll", "strtol"): 3,
            ("libonig-5.dll", "onig_set_parse_depth_limit"): 1,
        }
        for identity, argument_words in expected_arities.items():
            with self.subTest(import_identity=identity):
                contract = selected[identity]
                self.assertEqual(contract.arity_kind, "fixed")
                self.assertEqual(contract.argument_words, argument_words)
                self.assertEqual(contract.contract["disposition"], "returns")

        wgetmainargs = selected[(
            "msvcrt.dll", "__wgetmainargs"
        )].contract
        self.assertEqual(
            [row["argument"] for row in wgetmainargs["out_pointer_relations"]],
            [1, 2],
        )
        self.assertTrue(all(
            row["pointee_shape"]["element"]["unit_bytes"] == 2
            for row in wgetmainargs["out_pointer_relations"]
        ))
        self.assertEqual(
            selected[("msvcrt.dll", "strtol")].contract["memory_footprints"][1],
            {
                "access": "write",
                "base_argument": 1,
                "offset": 0,
                "size": {"kind": "fixed", "bytes": 4},
                "nullable": True,
            },
        )

    def test_message_loop_abi_facts_do_not_claim_external_effects(self) -> None:
        profile = (
            _REPOSITORY_ROOT
            / "profiles/pe32-win32-windowing-runtime-v1.json"
        )
        selected = load_machine_import_profile_set([profile]).by_identity()
        for (dll, symbol), argument_words in _ABI_ONLY_PROFILE_ARITIES.items():
            with self.subTest(import_identity=(dll, symbol)):
                contract = next(
                    value
                    for identity, value in selected.items()
                    if identity.dll == dll and identity.value == symbol
                )
                self.assertEqual(contract.arity_kind, "fixed")
                self.assertEqual(contract.argument_words, argument_words)
                self.assertEqual(
                    contract.contract["abi_template"], "pe32-stdcall-v1"
                )
                self.assertNotIn("memory_effect", contract.contract)
                self.assertNotIn("world_effect", contract.contract)
                self.assertNotIn("callback_effect", contract.contract)

        contracts = _machine_import_contracts([profile])
        event = {
            "kind": "external_call",
            "dll": "user32.dll",
            "symbol": "PeekMessageA",
            "ordinal": None,
            "arguments": [],
            "stack_inputs": [],
        }
        annotated = _annotate_machine_import_arguments({
            "outcome": {"kind": "fallthrough", "target_rva": 0x1010},
            "external_events": [event],
            "ordered_events": [event],
        }, contracts)["external_events"][0]["abi_contract"]
        self.assertEqual(annotated["template"], "pe32-stdcall-v1")
        self.assertEqual(annotated["argument_words"], 5)
        self.assertEqual(annotated["disposition"], "returns")
        for field in (
            "result_register_relations",
            "memory_effect",
            "memory_footprints",
            "world_effect",
            "callback_effect",
        ):
            self.assertNotIn(field, annotated)

    def test_callback_profiles_declare_source_abi_and_lifetime(self) -> None:
        profile_set = load_machine_import_profile_set([
            _REPOSITORY_ROOT / "profiles/pe32-msvcrt-machine-runtime-v1.json"
        ])
        callbacks = [
            contract.contract
            for contract in profile_set.contracts
            if contract.contract.get("world_effect") == "callbackRegistration"
        ]
        self.assertTrue(callbacks)
        for contract in callbacks:
            with self.subTest(contract=contract["id"]):
                self.assertEqual(contract["callback_effect"], "explicit")
                protocol = contract["callback_protocol"]
                self.assertEqual(
                    protocol["format"],
                    "spaghetti-extractor-callback-protocol-v1",
                )
                self.assertIn("lifetime", protocol)
                self.assertIn("signature", protocol)
                self.assertIn("source", protocol)
        for contract in profile_set.contracts:
            if "callback_protocol" in contract.contract:
                self.assertEqual(
                    contract.contract.get("callback_effect"),
                    "explicit",
                    contract.contract.get("id"),
                )
            else:
                self.assertNotEqual(
                    contract.contract.get("callback_effect"),
                    "explicit",
                    contract.contract.get("id"),
                )

    def test_kernel32_exception_filter_has_exact_callback_contract(self) -> None:
        profile_set = load_machine_import_profile_set([
            _REPOSITORY_ROOT / "profiles/pe32-kernel32-runtime-v1.json"
        ])
        identity = MachineImportIdentity(
            "kernel32.dll", "symbol", "SetUnhandledExceptionFilter"
        )
        contract = profile_set.by_identity()[identity].contract

        self.assertEqual(contract["argument_words"], 1)
        self.assertEqual(contract["world_effect"], "callbackRegistration")
        self.assertEqual(contract["callback_effect"], "explicit")
        protocol = contract["callback_protocol"]
        self.assertEqual(protocol["id"], "win32-unhandled-exception-filter")
        self.assertEqual(protocol["action"], "replace")
        self.assertEqual(protocol["source"], {
            "kind": "argument_word",
            "argument": 0,
            "sentinels": [{"word": 0, "kind": "null"}],
        })
        self.assertEqual(protocol["signature"], {
            "abi_template": "pe32-stdcall-v1",
            "argument_words": 1,
            "stack_cleanup_bytes": 4,
            "result": {"kind": "word", "register": "eax"},
        })
        self.assertEqual(protocol["previous_result"], {
            "register": "eax",
            "nullable": True,
            "sentinels": [{"word": 0, "kind": "null"}],
        })

    def test_kernel32_external_exception_services_are_typed(self) -> None:
        profile_set = load_machine_import_profile_set([
            _REPOSITORY_ROOT / "profiles/pe32-kernel32-runtime-v1.json"
        ])
        contracts = profile_set.by_identity()
        unwind = contracts[MachineImportIdentity(
            "kernel32.dll", "symbol", "RtlUnwind"
        )].contract
        self.assertEqual(unwind["disposition"], "nonlocal")
        self.assertEqual(unwind["result_register_relations"], [])
        self.assertEqual(
            unwind["external_service_protocol"]["behavior"]["outcome"],
            "nonlocal",
        )
        exception_filter = contracts[MachineImportIdentity(
            "kernel32.dll", "symbol", "UnhandledExceptionFilter"
        )].contract
        service = exception_filter["external_service_protocol"]
        self.assertEqual(service["kind"], "unhandled_exception_filter")
        self.assertEqual(service["object_view"], {
            "kind": "win32_exception_pointers_v1",
            "size_bytes": 8,
            "exception_record_pointer_offset": 0,
            "context_pointer_offset": 4,
            "exception_record_view": "checked_exception_record_v1",
            "context_view": "x86_context_v1",
            "root_access": "read",
            "referent_access": "read_write",
            "lifetime": "during_call",
        })

    def test_nonlocal_profile_without_exact_service_fails_closed(self) -> None:
        source = json.loads((
            _REPOSITORY_ROOT / "profiles/pe32-kernel32-runtime-v1.json"
        ).read_text(encoding="utf-8"))
        unwind = next(
            row for row in source["machine_import_signatures"]
            if row.get("import", {}).get("symbol") == "RtlUnwind"
        )
        unwind["external_service_protocol"]["behavior"]["outcome"] = (
            "normal"
        )
        with tempfile.TemporaryDirectory() as temporary:
            path = _write(Path(temporary) / "profile.json", source)
            with self.assertRaisesRegex(
                MachineImportProfileError,
                "nonlocal-unwind contract is unsupported",
            ):
                load_machine_import_profile_set([path])

    def test_reviewed_dll_policy_expands_to_exact_pe_import_abi(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            original = root / "fixture.exe"
            original.write_bytes(
                pe32_import_image(b"\xc3", symbol="ShowWindow", dll="USER32.dll")
            )
            policy = _write(root / "policy.json", {
                "format": "spaghetti-extractor-import-abi-policy-v1",
                "id": "fixture-policy",
                "rules": [{
                    "dll": "user32.dll",
                    "abi_template": "pe32-stdcall-v1",
                }],
            })
            output = root / "expanded.json"

            expanded = expand_import_abi_policy(
                original_pe=original, policy=policy, out=output
            )
            selected = list(load_selected_import_abis([output]).values())

            self.assertEqual(expanded["status"], "complete")
            self.assertEqual(expanded["counts"], {"imports": 1, "dlls": 1})
            self.assertEqual(selected[0].identity.dll, "user32.dll")
            self.assertEqual(selected[0].identity.value, "ShowWindow")
            self.assertEqual(
                selected[0].abi.preserved_registers,
                ("ebp", "ebx", "edi", "esi"),
            )
            self.assertEqual(
                selected[0].contract["import"],
                {"dll": "user32.dll", "symbol": "ShowWindow"},
            )

    def test_reviewed_dll_policy_fails_closed_on_uncovered_import(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            original = root / "fixture.exe"
            original.write_bytes(
                pe32_import_image(b"\xc3", symbol="ShowWindow", dll="USER32.dll")
            )
            policy = _write(root / "policy.json", {
                "format": "spaghetti-extractor-import-abi-policy-v1",
                "id": "fixture-policy",
                "rules": [{
                    "dll": "kernel32.dll",
                    "abi_template": "pe32-stdcall-v1",
                }],
            })

            with self.assertRaisesRegex(Exception, "does not cover DLLs"):
                expand_import_abi_policy(
                    original_pe=original,
                    policy=policy,
                    out=root / "expanded.json",
                )

    def test_includes_are_loaded_first_and_explicit_override_wins(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _write(root / "base.json", {
                "format": "spaghetti-extractor-external-environment-profile-v1",
                "id": "base",
                "machine_import_call_contracts": [_contract("Call", words=1)],
            })
            top = _write(root / "top.json", {
                "format": "spaghetti-extractor-static-machine-import-profile-v1",
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
                "format": "spaghetti-extractor-external-environment-profile-v1",
                "id": "base",
                "machine_import_call_contracts": [_contract("Call")],
            })
            top = _write(root / "top.json", {
                "format": "spaghetti-extractor-static-machine-import-profile-v1",
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
                "format": "spaghetti-extractor-static-machine-import-profile-v1",
                "id": "first",
                "includes": ["second.json"],
                "machine_import_signatures": [],
            })
            _write(root / "second.json", {
                "format": "spaghetti-extractor-static-machine-import-profile-v1",
                "id": "second",
                "includes": ["first.json"],
                "machine_import_signatures": [],
            })
            with self.assertRaisesRegex(MachineImportProfileError, "include cycle"):
                load_machine_import_profile_set([first])

    def test_variadic_minimum_is_not_materialized_as_exact_arguments(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            profile = _write(Path(temporary) / "profile.json", {
                "format": "spaghetti-extractor-static-machine-import-profile-v1",
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
                _machine_import_contracts([profile]),
            )

    def test_stdcall_callback_thunk_uses_return_address_offset(self) -> None:
        contract = _contract(
            "RegisterCallback", abi="pe32-stdcall-v1", words=1
        )
        contract.update({
            "world_effect": "callbackRegistration",
            "callback_source": {"kind": "argument_word", "argument": 0},
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
        self.assertEqual(
            actual["abi_contract"]["callback_source"],
            {"kind": "argument_word", "argument": 0},
        )
        self.assertNotIn(
            "world_effect_argument", actual["abi_contract"]
        )
        self.assertEqual(actual["stack_inputs"][0]["offset"], 4)

    def test_structured_callback_source_is_canonicalized(self) -> None:
        contract = _contract(
            "RegisterClassA", abi="pe32-stdcall-v1", words=1
        )
        contract.update({
            "world_effect": "callbackRegistration",
            "callback_source": {
                "kind": "argument_pointee",
                "argument": 0,
                "offset": 4,
            },
            "callback_lifetime": "until_class_unregistered_or_process_exit",
            "callback_abi": {
                "kind": "generic_callback",
                "argument_words": 4,
                "stack_cleanup_bytes": 16,
                "nullable": False,
            },
        })
        contracts = {
            ("user32.dll", "RegisterClassA", None): contract,
        }
        event = {
            "kind": "external_call",
            "dll": "user32.dll",
            "symbol": "RegisterClassA",
            "ordinal": None,
            "arguments": [],
            "stack_inputs": [],
        }
        row = {
            "outcome": {"kind": "fallthrough"},
            "external_events": [event],
            "ordered_events": [event],
        }

        actual = _annotate_machine_import_arguments(row, contracts)[
            "external_events"
        ][0]

        self.assertEqual(actual["abi_contract"]["callback_source"], {
            "kind": "argument_pointee",
            "argument": 0,
            "offset": 4,
        })
        self.assertEqual(actual["abi_contract"]["argument_words"], 1)
        self.assertEqual(actual["stack_inputs"][0]["offset"], 0)

    def test_selected_profile_evidence_survives_callsite_annotation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            profile = _write(Path(temporary) / "profile.json", {
                "format": "spaghetti-extractor-external-environment-profile-v1",
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
                    "out_interface_relations": [{
                        "argument_index": 1,
                        "interface_id": "IFixture",
                        "write_width": 4,
                        "object_size": 4,
                        "vtable_size": 8,
                        "nullable": True,
                        "success_condition": "hresult_succeeded_eax",
                    }],
                }],
            })
            contracts = _machine_import_contracts([profile])
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
            self.assertEqual(actual["out_interface_relations"], [{
                "argument_index": 1,
                "interface_id": "IFixture",
                "write_width": 4,
                "object_size": 4,
                "vtable_size": 8,
                "nullable": True,
                "success_condition": "hresult_succeeded_eax",
            }])





if __name__ == "__main__":
    unittest.main()
