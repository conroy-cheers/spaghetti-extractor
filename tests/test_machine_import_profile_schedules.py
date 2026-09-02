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

class MachineImportProfileScheduleTests(unittest.TestCase):
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
