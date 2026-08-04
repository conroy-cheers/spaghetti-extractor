from __future__ import annotations

import json
import unittest
from pathlib import Path


class StageAMachineImportProfileTests(unittest.TestCase):
    def test_runtime_profile_keeps_returns_and_callback_classes_explicit(self) -> None:
        root = Path(__file__).parents[1]
        payload = json.loads((
            root / "profiles/pe32-msvcrt-machine-runtime-v1.json"
        ).read_text(encoding="utf-8"))
        self.assertEqual(payload["includes"], [
            "pe32-kernel32-lockstep-v1.json",
            "pe32-msvcrt-lockstep-v1.json",
        ])
        entries = {
            (item["import"]["dll"].lower(), item["import"]["symbol"]): item
            for item in payload["machine_import_signatures"]
        }
        kernel_payload = json.loads((
            root / "profiles/pe32-kernel32-lockstep-v1.json"
        ).read_text(encoding="utf-8"))
        entries.update({
            (item["import"]["dll"].lower(), item["import"]["symbol"]): item
            for item in kernel_payload["machine_import_call_contracts"]
            if (item["import"]["dll"].lower(), item["import"]["symbol"])
            not in entries
        })
        for identity in (
            ("kernel32.dll", "VirtualQuery"),
            ("kernel32.dll", "VirtualProtect"),
            ("kernel32.dll", "GetLastError"),
            ("kernel32.dll", "TlsGetValue"),
            ("msvcrt.dll", "atexit"),
        ):
            self.assertTrue(entries[identity]["override"])
            self.assertTrue(entries[identity]["result_register_relations"])
        locale = entries[("msvcrt.dll", "localeconv")]
        self.assertEqual(locale["arity"], {"kind": "fixed", "words": 0})
        self.assertEqual(locale["world_effect"], "dynamicRanges")
        self.assertEqual(
            locale["result_register_relations"][0]["required_words"],
            [
                {"offset": 0, "relation": "nullable_dynamic_pointer"},
                {"offset": 4, "relation": "nullable_dynamic_pointer"},
            ],
        )
        for identity in (
            ("kernel32.dll", "SetUnhandledExceptionFilter"),
            ("msvcrt.dll", "atexit"),
            ("msvcrt.dll", "__setusermatherr"),
        ):
            entry = entries[identity]
            self.assertEqual(
                entry.get("callback_behavior", "registration"),
                "registration",
            )
            self.assertEqual(entry["world_effect"], "callbackRegistration")
        for symbol in ("exit", "_cexit", "_initterm"):
            entry = entries[("msvcrt.dll", symbol)]
            self.assertEqual(entry["callback_behavior"], "nested_frames")
            self.assertEqual(entry["disposition"], "protocol")

if __name__ == "__main__":
    unittest.main()
