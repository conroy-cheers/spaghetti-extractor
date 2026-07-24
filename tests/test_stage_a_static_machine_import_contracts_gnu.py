from __future__ import annotations

import hashlib
import json
import unittest
from pathlib import Path


class StageAGnuMachineImportBlockerReportTests(unittest.TestCase):
    def test_report_records_complete_boundary_and_legacy_global_frontiers(self) -> None:
        root = Path(__file__).parents[1]
        report_path = root / "docs/gnu-hello-machine-import-contract-blockers.json"
        report = json.loads(report_path.read_text(encoding="utf-8"))

        self.assertEqual(report["snapshot"]["prior_requested_import_count"], 54)
        self.assertEqual(report["snapshot"]["current_rooted_import_count"], 59)
        self.assertEqual(
            report["snapshot"]["newly_reachable_since_prior_inventory"],
            [
                "kernel32.dll!WideCharToMultiByte",
                "msvcrt.dll!atoi",
                "msvcrt.dll!calloc",
                "msvcrt.dll!vfprintf",
                "msvcrt.dll!wcslen",
            ],
        )
        self.assertEqual(report["counts"]["lean_profile_signatures"], 59)
        self.assertEqual(report["counts"]["checked_boundary_proposals"], 192)
        self.assertEqual(report["counts"]["imports_with_boundary_proposals"], 59)
        self.assertEqual(report["blocker_counts"], {})
        self.assertEqual(report["blocked_imports"], [])
        self.assertEqual(
            {
                (item["import"], item["reason_code"])
                for item in report["global_contract_export"]["residuals"]
            },
            {
                ("msvcrt.dll!_cexit", "nested_frames_require_boundary_contract"),
                ("msvcrt.dll!_initterm", "nested_frames_require_boundary_contract"),
                ("msvcrt.dll!exit", "nested_frames_require_boundary_contract"),
                ("msvcrt.dll!fprintf", "variadic_requires_boundary_contract"),
                ("msvcrt.dll!fwprintf", "variadic_requires_boundary_contract"),
            },
        )
        self.assertEqual(report["global_contract_export"]["status"], "incomplete")
        self.assertEqual(
            report["boundary_contract_export"]["status"],
            "generated_with_checked_mixed_original_projection",
        )
        self.assertEqual(report["boundary_contract_export"]["entries"], 192)
        self.assertIn(
            "variadic arity is never replaced by minimum arity",
            report["boundary_contract_export"]["properties"],
        )
        self.assertEqual(report["blockers"], [])
        self.assertFalse(report["authority"]["profile_status_fields_trusted"])
        self.assertFalse(report["authority"]["whole_path_evidence_accepted"])

        profile_text = (
            root / "profiles/pe32-msvcrt-machine-runtime-v1.json"
        ).read_text(encoding="utf-8").lower()
        self.assertNotIn("gnu", profile_text)
        self.assertNotIn("hello", profile_text)

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

    def test_report_hashes_match_local_gnu_artifacts_when_available(self) -> None:
        root = Path(__file__).parents[1]
        export = root / "build/stage-b-gnu-hello-roundtrip/stage-a-static-export-v2"
        reference = export / "reference-contract.json"
        state_machine = export / "state-machine.jsonl"
        if not reference.is_file() or not state_machine.is_file():
            self.skipTest("local GNU hello static export is unavailable")
        report = json.loads((
            root / "docs/gnu-hello-machine-import-contract-blockers.json"
        ).read_text(encoding="utf-8"))
        self.assertEqual(
            _sha256(reference), report["snapshot"]["reference_contract_sha256"]
        )
        self.assertEqual(
            _sha256(state_machine), report["snapshot"]["state_machine_sha256"]
        )


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


if __name__ == "__main__":
    unittest.main()
