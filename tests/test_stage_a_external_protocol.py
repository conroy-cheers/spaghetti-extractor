from __future__ import annotations

import json
import unittest
from pathlib import Path

from spaghetti_extractor.relational.analyses.external import (
    _import_thunk_boundary_stack_windows,
    _machine_call_argument_count_blocker,
    _machine_import_call_contract_analysis,
)


class StageAExternalProtocolTests(unittest.TestCase):
    @staticmethod
    def _kernel32_contract(symbol: str) -> dict:
        profile_path = (
            Path(__file__).parents[1]
            / "profiles"
            / "pe32-kernel32-lockstep-v1.json"
        )
        profile = json.loads(profile_path.read_text(encoding="utf-8"))
        return next(
            contract
            for contract in profile["machine_import_call_contracts"]
            if contract["import"].get("symbol") == symbol
        )

    @staticmethod
    def _msvcrt_contract(symbol: str) -> dict:
        profile_path = (
            Path(__file__).parents[1]
            / "profiles"
            / "pe32-msvcrt-lockstep-v1.json"
        )
        profile = json.loads(profile_path.read_text(encoding="utf-8"))
        return next(
            contract
            for contract in profile["machine_import_call_contracts"]
            if contract["import"].get("symbol") == symbol
        )

    @staticmethod
    def _memcpy_contract() -> dict:
        profile_path = (
            Path(__file__).parents[1]
            / "profiles"
            / "pe32-msvcrt-lockstep-v1.json"
        )
        profile = json.loads(profile_path.read_text(encoding="utf-8"))
        raw = next(
            contract
            for contract in profile["machine_import_call_contracts"]
            if contract["import"].get("symbol") == "memcpy"
        )
        return {
            "id": raw["id"],
            "import": raw["import"],
            "stack_argument_offsets": [0, 4, 8],
            "stack_result_delta": 0,
            "preserved_registers": ["ebp", "ebx", "edi", "esi"],
            "clobbered_registers": ["eax", "ecx", "edx"],
            "result_register_relations": raw["result_register_relations"],
            "disposition": "returns",
            "memory_effect": raw["memory_effect"],
            "memory_footprints": raw["memory_footprints"],
            "world_effect": raw["world_effect"],
        }

    @staticmethod
    def _external_jump(arguments: list[dict]) -> dict:
        imported = {
            "dll": list(b"msvcrt.dll"),
            "name": {"op": "symbol", "bytes": list(b"memcpy")},
        }
        return {"outcome": {
            "op": "external_jump",
            "import": imported,
            "arguments": arguments,
        }}

    def test_memcpy_profile_declares_argument_sized_read_write_footprints(self):
        contract = self._memcpy_contract()
        self.assertEqual(contract["stack_argument_offsets"], [0, 4, 8])
        self.assertEqual(contract["result_register_relations"], [
            {"register": "eax", "relation": "related_word"},
        ])
        self.assertEqual(contract["memory_effect"], "argumentRanges")
        self.assertEqual(
            [footprint["access"] for footprint in contract["memory_footprints"]],
            ["write", "read"],
        )
        self.assertEqual(
            [footprint["base_argument"] for footprint in contract["memory_footprints"]],
            [0, 1],
        )
        self.assertTrue(all(
            footprint["size"]
            == {"kind": "argument", "argument": 2, "scale": 1}
            for footprint in contract["memory_footprints"]
        ))

    def test_set_unhandled_exception_filter_profile_tracks_callback_pair(self):
        contract = self._kernel32_contract("SetUnhandledExceptionFilter")
        self.assertEqual(contract["abi_template"], "pe32-stdcall-v1")
        self.assertEqual(contract["argument_words"], 1)
        self.assertEqual(contract["memory_effect"], "none")
        self.assertEqual(contract["memory_footprints"], [])
        self.assertEqual(contract["world_effect"], "callbackRegistration")
        self.assertEqual(contract["world_effect_argument"], 0)
        self.assertEqual(
            contract["result_register_relations"],
            [{"register": "eax", "relation": "related_word"}],
        )

    def test_narrow_and_wide_initial_environment_accessors_share_contract_shape(self):
        narrow = self._msvcrt_contract("__p___initenv")
        wide = self._msvcrt_contract("__p___winitenv")
        ignored = {"id", "import"}
        self.assertEqual(
            {key: value for key, value in narrow.items() if key not in ignored},
            {key: value for key, value in wide.items() if key not in ignored},
        )
        self.assertEqual(narrow["abi_template"], "pe32-cdecl-v1")
        self.assertEqual(narrow["argument_words"], 0)
        self.assertEqual(narrow["world_effect"], "dynamicRanges")

    def test_errno_accessor_tracks_a_paired_nonnull_word(self):
        contract = self._msvcrt_contract("_errno")
        self.assertEqual(contract["abi_template"], "pe32-cdecl-v1")
        self.assertEqual(contract["argument_words"], 0)
        self.assertEqual(contract["memory_effect"], "none")
        self.assertEqual(contract["memory_footprints"], [])
        self.assertEqual(contract["world_effect"], "dynamicRanges")
        self.assertEqual(contract["result_register_relations"], [{
            "register": "eax",
            "relation": "dynamic_range_base",
            "size": {"kind": "fixed", "bytes": 4},
            "minimum_size": 4,
            "required_words": [{
                "offset": 0,
                "relation": "related_word",
            }],
            "nullable": False,
        }])

    def test_iswctype_is_an_exact_two_word_stateful_query(self):
        contract = self._msvcrt_contract("iswctype")
        self.assertEqual(contract["abi_template"], "pe32-cdecl-v1")
        self.assertEqual(contract["argument_words"], 2)
        self.assertEqual(
            contract["result_register_relations"],
            [{"register": "eax", "relation": "exact"}],
        )
        self.assertEqual(contract["memory_effect"], "relationalState")
        self.assertEqual(contract["memory_footprints"], [])
        self.assertEqual(contract["world_effect"], "none")

    def test_kernel32_text_and_loader_contracts_bound_every_caller_range(self):
        wide = self._kernel32_contract("WideCharToMultiByte")
        self.assertEqual(wide["abi_template"], "pe32-stdcall-v1")
        self.assertEqual(wide["argument_words"], 8)
        self.assertEqual(wide["world_effect"], "tlsState")
        self.assertEqual(
            wide["result_register_relations"],
            [{"register": "eax", "relation": "exact"}],
        )
        self.assertEqual(
            [
                (item["access"], item["base_argument"], item["nullable"])
                for item in wide["memory_footprints"]
            ],
            [
                ("read", 2, False),
                ("write", 4, True),
                ("read", 6, True),
                ("write", 7, True),
            ],
        )
        self.assertEqual(
            wide["memory_footprints"][0]["size"],
            {
                "kind": "argument_or_bounded_terminated",
                "length_argument": 3,
                "terminated_value": 0xFFFFFFFF,
                "source_argument": 2,
                "source_offset": 0,
                "unit_bytes": 2,
                "sentinel": [0, 0],
                "max_units": 524288,
            },
        )
        self.assertEqual(
            [item["size"] for item in wide["memory_footprints"][1:]],
            [
                {"kind": "argument", "argument": 5, "scale": 1},
                {"kind": "fixed", "bytes": 2},
                {"kind": "fixed", "bytes": 4},
            ],
        )

        multi = self._kernel32_contract("MultiByteToWideChar")
        self.assertEqual(multi["abi_template"], "pe32-stdcall-v1")
        self.assertEqual(multi["argument_words"], 6)
        self.assertEqual(multi["world_effect"], "tlsState")
        self.assertEqual(
            multi["memory_footprints"][0]["size"],
            {
                "kind": "argument_or_bounded_terminated",
                "length_argument": 3,
                "terminated_value": 0xFFFFFFFF,
                "source_argument": 2,
                "source_offset": 0,
                "unit_bytes": 1,
                "sentinel": [0],
                "max_units": 1048576,
            },
        )
        self.assertEqual(
            multi["memory_footprints"][1],
            {
                "access": "write",
                "base_argument": 4,
                "offset": 0,
                "size": {"kind": "argument", "argument": 5, "scale": 2},
                "nullable": True,
            },
        )

        lead_byte = self._kernel32_contract("IsDBCSLeadByteEx")
        self.assertEqual(lead_byte["argument_words"], 2)
        self.assertEqual(lead_byte["memory_effect"], "none")
        self.assertEqual(lead_byte["memory_footprints"], [])
        self.assertEqual(lead_byte["world_effect"], "none")

        for symbol, base_argument, nullable in (
            ("GetModuleHandleA", 0, True),
            ("GetProcAddress", 1, False),
        ):
            loader = self._kernel32_contract(symbol)
            self.assertEqual(loader["abi_template"], "pe32-stdcall-v1")
            self.assertEqual(loader["memory_effect"], "readOnly")
            self.assertEqual(loader["world_effect"], "tlsState")
            self.assertEqual(len(loader["memory_footprints"]), 1)
            footprint = loader["memory_footprints"][0]
            self.assertEqual(footprint["base_argument"], base_argument)
            self.assertEqual(footprint["nullable"], nullable)
            self.assertEqual(footprint["size"]["kind"], "bounded_terminated")
            self.assertEqual(footprint["size"]["source_argument"], base_argument)

    def test_gnu_hello_missing_identity_inventory_stays_fail_closed(self):
        direct_sites = {
            ("kernel32.dll", "WideCharToMultiByte"): 1,
            ("kernel32.dll", "IsDBCSLeadByteEx"): 1,
            ("kernel32.dll", "MultiByteToWideChar"): 2,
            ("kernel32.dll", "GetModuleHandleA"): 1,
            ("kernel32.dll", "GetProcAddress"): 1,
            ("msvcrt.dll", "__p___argv"): 3,
        }
        thunk_sites = {
            ("msvcrt.dll", "__p___mb_cur_max"): 1,
            ("msvcrt.dll", "_lock"): 1,
            ("msvcrt.dll", "memchr"): 1,
            ("msvcrt.dll", "memcmp"): 1,
            ("msvcrt.dll", "memset"): 2,
            ("msvcrt.dll", "strchr"): 4,
            ("msvcrt.dll", "strlen"): 43,
            ("msvcrt.dll", "strncmp"): 3,
            ("msvcrt.dll", "strrchr"): 2,
            ("msvcrt.dll", "wcslen"): 2,
        }
        excluded_thunk_sites = {
            ("msvcrt.dll", "__getmainargs"): 1,
            ("msvcrt.dll", "__setusermatherr"): 1,
            ("msvcrt.dll", "_cexit"): 1,
            ("msvcrt.dll", "_initterm"): 1,
            ("msvcrt.dll", "atoi"): 1,
            ("msvcrt.dll", "fprintf"): 2,
            ("msvcrt.dll", "fputc"): 19,
            ("msvcrt.dll", "fputwc"): 8,
            ("msvcrt.dll", "fwprintf"): 6,
            ("msvcrt.dll", "fwrite"): 5,
            ("msvcrt.dll", "getenv"): 1,
            ("msvcrt.dll", "localeconv"): 4,
            ("msvcrt.dll", "setlocale"): 4,
            ("msvcrt.dll", "strerror"): 3,
            ("msvcrt.dll", "vfprintf"): 1,
        }
        kernel_profile = json.loads((
            Path(__file__).parents[1]
            / "profiles"
            / "pe32-kernel32-lockstep-v1.json"
        ).read_text(encoding="utf-8"))
        msvcrt_profile = json.loads((
            Path(__file__).parents[1]
            / "profiles"
            / "pe32-msvcrt-lockstep-v1.json"
        ).read_text(encoding="utf-8"))
        contracts = {
            (item["import"]["dll"], item["import"]["symbol"]): item
            for item in [
                *kernel_profile["machine_import_call_contracts"],
                *msvcrt_profile["machine_import_call_contracts"],
            ]
        }

        self.assertEqual(sum(direct_sites.values()), 9)
        self.assertEqual(sum(thunk_sites.values()), 60)
        self.assertEqual(sum(excluded_thunk_sites.values()), 58)
        self.assertTrue((direct_sites.keys() | thunk_sites.keys()) <= contracts.keys())
        self.assertTrue(excluded_thunk_sites.keys().isdisjoint(contracts))
        for identity in direct_sites.keys() | thunk_sites.keys():
            contract = contracts[identity]
            self.assertNotEqual(contract["memory_effect"], "relationalState")
            if contract["memory_effect"] == "readOnly":
                self.assertTrue(contract["memory_footprints"])
                self.assertTrue(all(
                    footprint["access"] == "read"
                    for footprint in contract["memory_footprints"]
                ))
            elif contract["memory_effect"] == "argumentRanges":
                self.assertTrue(any(
                    footprint["access"] == "write"
                    for footprint in contract["memory_footprints"]
                ))

    def test_import_thunk_return_slot_moves_only_esp_window(self):
        windows = [
            {
                "range_id": 0,
                "original_register": "esp",
                "candidate_register": "esp",
                "bytes_below": 8,
                "bytes_above": 20,
            },
            {
                "range_id": 0,
                "original_register": "ebp",
                "candidate_register": "ebp",
                "bytes_below": 4,
                "bytes_above": 32,
            },
        ]
        translated, blocker = _import_thunk_boundary_stack_windows(windows)
        self.assertIsNone(blocker)
        self.assertEqual(
            [(item["original_register"], item["bytes_below"], item["bytes_above"])
             for item in translated],
            [("esp", 12, 16), ("ebp", 4, 32)],
        )

        _, blocker = _import_thunk_boundary_stack_windows([{
            **windows[0], "candidate_register": "ebp",
        }])
        self.assertIn("asymmetric ESP", blocker or "")

    def test_machine_contract_argument_count_accepts_only_complete_pair(self):
        contract = self._memcpy_contract()
        arguments = [{"op": "constant", "value": value} for value in (1, 2, 3)]
        self.assertIsNone(
            _machine_call_argument_count_blocker(contract, arguments, arguments)
        )
        self.assertEqual(
            _machine_call_argument_count_blocker(contract, arguments[:2], arguments),
            "machine import contract expects 3 argument words; recovered 2 original "
            "and 3 candidate",
        )
        self.assertIn(
            "not recovered as expression lists",
            _machine_call_argument_count_blocker(contract, None, arguments),
        )

    def test_machine_call_analysis_fails_closed_on_missing_extent_argument(self):
        contract = self._memcpy_contract()
        complete = [{"op": "constant", "value": value} for value in (1, 2, 8)]
        incomplete = complete[:2]
        behaviors = [
            {
                "original_ir": self._external_jump(complete),
                "candidate_ir": self._external_jump(complete),
            },
            {
                "original_ir": self._external_jump(incomplete),
                "candidate_ir": self._external_jump(incomplete),
            },
        ]
        analysis = _machine_import_call_contract_analysis(
            {
                "regions": [{"id": "complete"}, {"id": "incomplete"}],
                "machine_import_call_contracts": [contract],
            },
            behaviors,
        )
        self.assertEqual(
            [call["status"] for call in analysis["calls"]],
            ["candidate_requires_lean_replay", "incomplete"],
        )
        self.assertEqual(analysis["counts"]["contracted_call_sites"], 2)
        self.assertEqual(analysis["counts"]["argument_recovery_candidates"], 1)
        self.assertEqual(analysis["counts"]["incomplete_call_sites"], 1)


if __name__ == "__main__":
    unittest.main()
