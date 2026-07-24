from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from tests.pe_fixtures import pe32_import_image

from spaghetti_extractor.relational.lean.static_machine_import_contracts import (
    StaticImportIdentity,
    StaticMachineImportLeanBindings,
    plan_static_machine_import_contracts,
    write_static_machine_import_contracts,
)
from spaghetti_extractor.stage_binary import _parse_stage_a_pe


class StageAStaticMachineImportContractTests(unittest.TestCase):
    def test_direct_iat_boundary_is_profiled_and_emitted(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            fixture = _write_fixture(root, via_thunk=False)
            plan = plan_static_machine_import_contracts(**fixture.plan_arguments)

            self.assertTrue(plan.complete, plan.to_json())
            self.assertEqual(len(plan.signatures), 1)
            self.assertEqual(len(plan.boundaries), 1)
            self.assertEqual(plan.boundaries[0].route, "direct")
            self.assertEqual(plan.boundaries[0].argument_words, 1)
            lean, report = write_static_machine_import_contracts(
                root / "generated", plan, fixture.bindings
            )
            self.assertIn(
                "generatedStaticMachineImportProfilesChecked",
                lean.read_text(encoding="utf-8"),
            )
            self.assertIn(
                "def generatedMachineImportCallContracts :",
                lean.read_text(encoding="utf-8"),
            )
            self.assertTrue(plan.global_contracts_ready)
            payload = json.loads(report.read_text(encoding="utf-8"))
            self.assertEqual(payload["status"], "ready")
            self.assertEqual(
                payload["global_contract_export"],
                {"status": "ready", "residuals": []},
            )
            self.assertFalse(payload["authority"]["profile_status_fields_trusted"])

    def test_profile_includes_are_relative_deduplicated_and_overrideable(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            fixture = _write_fixture(root, via_thunk=False)
            base = root / "base.json"
            (root / "profile.json").rename(base)
            (root / "profile.json").write_text(json.dumps({
                "format": "stage-a-static-machine-import-profile-v1",
                "id": "composed-machine-import-profile-v1",
                "includes": ["base.json"],
                "machine_import_signatures": [],
            }), encoding="utf-8")
            fixture.plan_arguments["profile_paths"] = [
                base, root / "profile.json"
            ]

            plan = plan_static_machine_import_contracts(**fixture.plan_arguments)

            self.assertTrue(plan.complete, plan.to_json())
            self.assertEqual(len(plan.signatures), 1)
            self.assertEqual(
                plan.signatures[0].profile_id,
                "synthetic-machine-import-profile-v1",
            )

    def test_callback_registration_remains_an_explicit_world_effect(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            fixture = _write_fixture(root, via_thunk=False)
            profile = root / "profile.json"
            payload = json.loads(profile.read_text(encoding="utf-8"))
            entry = payload["machine_import_signatures"][0]
            entry.update({
                "callback_behavior": "registration",
                "world_effect": "callbackRegistration",
                "world_effect_argument": 0,
            })
            profile.write_text(json.dumps(payload), encoding="utf-8")

            plan = plan_static_machine_import_contracts(**fixture.plan_arguments)

            self.assertTrue(plan.complete, plan.to_json())
            self.assertEqual(plan.signatures[0].callback_mode, "registration")
            self.assertEqual(
                plan.signatures[0].contract["world_effect"],
                "callbackRegistration",
            )
            lean, _ = write_static_machine_import_contracts(
                root / "generated", plan, fixture.bindings
            )
            source = lean.read_text(encoding="utf-8")
            self.assertIn("callbackMode := .registration", source)
            self.assertIn("worldEffect := .callbackRegistration 0", source)

    def test_direct_caller_to_iat_thunk_emits_checked_path_route(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = _write_fixture(Path(temporary), via_thunk=True)
            plan = plan_static_machine_import_contracts(**fixture.plan_arguments)

            self.assertTrue(plan.complete, plan.to_json())
            self.assertEqual(len(plan.boundaries), 1)
            boundary = plan.boundaries[0]
            self.assertEqual(boundary.route, "via_thunk")
            self.assertEqual(boundary.thunk_rva, 0x1020)
            self.assertEqual(boundary.argument_evidence,
                             "declarative_fixed_abi_plus_exact_decode")

    def test_external_tail_uses_checked_enclosing_call_frame(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = _write_fixture(
                Path(temporary), via_thunk=False, framed_tail=True
            )
            plan = plan_static_machine_import_contracts(**fixture.plan_arguments)

            self.assertTrue(plan.complete, plan.to_json())
            self.assertEqual(len(plan.boundaries), 1)
            boundary = plan.boundaries[0]
            self.assertEqual(boundary.route, "framed_direct_tail")
            self.assertEqual(boundary.frame_entry_rva, 0x1010)
            self.assertEqual(boundary.tail_rva, 0x1015)
            self.assertEqual(boundary.execution_source_rva, 0x1015)
            self.assertEqual(boundary.continuation_rva, 0x1005)

    def test_external_tail_through_thunk_uses_checked_enclosing_call_frame(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = _write_fixture(
                Path(temporary), via_thunk=True, framed_tail=True
            )
            plan = plan_static_machine_import_contracts(**fixture.plan_arguments)

            self.assertTrue(plan.complete, plan.to_json())
            self.assertEqual(len(plan.boundaries), 1)
            boundary = plan.boundaries[0]
            self.assertEqual(boundary.route, "framed_thunk_tail")
            self.assertEqual(boundary.frame_entry_rva, 0x1010)
            self.assertEqual(boundary.tail_rva, 0x1010)
            self.assertEqual(boundary.thunk_rva, 0x1020)
            self.assertEqual(boundary.execution_source_rva, 0x1020)
            self.assertEqual(boundary.continuation_rva, 0x1005)

    def test_register_indirect_iat_seed_is_an_explicit_route(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = _write_fixture(
                Path(temporary), via_thunk=False, register_indirect=True
            )
            plan = plan_static_machine_import_contracts(**fixture.plan_arguments)

            self.assertTrue(plan.complete, plan.to_json())
            boundary = plan.boundaries[0]
            self.assertEqual(boundary.route, "register_indirect")
            self.assertEqual(boundary.dispatch_register, "ecx")
            self.assertEqual(boundary.iat_rva, 0x2040)
            self.assertEqual(boundary.source_rva, 0x1004)
            self.assertEqual(boundary.execution_source_rva, 0x1004)
            self.assertEqual(boundary.source_size, 15)

    def test_register_indirect_iat_call_is_discovered_from_exact_control(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = _write_fixture(
                Path(temporary), via_thunk=False, register_indirect=True
            )
            fixture.plan_arguments["required_imports"] = []

            plan = plan_static_machine_import_contracts(**fixture.plan_arguments)

            self.assertTrue(plan.complete, plan.to_json())
            self.assertEqual(
                plan.required,
                (StaticImportIdentity("fixture.dll", symbol="FixtureCall"),),
            )
            self.assertEqual(len(plan.boundaries), 1)
            self.assertEqual(plan.boundaries[0].route, "register_indirect")

    def test_register_iat_seed_crosses_a_decoded_region_boundary(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = _write_fixture(
                Path(temporary),
                via_thunk=False,
                register_indirect=True,
                split_register_seed=True,
            )
            plan = plan_static_machine_import_contracts(**fixture.plan_arguments)

            self.assertTrue(plan.complete, plan.to_json())
            self.assertEqual(len(plan.boundaries), 1)
            boundary = plan.boundaries[0]
            self.assertEqual(boundary.route, "register_indirect")
            self.assertEqual(boundary.dispatch_register, "ecx")
            self.assertEqual(boundary.iat_rva, 0x2040)
            self.assertEqual(boundary.source_rva, 0x1004)
            self.assertEqual(boundary.source_size, 15)

    def test_register_iat_seed_does_not_cross_an_intervening_call(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = _write_fixture(
                Path(temporary),
                via_thunk=False,
                register_indirect=True,
                split_register_seed=True,
                intervening_register_call=True,
            )
            plan = plan_static_machine_import_contracts(**fixture.plan_arguments)

            self.assertFalse(plan.complete)
            self.assertEqual(plan.boundaries, ())
            self.assertEqual(
                {blocker.reason_code for blocker in plan.blockers},
                {"reachable_import_has_no_checked_boundary"},
            )

    def test_register_iat_seed_does_not_cross_an_intervening_branch(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = _write_fixture(
                Path(temporary),
                via_thunk=False,
                register_indirect=True,
                split_register_seed=True,
                intervening_register_branch=True,
            )
            plan = plan_static_machine_import_contracts(**fixture.plan_arguments)

            self.assertFalse(plan.complete)
            self.assertEqual(plan.boundaries, ())
            self.assertEqual(
                {blocker.reason_code for blocker in plan.blockers},
                {"reachable_import_has_no_checked_boundary"},
            )

    def test_register_iat_seed_survives_checked_stack_save_and_restore(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = _write_fixture(
                Path(temporary),
                via_thunk=False,
                restored_register_call=True,
            )
            plan = plan_static_machine_import_contracts(**fixture.plan_arguments)

            self.assertTrue(plan.complete, plan.to_json())
            self.assertEqual(len(plan.boundaries), 2)
            boundary = plan.boundaries[1]
            self.assertEqual(boundary.route, "restored_register_indirect")
            self.assertEqual(boundary.dispatch_register, "ecx")
            self.assertEqual(boundary.iat_rva, 0x2040)
            self.assertEqual(boundary.seed_rva, 0x1000)
            self.assertEqual(boundary.restore_rva, 0x1013)
            self.assertEqual(boundary.source_rva, 0x1020)
            self.assertEqual(boundary.saved_stack_offset, 8)

    def test_unknown_abi_and_effects_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            fixture = _write_fixture(root, via_thunk=False)
            profile = root / "profile.json"
            payload = json.loads(profile.read_text(encoding="utf-8"))
            entry = payload["machine_import_signatures"][0]
            entry["abi_template"] = "unknown-abi"
            entry.pop("world_effect")
            profile.write_text(json.dumps(payload), encoding="utf-8")

            plan = plan_static_machine_import_contracts(**fixture.plan_arguments)

            self.assertFalse(plan.profile_ready)
            self.assertEqual(
                {item.reason_code for item in plan.blockers},
                {"invalid_machine_import_profile"},
            )
            self.assertEqual(plan.signatures, ())

    def test_reference_inventory_mismatch_is_a_hard_blocker(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            fixture = _write_fixture(root, via_thunk=False)
            reference = root / "reference-contract.json"
            payload = json.loads(reference.read_text(encoding="utf-8"))
            payload["original"]["imports"][0]["thunk_rva"] += 4
            reference.write_text(json.dumps(payload), encoding="utf-8")

            plan = plan_static_machine_import_contracts(**fixture.plan_arguments)

            self.assertFalse(plan.complete)
            self.assertIn(
                "exact_import_inventory_mismatch",
                {item.reason_code for item in plan.blockers},
            )

    def test_variadic_site_requires_contiguous_static_argument_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            fixture = _write_fixture(root, via_thunk=True, variadic=True)
            state_machine = root / "state-machine.jsonl"
            rows = [json.loads(line) for line in state_machine.read_text().splitlines()]
            rows[0]["external_events"][0]["stack_inputs"] = [
                {"offset": 0, "width": 4},
                {"offset": 8, "width": 4},
            ]
            state_machine.write_text(
                "".join(json.dumps(row) + "\n" for row in rows),
                encoding="utf-8",
            )

            plan = plan_static_machine_import_contracts(**fixture.plan_arguments)

            self.assertFalse(plan.complete)
            self.assertIn(
                "variadic_argument_inventory_incomplete",
                {item.reason_code for item in plan.blockers},
            )
            self.assertNotIn(
                "reachable_import_has_no_checked_boundary",
                {item.reason_code for item in plan.blockers},
            )

    def test_variadic_site_exports_boundary_inventory_not_global_minimum(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            fixture = _write_fixture(root, via_thunk=True, variadic=True)

            plan = plan_static_machine_import_contracts(**fixture.plan_arguments)

            self.assertTrue(plan.complete, plan.to_json())
            self.assertFalse(plan.global_contracts_ready)
            self.assertEqual(plan.boundaries[0].argument_words, 2)
            lean, report = write_static_machine_import_contracts(
                root / "generated", plan, fixture.bindings
            )
            source = lean.read_text(encoding="utf-8")
            self.assertIn(
                "def generatedMachineImportBoundaryCallContracts :", source
            )
            self.assertIn(
                "def generatedMachineImportBoundaryContracts :", source
            )
            self.assertNotIn(
                "def generatedMachineImportCallContracts :", source
            )
            self.assertEqual(
                json.loads(report.read_text(encoding="utf-8"))[
                    "global_contract_export"
                ]["residuals"],
                [{
                    "import": "fixture.dll!FixtureCall",
                    "reason_code": "variadic_requires_boundary_contract",
                }],
            )

    def test_nested_callback_protocol_has_checked_boundary_contract(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            fixture = _write_fixture(root, via_thunk=False, nested=True)
            plan = plan_static_machine_import_contracts(**fixture.plan_arguments)

            self.assertTrue(plan.profile_ready, plan.to_json())
            self.assertTrue(plan.complete, plan.to_json())
            self.assertEqual(plan.signatures[0].callback_mode, "nestedFrames")
            self.assertEqual(len(plan.boundaries), 1)
            self.assertFalse(plan.global_contracts_ready)
            lean, report = write_static_machine_import_contracts(
                root / "generated", plan, fixture.bindings
            )
            self.assertNotIn(
                "def generatedMachineImportCallContracts :",
                lean.read_text(encoding="utf-8"),
            )
            self.assertIn(
                "def generatedMachineImportBoundaryCallContracts :",
                lean.read_text(encoding="utf-8"),
            )
            self.assertEqual(
                json.loads(report.read_text(encoding="utf-8"))[
                    "global_contract_export"
                ],
                {
                    "status": "incomplete",
                    "residuals": [{
                        "import": "fixture.dll!FixtureCall",
                        "reason_code": "nested_frames_require_boundary_contract",
                    }],
                },
            )
            self.assertEqual(plan.blockers, ())


class _Fixture:
    def __init__(self, root: Path, *, pe: Path) -> None:
        self.bindings = StaticMachineImportLeanBindings(
            module="StageA.GeneratedStaticMachineImportFixturePE",
            namespace="StageA.Generated.StaticMachineImportFixturePE",
        )
        self.plan_arguments = {
            "original_pe": pe,
            "reference_contract": root / "reference-contract.json",
            "state_machine": root / "state-machine.jsonl",
            "required_imports": [
                StaticImportIdentity("fixture.dll", symbol="FixtureCall")
            ],
            "reachable_source_rvas": [0x1000],
            "profile_paths": [root / "profile.json"],
        }


def _write_fixture(
    root: Path,
    *,
    via_thunk: bool,
    variadic: bool = False,
    nested: bool = False,
    register_indirect: bool = False,
    split_register_seed: bool = False,
    intervening_register_call: bool = False,
    intervening_register_branch: bool = False,
    restored_register_call: bool = False,
    framed_tail: bool = False,
) -> _Fixture:
    if framed_tail:
        return _write_framed_tail_fixture(root, via_thunk=via_thunk)
    if restored_register_call:
        return _write_restored_register_fixture(root)
    iat_va = 0x402040
    if register_indirect:
        if intervening_register_call and intervening_register_branch:
            raise AssertionError("only one intervening register control is supported")
        intervening = (
            b"\xff\xd0" if intervening_register_call else
            b"\x74\x00" if intervening_register_branch else
            b""
        )
        intervening_size = len(intervening)
        caller = (
            b"\x53\x83\xec\x04"
            + b"\x8b\x0d" + iat_va.to_bytes(4, "little")
            + intervening
            + b"\xc7\x04\x24\x07\x00\x00\x00\xff\xd1"
        )
        code = caller
    elif via_thunk:
        caller = b"\xc7\x04\x24\x07\x00\x00\x00\xe8\x14\x00\x00\x00"
        code = caller.ljust(0x20, b"\x90") + b"\xff\x25" + iat_va.to_bytes(4, "little")
    else:
        caller = b"\xc7\x04\x24\x07\x00\x00\x00\xff\x15" + iat_va.to_bytes(4, "little")
        code = caller
    pe_path = root / "fixture.exe"
    pe_path.write_bytes(pe32_import_image(
        code, symbol="FixtureCall", dll="fixture.dll"
    ))
    binary = _parse_stage_a_pe(pe_path)
    try:
        imports = [
            {
                "dll": item.dll,
                "symbol": item.symbol,
                "ordinal": item.ordinal,
                "thunk_rva": item.thunk_rva,
            }
            for item in binary.imports
        ]
    finally:
        binary.pe.close()
    (root / "reference-contract.json").write_text(
        json.dumps({"original": {"imports": imports}}), encoding="utf-8"
    )

    arity: dict[str, object]
    if variadic:
        arity = {
            "kind": "variadic",
            "minimum_words": 2,
            "format_argument": 1,
            "format_unit_bytes": 1,
        }
        profile_entries_key = "machine_import_signatures"
    else:
        arity = {"kind": "fixed", "words": 1}
        profile_entries_key = "machine_import_signatures"
    profile_entry: dict[str, object] = {
        "import": {"dll": "fixture.dll", "symbol": "FixtureCall"},
        "abi_template": "pe32-cdecl-v1",
        "arity": arity,
        "memory_effect": "none",
        "memory_footprints": [],
        "world_effect": "none",
    }
    if nested:
        profile_entry.update({
            "disposition": "protocol",
            "callback_behavior": "nested_frames",
            "memory_effect": "relationalState",
        })
    (root / "profile.json").write_text(json.dumps({
        "format": "stage-a-static-machine-import-profile-v1",
        "id": "synthetic-machine-import-profile-v1",
        profile_entries_key: [profile_entry],
    }), encoding="utf-8")

    caller_row = {
        "original": {
            "rva_start": 0x1000,
            "rva_end": 0x1000 + len(caller),
            "size": len(caller),
        },
        "instructions": (
            ([
                {"rva": 0x1000, "size": 1, "bytes": "53",
                 "mnemonic": "push", "op_str": "ebx"},
                {"rva": 0x1001, "size": 3, "bytes": "83ec04",
                 "mnemonic": "sub", "op_str": "esp, 4"},
                {"rva": 0x1004, "size": 6, "bytes": "8b0d40204000",
                 "mnemonic": "mov", "op_str": "ecx, dword ptr [0x402040]"},
            ] + ([{
                "rva": 0x100A,
                "size": 2,
                "bytes": intervening.hex(),
                "mnemonic": "call" if intervening_register_call else "je",
                "op_str": "eax" if intervening_register_call else "0x40100c",
            }] if intervening else []) + [
                {"rva": 0x100A + intervening_size,
                 "size": 7, "bytes": "c7042407000000",
                 "mnemonic": "mov", "op_str": "dword ptr [esp], 7"},
                {"rva": 0x1011 + intervening_size,
                 "size": 2, "bytes": "ffd1",
                 "mnemonic": "call", "op_str": "ecx"},
            ])
            if register_indirect else
            [
                {"rva": 0x1000, "size": 7, "bytes": "c7042407000000",
                 "mnemonic": "mov", "op_str": "dword ptr [esp], 7"},
                {"rva": 0x1007, "size": 5, "bytes": "e814000000",
                 "mnemonic": "call", "op_str": "0x401020"},
            ]
            if via_thunk else
            [
                {"rva": 0x1000, "size": 7, "bytes": "c7042407000000",
                 "mnemonic": "mov", "op_str": "dword ptr [esp], 7"},
                {"rva": 0x1007, "size": 6, "bytes": "ff1540204000",
                 "mnemonic": "call", "op_str": "dword ptr [0x402040]"},
            ]
        ),
        "external_events": ([] if register_indirect else [{
            "dll": "fixture.dll",
            "symbol": "FixtureCall",
            "ordinal": None,
            "stack_inputs": [
                {"offset": offset, "width": 4}
                for offset in ((0, 4) if variadic else (0,))
            ],
        }]),
        "ordered_events": ([{
            "kind": "indirect_call",
            "instruction_rva": 0x1011 + intervening_size,
            "target": {
                "op": "load",
                "width": 4,
                "address": {"op": "const", "width": 32, "value": iat_va},
            },
            "stack_inputs": [{"offset": 0, "width": 4}],
        }] if register_indirect else []),
    }
    rows = [caller_row]
    if split_register_seed:
        if not register_indirect:
            raise AssertionError("split_register_seed requires register_indirect")
        rows = [{
            **caller_row,
            "original": {"rva_start": 0x1000, "rva_end": 0x100A, "size": 10},
            "instructions": caller_row["instructions"][:3],
            "ordered_events": [],
        }, {
            **caller_row,
            "original": {
                "rva_start": 0x100A,
                "rva_end": 0x1013 + intervening_size,
                "size": 9 + intervening_size,
            },
            "instructions": caller_row["instructions"][3:],
            "ordered_events": [{
                "kind": "indirect_call",
                "instruction_rva": 0x1011 + intervening_size,
                "target": {"op": "reg", "name": "ecx", "width": 32},
                "stack_inputs": [{"offset": 0, "width": 4}],
            }],
        }]
    if via_thunk:
        rows.append({
            "original": {"rva_start": 0x1020, "rva_end": 0x1026, "size": 6},
            "instructions": [{
                "rva": 0x1020, "size": 6, "bytes": "ff2540204000",
                "mnemonic": "jmp", "op_str": "dword ptr [0x402040]",
            }],
            "external_events": [],
            "ordered_events": [],
        })
    (root / "state-machine.jsonl").write_text(
        "".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8"
    )
    fixture = _Fixture(root, pe=pe_path)
    if split_register_seed:
        fixture.plan_arguments["reachable_source_rvas"] = [0x1000, 0x100A]
    return fixture


def _write_restored_register_fixture(root: Path) -> _Fixture:
    iat_va = 0x402040
    seed = (
        b"\x8b\x0d" + iat_va.to_bytes(4, "little")
        + b"\x89\x4c\x24\x08"
        + b"\xc7\x04\x24\x07\x00\x00\x00"
        + b"\xff\xd1"
    )
    restore = b"\x83\xec\x04\x8b\x4c\x24\x08\x85\xc0\x74\x02"
    dispatch = b"\xc7\x04\x24\x08\x00\x00\x00\xff\xd1"
    code = seed + restore + b"\x90\x90" + dispatch
    pe_path = root / "fixture.exe"
    pe_path.write_bytes(pe32_import_image(
        code, symbol="FixtureCall", dll="fixture.dll"
    ))
    binary = _parse_stage_a_pe(pe_path)
    try:
        imports = [
            {
                "dll": item.dll,
                "symbol": item.symbol,
                "ordinal": item.ordinal,
                "thunk_rva": item.thunk_rva,
            }
            for item in binary.imports
        ]
    finally:
        binary.pe.close()
    (root / "reference-contract.json").write_text(
        json.dumps({"original": {"imports": imports}}), encoding="utf-8"
    )
    (root / "profile.json").write_text(json.dumps({
        "format": "stage-a-static-machine-import-profile-v1",
        "id": "synthetic-restored-register-profile-v1",
        "machine_import_signatures": [{
            "import": {"dll": "fixture.dll", "symbol": "FixtureCall"},
            "abi_template": "pe32-stdcall-v1",
            "arity": {"kind": "fixed", "words": 1},
            "memory_effect": "readOnly",
            "memory_footprints": [],
            "world_effect": "none",
        }],
    }), encoding="utf-8")
    rows = [{
        "original": {"rva_start": 0x1000, "rva_end": 0x1013, "size": 0x13},
        "instructions": [
            {"rva": 0x1000, "size": 6, "bytes": "8b0d40204000",
             "mnemonic": "mov", "op_str": "ecx, dword ptr [0x402040]"},
            {"rva": 0x1006, "size": 4, "bytes": "894c2408",
             "mnemonic": "mov", "op_str": "dword ptr [esp + 8], ecx"},
            {"rva": 0x100A, "size": 7, "bytes": "c7042407000000",
             "mnemonic": "mov", "op_str": "dword ptr [esp], 7"},
            {"rva": 0x1011, "size": 2, "bytes": "ffd1",
             "mnemonic": "call", "op_str": "ecx"},
        ],
        "external_events": [],
        "ordered_events": [{
            "kind": "indirect_call",
            "instruction_rva": 0x1011,
            "target": {
                "op": "load",
                "width": 4,
                "address": {"op": "const", "width": 32, "value": iat_va},
            },
            "stack_inputs": [{"offset": 0, "width": 4}],
        }],
    }, {
        "original": {"rva_start": 0x1013, "rva_end": 0x101E, "size": 0xB},
        "instructions": [
            {"rva": 0x1013, "size": 3, "bytes": "83ec04",
             "mnemonic": "sub", "op_str": "esp, 4"},
            {"rva": 0x1016, "size": 4, "bytes": "8b4c2408",
             "mnemonic": "mov", "op_str": "ecx, dword ptr [esp + 8]"},
            {"rva": 0x101A, "size": 2, "bytes": "85c0",
             "mnemonic": "test", "op_str": "eax, eax"},
            {"rva": 0x101C, "size": 2, "bytes": "7402",
             "mnemonic": "je", "op_str": "0x401020"},
        ],
        "external_events": [],
        "ordered_events": [],
    }, {
        "original": {"rva_start": 0x1020, "rva_end": 0x1029, "size": 9},
        "instructions": [
            {"rva": 0x1020, "size": 7, "bytes": "c7042408000000",
             "mnemonic": "mov", "op_str": "dword ptr [esp], 8"},
            {"rva": 0x1027, "size": 2, "bytes": "ffd1",
             "mnemonic": "call", "op_str": "ecx"},
        ],
        "external_events": [],
        "ordered_events": [{
            "kind": "indirect_call",
            "instruction_rva": 0x1027,
            "target": {"op": "reg", "name": "ecx", "width": 32},
            "stack_inputs": [{"offset": 0, "width": 4}],
        }],
    }]
    (root / "state-machine.jsonl").write_text(
        "".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8"
    )
    fixture = _Fixture(root, pe=pe_path)
    fixture.plan_arguments["reachable_source_rvas"] = [0x1000, 0x1013, 0x1020]
    return fixture


def _write_framed_tail_fixture(root: Path, *, via_thunk: bool) -> _Fixture:
    fixture = _write_fixture(root, via_thunk=False)
    iat_va = 0x402040
    caller = b"\xe8\x0b\x00\x00\x00"
    if via_thunk:
        tail = b"\xe9\x0b\x00\x00\x00"
        thunk = b"\xff\x25" + iat_va.to_bytes(4, "little")
        code = caller.ljust(0x10, b"\x90") + tail
        code = code.ljust(0x20, b"\x90") + thunk
    else:
        entry = b"\xe8\x1b\x00\x00\x00"
        tail = b"\xff\x25" + iat_va.to_bytes(4, "little")
        code = caller.ljust(0x10, b"\x90") + entry + tail
        code = code.ljust(0x30, b"\x90") + b"\xc3"
    pe_path = root / "fixture.exe"
    pe_path.write_bytes(pe32_import_image(
        code, symbol="FixtureCall", dll="fixture.dll"
    ))
    binary = _parse_stage_a_pe(pe_path)
    try:
        imports = [
            {
                "dll": item.dll,
                "symbol": item.symbol,
                "ordinal": item.ordinal,
                "thunk_rva": item.thunk_rva,
            }
            for item in binary.imports
        ]
    finally:
        binary.pe.close()
    (root / "reference-contract.json").write_text(
        json.dumps({"original": {"imports": imports}}), encoding="utf-8"
    )
    rows = [{
        "function": "caller",
        "original": {"rva_start": 0x1000, "rva_end": 0x1005, "size": 5},
        "instructions": [{
            "rva": 0x1000, "size": 5, "bytes": "e80b000000",
            "mnemonic": "call", "op_str": "0x401010",
        }],
        "external_events": [],
        "ordered_events": [],
    }]
    if via_thunk:
        rows.extend([{
            "function": "tail-wrapper",
            "original": {"rva_start": 0x1010, "rva_end": 0x1015, "size": 5},
            "instructions": [{
                "rva": 0x1010, "size": 5, "bytes": "e90b000000",
                "mnemonic": "jmp", "op_str": "0x401020",
            }],
            "external_events": [],
            "ordered_events": [],
        }, {
            "function": "FixtureCall",
            "original": {"rva_start": 0x1020, "rva_end": 0x1026, "size": 6},
            "instructions": [{
                "rva": 0x1020, "size": 6, "bytes": "ff2540204000",
                "mnemonic": "jmp", "op_str": "dword ptr [0x402040]",
            }],
            "external_events": [{
                "dll": "fixture.dll", "symbol": "FixtureCall", "ordinal": None,
                "stack_inputs": [{"offset": 0, "width": 4}],
            }],
            "ordered_events": [],
        }])
    else:
        rows.extend([{
            "function": "tail-wrapper",
            "original": {"rva_start": 0x1010, "rva_end": 0x1015, "size": 5},
            "instructions": [{
                "rva": 0x1010, "size": 5, "bytes": "e81b000000",
                "mnemonic": "call", "op_str": "0x401030",
            }],
            "external_events": [],
            "ordered_events": [],
        }, {
            "function": "tail-wrapper",
            "original": {"rva_start": 0x1015, "rva_end": 0x101B, "size": 6},
            "instructions": [{
                "rva": 0x1015, "size": 6, "bytes": "ff2540204000",
                "mnemonic": "jmp", "op_str": "dword ptr [0x402040]",
            }],
            "external_events": [{
                "dll": "fixture.dll", "symbol": "FixtureCall", "ordinal": None,
                "stack_inputs": [{"offset": 0, "width": 4}],
            }],
            "ordered_events": [],
        }, {
            "function": "helper",
            "original": {"rva_start": 0x1030, "rva_end": 0x1031, "size": 1},
            "instructions": [{
                "rva": 0x1030, "size": 1, "bytes": "c3",
                "mnemonic": "ret", "op_str": "",
            }],
            "external_events": [],
            "ordered_events": [],
        }])
    (root / "state-machine.jsonl").write_text(
        "".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8"
    )
    fixture.plan_arguments["reachable_source_rvas"] = [
        int(row["original"]["rva_start"]) for row in rows
    ]
    return fixture


if __name__ == "__main__":
    unittest.main()
