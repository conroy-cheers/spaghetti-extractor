from __future__ import annotations

from tests.unit.reconstruction.ir._support import *


class ReconstructionIRMaterializationModelTests(unittest.TestCase):
    def test_executable_data_and_instruction_interiors_precede_control_closure(self) -> None:
        def unit(
            identity: str,
            start: int,
            end: int,
            *,
            outcome: dict[str, object],
            instruction_end: int | None = None,
        ) -> dict[str, object]:
            return {
                "id": identity,
                "source": {
                    "original": {"rva_start": start, "rva_end": end},
                },
                "source_location": {"block_id": identity},
                "instructions": [{
                    "rva_start": start,
                    "rva_end": instruction_end or end,
                    "instruction_sha256": "a" * 64,
                }],
                "semantics": {
                    "outcome": outcome,
                    "external_events": [],
                    "register_writes": [],
                },
                "control": {
                    "kind": outcome["kind"],
                    "direct_targets": (
                        [outcome["target_rva"]]
                        if isinstance(outcome.get("target_rva"), int)
                        else []
                    ),
                    "has_indirect_target": outcome["kind"] == "indirect_jump",
                },
            }

        table_expression = {
            "op": "load",
            "width": 4,
            "address": {
                "op": "add32",
                "args": [
                    {"op": "const", "value": 0x401010, "width": 32},
                    {
                        "op": "mul32",
                        "args": [
                            {"op": "const", "value": 0, "width": 32},
                            {"op": "const", "value": 4, "width": 32},
                        ],
                    },
                ],
            },
        }
        units = [
            unit(
                "root",
                0x1000,
                0x1002,
                outcome={"kind": "indirect_jump", "target": table_expression},
            ),
            unit(
                "table-decode",
                0x1010,
                0x1014,
                outcome={"kind": "fallthrough", "target_rva": 0x1014},
            ),
            unit(
                "target",
                0x1020,
                0x1025,
                outcome={"kind": "return"},
            ),
            unit(
                "interior-decode",
                0x1021,
                0x1023,
                outcome={"kind": "return"},
            ),
        ]
        image = bytearray(0x30)
        image[0x10:0x14] = (0x401020).to_bytes(4, "little")
        with tempfile.TemporaryDirectory() as temporary:
            original = Path(temporary) / "original.exe"
            original.write_bytes(pe32_image(bytes(image), virtual_size=len(image)))
            binary = _parse_stage_a_pe(original)
            try:
                retained, classification, issues, recoveries = (
                    _classify_executable_data_before_control(
                        binary=binary,
                        units=units,
                        static_program={"roots": [], "noncode_ranges": []},
                        finite_dataflow_factory=FiniteU32Dataflow,
                    )
                )
            finally:
                binary.pe.close()

        self.assertEqual(classification["status"], "complete")
        self.assertEqual(issues, [])
        self.assertEqual(len(recoveries), 1)
        self.assertEqual(recoveries[0]["kind"], "indirect_jump")
        self.assertEqual(
            recoveries[0]["recovery_kind"],
            "pe32_indexed_absolute_jump_table",
        )
        self.assertEqual(
            recoveries[0]["target_set_dependency"]["dependency_kind"],
            "bounded_selector",
        )
        self.assertEqual(
            [row["id"] for row in retained],
            ["root", "target"],
        )
        self.assertEqual(
            [
                (row["rva_start"], row["rva_end"])
                for row in classification["immutable_data_ranges"]
            ],
            [(0x1010, 0x1014)],
        )
        self.assertEqual(
            {row["unit_id"]: row["reason"] for row in classification["excluded_units"]},
            {
                "table-decode": "intersects_checked_immutable_executable_data",
                "interior-decode": "starts_inside_rooted_reachable_instruction",
            },
        )

    def test_predecessor_history_crosses_one_instruction_cutpoint(self) -> None:
        compare = {
            "id": "compare",
            "source": {"original": {"rva_start": 0x1000, "rva_end": 0x1003}},
            "instructions": [{"mnemonic": "cmp"}],
            "semantics": {
                "external_events": [],
                "outcome": {"kind": "fallthrough", "target_rva": 0x1003},
            },
        }
        branch = {
            "id": "branch",
            "source": {"original": {"rva_start": 0x1003, "rva_end": 0x1005}},
            "instructions": [{"mnemonic": "ja"}],
            "semantics": {
                "external_events": [],
                "outcome": {
                    "kind": "branch",
                    "true_target_rva": 0x1100,
                    "false_target_rva": 0x1005,
                },
            },
        }

        history = _bounded_predecessor_instruction_history(
            branch,
            predecessors_by_target={0x1003: [compare]},
        )

        self.assertEqual(
            [instruction["mnemonic"] for instruction in history],
            ["cmp", "ja"],
        )

    def test_global_target_profile_does_not_replace_finite_site_inventory(self) -> None:
        row = _row(
            "semantic-transfer:indirect",
            0x1000,
            b"\xff\xe0",
            outcome={"kind": "indirect_jump", "target": _expr_register("eax")},
        )
        profile = {
            "format": "stage-a-indirect-target-profile-v1",
            "id": "pe32-static-cutpoints-and-paired-callables-v1",
            "status": "accepted_assumption",
            "internal_target_domain": "all_checked_machine_ir_unit_starts",
            "external_target_domain": "paired_external_callable_resources",
            "runtime_rejection_required": True,
            "assumption": {
                "id": "complete-static-indirect-target-recovery",
                "scope": "fixture",
                "statement": "Fixture indirect targets remain in the checked domains.",
            },
        }
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            original = root / "original.exe"
            machine = root / "state-machine.jsonl"
            profile_path = root / "target-profile.json"
            original.write_bytes(pe32_image(b"\xff\xe0", virtual_size=2))
            _write_machine(machine, [row])
            profile_path.write_text(json.dumps(profile), encoding="utf-8")

            unprofiled = export_machine_ir_package(
                state_machine=machine, original_pe=original, out=root / "unprofiled"
            )
            profiled = export_machine_ir_package(
                state_machine=machine,
                original_pe=original,
                indirect_target_profile=profile_path,
                out=root / "profiled",
            )
            manifest = _read_json(profiled.manifest)

            self.assertEqual(unprofiled.status, "incomplete")
            self.assertEqual(profiled.status, "incomplete")
            self.assertEqual(
                manifest["control"]["counts"]["closed_indirect_exits"], 0
            )
            self.assertEqual(
                manifest["control"]["indirect_exits"][0]["closure"],
                "explicit_trusted_target_profile_without_inventory",
            )
            self.assertEqual(
                manifest["control"]["reachability"]["status"], "incomplete"
            )
            self.assertEqual(
                manifest["trust_assumptions"][0]["id"],
                "complete-static-indirect-target-recovery",
            )

    def test_exact_finite_target_is_materialized_from_pe_bytes(self) -> None:
        encoded = b"\xff\x24\x85\x10\x10\x40\x00"
        target_expression = {
            "op": "load",
            "width": 4,
            "address": {
                "op": "add32",
                "args": [
                    {"op": "const", "value": 0x401010, "width": 32},
                    {
                        "op": "mul32",
                        "args": [
                            {"op": "const", "value": 0, "width": 32},
                            {"op": "const", "value": 4, "width": 32},
                        ],
                    },
                ],
            },
        }
        row = _row(
            "semantic-transfer:dispatch",
            0x1000,
            encoded,
            outcome={"kind": "indirect_jump", "target": target_expression},
        )
        code = bytearray(b"\x90" * 0x22)
        code[: len(encoded)] = encoded
        code[0x10:0x14] = (0x401020).to_bytes(4, "little")
        code[0x20:0x22] = b"\x90\xc3"

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            original = root / "original.exe"
            machine = root / "state-machine.jsonl"
            original.write_bytes(pe32_image(bytes(code), virtual_size=len(code)))
            _write_machine(machine, [row])

            package = export_machine_ir_package(
                state_machine=machine,
                original_pe=original,
                out=root / "out",
            )
            manifest = _read_json(package.manifest)
            units = _read_jsonl(package.machine_ir)
            recovery = manifest["control"]["recovered_indirect_targets"][0]

        materialized = next(
            unit
            for unit in units
            if unit["source"]["original"]["rva_start"] == 0x1020
        )
        self.assertEqual(materialized["status"], "qualified")
        self.assertEqual(
            materialized["preparation"]["target_cutpoint_materialization"][
                "target_rva"
            ],
            0x1020,
        )
        self.assertEqual(recovery["unit_binding"]["status"], "complete")
        self.assertEqual(recovery["target_unit_ids"], [materialized["id"]])
        self.assertEqual(manifest["counts"]["materialized_target_units"], 1)
        self.assertEqual(
            manifest["control"]["target_cutpoint_materialization"]["status"],
            "complete",
        )

    def test_rooted_direct_target_materialization_reaches_fixed_point(self) -> None:
        root = _row(
            "semantic-transfer:root",
            0x1000,
            b"\x90",
            outcome={"kind": "fallthrough", "target_rva": 0x1001},
        )
        code = b"\x90\xeb\x01\x90\xc3"

        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            original = directory / "original.exe"
            machine = directory / "state-machine.jsonl"
            original.write_bytes(pe32_image(code, virtual_size=len(code)))
            _write_machine(machine, [root])

            package = export_machine_ir_package(
                state_machine=machine,
                original_pe=original,
                out=directory / "out",
            )
            manifest = _read_json(package.manifest)
            units = _read_jsonl(package.machine_ir)

        materialized_starts = {
            unit["source"]["original"]["rva_start"]
            for unit in units
            if "target_cutpoint_materialization" in unit["preparation"]
        }
        closure = manifest["control"]["target_cutpoint_materialization"]
        self.assertEqual(materialized_starts, {0x1001, 0x1004})
        self.assertTrue(closure["cutpoint_closure_converged"])
        self.assertEqual(
            [row["materialized_units"] for row in closure["cutpoint_closure_iterations"]],
            [1, 1, 0],
        )

    def test_unreachable_direct_target_is_not_materialized(self) -> None:
        root = _row(
            "semantic-transfer:root",
            0x1000,
            b"\xc3",
            outcome={"kind": "return", "stack_pop_bytes": 4},
        )
        speculative = _row(
            "semantic-transfer:speculative",
            0x1001,
            b"\xeb\xfe",
            outcome={"kind": "direct_jump", "target_rva": 0xDEADBEEF},
        )
        code = b"\xc3\xeb\xfe"

        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            original = directory / "original.exe"
            machine = directory / "state-machine.jsonl"
            original.write_bytes(pe32_image(code, virtual_size=len(code)))
            _write_machine(machine, [root, speculative])

            package = export_machine_ir_package(
                state_machine=machine,
                original_pe=original,
                out=directory / "out",
            )
            manifest = _read_json(package.manifest)

        closure = manifest["control"]["target_cutpoint_materialization"]
        self.assertEqual(closure["status"], "complete")
        self.assertEqual(closure["counts"]["materialized_units"], 0)
        self.assertEqual(closure["issues"], [])

    def test_terminating_external_disposition_removes_nominal_fallthrough(self) -> None:
        event = {
            "kind": "external_call",
            "instruction_rva": 0x1000,
            "return_rva": 0x1006,
            "dll": "msvcrt.dll",
            "symbol": "abort",
            "ordinal": None,
            "arguments": [],
        }
        row = _row(
            "semantic-transfer:abort",
            0x1000,
            b"\xff\x15\x40\x20\x40\x00",
            outcome={"kind": "fallthrough", "target_rva": 0x1006},
            external_events=[event],
            ordered_events=[{"family": "external", **event}],
            control_disposition={
                "kind": "terminates_after_external_event",
                "authority": "external_profile_machine_import_contract",
            },
        )

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            original = root / "original.exe"
            machine = root / "state-machine.jsonl"
            original.write_bytes(
                pe32_import_image(
                    b"\xff\x15\x40\x20\x40\x00",
                    symbol="abort",
                    dll="msvcrt.dll",
                )
            )
            _write_machine(machine, [row])

            package = export_machine_ir_package(
                state_machine=machine, original_pe=original, out=root / "out"
            )
            manifest = _read_json(package.manifest)
            unit = _read_jsonl(package.machine_ir)[0]

            self.assertEqual(package.status, "qualified")
            self.assertEqual(
                manifest["authority_bindings"]["binary"]["machine_ir_sha256"],
                manifest["artifacts"]["machine_ir"]["sha256"],
            )
            self.assertEqual(
                manifest["authority_bindings"]["units"][0]["unit_id"],
                unit["id"],
            )
            self.assertEqual(manifest["control"]["counts"]["direct_targets"], 0)
            self.assertEqual(unit["control"]["direct_targets"], [])
            self.assertEqual(
                unit["control"]["disposition"]["kind"],
                "terminates_after_external_event",
            )

    def test_checked_decode_site_is_bound_into_canonical_call_event(self) -> None:
        call = b"\xff\x15\x40\x20\x40\x00"
        event = {
            "kind": "external_call",
            "return_rva": 0x1006,
            "dll": "KERNEL32.dll",
            "symbol": "GetLastError",
            "ordinal": None,
            "arguments": [],
        }
        rows = [
            _row(
                "semantic-transfer:call",
                0x1000,
                call,
                outcome={"kind": "fallthrough", "target_rva": 0x1006},
                external_events=[event],
                ordered_events=[{
                    "family": "external",
                    "instruction_rva": 0x1000,
                    **event,
                }],
            ),
            _row(
                "semantic-transfer:return",
                0x1006,
                b"\xc3",
                outcome={"kind": "return"},
            ),
        ]

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            original = root / "original.exe"
            machine = root / "state-machine.jsonl"
            original.write_bytes(
                pe32_import_image(call + b"\xc3", symbol="GetLastError")
            )
            _write_machine(machine, rows)

            package = export_machine_ir_package(
                state_machine=machine, original_pe=original, out=root / "out"
            )
            unit = _read_jsonl(package.machine_ir)[0]

            self.assertEqual(package.status, "qualified")
            self.assertEqual(
                unit["semantics"]["external_events"][0]["instruction_rva"],
                0x1000,
            )

    def test_immutable_pointer_slot_refines_indirect_decode_to_internal_call(self) -> None:
        call = b"\xff\x15\x40\x20\x40\x00"
        event = {
            "kind": "internal_call",
            "return_rva": 0x1006,
            "target_rva": 0x1010,
        }
        rows = [
            _row(
                "semantic-transfer:call",
                0x1000,
                call,
                outcome={"kind": "fallthrough", "target_rva": 0x1006},
                external_events=[event],
                ordered_events=[{
                    "family": "external",
                    "instruction_rva": 0x1000,
                    **event,
                }],
            ),
            _row(
                "semantic-transfer:return",
                0x1010,
                b"\xc3",
                outcome={"kind": "return"},
            ),
        ]

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            original = root / "original.exe"
            machine = root / "state-machine.jsonl"
            original.write_bytes(
                pe32_image_with_pointer_slot(
                    call.ljust(0x10, b"\x90") + b"\xc3",
                    target_rva=0x1010,
                )
            )
            _write_machine(machine, rows)

            package = export_machine_ir_package(
                state_machine=machine, original_pe=original, out=root / "out"
            )
            unit = _read_jsonl(package.machine_ir)[0]
            reconciliation = unit["control"]["decoded_reconciliation"]

            self.assertEqual(package.status, "qualified")
            self.assertEqual(reconciliation["status"], "complete")
            witness = reconciliation["decoded_call_sites"][0][
                "immutable_internal_target"
            ]
            self.assertEqual(witness["slot_rva"], 0x2040)
            self.assertEqual(witness["target_rva"], 0x1010)
            self.assertEqual(
                witness["authority"],
                "exact_initialized_nonwritable_pe_slot_v1",
            )


if __name__ == "__main__":
    unittest.main()
