from __future__ import annotations

from tests.unit.reconstruction.ir._support import *


class ReconstructionIRFailurePolicyTests(unittest.TestCase):
    def test_structured_recovery_failure_does_not_require_legacy_message(self) -> None:
        self.assertEqual(
            _recovery_failure_message({"code": "value_origin_unresolved"}),
            "value_origin_unresolved",
        )

    def test_unknown_non_control_terminal_instruction_recovers_fallthrough(self):
        instruction = _Instruction(
            rva=0x1000,
            size=1,
            digest="0" * 64,
            mnemonic="inc",
            operands=(),
            registers_read=("eax",),
            registers_written=("eax",),
            groups=("not64bitmode",),
        )

        recovered = _recover_unknown_fallthrough(
            {"kind": "unknown"}, [instruction], RvaSpan(0x1000, 0x1001)
        )

        self.assertEqual(
            recovered["outcome"],
            {"kind": "fallthrough", "target_rva": 0x1001},
        )

    def test_unknown_control_or_trap_instruction_does_not_recover_fallthrough(self):
        def instruction(mnemonic: str, groups: tuple[str, ...]) -> _Instruction:
            return _Instruction(
                rva=0x1000,
                size=2,
                digest="0" * 64,
                mnemonic=mnemonic,
                operands=(),
                registers_read=(),
                registers_written=(),
                groups=groups,
            )

        span = RvaSpan(0x1000, 0x1002)
        self.assertIsNone(
            _recover_unknown_fallthrough(
                {"kind": "unknown"}, [instruction("jmp", ("jump",))], span
            )
        )
        self.assertIsNone(
            _recover_unknown_fallthrough(
                {"kind": "unknown"}, [instruction("ud2", ())], span
            )
        )

    def test_exceptional_control_closes_only_explicit_terminal_faults(self) -> None:
        terminal_fault = {
            "kind": "divide_error",
            "condition": {"op": "true"},
            "instruction_rva": 0x1000,
        }
        row = _row(
            "semantic-transfer:fault",
            0x1000,
            b"\x90",
            outcome={"kind": "fault", "fault_kind": "divide_error"},
            faults=[terminal_fault],
            ordered_events=[{"family": "fault", **terminal_fault}],
        )

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            original = root / "original.exe"
            machine = root / "state-machine.jsonl"
            original.write_bytes(pe32_image(b"\x90", virtual_size=1))
            _write_machine(machine, [row])

            package = export_machine_ir_package(
                state_machine=machine, original_pe=original, out=root / "out"
            )
            inventory = _read_json(package.manifest)["control"][
                "exceptional_control"
            ]
            transition = inventory["transitions"][0]

            self.assertEqual(inventory["status"], "complete")
            self.assertEqual(transition["status"], "complete")
            self.assertEqual(transition["disposition"]["kind"], "termination")
            self.assertTrue(transition["disposition"]["observable"])
            self.assertEqual(
                transition["fault_sha256"],
                sha256_bytes(
                    json.dumps(
                        terminal_fault, sort_keys=True, separators=(",", ":")
                    ).encode("utf-8")
                ),
            )
            certificate = transition["disposition"]["evidence"]["certificate"]
            self.assertEqual(certificate["fault_sha256"], transition["fault_sha256"])
            self.assertEqual(
                certificate["source_contract_sha256"], row["contract_sha256"]
            )

    def test_exceptional_control_leaves_conditional_fault_unresolved(self) -> None:
        conditional_fault = {
            "kind": "divide_error",
            "condition": {"op": "flag", "name": "zf"},
            "instruction_rva": 0x1000,
        }
        rows = [
            _row(
                "semantic-transfer:divide",
                0x1000,
                b"\x90",
                outcome={"kind": "fallthrough", "target_rva": 0x1001},
                faults=[conditional_fault],
                ordered_events=[{"family": "fault", **conditional_fault}],
            ),
            _row(
                "semantic-transfer:return",
                0x1001,
                b"\xc3",
                outcome={"kind": "return", "value": _expr_register("eax")},
            ),
            _row(
                "semantic-transfer:unreachable-fault",
                0x1002,
                b"\x90",
                outcome={"kind": "fault", "fault_kind": "invalid_opcode"},
                faults=[{
                    "kind": "invalid_opcode",
                    "condition": {"op": "true"},
                    "instruction_rva": 0x1002,
                }],
            ),
        ]

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            original = root / "original.exe"
            machine = root / "state-machine.jsonl"
            original.write_bytes(pe32_image(b"\x90\xc3\x90", virtual_size=3))
            _write_machine(machine, rows)

            package = export_machine_ir_package(
                state_machine=machine, original_pe=original, out=root / "out"
            )
            inventory = _read_json(package.manifest)["control"][
                "exceptional_control"
            ]
            transition = inventory["transitions"][0]

            self.assertEqual(inventory["status"], "incomplete")
            self.assertEqual(len(inventory["transitions"]), 1)
            self.assertEqual(
                transition["source_unit_id"], "semantic-transfer:divide"
            )
            self.assertEqual(transition["status"], "incomplete")
            self.assertEqual(transition["disposition"]["kind"], "unresolved")
            self.assertEqual(
                transition["disposition"]["evidence"]["status"],
                "checked_possible",
            )

    def test_exceptional_control_closes_proved_infeasible_divide_error(self) -> None:
        condition = {
            "op": "not",
            "args": [
                {
                    "op": "udiv_valid32",
                    "args": [
                        {"op": "const", "value": 0, "width": 32},
                        {"op": "reg", "name": "eax", "width": 32},
                        {"op": "const", "value": 15, "width": 32},
                    ],
                }
            ],
        }
        fault = {
            "kind": "divide_error",
            "condition": condition,
            "instruction_rva": 0x1000,
        }
        rows = [
            _row(
                "semantic-transfer:divide",
                0x1000,
                b"\x90",
                outcome={"kind": "fallthrough", "target_rva": 0x1001},
                faults=[fault],
                ordered_events=[{"family": "fault", **fault}],
            ),
            _row(
                "semantic-transfer:return",
                0x1001,
                b"\xc3",
                outcome={"kind": "return", "value": _expr_register("eax")},
            ),
        ]

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            original = root / "original.exe"
            machine = root / "state-machine.jsonl"
            original.write_bytes(pe32_image(b"\x90\xc3", virtual_size=2))
            _write_machine(machine, rows)

            package = export_machine_ir_package(
                state_machine=machine, original_pe=original, out=root / "out"
            )
            inventory = _read_json(package.manifest)["control"][
                "exceptional_control"
            ]
            transition = inventory["transitions"][0]

            self.assertEqual(inventory["status"], "complete")
            self.assertEqual(transition["status"], "complete")
            self.assertEqual(transition["disposition"]["kind"], "infeasible")
            self.assertFalse(transition["disposition"]["observable"])
            evidence = transition["disposition"]["evidence"]
            self.assertEqual(evidence["status"], "checked")
            self.assertEqual(
                evidence["checker"],
                "stage-a-machine-ir-qf-bv-fault-infeasibility-v1",
            )
            certificate = evidence["certificate"]
            self.assertEqual(certificate["fault_kind"], "divide_error")
            self.assertEqual(
                certificate["predicate_sha256"],
                sha256_bytes(
                    json.dumps(
                        condition, sort_keys=True, separators=(",", ":")
                    ).encode("utf-8")
                ),
            )
            self.assertEqual(
                certificate["source_contract_sha256"], rows[0]["contract_sha256"]
            )

    def test_exceptional_control_does_not_close_platform_false_predicates(
        self,
    ) -> None:
        faults = [
            {
                "kind": kind,
                "condition": {"op": "false"},
                "instruction_rva": 0x1000,
            }
            for kind in (
                "page_fault",
                "general_protection",
                "x87_exception",
            )
        ]
        rows = [
            _row(
                "semantic-transfer:x87",
                0x1000,
                b"\x90",
                outcome={"kind": "fallthrough", "target_rva": 0x1001},
                faults=faults,
                ordered_events=[
                    {"family": "fault", **fault} for fault in faults
                ],
            ),
            _row(
                "semantic-transfer:return",
                0x1001,
                b"\xc3",
                outcome={"kind": "return", "value": _expr_register("eax")},
            ),
        ]

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            original = root / "original.exe"
            machine = root / "state-machine.jsonl"
            original.write_bytes(pe32_image(b"\x90\xc3", virtual_size=2))
            _write_machine(machine, rows)

            package = export_machine_ir_package(
                state_machine=machine, original_pe=original, out=root / "out"
            )
            transitions = _read_json(package.manifest)["control"][
                "exceptional_control"
            ]["transitions"]

            self.assertEqual(len(transitions), 3)
            for transition in transitions:
                self.assertEqual(transition["status"], "incomplete")
                self.assertEqual(
                    transition["disposition"]["kind"], "unresolved"
                )
                self.assertEqual(
                    transition["disposition"]["evidence"]["status"],
                    "unchecked",
                )

    def test_exceptional_control_abstracts_loads_for_infeasibility_only(self) -> None:
        loaded_dividend = {
            "op": "load",
            "width": 4,
            "address": {"op": "reg", "name": "esp", "width": 32},
        }
        loaded_divisor = {
            "op": "load",
            "width": 4,
            "address": {
                "op": "add32",
                "args": [
                    {"op": "reg", "name": "esp", "width": 32},
                    {"op": "const", "value": 4, "width": 32},
                ],
            },
        }
        faults = [
            {
                "kind": "divide_error",
                "condition": {
                    "op": "not",
                    "args": [
                        {
                            "op": "udiv_valid32",
                            "args": [
                                {"op": "const", "value": 0, "width": 32},
                                loaded_dividend,
                                {"op": "const", "value": 15, "width": 32},
                            ],
                        }
                    ],
                },
                "instruction_rva": 0x1000,
            },
            {
                "kind": "divide_error",
                "condition": {
                    "op": "not",
                    "args": [
                        {
                            "op": "udiv_valid32",
                            "args": [
                                {"op": "const", "value": 0, "width": 32},
                                {"op": "reg", "name": "eax", "width": 32},
                                loaded_divisor,
                            ],
                        }
                    ],
                },
                "instruction_rva": 0x1000,
            },
        ]
        rows = [
            _row(
                "semantic-transfer:divide",
                0x1000,
                b"\x90",
                outcome={"kind": "fallthrough", "target_rva": 0x1001},
                faults=faults,
                ordered_events=[
                    {"family": "fault", **fault} for fault in faults
                ],
            ),
            _row(
                "semantic-transfer:return",
                0x1001,
                b"\xc3",
                outcome={"kind": "return", "value": _expr_register("eax")},
            ),
        ]

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            original = root / "original.exe"
            machine = root / "state-machine.jsonl"
            original.write_bytes(pe32_image(b"\x90\xc3", virtual_size=2))
            _write_machine(machine, rows)

            package = export_machine_ir_package(
                state_machine=machine, original_pe=original, out=root / "out"
            )
            transitions = _read_json(package.manifest)["control"][
                "exceptional_control"
            ]["transitions"]

            self.assertEqual(transitions[0]["status"], "complete")
            abstraction = transitions[0]["disposition"]["evidence"][
                "certificate"
            ]["stateful_leaf_abstractions"]
            self.assertEqual(len(abstraction), 1)
            self.assertEqual(abstraction[0]["source_op"], "load")
            self.assertEqual(abstraction[0]["width"], 32)
            self.assertEqual(transitions[1]["status"], "incomplete")
            self.assertEqual(
                transitions[1]["disposition"]["evidence"]["status"],
                "checked_abstract_possible",
            )
            analysis = transitions[1]["disposition"]["evidence"]["analysis"]
            self.assertEqual(
                analysis["stateful_leaf_abstractions"][0]["source_op"], "load"
            )

    def test_exceptional_control_requires_scc_invariant_for_branch_fact(self) -> None:
        zero = {"op": "const", "value": 0, "width": 32}
        divisor = {"op": "reg", "name": "esi", "width": 32}
        is_zero = {
            "op": "eq",
            "args": [
                {"op": "and32", "args": [divisor, divisor]},
                zero,
            ],
        }
        nonzero = {"op": "not", "args": [is_zero]}
        fault = {
            "kind": "divide_error",
            "condition": {
                "op": "not",
                "args": [
                    {
                        "op": "udiv_valid32",
                        "args": [zero, _expr_register("eax"), divisor],
                    }
                ],
            },
            "instruction_rva": 0x1001,
        }
        predecessor = _row(
            "semantic-transfer:guard",
            0x1000,
            b"\x90",
            outcome={
                "kind": "branch",
                "condition": is_zero,
                "true_target_rva": 0x1002,
                "false_target_rva": 0x1001,
            },
            edge_conditions=[
                {"target_rva": 0x1002, "condition": is_zero},
                {"target_rva": 0x1001, "condition": nonzero},
            ],
        )
        rows = [
            predecessor,
            _row(
                "semantic-transfer:divide",
                0x1001,
                b"\x90",
                outcome={"kind": "fallthrough", "target_rva": 0x1002},
                faults=[fault],
                ordered_events=[{"family": "fault", **fault}],
            ),
            _row(
                "semantic-transfer:return",
                0x1002,
                b"\xc3",
                outcome={"kind": "return", "value": _expr_register("eax")},
            ),
        ]

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            original = root / "original.exe"
            machine = root / "state-machine.jsonl"
            original.write_bytes(pe32_image(b"\x90\x90\xc3", virtual_size=3))
            _write_machine(machine, rows)

            package = export_machine_ir_package(
                state_machine=machine, original_pe=original, out=root / "out"
            )
            transition = _read_json(package.manifest)["control"][
                "exceptional_control"
            ]["transitions"][0]

            self.assertEqual(transition["status"], "incomplete")
            evidence = transition["disposition"]["evidence"]
            requirement = evidence["scc_invariant_requirement"]
            self.assertEqual(
                requirement["format"],
                "stage-a-scc-exception-invariant-requirement-v2",
            )
            self.assertEqual(
                requirement["reason"],
                "checked_scc_invariant_certificate_required",
            )
            self.assertEqual(requirement["source_unit_id"], rows[1]["id"])

    def test_terminal_fault_without_exact_fault_record_is_incomplete(self) -> None:
        row = _row(
            "semantic-transfer:fault",
            0x1000,
            b"\x90",
            outcome={"kind": "fault", "fault_kind": "invalid_opcode"},
        )

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            original = root / "original.exe"
            machine = root / "state-machine.jsonl"
            original.write_bytes(pe32_image(b"\x90", virtual_size=1))
            _write_machine(machine, [row])

            package = export_machine_ir_package(
                state_machine=machine, original_pe=original, out=root / "out"
            )
            manifest = _read_json(package.manifest)

            self.assertEqual(package.status, "incomplete")
            self.assertEqual(
                manifest["control"]["exceptional_control"]["transitions"], []
            )
            self.assertIn(
                "terminal_fault_missing_fault_record",
                {issue["category"] for issue in manifest["issues"]},
            )


if __name__ == "__main__":
    unittest.main()
