from __future__ import annotations

from tests.unit.candidate.interpreter._support import *


class InterpreterValidationTests(unittest.TestCase):
    def test_rep_stosd_event_validation_fails_closed(self) -> None:
        base = {
            "family": "external",
            "kind": "rep_stosd",
            "index": 0,
            "instruction_rva": 0x1000,
            "destination": {"op": "reg", "name": "edi", "width": 32},
            "value": {"op": "reg", "name": "eax", "width": 32},
            "count": {"op": "reg", "name": "ecx", "width": 32},
            "direction_flag": {"op": "flag", "name": "df"},
            "effect_model": "symbolic_string_fill_v1",
        }
        cases = (
            ({"effect_model": "unchecked"}, "symbolic_string_fill_v1"),
            ({"index": 1}, "event index"),
            ({"source": {"op": "reg", "name": "esi", "width": 32}}, "source address"),
        )
        for mutation, message in cases:
            with self.subTest(mutation=mutation):
                with tempfile.TemporaryDirectory() as temporary:
                    machine = Path(temporary) / "state-machine.jsonl"
                    row = _row()
                    row["ordered_events"] = [{**base, **mutation}]
                    _write_machine(machine, [row])
                    with self.assertRaisesRegex(CandidateInterpreterError, message) as raised:
                        compile_spx_interpreter_program(machine)
                    self.assertEqual(
                        raised.exception.code, "malformed_rep_stosd_event"
                    )

    def test_rep_scas_event_validation_fails_closed(self) -> None:
        cases = (
            ({"element_width": 2}, "byte element width"),
            ({"address_size": 16}, "32-bit address size"),
            ({"repeat_condition": "unchecked"}, "while_not_equal_v1"),
            ({"comparison_model": "unchecked"}, "subtraction_flags_v1"),
            ({"segment_model": "unchecked"}, "flat_es_zero_v1"),
            ({"effect_model": "unchecked"}, "symbolic_string_scan_v1"),
            ({"restart_semantics": "unchecked"}, "element_committed_v1"),
            ({"fault_model": "unchecked"}, "read_before_commit_v1"),
            ({"owned_register_outputs": ["edi"]}, "owned-output inventory"),
        )
        for (mutation, message) in cases:
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as temporary:
                machine = Path(temporary) / "state-machine.jsonl"
                row = _row()
                row["ordered_events"] = [{**_rep_scas_event(), **mutation}]
                _write_machine(machine, [row])
                with self.assertRaisesRegex(CandidateInterpreterError, message) as raised:
                    compile_spx_interpreter_program(machine)
                self.assertEqual(raised.exception.code, "malformed_rep_scas_event")

    def test_unsupported_operation_fails_before_emission(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            machine = Path(temporary) / "state-machine.jsonl"
            _write_machine(machine, [_row(expression={"op": "target_specific_magic"})])
            with self.assertRaisesRegex(CandidateInterpreterError, "unsupported semantic op"):
                compile_spx_interpreter_program(machine)

    def test_duplicate_rva_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            machine = Path(temporary) / "state-machine.jsonl"
            second = dict(_row())
            second["id"] = "semantic-transfer:other"
            _write_machine(machine, [_row(), second])
            with self.assertRaisesRegex(CandidateInterpreterError, "duplicate transfer RVA"):
                compile_spx_interpreter_program(machine)

    def test_symbolic_x87_state_requires_checked_replay(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            machine = Path(temporary) / "state-machine.jsonl"
            row = _row()
            row["fpu_state"] = {
                "model": "symbolic_x87_stack_v1",
                "stack": [{"op": "fpu_reg", "args": [index]} for index in range(8)],
                "control": {"op": "fpu_control", "args": []},
                "status": {"op": "fpu_status", "args": []},
            }
            _write_machine(machine, [row])
            with self.assertRaisesRegex(
                CandidateInterpreterError, "exact checked replay schedule"
            ) as raised:
                compile_spx_interpreter_program(machine)
            self.assertEqual(raised.exception.code, "x87_checked_replay_required")
            self.assertIn("instruction-ordered effect schedule", raised.exception.next_action)


if __name__ == "__main__":
    unittest.main()
