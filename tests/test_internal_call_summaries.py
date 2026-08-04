from __future__ import annotations

import unittest

from spaghetti_extractor.import_abi import SelectedImportABI
from spaghetti_extractor.internal_call_summaries import (
    INTERNAL_CALL_SUMMARY_FORMAT,
    derive_internal_call_preservation_summaries,
)
from spaghetti_extractor.machine_abi import resolve_machine_call_abi
from spaghetti_extractor.machine_import_profiles import MachineImportIdentity


REGISTERS = ("eax", "ebp", "ebx", "ecx", "edi", "edx", "esi", "esp")


def reg(name: str) -> dict[str, object]:
    return {"op": "reg", "name": name, "width": 32}


def const(value: int) -> dict[str, object]:
    return {"op": "const", "value": value, "width": 32}


def add(left: object, right: object) -> dict[str, object]:
    return {"op": "add32", "args": [left, right]}


def sub(left: object, right: object) -> dict[str, object]:
    return {"op": "sub32", "args": [left, right]}


def load(address: object) -> dict[str, object]:
    return {"op": "load", "address": address, "width": 4}


def unit(
    identifier: str,
    rva: int,
    *,
    outcome: str,
    writes: list[dict[str, object]] | None = None,
    memory: list[dict[str, object]] | None = None,
    events: list[dict[str, object]] | None = None,
) -> dict[str, object]:
    return {
        "id": identifier,
        "source": {"original": {"rva_start": rva, "rva_end": rva + 1}},
        "semantics": {
            "outcome": {"kind": outcome},
            "register_writes": writes or [],
            "memory_events": memory or [],
            "external_events": events or [],
        },
    }


def internal_call(target_rva: int) -> dict[str, object]:
    return {
        "kind": "internal_call",
        "target_rva": target_rva,
        "register_inputs": {register: reg(register) for register in REGISTERS},
    }


class InternalCallSummaryTests(unittest.TestCase):
    def test_leaf_callee_preserves_untouched_nonvolatile_registers(self) -> None:
        result = self._derive(
            units=[
                unit("root", 0x1000, outcome="fallthrough", events=[internal_call(0x2000)]),
                unit("callee", 0x2000, outcome="return"),
            ],
            direct=[self._edge("root", "done")],
            calls=[self._call_edge("root", "callee", 0)],
            extra_units=[unit("done", 0x1001, outcome="return")],
        )

        self.assertEqual(result["format"], INTERNAL_CALL_SUMMARY_FORMAT)
        summary = self._summary(result, "callee")
        self.assertEqual(summary["status"], "complete")
        self.assertEqual(summary["preserved_registers"], ["ebp", "ebx", "edi", "esi"])

    def test_return_stack_effect_produces_exact_cleanup_summary(self) -> None:
        result = self._derive(
            units=[
                unit("root", 0x1000, outcome="fallthrough", events=[internal_call(0x2000)]),
                unit(
                    "callee",
                    0x2000,
                    outcome="return",
                    writes=[{
                        "register": "esp",
                        "value": add(reg("esp"), const(4)),
                    }],
                ),
            ],
            direct=[self._edge("root", "done")],
            calls=[self._call_edge("root", "callee", 0)],
            extra_units=[unit("done", 0x1001, outcome="return")],
        )

        self.assertEqual(
            self._summary(result, "callee")["stack_cleanup"],
            {
                "status": "complete",
                "stack_delta": 0,
                "return_stack_offset": 4,
            },
        )

    def test_ret_immediate_produces_callee_cleanup_bytes(self) -> None:
        result = self._derive(
            units=[
                unit("root", 0x1000, outcome="fallthrough", events=[internal_call(0x2000)]),
                unit(
                    "callee",
                    0x2000,
                    outcome="return",
                    writes=[{
                        "register": "esp",
                        "value": add(reg("esp"), const(12)),
                    }],
                ),
            ],
            direct=[self._edge("root", "done")],
            calls=[self._call_edge("root", "callee", 0)],
            extra_units=[unit("done", 0x1001, outcome="return")],
        )

        self.assertEqual(
            self._summary(result, "callee")["stack_cleanup"]["stack_delta"], 8
        )

    def test_explicit_write_removes_only_that_preservation_claim(self) -> None:
        result = self._derive(
            units=[
                unit("root", 0x1000, outcome="fallthrough", events=[internal_call(0x2000)]),
                unit(
                    "callee",
                    0x2000,
                    outcome="return",
                    writes=[{"register": "esi", "value": const(7)}],
                ),
            ],
            direct=[self._edge("root", "done")],
            calls=[self._call_edge("root", "callee", 0)],
            extra_units=[unit("done", 0x1001, outcome="return")],
        )

        self.assertEqual(
            self._summary(result, "callee")["preserved_registers"],
            ["ebp", "ebx", "edi"],
        )

    def test_unsupported_instruction_invalidates_its_decoded_register_writes(self) -> None:
        callee = unit("callee", 0x2000, outcome="return")
        callee["instructions"] = [{
            "mnemonic": "inc",
            "registers_written": ["eflags", "esi"],
            "operands": [{
                "kind": "register",
                "name": "esi",
                "access": "read_write",
            }],
        }]
        callee["semantics"]["instruction_effect_schedule"] = {
            "status": "incomplete",
            "blockers": [{"index": 0}],
        }
        result = self._derive(
            units=[
                unit("root", 0x1000, outcome="fallthrough", events=[internal_call(0x2000)]),
                callee,
            ],
            direct=[self._edge("root", "done")],
            calls=[self._call_edge("root", "callee", 0)],
            extra_units=[unit("done", 0x1001, outcome="return")],
        )

        self.assertNotIn("esi", self._summary(result, "callee")["preserved_registers"])

    def test_stack_save_and_restore_recovers_register_origin(self) -> None:
        result = self._derive(
            units=[
                unit("root", 0x1000, outcome="fallthrough", events=[internal_call(0x2000)]),
                unit(
                    "save",
                    0x2000,
                    outcome="fallthrough",
                    writes=[{"register": "esp", "value": sub(reg("esp"), const(4))}],
                    memory=[{
                        "kind": "write",
                        "address": sub(reg("esp"), const(4)),
                        "value": reg("esi"),
                        "width": 4,
                    }],
                ),
                unit(
                    "restore",
                    0x2001,
                    outcome="return",
                    writes=[
                        {"register": "esi", "value": load(reg("esp"))},
                        {"register": "esp", "value": add(reg("esp"), const(8))},
                    ],
                ),
            ],
            direct=[self._edge("root", "done"), self._edge("save", "restore")],
            calls=[self._call_edge("root", "save", 0)],
            extra_units=[unit("done", 0x1001, outcome="return")],
        )

        self.assertIn("esi", self._summary(result, "save")["preserved_registers"])

    def test_all_return_paths_must_preserve_the_register(self) -> None:
        result = self._derive(
            units=[
                unit("root", 0x1000, outcome="fallthrough", events=[internal_call(0x2000)]),
                unit("branch", 0x2000, outcome="branch"),
                unit("same", 0x2001, outcome="return"),
                unit(
                    "different",
                    0x2002,
                    outcome="return",
                    writes=[{"register": "esi", "value": const(1)}],
                ),
            ],
            direct=[
                self._edge("root", "done"),
                self._edge("branch", "same"),
                self._edge("branch", "different"),
            ],
            calls=[self._call_edge("root", "branch", 0)],
            extra_units=[unit("done", 0x1001, outcome="return")],
        )

        self.assertNotIn("esi", self._summary(result, "branch")["preserved_registers"])

    def test_nested_direct_calls_compose_at_fixed_point(self) -> None:
        result = self._derive(
            units=[
                unit("root", 0x1000, outcome="fallthrough", events=[internal_call(0x2000)]),
                unit("outer", 0x2000, outcome="fallthrough", events=[internal_call(0x3000)]),
                unit("outer_return", 0x2001, outcome="return"),
                unit("inner", 0x3000, outcome="return"),
            ],
            direct=[
                self._edge("root", "done"),
                self._edge("outer", "outer_return"),
            ],
            calls=[
                self._call_edge("root", "outer", 0),
                self._call_edge("outer", "inner", 0),
            ],
            extra_units=[unit("done", 0x1001, outcome="return")],
        )

        self.assertGreaterEqual(result["fixed_point_rounds"], 2)
        self.assertIn("esi", self._summary(result, "inner")["preserved_registers"])
        self.assertIn("esi", self._summary(result, "outer")["preserved_registers"])

    def test_profiled_external_call_preserves_nonvolatile_registers(self) -> None:
        identity = MachineImportIdentity("kernel32.dll", "symbol", "GetTickCount")
        event = {
            "kind": "external_call",
            "dll": identity.dll,
            "symbol": identity.value,
            "register_inputs": {register: reg(register) for register in REGISTERS},
        }
        result = self._derive(
            units=[
                unit("root", 0x1000, outcome="fallthrough", events=[internal_call(0x2000)]),
                unit("callee", 0x2000, outcome="fallthrough", events=[event]),
                unit("callee_return", 0x2001, outcome="return"),
            ],
            direct=[
                self._edge("root", "done"),
                self._edge("callee", "callee_return"),
            ],
            calls=[self._call_edge("root", "callee", 0)],
            extra_units=[unit("done", 0x1001, outcome="return")],
            import_abis={identity: self._selected_abi(identity)},
        )

        self.assertIn("esi", self._summary(result, "callee")["preserved_registers"])

    def test_recovered_fixed_arity_import_composes_stack_cleanup(self) -> None:
        identity = MachineImportIdentity("user32.dll", "symbol", "ShowWindow")
        event = {
            "kind": "indirect_call",
            "register_inputs": {
                **{register: reg(register) for register in REGISTERS},
                "esp": sub(reg("esp"), const(8)),
            },
        }
        units = [
            unit("root", 0x1000, outcome="fallthrough", events=[internal_call(0x2000)]),
            unit("callee", 0x2000, outcome="fallthrough", events=[event]),
            unit(
                "callee_return",
                0x2001,
                outcome="return",
                writes=[{
                    "register": "esp",
                    "value": add(reg("esp"), const(4)),
                }],
            ),
            unit("done", 0x1001, outcome="return"),
        ]
        result = derive_internal_call_preservation_summaries(
            units=units,
            roots=["root"],
            direct_edges=[
                self._edge("root", "done"),
                self._edge("callee", "callee_return"),
            ],
            internal_call_edges=[self._call_edge("root", "callee", 0)],
            recovered_indirect_targets=[{
                "id": "exit:callee",
                "status": "recovered",
                "target_unit_ids": [],
                "external_targets": [{
                    "import": {"dll": identity.dll, "symbol": identity.value},
                }],
            }],
            indirect_exits=[{
                "id": "exit:callee",
                "source_unit_id": "callee",
                "source_event_index": 0,
                "kind": "indirect_call",
            }],
            import_abis={identity: self._selected_abi(identity, argument_words=2)},
        )

        self.assertEqual(
            self._summary(result, "callee")["stack_cleanup"],
            {
                "status": "complete",
                "stack_delta": 0,
                "return_stack_offset": 4,
            },
        )

    def test_unresolved_indirect_jump_fails_closed(self) -> None:
        units = [
            unit("root", 0x1000, outcome="fallthrough", events=[internal_call(0x2000)]),
            unit("callee", 0x2000, outcome="indirect_jump"),
            unit("done", 0x1001, outcome="return"),
        ]
        result = derive_internal_call_preservation_summaries(
            units=units,
            roots=["root"],
            direct_edges=[self._edge("root", "done")],
            internal_call_edges=[self._call_edge("root", "callee", 0)],
            recovered_indirect_targets=[],
            indirect_exits=[{
                "id": "exit",
                "source_unit_id": "callee",
                "source_event_index": None,
                "kind": "indirect_jump",
            }],
            import_abis={},
        )

        summary = self._summary(result, "callee")
        self.assertEqual(summary["status"], "incomplete")
        self.assertIn("unresolved_indirect_jump", summary["blocker_codes"])
        self.assertEqual(summary["preserved_registers"], [])

    def _derive(
        self,
        *,
        units: list[dict[str, object]],
        direct: list[dict[str, object]],
        calls: list[dict[str, object]],
        extra_units: list[dict[str, object]],
        import_abis: dict[MachineImportIdentity, SelectedImportABI] | None = None,
    ) -> dict[str, object]:
        return derive_internal_call_preservation_summaries(
            units=[*units, *extra_units],
            roots=["root"],
            direct_edges=direct,
            internal_call_edges=calls,
            recovered_indirect_targets=[],
            indirect_exits=[],
            import_abis=import_abis or {},
        )

    @staticmethod
    def _edge(source: str, target: str) -> dict[str, object]:
        return {
            "kind": "direct_control",
            "source_unit_id": source,
            "resolved_unit_id": target,
            "status": "resolved",
        }

    @staticmethod
    def _call_edge(source: str, target: str, event_index: int) -> dict[str, object]:
        return {
            "kind": "internal_call",
            "source_unit_id": source,
            "source_event_index": event_index,
            "resolved_unit_id": target,
            "status": "resolved",
        }

    @staticmethod
    def _summary(result: dict[str, object], target: str) -> dict[str, object]:
        summaries = result["summaries"]
        assert isinstance(summaries, list)
        return next(row for row in summaries if row["target_unit_id"] == target)

    @staticmethod
    def _selected_abi(
        identity: MachineImportIdentity,
        *,
        argument_words: int | None = None,
    ) -> SelectedImportABI:
        abi = resolve_machine_call_abi("pe32-stdcall-v1")
        assert abi is not None
        return SelectedImportABI(
            identity=identity,
            abi=abi,
            profile_id="test",
            profile_sha256="0" * 64,
            entry_key="test",
            entry_index=0,
            argument_words=argument_words,
        )


if __name__ == "__main__":
    unittest.main()
