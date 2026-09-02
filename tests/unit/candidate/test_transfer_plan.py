from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.artifacts.artifact_set import canonical_sha256_v3
from spaghetti_extractor.transfer.evaluator import (
    compare_observations,
    evaluate_transfer_plan_case,
    generated_differential_cases,
    inspect_transfer_plan,
    minimize_mismatch_case,
)
from spaghetti_extractor.transfer.model import TransferPlanError
from spaghetti_extractor.transfer.operations import (
    call_native_exception_fault_payload_v3,
    operation_registry_payload_v2,
)
from spaghetti_extractor.transfer.plan import (
    compile_exact_machine_ir,
    load_executable_transfer_plan,
    write_executable_transfer_plan,
)
from spaghetti_extractor.transfer.x87 import (
    X87_CHECKED_DECODER,
    X87_CHECKED_EXECUTOR,
)
from spaghetti_extractor.util import sha256_bytes
from spaghetti_extractor.testkit.transfer_fixture import (
    as_machine_ir_unit as _test_machine_ir_unit,
    transfer_row as _row,
    write_fixture_transfer_plan as _write_transfer_plan,
)


def _write_machine(path: Path, rows: list[dict[str, object]]) -> None:
    path.write_text(
        "".join(json.dumps(row, sort_keys=True) + "\n" for row in rows),
        encoding="utf-8",
    )


def _external_call_event(
    *,
    kind: str = "external_call",
    native_exception_operations: list[str] | None = None,
) -> dict[str, object]:
    event: dict[str, object] = {
        "family": "external",
        "kind": kind,
        "instruction_rva": 0x1000,
        "target_rva": 0,
        "return_rva": 0x1003,
        "dll": "kernel32.dll",
        "symbol": "RaiseException",
        "ordinal": None,
        "register_inputs": {
            name: {"op": "reg", "name": name, "width": 32}
            for name in (
                "eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp"
            )
        },
        "flag_inputs": {
            name: {"op": "flag", "name": name}
            for name in ("cf", "zf", "sf", "of", "pf", "df")
        },
        "arguments": [],
        "stack_inputs": [],
    }
    if native_exception_operations is not None:
        event["native_exception_operations"] = native_exception_operations
    return event


def _typed_x87_row() -> dict[str, object]:
    row = _row()
    identity = str(row["id"])
    encoded = b"\xd9\x00"  # fld dword ptr [eax]
    digest = sha256_bytes(encoded)
    address = {
        "op": "add32",
        "args": [
            {"op": "const", "value": 0, "width": 32},
            {"op": "reg", "name": "eax", "width": 32},
        ],
    }
    memory = {"kind": "read", "width": 4, "address": address}
    ordered = {**memory, "family": "memory", "instruction_rva": 0x1000}
    effects = {
        "call_effects": [],
        "control": {"kind": "fallthrough", "target_rva": 0x1002},
        "memory_events": [memory],
        "ordered_events": [ordered],
        "register_writes": [],
        "defined_flag_writes": [],
        "undefined_flag_writes": [],
        "undefined_flags": [],
        "faults": [],
    }
    row.update({
        "instruction_bytes_sha256": digest,
        "original": {"rva_start": 0x1000, "rva_end": 0x1002, "size": 2},
        "instructions": [{
            "rva_start": 0x1000,
            "rva_end": 0x1002,
            "size": 2,
            "instruction_sha256": digest,
            "mnemonic": "fld",
            "operands": [{
                "kind": "memory",
                "access": "read",
                "segment": None,
                "base": "eax",
                "index": None,
                "scale": 1,
                "displacement": 0,
                "width_bits": 32,
            }],
        }],
        "register_writes": [],
        "memory_events": [memory],
        "ordered_events": [ordered],
        "fpu_state": {
            "model": "native_exact_x87_command_replay_obligation_v1",
            "typed_replay": {"image_base": 0x400000},
        },
        "x87_micro_ops": [{
            "format": "spaghetti-extractor-x87-micro-op-v1",
            "id": f"{identity}:x87:00001000",
            "unit_id": identity,
            "checked_decoder": X87_CHECKED_DECODER,
            "checked_executor": X87_CHECKED_EXECUTOR,
            "physical_state_effect": "defined_by_checked_typed_x87_executor",
            "transfer_instruction_sha256": digest,
            "instruction_sha256": digest,
            "rva_start": 0x1000,
            "rva_end": 0x1002,
            "size": 2,
            "mnemonic": "fld",
            "operands": [{
                "kind": "memory",
                "access": "read",
                "segment": None,
                "base": "eax",
                "index": None,
                "scale": 1,
                "displacement": 0,
                "width_bits": 32,
            }],
        }],
        "instruction_effect_schedule": {
            "format": "spaghetti-extractor-static-instruction-effects-v1",
            "status": "complete",
            "proof_authority": False,
            "blockers": [],
            "ordering": "strict_contiguous_rva_order",
            "rva_start": 0x1000,
            "rva_end": 0x1002,
            "counts": {
                "instructions": 1,
                "ordinary_instructions": 0,
                "x87_singletons": 1,
                "blockers": 0,
            },
            "records": [{
                "rva_start": 0x1000,
                "rva_end": 0x1002,
                "instruction_class": "x87_singleton_checked_replay",
                "classification": {
                    "status": "proposal_requires_lean_exact_byte_replay",
                    "proof_authority": False,
                    "checked_decoder": X87_CHECKED_DECODER,
                    "checked_executor": X87_CHECKED_EXECUTOR,
                },
                "effects": effects,
            }],
        },
        "outcome": {"kind": "fallthrough", "target_rva": 0x1002},
    })
    return row


class ExecutableTransferPlanTests(unittest.TestCase):
    def test_checked_x87_action_covers_its_machine_memory_occurrence(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            machine = root / "machine-ir.jsonl"
            _write_machine(machine, [_test_machine_ir_unit(_typed_x87_row())])
            plan = _write_transfer_plan(machine)
            payload, transfers = load_executable_transfer_plan(plan)

        self.assertEqual(payload["status"], "complete")
        self.assertEqual(len(transfers), 1)
        self.assertIn("typed_x87", {action.op for action in transfers[0].actions})

    def test_checked_x87_action_rejects_wrong_machine_memory_direction(self) -> None:
        row = _typed_x87_row()
        row["memory_events"][0]["kind"] = "write"
        row["ordered_events"][0]["kind"] = "write"
        row["instruction_effect_schedule"]["records"][0]["effects"] = {
            **row["instruction_effect_schedule"]["records"][0]["effects"],
            "memory_events": row["memory_events"],
            "ordered_events": row["ordered_events"],
        }
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            machine = root / "machine-ir.jsonl"
            _write_machine(machine, [_test_machine_ir_unit(row)])
            plan = _write_transfer_plan(machine)
            payload, transfers = load_executable_transfer_plan(
                plan, require_complete=False
            )

        self.assertEqual(payload["status"], "incomplete")
        self.assertEqual(transfers, ())
        self.assertIn(
            "typed_x87_memory_event_mismatch",
            {blocker["code"] for blocker in payload["semantic_blockers"]},
        )

    def test_unscheduled_external_event_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            machine = root / "machine-ir.jsonl"
            row = _row()
            row["external_events"] = [_external_call_event()]
            row["ordered_events"] = []
            _write_machine(machine, [_test_machine_ir_unit(row)])
            plan = _write_transfer_plan(machine)
            payload, transfers = load_executable_transfer_plan(
                plan, require_complete=False
            )

        self.assertEqual(payload["status"], "incomplete")
        self.assertEqual(transfers, ())
        self.assertIn(
            "external_event_coverage_mismatch",
            {row["code"] for row in payload["semantic_blockers"]},
        )

    def test_unscheduled_memory_event_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            machine = root / "machine-ir.jsonl"
            row = _row()
            row["memory_events"] = [{
                "kind": "write",
                "width": 4,
                "address": {"op": "const", "value": 0x2000, "width": 32},
                "value": {"op": "const", "value": 7, "width": 32},
            }]
            row["ordered_events"] = []
            _write_machine(machine, [_test_machine_ir_unit(row)])
            plan = _write_transfer_plan(machine)
            payload, transfers = load_executable_transfer_plan(
                plan, require_complete=False
            )

        self.assertEqual(payload["status"], "incomplete")
        self.assertEqual(transfers, ())
        self.assertIn(
            "memory_event_coverage_mismatch",
            {row["code"] for row in payload["semantic_blockers"]},
        )

    def test_divide_fault_owns_exact_native_exception_metadata(self) -> None:
        divide = next(
            row for row in operation_registry_payload_v2()
            if row["category"] == "effect" and row["name"] == "divide_if"
        )
        self.assertEqual(divide["native_exception"], {
            "code": 0xC0000094,
            "flags_mask": 1,
            "flags_value": 0,
            "parameter_count": 0,
            "continuable": True,
            "access_violation": None,
        })

    def test_access_violation_owns_exact_native_exception_metadata(self) -> None:
        access = next(
            row for row in operation_registry_payload_v2()
            if row["category"] == "effect"
            and row["name"] == "access_violation_if"
        )
        self.assertEqual(access["native_exception"], {
            "code": 0xC0000005,
            "flags_mask": 1,
            "flags_value": 0,
            "parameter_count": 2,
            "continuable": True,
            "access_violation": {
                "operation_parameter": 0,
                "address_parameter": 1,
            },
        })

    def test_access_violation_compiles_and_evaluates_from_one_fault_event(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            machine = root / "machine-ir.jsonl"
            row = _row()
            fault = {
                "kind": "access_violation",
                "instruction_rva": 0x1000,
                "condition": {"op": "true"},
                "operation": {"op": "const", "value": 1, "width": 32},
                "address": {
                    "op": "const", "value": 0xDEADBEEF, "width": 32,
                },
            }
            row["faults"] = [fault]
            row["ordered_events"] = [{"family": "fault", **fault}]
            _write_machine(machine, [_test_machine_ir_unit(row)])
            plan = _write_transfer_plan(machine)
            payload, _transfers = load_executable_transfer_plan(
                plan, require_complete=True
            )
            access = next(
                effect for effect in payload["transfers"][0]["effects"]
                if effect["op"] == "access_violation_if"
            )
            self.assertEqual(access["parameters"]["aux"], 0)
            self.assertEqual(
                payload["transfers"][0]["exception_occurrences"],
                [{
                    "fault_index": 0,
                    "fault_sha256": canonical_sha256_v3(fault),
                    "occurrence_kind": "effect",
                    "effect_index": access["id"],
                    "operation": "access_violation_if",
                    "call_id": None,
                    "call_event_index": None,
                }],
            )
            observation = evaluate_transfer_plan_case(plan, {
                "format": "spaghetti-extractor-transfer-evaluator-case-v1",
                "id": "access-violation",
                "entry_rva": 0x1000,
                "state": {},
                "memory": [],
                "undefined_values": {},
            })
            self.assertEqual(observation["result"]["kind"], "memory_fault")

    def test_external_call_exception_inventory_round_trips_canonically(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            machine = root / "machine-ir.jsonl"
            row = _row()
            call = _external_call_event(
                native_exception_operations=[
                    "access_violation_if", "divide_if"
                ]
            )
            row["external_events"] = [call]
            row["ordered_events"] = [call]
            _write_machine(machine, [_test_machine_ir_unit(row)])
            direct, blockers = compile_exact_machine_ir(machine)
            self.assertEqual(blockers, [])
            payload, decoded = load_executable_transfer_plan(
                _write_transfer_plan(machine), require_complete=True
            )

        self.assertEqual(decoded, direct)
        self.assertEqual(
            payload["transfers"][0]["calls"][0][
                "native_exception_operations"
            ],
            ["access_violation_if", "divide_if"],
        )
        call_row = payload["transfers"][0]["calls"][0]
        call_effect = next(
            effect for effect in payload["transfers"][0]["effects"]
            if effect["op"] == "call"
        )
        self.assertEqual(
            payload["transfers"][0]["exception_occurrences"],
            [
                {
                    "fault_index": fault_index,
                    "fault_sha256": canonical_sha256_v3(
                        call_native_exception_fault_payload_v3(
                            call_kind=call_row["kind"],
                            event_index=call_row["event_index"],
                            instruction_rva=call_row["instruction_rva"],
                            operation=operation,
                            exception_index=fault_index,
                        )
                    ),
                    "occurrence_kind": "call",
                    "effect_index": call_effect["id"],
                    "operation": operation,
                    "call_id": 0,
                    "call_event_index": call_row["event_index"],
                }
                for fault_index, operation in enumerate(
                    ("access_violation_if", "divide_if")
                )
            ],
        )

    def test_instruction_scheduled_call_uses_aggregate_boundary_inventory(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            machine = root / "machine-ir.jsonl"
            row = _row()
            call = _external_call_event()
            row["external_events"] = [call]
            row["ordered_events"] = [call]
            row["instruction_effect_schedule"] = {
                "format": "spaghetti-extractor-static-instruction-effects-v1",
                "status": "complete",
                "proof_authority": False,
                "blockers": [],
                "ordering": "strict_contiguous_rva_order",
                "rva_start": 0x1000,
                "rva_end": 0x1003,
                "counts": {
                    "instructions": 1,
                    "ordinary_instructions": 1,
                    "x87_singletons": 0,
                    "blockers": 0,
                },
                "records": [{
                    "rva_start": 0x1000,
                    "rva_end": 0x1003,
                    "instruction_class": "ordinary_symbolic_instruction",
                    "classification": {
                        "status": "proposal_requires_lean_exact_byte_replay",
                        "proof_authority": False,
                        "checked_decoder": X87_CHECKED_DECODER,
                        "checked_executor": X87_CHECKED_EXECUTOR,
                    },
                    "effects": {
                        "control": {
                            "kind": "fallthrough", "target_rva": 0x1003,
                        },
                        "ordered_events": [call],
                        "register_writes": row["register_writes"],
                        "defined_flag_writes": [],
                        "undefined_flag_writes": [],
                        "undefined_flags": [],
                    },
                }],
            }
            _write_machine(machine, [_test_machine_ir_unit(row)])
            payload, transfers = load_executable_transfer_plan(
                _write_transfer_plan(machine), require_complete=True
            )

        self.assertEqual(payload["status"], "complete")
        self.assertEqual(len(transfers[0].calls), 1)
        self.assertEqual(transfers[0].calls[0].symbol, "RaiseException")

    def test_external_call_exception_inventory_fails_closed(self) -> None:
        invalid_cases = (
            (["divide_if", "access_violation_if"], "not canonical"),
            (["divide_if", "divide_if"], "not canonical"),
            (["unknown_fault_if"], "no canonical metadata"),
        )
        for operations, message in invalid_cases:
            with self.subTest(operations=operations):
                with tempfile.TemporaryDirectory() as temporary:
                    machine = Path(temporary) / "machine-ir.jsonl"
                    row = _row()
                    call = _external_call_event(
                        native_exception_operations=operations
                    )
                    row["external_events"] = [call]
                    row["ordered_events"] = [call]
                    _write_machine(machine, [_test_machine_ir_unit(row)])
                    with self.assertRaisesRegex(TransferPlanError, message):
                        compile_exact_machine_ir(machine)

        with tempfile.TemporaryDirectory() as temporary:
            machine = Path(temporary) / "machine-ir.jsonl"
            row = _row()
            call = _external_call_event(
                kind="internal_call",
                native_exception_operations=["divide_if"],
            )
            row["external_events"] = [call]
            row["ordered_events"] = [call]
            _write_machine(machine, [_test_machine_ir_unit(row)])
            with self.assertRaisesRegex(
                TransferPlanError,
                "internal calls cannot carry",
            ):
                compile_exact_machine_ir(machine)

    def test_serialized_call_exception_inventory_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            machine = root / "machine-ir.jsonl"
            row = _row()
            call = _external_call_event(
                native_exception_operations=["divide_if"]
            )
            row["external_events"] = [call]
            row["ordered_events"] = [call]
            _write_machine(machine, [_test_machine_ir_unit(row)])
            plan = _write_transfer_plan(machine)
            original = json.loads(plan.read_text(encoding="utf-8"))
            corruptions = (
                (
                    lambda value: value["transfers"][0]["calls"][0].update({
                        "native_exception_operations": [
                            "divide_if", "divide_if"
                        ]
                    }),
                    "not canonical",
                ),
                (
                    lambda value: value["transfers"][0]["calls"][0].update({
                        "native_exception_operations": ["unknown_fault_if"]
                    }),
                    "no canonical metadata",
                ),
                (
                    lambda value: value["transfers"][0]["calls"][0].update({
                        "kind": "internal_call"
                    }),
                    "internal calls cannot carry",
                ),
                (
                    lambda value: value["transfers"][0][
                        "exception_occurrences"
                    ][0].update({"operation": "access_violation_if"}),
                    "exception occurrence contradicts",
                ),
                (
                    lambda value: value["transfers"][0][
                        "exception_occurrences"
                    ][0].update({"call_id": 1}),
                    "exception occurrence contradicts",
                ),
                (
                    lambda value: value["transfers"][0][
                        "exception_occurrences"
                    ][0].update({"fault_sha256": "not-a-digest"}),
                    "SHA-256",
                ),
            )
            for mutate, message in corruptions:
                with self.subTest(message=message):
                    payload = json.loads(json.dumps(original))
                    mutate(payload)
                    payload["plan_sha256"] = canonical_sha256_v3({
                        key: item
                        for key, item in payload.items()
                        if key != "plan_sha256"
                    })
                    plan.write_text(json.dumps(payload), encoding="utf-8")
                    with self.assertRaisesRegex(TransferPlanError, message):
                        load_executable_transfer_plan(plan)

    def _plan(self, root: Path) -> Path:
        machine = root / "machine-ir.jsonl"
        _write_machine(machine, [_test_machine_ir_unit(_row())])
        return _write_transfer_plan(machine)

    def test_round_trip_and_veto_only_host_evaluation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            plan = self._plan(Path(temporary))
            payload, transfers = load_executable_transfer_plan(
                plan, require_complete=True
            )
            self.assertEqual(payload["counts"]["compiled_transfers"], 1)
            self.assertEqual(
                payload["format"],
                "spaghetti-extractor-executable-transfer-plan-v2",
            )
            expression = payload["transfers"][0]["expressions"][0]
            self.assertEqual(expression["id"], 0)
            self.assertEqual(expression["result_sort"], "bitvector")
            self.assertEqual(expression["width_bits"], 32)
            self.assertEqual(
                payload["transfers"][0]["terminator"]["op"],
                "outcome_fallthrough",
            )
            self.assertEqual(transfers[0].identity, "semantic-transfer:fixture")
            observation = evaluate_transfer_plan_case(plan, {
                "format": "spaghetti-extractor-transfer-evaluator-case-v1",
                "id": "increment-eax",
                "entry_rva": 0x1000,
                "state": {"registers": {"eax": 41}},
                "memory": [],
                "undefined_values": {},
            })
            self.assertEqual(observation["authority"], "none; veto-only diagnostic observation")
            self.assertEqual(observation["state"]["registers"]["eax"], 42)
            self.assertEqual(observation["result"], {
                "kind": "fallthrough", "target_rva": 0x1003, "value": 0,
            })

    def test_auxiliary_carry_round_trips_through_the_canonical_plan(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            machine = root / "machine-ir.jsonl"
            row = _row()
            row["flag_writes"] = [{"flag": "af", "value": {"op": "true"}}]
            _write_machine(machine, [_test_machine_ir_unit(row)])
            plan = _write_transfer_plan(machine)
            payload, _transfers = load_executable_transfer_plan(
                plan, require_complete=True
            )

            actions = payload["transfers"][0]["effects"]
            auxiliary_carry = next(
                action
                for action in actions
                if action["op"] == "set_flag"
                and action["parameters"]["aux"] == 6
            )
            self.assertEqual(len(auxiliary_carry["operands"]), 1)
            expression_by_id = {
                expression["id"]: expression
                for expression in payload["transfers"][0]["expressions"]
            }
            self.assertEqual(
                expression_by_id[auxiliary_carry["operands"][0]]["op"],
                "true",
            )

            observation = evaluate_transfer_plan_case(plan, {
                "format": "spaghetti-extractor-transfer-evaluator-case-v1",
                "id": "set-auxiliary-carry",
                "entry_rva": 0x1000,
                "state": {"eflags": 0x202},
                "memory": [],
                "undefined_values": {},
            })
            self.assertEqual(observation["state"]["eflags"], 0x212)

    def test_v2_codec_preserves_the_exact_compiler_model(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            machine = root / "machine-ir.jsonl"
            row = _row()
            row["outcome"] = {
                "kind": "indirect_jump",
                "target": {"op": "reg", "name": "eax", "width": 32},
            }
            _write_machine(machine, [_test_machine_ir_unit(row)])
            direct, blockers = compile_exact_machine_ir(machine)
            self.assertEqual(blockers, [])
            _payload, decoded = load_executable_transfer_plan(
                _write_transfer_plan(machine), require_complete=True
            )
            self.assertEqual(decoded, direct)

    def test_declared_nonlocal_outcome_is_canonical_and_veto_only(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            machine = root / "machine-ir.jsonl"
            row = _row()
            row["outcome"] = {
                "kind": "nonlocal",
                "target": {"op": "const", "value": 0x2000, "width": 32},
                "value": {"op": "const", "value": 9, "width": 32},
            }
            _write_machine(machine, [_test_machine_ir_unit(row)])
            plan = _write_transfer_plan(machine)
            payload, _transfers = load_executable_transfer_plan(
                plan, require_complete=True
            )
            self.assertEqual(
                payload["transfers"][0]["terminator"]["op"],
                "outcome_nonlocal",
            )
            observation = evaluate_transfer_plan_case(plan, {
                "format": "spaghetti-extractor-transfer-evaluator-case-v1",
                "id": "declared-nonlocal",
                "entry_rva": 0x1000,
                "state": {},
                "memory": [],
                "undefined_values": {},
            })
            self.assertEqual(observation["result"], {
                "kind": "nonlocal", "target_rva": 0x2000, "value": 9,
            })
            self.assertEqual(
                observation["authority"],
                "none; veto-only diagnostic observation",
            )

    def test_checked_finite_routes_are_compiled_into_canonical_ir(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            machine = root / "machine-ir.jsonl"
            row = _row()
            row["outcome"] = {
                "kind": "indirect_jump",
                "target": {"op": "reg", "name": "eax", "width": 32},
            }
            _write_machine(machine, [_test_machine_ir_unit(row)])
            _write_transfer_plan(machine)
            manifest = root / "machine-ir-transfer-manifest.json"
            manifest_payload = json.loads(manifest.read_text(encoding="utf-8"))
            manifest_payload["control"] = {
                "recovered_indirect_targets": [{
                    "source_unit_id": "semantic-transfer:fixture",
                    "source_rva": 0x1000,
                    "status": "recovered",
                    "closure": "checked_finite_target_inventory",
                    "failure": None,
                    "entries": [
                        {"index": 0, "target_rva": 0x2000,
                         "target_address": 0x402000},
                        {"index": 1, "target_rva": 0x3000,
                         "target_address": 0x403000},
                    ],
                }],
            }
            manifest.write_text(
                json.dumps(manifest_payload, sort_keys=True), encoding="utf-8"
            )
            output = root / "with-routes"
            payload = write_executable_transfer_plan(
                machine_ir=machine,
                machine_ir_manifest=manifest,
                out=output,
            )
            decoded, _transfers = load_executable_transfer_plan(
                output / "executable-transfer-plan.json", require_complete=True
            )

        self.assertEqual(decoded["finite_control_routes"], payload[
            "finite_control_routes"
        ])
        self.assertEqual(
            payload["finite_control_routes"][0]["routes"],
            [
                {"selector_value": 0, "target_rva": 0x2000,
                 "target_address": 0x402000},
                {"selector_value": 1, "target_rva": 0x3000,
                 "target_address": 0x403000},
            ],
        )

    def test_v2_preserves_stable_undefined_identity_and_interprets_uses(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            machine = root / "machine-ir.jsonl"
            row = _row(expression={
                "op": "undefined_bv",
                "id": "fixture:undefined:eax",
                "reason": "fixture",
                "defined_value": {"op": "const", "value": 0, "width": 32},
            })
            _write_machine(machine, [_test_machine_ir_unit(row)])
            plan = _write_transfer_plan(machine)
            payload, transfers = load_executable_transfer_plan(
                plan, require_complete=True
            )
            undefined = next(
                node for node in transfers[0].nodes
                if node.op == "undefined_bv"
            )
            self.assertEqual(undefined.identity, "fixture:undefined:eax")
            analysis = payload["diagnostics"]["transfer_definedness"]
            self.assertEqual(analysis["status"], "complete")
            self.assertEqual(analysis["counts"]["undefined_nodes"], 1)
            self.assertEqual(
                analysis["slots"][0]["classification"], "behavior_relevant"
            )
            self.assertEqual(payload["counts"]["undefined_nodes"], 1)

    def test_host_evaluator_uses_canonical_width_value_sign_extend_order(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            machine = root / "machine-ir.jsonl"
            row = _row(expression={
                "op": "sign_extend",
                "args": [
                    {"op": "const", "value": 8, "width": 32},
                    {"op": "const", "value": 0x80, "width": 32},
                ],
            })
            _write_machine(machine, [_test_machine_ir_unit(row)])
            observed = evaluate_transfer_plan_case(
                _write_transfer_plan(machine),
                {
                    "format": "spaghetti-extractor-transfer-evaluator-case-v1",
                    "id": "sign-extend-i8",
                    "entry_rva": 0x1000,
                    "state": {},
                    "memory": [],
                    "undefined_values": {},
                },
            )

        self.assertEqual(observed["state"]["registers"]["eax"], 0xFFFFFF80)

    def test_generated_cases_and_comparison_never_authorize(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            plan = self._plan(Path(temporary))
            cases = generated_differential_cases(plan)
            self.assertEqual(len(cases), 4)
            observed = evaluate_transfer_plan_case(plan, cases[0])
            comparison = compare_observations(observed, observed)
            self.assertEqual(comparison["status"], "match")
            self.assertEqual(comparison["authority"], "none; mismatch veto only")
            changed = json.loads(json.dumps(observed))
            changed["state"]["registers"]["eax"] ^= 1
            self.assertEqual(
                compare_observations(observed, changed)["status"], "mismatch"
            )
            view = inspect_transfer_plan(plan)
            self.assertEqual(view["authority"], "none; inspection only")
            self.assertEqual(view["units"][0]["id"], "semantic-transfer:fixture")

            def expected(case):
                return evaluate_transfer_plan_case(plan, case)

            def divergent(case):
                value = json.loads(json.dumps(expected(case)))
                value["result"]["value"] ^= 1
                return value

            noisy = json.loads(json.dumps(cases[0]))
            noisy["state"]["registers"]["eax"] = 123
            minimized = minimize_mismatch_case(noisy, expected, divergent)
            self.assertEqual(minimized["state"]["registers"]["eax"], 0)

    def test_stale_self_hash_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            plan = self._plan(Path(temporary))
            payload = json.loads(plan.read_text(encoding="utf-8"))
            payload["entry_targets"] = []
            plan.write_text(json.dumps(payload), encoding="utf-8")
            with self.assertRaisesRegex(
                TransferPlanError, "self hash is stale"
            ):
                load_executable_transfer_plan(plan)

    def test_typed_nodes_dense_ids_and_terminators_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            plan = self._plan(Path(temporary))
            original = json.loads(plan.read_text(encoding="utf-8"))
            corruptions = (
                (
                    lambda value: value["transfers"][0]["expressions"][0].update(
                        {"id": 1}
                    ),
                    "dense ID",
                ),
                (
                    lambda value: value["transfers"][0]["expressions"][0].update(
                        {"result_sort": "predicate"}
                    ),
                    "type metadata",
                ),
                (
                    lambda value: value["transfers"][0]["terminator"].update(
                        {"op": "outcome_unknown"}
                    ),
                    "terminator operation",
                ),
            )
            for mutate, message in corruptions:
                with self.subTest(message=message):
                    payload = json.loads(json.dumps(original))
                    mutate(payload)
                    payload["plan_sha256"] = canonical_sha256_v3({
                        key: item
                        for key, item in payload.items()
                        if key != "plan_sha256"
                    })
                    plan.write_text(json.dumps(payload), encoding="utf-8")
                    with self.assertRaisesRegex(TransferPlanError, message):
                        load_executable_transfer_plan(plan)

    def test_transfer_plan_v1_has_no_compatibility_reader(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            plan = self._plan(Path(temporary))
            payload = json.loads(plan.read_text(encoding="utf-8"))
            payload["format"] = "spaghetti-extractor-executable-transfer-plan-v1"
            payload["plan_sha256"] = canonical_sha256_v3({
                key: item for key, item in payload.items() if key != "plan_sha256"
            })
            plan.write_text(json.dumps(payload), encoding="utf-8")
            with self.assertRaisesRegex(TransferPlanError, "format is unsupported"):
                load_executable_transfer_plan(plan)

    def test_typed_byte_counts_are_not_raw_instruction_material(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            machine = root / "machine-ir.jsonl"
            unit = _test_machine_ir_unit(_row())
            unit["abi_envelope"] = {
                "stack_cleanup": {"kind": "caller", "bytes": 0}
            }
            _write_machine(machine, [unit])
            payload, _ = load_executable_transfer_plan(
                _write_transfer_plan(machine), require_complete=True
            )
            self.assertEqual(payload["status"], "complete")

            unit["instructions"] = [{"bytes": "90"}]
            _write_machine(machine, [unit])
            with self.assertRaisesRegex(
                TransferPlanError, "raw instruction material"
            ):
                _write_transfer_plan(machine)


if __name__ == "__main__":
    unittest.main()
