from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.artifacts.artifact_set import canonical_sha256_v3
from spaghetti_extractor.external.resolved import (
    ExternalEnvironmentError,
    ResolvedExternalEnvironmentV1,
    bind_checked_exception_protocol_v1,
    bind_launch_policy_v1,
)
from spaghetti_extractor.testkit.transfer_fixture import (
    as_machine_ir_unit,
    transfer_row,
    write_fixture_transfer_plan,
)
from spaghetti_extractor.transfer.exception_semantics import (
    derive_checked_exception_transitions_v1,
)
from spaghetti_extractor.transfer.plan import load_executable_transfer_plan


def _environment(
    *, unsupported_threads: bool = False,
    checked_exception_protocols: list[dict[str, object]] | None = None,
) -> ResolvedExternalEnvironmentV1:
    launch = {
        "assumptions": {
            name: {"contract": f"fixture-{name}"}
            for name in (
                "argv", "environment", "fs", "iat", "initial_stack",
                "relocations",
            )
        },
        "feature_inventory": {
            "direct_syscalls": [],
            "executable_writes": [],
            "threads": ["fixture"] if unsupported_threads else [],
            "unknown_async_callbacks": [],
            "unmodelled_seh": [],
        },
        "format": "spaghetti-extractor-pe32-launch-assumption-template-v1",
        "schema_version": 1,
    }
    payload = {
        "format": "spaghetti-extractor-resolved-external-environment-v1",
        "status": "complete",
        "bindings": {
            "module_interface_sha256": "1" * 64,
            "module_pe_sha256": "2" * 64,
            "environment_intent_sha256": "3" * 64,
            "runtime_profile_pack_sha256s": [],
            "interface_profile_pack_sha256s": [],
        },
        "target": {
            "abi": "pe32-i686-mingw32",
            "data_layout": "pe32-ilp32-v1",
        },
        "launch_policy": bind_launch_policy_v1(
            launch,
            source_sha256="4" * 64,
            filename="fixture-launch.json",
        ),
        "canonical_boundaries": [],
        "interface_method_catalogs": [],
        "machine_import_contracts": [],
        "original_semantic_imports": [],
        "generated_runtime_support_imports": [],
        "loader_service_contracts": [],
        "static_authority_bindings": [],
        "checked_exception_protocols": (
            [] if checked_exception_protocols is None
            else checked_exception_protocols
        ),
        "blockers": [],
        "authority": "checked_static_environment",
    }
    payload["resolved_environment_sha256"] = canonical_sha256_v3(payload)
    return ResolvedExternalEnvironmentV1.parse(payload)


def _call() -> dict[str, object]:
    return {
        "family": "external",
        "kind": "external_call",
        "instruction_rva": 0x1000,
        "target_rva": 0,
        "return_rva": 0x1003,
        "dll": "kernel32.dll",
        "symbol": "RaiseException",
        "ordinal": None,
        "register_inputs": {
            name: {"op": "reg", "name": name, "width": 32}
            for name in (
                "eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp",
            )
        },
        "flag_inputs": {
            name: {"op": "flag", "name": name}
            for name in ("cf", "zf", "sf", "of", "pf", "df")
        },
        "arguments": [],
        "stack_inputs": [],
        "native_exception_operations": ["divide_if"],
    }


def _transfers(
    root: Path, *, condition: dict[str, object], include_call: bool = False
):
    row = transfer_row()
    fault = {
        "kind": "divide_error",
        "instruction_rva": 0x1000,
        "condition": condition,
    }
    events: list[dict[str, object]] = [{"family": "fault", **fault}]
    row["faults"] = [fault]
    if include_call:
        call = _call()
        row["external_events"] = [call]
        events.append(call)
    row["ordered_events"] = events
    machine = root / "machine-ir.jsonl"
    machine.write_text(
        json.dumps(as_machine_ir_unit(row), sort_keys=True) + "\n",
        encoding="utf-8",
    )
    _payload, transfers = load_executable_transfer_plan(
        write_fixture_transfer_plan(machine), require_complete=True
    )
    return transfers


class DirectExceptionSemanticsTests(unittest.TestCase):
    def test_checked_exception_protocol_requires_a_semantic_target(self) -> None:
        with self.assertRaisesRegex(
            ExternalEnvironmentError, "requires a handler or resumption"
        ):
            bind_checked_exception_protocol_v1(
                occurrence={
                    "unit_id": "semantic-transfer:fixture",
                    "source_rva": 0x1000,
                    "effect_index": 0,
                    "fault_index": 0,
                    "fault_sha256": "f" * 64,
                    "occurrence_kind": "effect",
                    "operation": "divide_if",
                    "call_index": None,
                },
                handler=None,
                resumption=None,
                unwind_unit_ids=[],
                state_projection={
                    "registers": [], "flags": [], "x87": [], "stack": [],
                    "exception_record": [], "context": [],
                },
            )

    def test_external_escape_protocol_authorizes_exact_resumption(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            transfers = _transfers(
                Path(temporary), condition={"op": "true"}
            )
            occurrence = transfers[0].exception_occurrences[0]
            protocol = bind_checked_exception_protocol_v1(
                occurrence={
                    "unit_id": transfers[0].identity,
                    "source_rva": transfers[0].rva_start,
                    "effect_index": occurrence.effect_index,
                    "fault_index": occurrence.fault_index,
                    "fault_sha256": occurrence.fault_sha256,
                    "occurrence_kind": occurrence.occurrence_kind,
                    "operation": occurrence.operation,
                    "call_index": occurrence.call_event_index,
                },
                handler=None,
                resumption={
                    "unit_id": transfers[0].identity,
                    "rva": transfers[0].rva_start,
                },
                unwind_unit_ids=[],
                state_projection={
                    "registers": ["edi"], "flags": [], "x87": [],
                    "stack": [], "exception_record": ["ExceptionCode"],
                    "context": ["Edi"],
                },
            )
            rows = derive_checked_exception_transitions_v1(
                transfers=transfers,
                environment=_environment(
                    checked_exception_protocols=[protocol]
                ),
            )
        self.assertEqual(len(rows), 1)
        transition = rows[0]
        self.assertTrue(transition.authorizing)
        self.assertEqual(transition.disposition, "terminates")
        self.assertIsNone(transition.handler_unit_id)
        self.assertEqual(transition.resumption_unit_id, transfers[0].identity)
        self.assertEqual(transition.resumption_rva, transfers[0].rva_start)

    def test_exact_environment_protocol_handles_transfer_occurrence(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            transfers = _transfers(
                Path(temporary), condition={"op": "true"}, include_call=True
            )
            call = next(
                occurrence
                for occurrence in transfers[0].exception_occurrences
                if occurrence.occurrence_kind == "call"
            )
            protocol = bind_checked_exception_protocol_v1(
                occurrence={
                    "unit_id": transfers[0].identity,
                    "source_rva": transfers[0].rva_start,
                    "effect_index": call.effect_index,
                    "fault_index": call.fault_index,
                    "fault_sha256": call.fault_sha256,
                    "occurrence_kind": call.occurrence_kind,
                    "operation": call.operation,
                    "call_index": call.call_event_index,
                },
                handler={
                    "unit_id": transfers[0].identity,
                    "rva": transfers[0].rva_start,
                },
                resumption=None,
                unwind_unit_ids=[],
                state_projection={
                    "registers": [], "flags": [], "x87": [], "stack": [],
                    "exception_record": [], "context": [],
                },
            )
            rows = derive_checked_exception_transitions_v1(
                transfers=transfers,
                environment=_environment(
                    checked_exception_protocols=[protocol]
                ),
            )
        handled = next(row for row in rows if row.occurrence_kind == "call")
        self.assertTrue(handled.authorizing)
        self.assertEqual(handled.disposition, "handled")
        self.assertEqual(handled.handler_unit_id, transfers[0].identity)
        self.assertEqual(handled.guard, {"kind": "constant", "value": True})

    def test_generic_process_policy_is_derived_without_authority_artifact(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            rows = derive_checked_exception_transitions_v1(
                transfers=_transfers(
                    Path(temporary), condition={"op": "true"}, include_call=True
                ),
                environment=_environment(),
            )
        self.assertEqual(len(rows), 2)
        ordinary, call = rows
        self.assertTrue(ordinary.authorizing)
        self.assertEqual(ordinary.disposition, "terminates")
        self.assertEqual(
            ordinary.guard,
            {"kind": "transfer_expression_v2", "node_id": 0},
        )
        self.assertEqual(ordinary.native_exception_code, 0xC0000094)
        self.assertFalse(call.authorizing)
        self.assertEqual(call.occurrence_kind, "call")
        self.assertEqual(call.blocker_code, "exception_fault_kind_unsupported")

    def test_static_false_guard_is_infeasible_without_launch_assumptions(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            rows = derive_checked_exception_transitions_v1(
                transfers=_transfers(Path(temporary), condition={"op": "false"}),
                environment=_environment(unsupported_threads=True),
            )
        self.assertEqual(len(rows), 1)
        self.assertTrue(rows[0].authorizing)
        self.assertEqual(rows[0].disposition, "infeasible")

    def test_unsupported_launch_features_remain_an_exact_blocker(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            rows = derive_checked_exception_transitions_v1(
                transfers=_transfers(Path(temporary), condition={"op": "true"}),
                environment=_environment(unsupported_threads=True),
            )
        self.assertEqual(len(rows), 1)
        self.assertFalse(rows[0].authorizing)
        self.assertEqual(
            rows[0].blocker_code,
            "exception_terminal_profile_unsupported_features",
        )


if __name__ == "__main__":
    unittest.main()
