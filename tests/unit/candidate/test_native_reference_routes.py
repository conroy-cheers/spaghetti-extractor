from __future__ import annotations

import json
import copy
import hashlib
from pathlib import Path
import tempfile
import unittest
from dataclasses import replace
from typing import Any

from spaghetti_extractor.transfer.closure import (
    ExecutionClosureContextV1,
    execution_closure_context_with_roots_v1,
    _execution_closure_kernel_context_payload_v1,
    _reference_state_kernel_payload_v1,
    build_module_execution_closure_v1,
    check_module_execution_closure_v1,
    join_reference_states_v1,
    validate_module_execution_closure_v1,
    write_module_execution_closure_v1,
)
from spaghetti_extractor.artifacts.artifact_set import canonical_sha256_v3
from spaghetti_extractor.transfer.formats import EXECUTABLE_TRANSFER_PLAN_FORMAT
from spaghetti_extractor.transfer.exception_semantics import (
    CheckedExceptionTransitionV1,
)
from spaghetti_extractor.transfer.operations import operation_registry_payload_v2
from spaghetti_extractor.transfer.operations import (
    EFFECT_OPERATIONS_V2,
    EXPRESSION_OPERATIONS_V2,
    TERMINATOR_OPERATIONS_V2,
)
from spaghetti_extractor.transfer.plan import _transfer_from_payload
from spaghetti_extractor.transfer.model import TransferPlanError
from spaghetti_extractor.testkit.transfer_fixture import (
    as_machine_ir_unit,
    transfer_row,
    write_fixture_transfer_plan,
)
from spaghetti_extractor.transfer.provenance import (
    CONFLICT_REFERENCE_V1,
    ExternalCallRuleV1,
    ExternalMemoryWriteV1,
    UNKNOWN_SCALAR_REFERENCE_V1,
    ReferenceAtomV1,
    ReferenceCatalogV1,
    ObjectRangeV1,
    ReferenceStateV1,
    ReferenceValueV1,
    ScalarFlagRelationV1,
    apply_reference_effects_v1,
    finite_reference_value_v1,
    interpret_reference_expressions_v1,
)
from spaghetti_extractor.transfer.x87 import (
    X87_CHECKED_DECODER,
    X87_CHECKED_EXECUTOR,
    typed_x87_operation_from_micro_op,
)

try:
    import spaghetti_extractor_transfer_native as native
except ImportError:  # pragma: no cover - host shells need not carry the extension
    native = None
else:  # pragma: no cover - an older installed extension is also unavailable
    if not all(hasattr(native, name) for name in (
        "join_reference_state_batches", "inspect_reference_transfer_plan",
        "inspect_reference_closure_inputs",
        "evaluate_reference_root_expressions",
        "evaluate_reference_root_effects",
        "evaluate_reference_closure_frontier",
        "evaluate_reference_closure_summary",
        "evaluate_reference_closure_receipt",
        "REFERENCE_KERNEL_OPERATION_REGISTRY_SHA256",
    )):
        native = None


def _value_payload(value: ReferenceValueV1) -> dict[str, Any]:
    return value.payload()


def _key_payload(key: tuple[str, str, int, int]) -> dict[str, Any]:
    return {
        "kind": key[0],
        "identity": key[1],
        "offset": key[2],
        "width": key[3],
    }


def _effect_exception_occurrence(
    operation: str, *, effect_index: int = 0, fault_sha256: str = "e" * 64,
) -> dict[str, Any]:
    return {
        "fault_index": 0,
        "fault_sha256": fault_sha256,
        "occurrence_kind": "effect",
        "effect_index": effect_index,
        "operation": operation,
        "call_id": None,
        "call_event_index": None,
    }


def _native_joins(
    cases: list[tuple[ReferenceStateV1, ReferenceStateV1]],
    *,
    baseline: dict[tuple[str, str, int, int], ReferenceValueV1],
    alternative_limit: int = 16,
) -> list[dict[str, Any]]:
    assert native is not None
    payload = {
        "alternative_limit": alternative_limit,
        "baseline_memory": [
            {**_key_payload(key), "value": _value_payload(value)}
            for key, value in sorted(baseline.items())
        ],
        "cases": [
            {
                "left": _reference_state_kernel_payload_v1(left),
                "right": _reference_state_kernel_payload_v1(right),
            }
            for left, right in cases
        ],
    }
    return json.loads(native.join_reference_state_batches(
        json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()
    ))["results"]


@unittest.skipIf(native is None, "native extension is unavailable")

class NativeReferenceRouteTests(unittest.TestCase):
    @staticmethod
    def _minimal_transfer_plan() -> dict[str, Any]:
        registry_sha256 = canonical_sha256_v3(operation_registry_payload_v2())
        plan = {
            "format": EXECUTABLE_TRANSFER_PLAN_FORMAT,
            "status": "complete",
            "bindings": {},
            "unit_inventory": [],
            "transfers": [{
                "identity": "semantic-transfer:native-fixture",
                "source": {
                    "rva_start": 0x1000,
                    "rva_end": 0x1001,
                    "contract_sha256": "a" * 64,
                    "instruction_bytes_sha256": "b" * 64,
                    "unit_ir_sha256": "e" * 64,
                },
                "expressions": [{
                    "id": 0,
                    "op": "const",
                    "operands": [],
                    "result_sort": "bitvector",
                    "width_bits": 32,
                    "parameters": {
                        "aux": 0,
                        "immediate": 7,
                        "identity": None,
                    },
                }],
                "effects": [{
                    "id": 0,
                    "op": "set_reg",
                    "operands": [0],
                    "parameters": {"aux": 0},
                }],
                "calls": [],
                "exception_occurrences": [],
                "x87_intrinsics": [],
                "terminator": {
                    "op": "outcome_return",
                    "operands": [0],
                    "parameters": {"aux": 0},
                },
            }],
            "direct_control_edges": [],
            "finite_control_routes": [],
            "atomic_effect_authority": [],
            "entry_targets": [0x1000],
            "runtime_provider_requirements": [],
            "operation_registry_sha256": registry_sha256,
            "diagnostics": {},
            "semantic_blockers": [],
            "counts": {},
            "authority": "exact_machine_semantics_only",
        }
        plan["plan_sha256"] = canonical_sha256_v3(plan)
        return plan

    def test_finite_route_outside_transfer_universe_is_an_honest_blocker(
        self,
    ) -> None:
        plan = self._minimal_transfer_plan()
        indirect = plan["transfers"][0]
        indirect["identity"] = "semantic-transfer:finite-missing-target"
        indirect["expressions"] = [{
            "id": 0, "op": "reg", "operands": [],
            "result_sort": "bitvector", "width_bits": 32,
            "parameters": {
                "aux": 0, "immediate": 0, "identity": None,
            },
        }]
        indirect["effects"] = []
        indirect["terminator"] = {
            "op": "outcome_indirect", "operands": [0],
            "parameters": {"aux": 0},
        }
        route_core = {
            "unit_id": indirect["identity"],
            "source_rva": 0x1000,
            "routes": [{
                "selector_value": 0,
                "target_rva": 0x1100,
                "target_address": 0x401100,
            }],
        }
        plan["finite_control_routes"] = [{
            **route_core,
            "route_inventory_sha256": canonical_sha256_v3(route_core),
        }]
        context = ExecutionClosureContextV1(
            roots=(0x1000,),
            catalog=ReferenceCatalogV1(
                guest_code_rvas=frozenset({0x1000, 0x1100}),
            ),
            authority_bindings={"fixture_sha256": "d" * 64},
            finite_control_targets={0x1000: (0x1100,)},
        )
        encoded_plan = json.dumps(
            plan, separators=(",", ":"), sort_keys=True
        ).encode()
        observed = json.loads(native.evaluate_reference_closure_receipt(
            encoded_plan,
            json.dumps(
                _execution_closure_kernel_context_payload_v1(context),
                separators=(",", ":"), sort_keys=True,
            ).encode(),
        ))
        expected = build_module_execution_closure_v1(
            transfer_plan_sha256=hashlib.sha256(encoded_plan).hexdigest(),
            transfers=tuple(
                _transfer_from_payload(row) for row in plan["transfers"]
            ),
            context=context,
        )
        for payload in (observed, expected):
            for metric in (
                "elapsed_milliseconds", "peak_rss_kib", "worklist_steps",
            ):
                payload["metrics"].pop(metric)

        self.assertEqual(observed, expected)
        self.assertFalse(observed["authorizes_execution"])
        self.assertEqual(observed["blockers"], [{
            "code": "execution_edge_outside_exact_universe",
            "source_rva": 0x1000,
            "target_rva": 0x1100,
            "edge_kind": "indirect_control",
        }])
