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
    ExecutionFunctionContextV1,
    execution_closure_context_with_roots_v1,
    _execution_closure_kernel_context_payload_v1,
    _reference_state_kernel_payload_v1,
    build_module_execution_closure_v1,
    check_module_execution_closure_v1,
    join_reference_states_v1,
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


class ExecutionClosureContextTests(unittest.TestCase):
    def test_function_context_retains_derived_identities(self) -> None:
        context = ExecutionFunctionContextV1(
            0x1000, 0x2000, (0x1010,)
        )
        expected = "execution-context:" + canonical_sha256_v3({
            "root_rva": 0x1000,
            "function_entry_rva": 0x2000,
            "call_string": [0x1010],
        })

        self.assertEqual(context.identity, expected)
        self.assertIs(context.identity, context.identity)
        self.assertEqual(
            context.frame_identity, f"captured_stack_frame:{expected}"
        )
        self.assertIs(context.frame_identity, context.frame_identity)
        self.assertEqual(
            context, ExecutionFunctionContextV1(
                0x1000, 0x2000, (0x1010,)
            )
        )

    def test_component_reroot_replaces_stale_initial_state_roots(self) -> None:
        shared = ReferenceStateV1()
        context = ExecutionClosureContextV1(
            roots=(0x1000,),
            catalog=ReferenceCatalogV1(
                guest_code_rvas=frozenset({0x1000, 0x2000})
            ),
            authority_bindings={"fixture_sha256": "d" * 64},
            initial_states={0x1000: shared},
        )

        rerooted = execution_closure_context_with_roots_v1(
            context, (0x2000,)
        )

        self.assertEqual(rerooted.roots, (0x2000,))
        self.assertEqual(set(rerooted.initial_states), {0x2000})
        self.assertEqual(rerooted.initial_states[0x2000].memory, shared.memory)

    def test_component_reroot_binds_canonical_boundary_exits(self) -> None:
        context = ExecutionClosureContextV1(
            roots=(0x1000,),
            catalog=ReferenceCatalogV1(
                guest_code_rvas=frozenset({0x1000, 0x2000})
            ),
            authority_bindings={"fixture_sha256": "d" * 64},
        )

        rerooted = execution_closure_context_with_roots_v1(
            context, (0x2000,), boundary_exit_rvas=(0x2000,)
        )

        self.assertEqual(rerooted.boundary_exit_rvas, (0x2000,))
