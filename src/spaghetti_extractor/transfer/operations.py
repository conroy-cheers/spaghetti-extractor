"""Typed operation registry for executable-transfer-plan-v2."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass

from .model import TransferPlanError, _Action, _Node


CALL_NATIVE_EXCEPTION_FAULT_KIND_V3 = "call_native_exception"


def call_native_exception_fault_payload_v3(
    *,
    call_kind: str,
    event_index: int,
    instruction_rva: int,
    operation: str,
    exception_index: int,
) -> dict[str, object]:
    """Name one exact exception occurrence at a canonical call site."""

    if call_kind not in {"external_call", "indirect_call"}:
        raise TransferPlanError(
            "native call exception is attached to a non-external call",
            code="call_exception_occurrence_invalid",
        )
    if not isinstance(operation, str) or not operation:
        raise TransferPlanError(
            "native call exception operation is malformed",
            code="call_exception_occurrence_invalid",
        )
    for value, context in (
        (event_index, "event index"),
        (instruction_rva, "instruction RVA"),
        (exception_index, "exception index"),
    ):
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise TransferPlanError(
                f"native call exception {context} is malformed",
                code="call_exception_occurrence_invalid",
            )
    return {
        "kind": CALL_NATIVE_EXCEPTION_FAULT_KIND_V3,
        "condition": {"op": "true"},
        "instruction_rva": instruction_rva,
        "call_kind": call_kind,
        "event_index": event_index,
        "operation": operation,
        "exception_index": exception_index,
    }


@dataclass(frozen=True)
class CoreOperationV2:
    name: str
    category: str
    result_sort: str | None
    width_bits: int | None
    minimum_arity: int
    maximum_arity: int
    native_exception: "NativeExceptionV2 | None" = None

    def validate_arity(self, arity: int) -> None:
        if not self.minimum_arity <= arity <= self.maximum_arity:
            raise TransferPlanError(
                f"transfer operation {self.name!r} has invalid arity {arity}",
                code="malformed_transfer_operation",
            )


@dataclass(frozen=True)
class NativeExceptionV2:
    """Native exception identity intrinsic to one canonical effect.

    Checked feasibility, handling, and root disposition remain authority-graph
    facts.  This registry row only prevents downstream renderers from inventing
    a second mapping from a canonical fault effect to Win32 exception metadata.
    """

    code: int
    flags_mask: int
    flags_value: int
    parameter_count: int
    continuable: bool
    access_violation: tuple[int, int] | None = None

    def payload(self) -> dict[str, object]:
        return {
            "code": self.code,
            "flags_mask": self.flags_mask,
            "flags_value": self.flags_value,
            "parameter_count": self.parameter_count,
            "continuable": self.continuable,
            "access_violation": (
                None
                if self.access_violation is None
                else {
                    "operation_parameter": self.access_violation[0],
                    "address_parameter": self.access_violation[1],
                }
            ),
        }


@dataclass(frozen=True)
class RuntimeProviderRuleV2:
    """One target-independent provider trigger over transfer-v2.

    ``layer`` keeps the compact semantic runtime requirements carried by the
    transfer plan distinct from the concrete providers required by the
    Behavioral-C realization. Both are selected from this one registry so a
    renderer cannot quietly invent a second operation-to-provider mapping.
    """

    provider: str
    layer: str
    always: bool = False
    expression_operations: tuple[str, ...] = ()
    effect_operations: tuple[str, ...] = ()
    terminator_operations: tuple[str, ...] = ()
    features: tuple[str, ...] = ()

    def payload(self) -> dict[str, object]:
        return {
            "provider": self.provider,
            "layer": self.layer,
            "always": self.always,
            "expression_operations": list(self.expression_operations),
            "effect_operations": list(self.effect_operations),
            "terminator_operations": list(self.terminator_operations),
            "features": list(self.features),
        }


def _spec(
    name: str,
    category: str,
    result_sort: str | None,
    width_bits: int | None,
    arity: int | tuple[int, int],
    *,
    native_exception: NativeExceptionV2 | None = None,
) -> CoreOperationV2:
    minimum, maximum = (arity, arity) if isinstance(arity, int) else arity
    return CoreOperationV2(
        name, category, result_sort, width_bits, minimum, maximum,
        native_exception,
    )


_PREDICATES: dict[str, int | tuple[int, int]] = {
    "true": 0,
    "false": 0,
    "flag": 0,
    "undefined_flag": (0, 1),
    "call_flag": 0,
    "ult32": 2,
    "eq": 2,
    "eq_bool": 2,
    "xor_bool": 2,
    "not": 1,
    "and_bool": (1, 5),
    "or_bool": (1, 5),
    "parity": 2,
    "add_overflow": 4,
    "sub_overflow": 4,
    "imul_overflow": 5,
    "mul_carry": 4,
    "udiv_valid32": 3,
    "sbb_borrow": 5,
    "sbb_overflow": 5,
    "adc_carry": 5,
    "adc_overflow": 5,
    "shift_cf": 2,
    "shift_of": 3,
    "fpu_pending_exception": 0,
}

_WORDS: dict[str, int | tuple[int, int]] = {
    "const": 0,
    "reg": 0,
    "fs_base": 0,
    "undefined_bv": (0, 1),
    "call_response": 0,
    "load": 1,
    "sub32": 2,
    "add32": (2, 4),
    "mul32": (2, 4),
    "xor32": (2, 4),
    "and32": (2, 4),
    "or32": (2, 4),
    "not32": 1,
    "neg32": 1,
    "shl32": 2,
    "lshr32": 2,
    "sar": 3,
    "sign_extend": 2,
    "ite": 3,
    "msb": (1, 2),
    "bool_to_bit": 1,
    "imul_low32": 2,
    "mul_low32": 2,
    "imul_high32": 2,
    "mul_high32": 2,
    "udiv_quot32": 3,
    "udiv_rem32": 3,
    "bsr_index": 2,
    "tzcnt": 2,
    "fpu_control": 0,
    "fpu_control_init": 0,
    "fpu_status": 0,
    "fpu_status_init": 0,
    "fpu_tag": 0,
    "fpu_last_opcode": 0,
    "fpu_instruction_pointer": 0,
    "fpu_code_selector": 0,
    "fpu_data_pointer": 0,
    "fpu_data_selector": 0,
    "fpu_control_load": 1,
    "fpu_control_word": 1,
    "fpu_status_word": 1,
}

_EFFECTS: dict[str, int] = {
    "eval_word": 1,
    "memory_write": 2,
    "divide_if": 1,
    "access_violation_if": 3,
    "call": 1,
    "rep_movsd": 4,
    "rep_movs": 4,
    "rep_stosd": 4,
    "rep_stos": 4,
    "rep_scas": 4,
    "set_reg": 1,
    "set_flag": 1,
    "sync_eflags": 0,
    "typed_x87": 1,
    "atomic_compare_exchange": 4,
    "atomic_exchange": 3,
}

_TERMINATORS: dict[str, int] = {
    "outcome_fallthrough": 1,
    "outcome_jump": 1,
    "outcome_branch": 3,
    "outcome_return": 1,
    "outcome_indirect": 1,
    "outcome_nonlocal": 2,
    "outcome_external": 0,
}


EXPRESSION_OPERATIONS_V2 = {
    **{
        name: _spec(name, "expression", "predicate", 1, arity)
        for name, arity in _PREDICATES.items()
    },
    **{
        name: _spec(name, "expression", "bitvector", 32, arity)
        for name, arity in _WORDS.items()
    },
}
def _native_effect_exception_v2(name: str) -> NativeExceptionV2 | None:
    if name == "divide_if":
        return NativeExceptionV2(
            code=0xC0000094,
            flags_mask=0x1,
            flags_value=0,
            parameter_count=0,
            continuable=True,
        )
    if name == "access_violation_if":
        return NativeExceptionV2(
            code=0xC0000005,
            flags_mask=0x1,
            flags_value=0,
            parameter_count=2,
            continuable=True,
            access_violation=(0, 1),
        )
    return None


EFFECT_OPERATIONS_V2 = {
    name: _spec(
        name,
        "effect",
        None,
        None,
        arity,
        native_exception=_native_effect_exception_v2(name),
    )
    for name, arity in _EFFECTS.items()
}
NATIVE_EXCEPTION_EFFECTS_V2 = frozenset(
    name
    for name, specification in EFFECT_OPERATIONS_V2.items()
    if specification.native_exception is not None
)


def native_exception_operations_for_call_v2(
    call: Mapping[str, object],
    *,
    strict_list: bool = False,
    context: str = "external-call",
) -> tuple[str, ...]:
    """Decode the canonical exception effects authorized at one call site."""

    raw = call.get("native_exception_operations", [])
    if not isinstance(raw, list):
        if strict_list:
            raise TransferPlanError(
                f"{context} native exception operations must be a list"
            )
        raw = []
    operations = tuple(
        item
        for item in raw
        if isinstance(item, str) and item
    )
    if len(operations) != len(raw):
        raise TransferPlanError(
            f"{context} native exception operation must be a non-empty string"
        )
    if operations != tuple(sorted(set(operations))):
        raise TransferPlanError(
            f"{context} native exception operations are not canonical",
            code="malformed_external_call_exception_inventory",
        )
    if any(name not in NATIVE_EXCEPTION_EFFECTS_V2 for name in operations):
        raise TransferPlanError(
            f"{context} native exception operation has no canonical metadata",
            code="unsupported_external_call_exception",
        )
    if operations and call.get("kind") not in {
        "external_call", "indirect_call"
    }:
        raise TransferPlanError(
            "internal calls cannot carry an external-callee exception inventory",
            code="malformed_external_call_exception_inventory",
        )
    return operations


TERMINATOR_OPERATIONS_V2 = {
    name: _spec(name, "terminator", None, None, arity)
    for name, arity in _TERMINATORS.items()
}


RUNTIME_PROVIDER_RULES_V2 = (
    RuntimeProviderRuleV2(
        provider="checked_memory", layer="transfer_plan", always=True,
    ),
    RuntimeProviderRuleV2(
        provider="checked_outcomes", layer="transfer_plan", always=True,
    ),
    RuntimeProviderRuleV2(
        provider="checked_calls", layer="transfer_plan",
        effect_operations=("call",), features=("calls",),
    ),
    RuntimeProviderRuleV2(
        provider="typed_x87", layer="transfer_plan",
        effect_operations=("typed_x87",),
    ),
    RuntimeProviderRuleV2(
        provider="checked_atomics", layer="transfer_plan",
        effect_operations=("atomic_compare_exchange", "atomic_exchange"),
    ),
    RuntimeProviderRuleV2(
        provider="memory.read", layer="behavioral_c",
        expression_operations=("load",),
        effect_operations=(
            "memory_write", "rep_movsd", "rep_movs", "rep_stosd",
            "rep_stos", "rep_scas",
        ),
    ),
    RuntimeProviderRuleV2(
        provider="memory.write", layer="behavioral_c",
        effect_operations=(
            "memory_write", "rep_movsd", "rep_movs", "rep_stosd",
            "rep_stos", "rep_scas",
        ),
    ),
    RuntimeProviderRuleV2(
        provider="call.dispatch", layer="behavioral_c",
        effect_operations=("call",), features=("calls",),
    ),
    RuntimeProviderRuleV2(
        provider="atomic.rmw", layer="behavioral_c",
        effect_operations=("atomic_compare_exchange", "atomic_exchange"),
    ),
    RuntimeProviderRuleV2(
        provider="x87.typed_exact", layer="behavioral_c",
        effect_operations=("typed_x87",),
    ),
    RuntimeProviderRuleV2(
        provider="definedness.choice", layer="behavioral_c",
        expression_operations=("undefined_bv", "undefined_flag"),
    ),
    RuntimeProviderRuleV2(
        provider="code_target.resolve", layer="behavioral_c",
        terminator_operations=("outcome_indirect",),
    ),
    RuntimeProviderRuleV2(
        provider="outcome.nonlocal", layer="behavioral_c",
        terminator_operations=("outcome_nonlocal",),
    ),
    RuntimeProviderRuleV2(
        provider="exception.access_violation", layer="behavioral_c",
        effect_operations=("access_violation_if",),
    ),
)


def runtime_provider_catalog_payload_v2() -> list[dict[str, object]]:
    """Return the sole canonical transfer-operation provider catalog."""

    return [
        row.payload()
        for row in sorted(
            RUNTIME_PROVIDER_RULES_V2,
            key=lambda item: (item.layer, item.provider),
        )
    ]


def runtime_provider_requirements_v2(
    transfers: Iterable[object], *, layer: str,
) -> list[str]:
    """Select provider identities for a collection of checked transfers."""

    rules = tuple(row for row in RUNTIME_PROVIDER_RULES_V2 if row.layer == layer)
    if not rules:
        raise TransferPlanError(
            f"unknown transfer runtime-provider layer {layer!r}",
            code="unsupported_runtime_provider_layer",
        )
    selected = {row.provider for row in rules if row.always}
    for transfer in transfers:
        nodes = getattr(transfer, "nodes", ())
        actions = getattr(transfer, "actions", ())
        node_ops = {getattr(node, "op", None) for node in nodes}
        action_ops = {getattr(action, "op", None) for action in actions}
        terminator = actions[-1].op if actions else None
        features: set[str] = set()
        if getattr(transfer, "calls", ()):
            features.add("calls")
        if getattr(transfer, "x87_operations", ()):
            features.add("x87_intrinsics")
        for rule in rules:
            if (
                node_ops.intersection(rule.expression_operations)
                or action_ops.intersection(rule.effect_operations)
                or terminator in rule.terminator_operations
                or features.intersection(rule.features)
            ):
                selected.add(rule.provider)
    return sorted(selected)


def expression_operation_v2(node: _Node) -> CoreOperationV2:
    spec = EXPRESSION_OPERATIONS_V2.get(node.op)
    if spec is None:
        raise TransferPlanError(
            f"transfer expression operation {node.op!r} is unsupported",
            code="unsupported_transfer_operation",
        )
    spec.validate_arity(len(node.args))
    if node.op == "load" and node.aux not in {1, 2, 4}:
        raise TransferPlanError(
            "transfer load width is unsupported",
            code="malformed_transfer_width",
        )
    return spec


def action_operation_v2(action: _Action, *, terminator: bool) -> CoreOperationV2:
    registry = TERMINATOR_OPERATIONS_V2 if terminator else EFFECT_OPERATIONS_V2
    spec = registry.get(action.op)
    if spec is None:
        raise TransferPlanError(
            f"transfer {'terminator' if terminator else 'effect'} operation "
            f"{action.op!r} is unsupported",
            code="unsupported_transfer_operation",
        )
    spec.validate_arity(len(action.args))
    if action.op in {
        "memory_write", "rep_movs", "rep_stos", "rep_scas",
        "atomic_compare_exchange", "atomic_exchange",
    } and action.aux not in {1, 2, 4}:
        raise TransferPlanError(
            f"transfer effect {action.op!r} has unsupported width",
            code="malformed_transfer_width",
        )
    return spec


def operation_registry_payload_v2() -> list[dict[str, object]]:
    specs = (
        *EXPRESSION_OPERATIONS_V2.values(),
        *EFFECT_OPERATIONS_V2.values(),
        *TERMINATOR_OPERATIONS_V2.values(),
    )
    return [
        {
            "name": row.name,
            "category": row.category,
            "result_sort": row.result_sort,
            "width_bits": row.width_bits,
            "minimum_arity": row.minimum_arity,
            "maximum_arity": row.maximum_arity,
            "native_exception": (
                None
                if row.native_exception is None
                else row.native_exception.payload()
            ),
        }
        for row in sorted(specs, key=lambda item: (item.category, item.name))
    ]


__all__ = [
    "CALL_NATIVE_EXCEPTION_FAULT_KIND_V3",
    "CoreOperationV2",
    "NativeExceptionV2",
    "RuntimeProviderRuleV2",
    "EFFECT_OPERATIONS_V2",
    "NATIVE_EXCEPTION_EFFECTS_V2",
    "EXPRESSION_OPERATIONS_V2",
    "TERMINATOR_OPERATIONS_V2",
    "RUNTIME_PROVIDER_RULES_V2",
    "action_operation_v2",
    "call_native_exception_fault_payload_v3",
    "expression_operation_v2",
    "native_exception_operations_for_call_v2",
    "operation_registry_payload_v2",
    "runtime_provider_catalog_payload_v2",
    "runtime_provider_requirements_v2",
]
