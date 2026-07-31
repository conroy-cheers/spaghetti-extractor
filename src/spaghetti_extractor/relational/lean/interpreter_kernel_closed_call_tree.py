"""Emit exact record bindings for generic checked call-tree closure.

The emitter accepts an explicit finite function inventory. Every internal or
indirect call must name an admitted target, while recursive source-RVA shapes
remain valid. Lean checks exact record lookup/decode facts, and the generic
call-aware equivalence theorem converts every finite authoritative derivation
to checked Step/Run/Invoke evidence without operation-specific premises.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Sequence

from ...errors import StageAInputError
from ...util import write_json


INTERPRETER_KERNEL_CLOSED_CALL_TREE_FORMAT = (
    "stage-a-relational-interpreter-kernel-closed-call-tree-v3"
)
INTERPRETER_KERNEL_CLOSED_CALL_TREE_PLAN_FILENAME = (
    "interpreter-kernel-closed-call-tree.json"
)
INTERPRETER_KERNEL_CLOSED_CALL_TREE_LEAN_FILENAME = (
    "GeneratedRelationalInterpreterKernelClosedCallTree.lean"
)

_LEAN_LOCAL = re.compile(r"[A-Za-z_][A-Za-z0-9_']*\Z")
_LEAN_QUALIFIED = re.compile(
    r"[A-Za-z_][A-Za-z0-9_']*(?:\.[A-Za-z_][A-Za-z0-9_']*)*\Z"
)
_CALL_KINDS = frozenset({"external", "internal", "indirect"})


class RelationalInterpreterKernelClosedCallTreeGenerationError(
    StageAInputError
):
    """Exact semantic function records cannot form a checked call tree."""


def _nat(value: object, context: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise RelationalInterpreterKernelClosedCallTreeGenerationError(
            f"{context} must be a natural number"
        )
    return value


def _lean_local(value: object, context: str) -> str:
    if not isinstance(value, str) or _LEAN_LOCAL.fullmatch(value) is None:
        raise RelationalInterpreterKernelClosedCallTreeGenerationError(
            f"{context} must be a Lean local identifier"
        )
    return value


def _lean_qualified(value: object, context: str) -> str:
    if not isinstance(value, str) or _LEAN_QUALIFIED.fullmatch(value) is None:
        raise RelationalInterpreterKernelClosedCallTreeGenerationError(
            f"{context} must be a Lean qualified identifier"
        )
    return value


@dataclass(frozen=True)
class ClosedCallTreeCallSpec:
    """One statically admitted semantic call edge."""

    call_index: int
    kind: str
    target_source_rva: int | None = None

    def payload(self) -> dict[str, Any]:
        return {
            "call_index": self.call_index,
            "kind": self.kind,
            "target_source_rva": self.target_source_rva,
        }


@dataclass(frozen=True)
class ExactCheckedSemanticFunctionSpec:
    """Lean names for one exact checked semantic function entry."""

    name: str
    source_rva: int
    program_record: str
    semantic_transfer: str
    lookup_exact: str
    decode_exact: str
    checked_exact: str
    calls: tuple[ClosedCallTreeCallSpec, ...] = ()
    # Accepted only so keyword-based v1 callers can migrate incrementally.
    # It is not validated against edges, serialized, or emitted to Lean.
    rank: int | None = None

    def payload(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "source_rva": self.source_rva,
            "program_record": self.program_record,
            "semantic_transfer": self.semantic_transfer,
            "lookup_exact": self.lookup_exact,
            "decode_exact": self.decode_exact,
            "checked_exact": self.checked_exact,
            "calls": [call.payload() for call in self.calls],
        }


@dataclass(frozen=True)
class InterpreterKernelClosedCallTreePlan:
    source_module: str
    namespace: str
    records_term: str
    functions: tuple[ExactCheckedSemanticFunctionSpec, ...]

    def payload(self) -> dict[str, Any]:
        return {
            "format": INTERPRETER_KERNEL_CLOSED_CALL_TREE_FORMAT,
            "acceptance_authority": False,
            "source_module": self.source_module,
            "namespace": self.namespace,
            "records_term": self.records_term,
            "control_mode": "finite-nested-semantic-evidence",
            "functions": [function.payload() for function in self.functions],
            "closed_components": [
                "unique_exact_semantic_function_entries",
                "exact_program_record_lookup",
                "exact_semantic_transfer_decode",
                "checked_semantic_transfer",
                "resolved_internal_call_targets",
                "resolved_indirect_call_targets",
                "call_aware_abstract_checked_equivalence",
                "rank_free_checked_call_tree_construction",
                "canonical_step_run_invoke_closure_adapter",
            ],
            "remaining_proof_premises": [],
        }


def exact_checked_semantic_function_specs_from_record_packs(
    *,
    source_rvas: Sequence[int],
    shard_size: int,
    calls_by_source_rva: Mapping[
        int, Sequence[ClosedCallTreeCallSpec]
    ] | None = None,
    record_namespace: str = (
        "StageA.GeneratedRelational.InterpreterKernelData"
    ),
) -> tuple[ExactCheckedSemanticFunctionSpec, ...]:
    """Bind exact checked-record pack entries to a semantic function catalog.

    ``source_rvas`` must be in the same order as the checked semantic record
    packs.  Call edges remain explicit untrusted proposals and are validated by
    the ordinary closed-call-tree planner.
    """

    size = _nat(shard_size, "semantic record shard size")
    if size == 0:
        raise RelationalInterpreterKernelClosedCallTreeGenerationError(
            "semantic record shard size must be positive"
        )
    namespace = _lean_qualified(
        record_namespace, "semantic record namespace"
    )
    sources = tuple(
        _nat(source_rva, f"semantic record {index} source RVA")
        for index, source_rva in enumerate(source_rvas)
    )
    if not sources:
        raise RelationalInterpreterKernelClosedCallTreeGenerationError(
            "semantic record inventory must not be empty"
        )
    if len(sources) != len(set(sources)):
        raise RelationalInterpreterKernelClosedCallTreeGenerationError(
            "semantic record source RVAs must be unique"
        )
    proposed_calls = calls_by_source_rva or {}
    unknown_sources = set(proposed_calls).difference(sources)
    if unknown_sources:
        first = min(unknown_sources)
        raise RelationalInterpreterKernelClosedCallTreeGenerationError(
            "semantic call inventory names unknown source RVA "
            f"0x{first:x}"
        )

    functions: list[ExactCheckedSemanticFunctionSpec] = []
    for ordinal, source_rva in enumerate(sources):
        pack_index, entry_offset = divmod(ordinal, size)
        record = (
            f"{namespace}."
            f"generatedInterpreterKernelSemanticRecordPack{pack_index:04d}"
            f"Entry{entry_offset:04d}"
        )
        functions.append(
            ExactCheckedSemanticFunctionSpec(
                name=f"function{ordinal:04d}",
                source_rva=source_rva,
                program_record=f"{record}.record",
                semantic_transfer=f"{record}.semantic.transfer",
                lookup_exact=f"{record}.lookupExact",
                decode_exact=f"{record}.semantic.decodeExact",
                checked_exact=f"{record}.semantic.checkedExact",
                calls=tuple(proposed_calls.get(source_rva, ())),
            )
        )
    return tuple(functions)


def _validate_call(
    call: ClosedCallTreeCallSpec,
    *,
    function_name: str,
) -> ClosedCallTreeCallSpec:
    call_index = _nat(call.call_index, f"{function_name} call index")
    if call.kind not in _CALL_KINDS:
        raise RelationalInterpreterKernelClosedCallTreeGenerationError(
            f"{function_name} call {call_index} has unsupported kind "
            f"{call.kind!r}"
        )
    target = call.target_source_rva
    if call.kind == "external":
        if target is not None:
            raise RelationalInterpreterKernelClosedCallTreeGenerationError(
                f"{function_name} external call {call_index} must not have "
                "an internal target"
            )
    else:
        target = _nat(
            target,
            f"{function_name} {call.kind} call {call_index} target RVA",
        )
    return ClosedCallTreeCallSpec(
        call_index=call_index,
        kind=call.kind,
        target_source_rva=target,
    )


def _validate_function(
    function: ExactCheckedSemanticFunctionSpec,
) -> ExactCheckedSemanticFunctionSpec:
    name = _lean_local(function.name, "semantic function name")
    calls = tuple(
        sorted(
            (
                _validate_call(call, function_name=name)
                for call in function.calls
            ),
            key=lambda call: call.call_index,
        )
    )
    call_indices = [call.call_index for call in calls]
    if len(call_indices) != len(set(call_indices)):
        raise RelationalInterpreterKernelClosedCallTreeGenerationError(
            f"{name} has duplicate semantic call indices"
        )
    return ExactCheckedSemanticFunctionSpec(
        name=name,
        source_rva=_nat(function.source_rva, f"{name} source RVA"),
        program_record=_lean_qualified(
            function.program_record, f"{name} program record"
        ),
        semantic_transfer=_lean_qualified(
            function.semantic_transfer, f"{name} semantic transfer"
        ),
        lookup_exact=_lean_qualified(
            function.lookup_exact, f"{name} exact lookup proof"
        ),
        decode_exact=_lean_qualified(
            function.decode_exact, f"{name} exact decode proof"
        ),
        checked_exact=_lean_qualified(
            function.checked_exact, f"{name} checked transfer proof"
        ),
        calls=calls,
        rank=None,
    )


def build_relational_interpreter_kernel_closed_call_tree_plan(
    *,
    source_module: str,
    records_term: str,
    functions: Sequence[ExactCheckedSemanticFunctionSpec],
    namespace: str = (
        "StageA.GeneratedRelational.InterpreterKernelClosedCallTree"
    ),
) -> InterpreterKernelClosedCallTreePlan:
    """Validate exact records and the statically resolved call inventory."""

    module = _lean_qualified(source_module, "source module")
    records = _lean_qualified(records_term, "semantic records term")
    generated_namespace = _lean_qualified(namespace, "generated namespace")
    checked = tuple(
        sorted(
            (_validate_function(function) for function in functions),
            key=lambda function: (function.source_rva, function.name),
        )
    )
    if not checked:
        raise RelationalInterpreterKernelClosedCallTreeGenerationError(
            "closed call tree requires at least one exact semantic function"
        )

    names = [function.name for function in checked]
    if len(names) != len(set(names)):
        raise RelationalInterpreterKernelClosedCallTreeGenerationError(
            "exact semantic function names must be unique"
        )
    source_rvas = [function.source_rva for function in checked]
    if len(source_rvas) != len(set(source_rvas)):
        raise RelationalInterpreterKernelClosedCallTreeGenerationError(
            "exact semantic function source RVAs must be unique"
        )

    by_source = {function.source_rva: function for function in checked}
    for function in checked:
        for call in function.calls:
            if call.kind == "external":
                continue
            if call.target_source_rva is None:
                raise RelationalInterpreterKernelClosedCallTreeGenerationError(
                    f"{call.kind} call in {function.name} at call "
                    f"{call.call_index} has no exact target RVA"
                )
            if call.target_source_rva not in by_source:
                control = (
                    "unresolved indirect call"
                    if call.kind == "indirect"
                    else "unresolved internal call"
                )
                raise RelationalInterpreterKernelClosedCallTreeGenerationError(
                    f"{control} in {function.name} at call "
                    f"{call.call_index}: target RVA "
                    f"0x{call.target_source_rva:x} is not an exact semantic "
                    "function record"
                )

    return InterpreterKernelClosedCallTreePlan(
        source_module=module,
        namespace=generated_namespace,
        records_term=records,
        functions=checked,
    )


def relational_interpreter_kernel_closed_call_tree_source(
    plan: InterpreterKernelClosedCallTreePlan,
) -> str:
    """Render exact static authority and finite-evidence adapters."""

    inventory_fields = "\n".join(
        f"""  function{ordinal:04d}LookupExact :
    lookupProgramRecord {plan.records_term} {function.source_rva} =
      some {function.program_record}
  function{ordinal:04d}DecodeExact :
    {function.program_record}.decode = some {function.semantic_transfer}
  function{ordinal:04d}CheckedExact :
    {function.semantic_transfer}.checked = true"""
        for ordinal, function in enumerate(plan.functions)
    )
    inventory_values = "\n".join(
        f"""  function{ordinal:04d}LookupExact := {function.lookup_exact}
  function{ordinal:04d}DecodeExact := {function.decode_exact}
  function{ordinal:04d}CheckedExact := {function.checked_exact}"""
        for ordinal, function in enumerate(plan.functions)
    )
    call_rows: list[str] = []
    for caller in plan.functions:
        for call in caller.calls:
            target = (
                "none"
                if call.target_source_rva is None
                else f"some {call.target_source_rva}"
            )
            call_rows.append(
                f"""{{ callerSourceRva := {caller.source_rva}
      callIndex := {call.call_index}
      kind := .{call.kind}
      targetSourceRva := {target} }}"""
            )

    call_list = ",\n    ".join(call_rows)
    return f"""import StageA.RelationalInterpreterKernelClosedCallTree
import StageA.{plan.source_module}

namespace {plan.namespace}

open StageA.Relational.Interpreter
open StageA.Relational.InterpreterKernel
open StageA.Relational.InterpreterKernelClosedCallTree

/-- Exact static identities for every admitted semantic function. -/
structure GeneratedExactCheckedSemanticFunctionInventory : Prop where
{inventory_fields}

def generatedExactCheckedSemanticFunctionInventory :
    GeneratedExactCheckedSemanticFunctionInventory := {{
{inventory_values}
}}

structure GeneratedClosedCallTreeCallEdge where
  callerSourceRva : Nat
  callIndex : Nat
  kind : CallKind
  targetSourceRva : Option Nat

def generatedClosedCallTreeCallEdges :
    List GeneratedClosedCallTreeCallEdge := [
    {call_list}
  ]

/-- The exact record inventory and the generic call-aware semantics together
produce a concrete finite closure.  No per-operation semantic premises remain. -/
structure GeneratedFiniteCheckedSemanticFunctionBindings : Prop where
  exactInventory : GeneratedExactCheckedSemanticFunctionInventory

def generatedFiniteCheckedSemanticFunctionBindings :
    GeneratedFiniteCheckedSemanticFunctionBindings := {{
  exactInventory := generatedExactCheckedSemanticFunctionInventory
}}

def GeneratedFiniteCheckedSemanticFunctionBindings.toClosure
    (_bindings : GeneratedFiniteCheckedSemanticFunctionBindings) :
    CheckedSemanticCallTreeClosure {plan.records_term} :=
  checkedSemanticCallTreeClosure {plan.records_term}

#print axioms generatedExactCheckedSemanticFunctionInventory
#print axioms generatedFiniteCheckedSemanticFunctionBindings
#print axioms GeneratedFiniteCheckedSemanticFunctionBindings.toClosure

end {plan.namespace}
"""


def write_relational_interpreter_kernel_closed_call_tree_bundle(
    *,
    out: Path | str,
    **kwargs: Any,
) -> InterpreterKernelClosedCallTreePlan:
    output = Path(out)
    output.mkdir(parents=True, exist_ok=True)
    plan = build_relational_interpreter_kernel_closed_call_tree_plan(**kwargs)
    write_json(
        output / INTERPRETER_KERNEL_CLOSED_CALL_TREE_PLAN_FILENAME,
        plan.payload(),
    )
    (
        output / INTERPRETER_KERNEL_CLOSED_CALL_TREE_LEAN_FILENAME
    ).write_text(
        relational_interpreter_kernel_closed_call_tree_source(plan),
        encoding="ascii",
    )
    return plan


__all__ = [
    "INTERPRETER_KERNEL_CLOSED_CALL_TREE_FORMAT",
    "INTERPRETER_KERNEL_CLOSED_CALL_TREE_LEAN_FILENAME",
    "INTERPRETER_KERNEL_CLOSED_CALL_TREE_PLAN_FILENAME",
    "ClosedCallTreeCallSpec",
    "ExactCheckedSemanticFunctionSpec",
    "InterpreterKernelClosedCallTreePlan",
    "RelationalInterpreterKernelClosedCallTreeGenerationError",
    "build_relational_interpreter_kernel_closed_call_tree_plan",
    "exact_checked_semantic_function_specs_from_record_packs",
    "relational_interpreter_kernel_closed_call_tree_source",
    "write_relational_interpreter_kernel_closed_call_tree_bundle",
]
