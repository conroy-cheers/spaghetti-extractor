"""Emit standalone exact internal direct-call register summaries for Lean.

This module is deliberately non-authoritative.  It validates only that the
proposal is unambiguous to serialize.  Lean decides exact decoding, finite CFG
closure, dependency grounding, and structural register-checker evidence.  The
generated module explicitly records that this evidence is not whole-callee
semantic acceptance authority.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal, Mapping

from ...errors import StageAInputError


INTERNAL_DIRECT_CALL_REGISTER_SUMMARY_LEAN_FILENAME = (
    "GeneratedRelationalInternalDirectCallRegisterSummary.lean"
)

_LEAN_QUALIFIED_NAME = re.compile(
    r"[A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z][A-Za-z0-9_]*)*\Z"
)
_REGISTERS = frozenset(("eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp"))
_U32_LIMIT = 1 << 32


class InternalDirectCallRegisterSummaryGenerationError(StageAInputError):
    """The proposal cannot be serialized as an unambiguous Lean term."""


def _nat(value: int, context: str, *, u32: bool = False) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise InternalDirectCallRegisterSummaryGenerationError(
            f"{context} must be a non-negative integer"
        )
    if u32 and value >= _U32_LIMIT:
        raise InternalDirectCallRegisterSummaryGenerationError(
            f"{context} must fit in an unsigned 32-bit word"
        )
    return value


def _register(value: str, context: str) -> str:
    if value not in _REGISTERS:
        raise InternalDirectCallRegisterSummaryGenerationError(
            f"{context} is not a supported IA-32 register"
        )
    return value


def _qualified(value: str, context: str) -> str:
    if not isinstance(value, str) or _LEAN_QUALIFIED_NAME.fullmatch(value) is None:
        raise InternalDirectCallRegisterSummaryGenerationError(
            f"{context} must be a qualified Lean identifier"
        )
    return value


def _module(value: str, context: str) -> str:
    if not isinstance(value, str) or _LEAN_QUALIFIED_NAME.fullmatch(value) is None:
        raise InternalDirectCallRegisterSummaryGenerationError(
            f"{context} must be a Lean module name"
        )
    return value


def _lean_list(values: list[str]) -> str:
    return "[" + ", ".join(values) + "]"


@dataclass(frozen=True)
class LeanSpan:
    start: int
    size: int

    def lean(self, context: str = "span") -> str:
        start = _nat(self.start, f"{context}.start", u32=True)
        size = _nat(self.size, f"{context}.size", u32=True)
        return f"{{ start := {start}, size := {size} }}"


@dataclass(frozen=True)
class LeanExactRegionPair:
    region_id: int
    original: LeanSpan
    candidate: LeanSpan

    def lean(self, context: str = "region") -> str:
        region_id = _nat(self.region_id, f"{context}.region_id")
        return (
            "{ id := "
            f"{region_id}, original := {self.original.lean(f'{context}.original')}, "
            f"candidate := {self.candidate.lean(f'{context}.candidate')} }}"
        )


EdgeKind = Literal[
    "direct",
    "direct_tail",
    "branch_taken",
    "branch_fallthrough",
    "nested_summary",
    "machine_import",
    "machine_import_tail",
    "finite_indirect",
    "finite_origin_call",
    "finite_origin_tail",
    "constant_indirect",
]


@dataclass(frozen=True)
class LeanCalleeEdge:
    source_region_id: int
    target_region_id: int
    kind: EdgeKind
    dependency_id: int | None = None

    def lean(self, context: str = "edge") -> str:
        source = _nat(self.source_region_id, f"{context}.source_region_id")
        target = _nat(self.target_region_id, f"{context}.target_region_id")
        if self.kind == "direct":
            constructor = ".direct"
        elif self.kind == "direct_tail":
            constructor = ".directTail"
        elif self.kind == "branch_taken":
            constructor = ".branchTaken"
        elif self.kind == "branch_fallthrough":
            constructor = ".branchFallthrough"
        elif self.kind == "constant_indirect":
            constructor = ".constantIndirect"
        elif self.kind in {
            "nested_summary",
            "machine_import",
            "machine_import_tail",
            "finite_indirect",
            "finite_origin_call",
            "finite_origin_tail",
        }:
            if self.dependency_id is None:
                raise InternalDirectCallRegisterSummaryGenerationError(
                    f"{context}.dependency_id is required for {self.kind}"
                )
            dependency = _nat(self.dependency_id, f"{context}.dependency_id")
            constructor = (
                f".nestedSummary {dependency}"
                if self.kind == "nested_summary"
                else (
                    f".machineImport {dependency}"
                    if self.kind == "machine_import"
                    else (
                        f".machineImportTail {dependency}"
                        if self.kind == "machine_import_tail"
                        else (
                        f".finiteIndirect {dependency}"
                        if self.kind == "finite_indirect"
                            else (
                                f".finiteOriginCall {dependency}"
                                if self.kind == "finite_origin_call"
                                else f".finiteOriginTail {dependency}"
                            )
                        )
                    )
                )
            )
        else:
            raise InternalDirectCallRegisterSummaryGenerationError(
                f"{context}.kind is unsupported"
            )
        if self.kind in {
            "direct",
            "direct_tail",
            "branch_taken",
            "branch_fallthrough",
            "constant_indirect",
        } and (
            self.dependency_id is not None
        ):
            raise InternalDirectCallRegisterSummaryGenerationError(
                f"{context}.dependency_id is only valid for dependency edges"
            )
        return (
            "{ sourceRegionId := "
            f"{source}, targetRegionId := {target}, kind := {constructor} }}"
        )


@dataclass(frozen=True)
class LeanReturnInventoryEntry:
    return_region_id: int
    continuation_region_id: int

    def lean(self, context: str = "return") -> str:
        return_id = _nat(self.return_region_id, f"{context}.return_region_id")
        continuation = _nat(
            self.continuation_region_id, f"{context}.continuation_region_id"
        )
        return (
            "{ returnRegionId := "
            f"{return_id}, continuationRegionId := {continuation} }}"
        )


def _legacy_expr_lean(expression: Mapping[str, Any], context: str) -> str:
    operation = expression.get("op")
    if operation == "reg":
        register = expression.get("name")
        if not isinstance(register, str):
            raise InternalDirectCallRegisterSummaryGenerationError(
                f"{context}.name must be a register"
            )
        return f".inputReg .{_register(register, f'{context}.name')}"
    if operation == "const":
        return f".constant {_nat(expression.get('value'), f'{context}.value', u32=True)}"
    constructors = {
        "add32": "add",
        "sub32": "sub",
        "and32": "bitAnd",
        "xor32": "bitXor",
        "or32": "bitOr",
        "mul32": "multiply",
    }
    constructor = constructors.get(operation)
    arguments = expression.get("args")
    if (
        constructor is None
        or not isinstance(arguments, list)
        or len(arguments) != 2
        or not all(isinstance(argument, Mapping) for argument in arguments)
    ):
        raise InternalDirectCallRegisterSummaryGenerationError(
            f"{context} is outside the finite-table index expression grammar"
        )
    left = _legacy_expr_lean(arguments[0], f"{context}.args[0]")
    right = _legacy_expr_lean(arguments[1], f"{context}.args[1]")
    return f".{constructor} ({left}) ({right})"


@dataclass(frozen=True)
class LeanFiniteIndirectJumpDependency:
    dependency_id: int
    source_region_id: int
    original_table_base: int
    candidate_table_base: int
    upper_exclusive: int
    original_index_expression: Mapping[str, Any]
    candidate_index_expression: Mapping[str, Any]
    entry_target_region_ids: tuple[int, ...]

    def lean(self, context: str = "finite indirect dependency") -> str:
        entries = _lean_list([
            str(_nat(value, f"{context}.entry_target_region_ids[{index}]"))
            for index, value in enumerate(self.entry_target_region_ids)
        ])
        return (
            "{ id := "
            f"{_nat(self.dependency_id, f'{context}.dependency_id')}, "
            "sourceRegionId := "
            f"{_nat(self.source_region_id, f'{context}.source_region_id')}, "
            "originalTableBase := "
            f"{_nat(self.original_table_base, f'{context}.original_table_base', u32=True)}, "
            "candidateTableBase := "
            f"{_nat(self.candidate_table_base, f'{context}.candidate_table_base', u32=True)}, "
            "upperExclusive := "
            f"{_nat(self.upper_exclusive, f'{context}.upper_exclusive', u32=True)}, "
            "originalIndexExpression := "
            f"{_legacy_expr_lean(self.original_index_expression, f'{context}.original_index_expression')}, "
            "candidateIndexExpression := "
            f"{_legacy_expr_lean(self.candidate_index_expression, f'{context}.candidate_index_expression')}, "
            f"entryTargetRegionIds := {entries} }}"
        )


@dataclass(frozen=True)
class LeanFiniteOriginTailTarget:
    target_id: int
    region_id: int

    def lean(self, context: str = "finite origin tail target") -> str:
        return (
            "{ targetId := "
            f"{_nat(self.target_id, f'{context}.target_id')}, "
            f"regionId := {_nat(self.region_id, f'{context}.region_id')} }}"
        )


@dataclass(frozen=True)
class LeanFiniteOriginTailDependency:
    dependency_id: int
    source_region_id: int
    route_term: str
    internal_targets: tuple[LeanFiniteOriginTailTarget, ...]
    authority_module: str
    route_authority_term: str

    def checked(self, context: str = "finite origin tail dependency") -> None:
        _nat(self.dependency_id, f"{context}.dependency_id")
        _nat(self.source_region_id, f"{context}.source_region_id")
        _qualified(self.route_term, f"{context}.route_term")
        _module(self.authority_module, f"{context}.authority_module")
        _qualified(self.route_authority_term, f"{context}.route_authority_term")
        if not self.internal_targets:
            raise InternalDirectCallRegisterSummaryGenerationError(
                f"{context}.internal_targets must not be empty"
            )
        for index, target in enumerate(self.internal_targets):
            target.lean(f"{context}.internal_targets[{index}]")

    def lean(self, context: str = "finite origin tail dependency") -> str:
        self.checked(context)
        targets = _lean_list([
            target.lean(f"{context}.internal_targets[{index}]")
            for index, target in enumerate(self.internal_targets)
        ])
        return (
            "{ id := "
            f"{_nat(self.dependency_id, f'{context}.dependency_id')}, "
            "sourceRegionId := "
            f"{_nat(self.source_region_id, f'{context}.source_region_id')}, "
            f"route := {self.route_term}, internalTargets := {targets} }}"
        )


@dataclass(frozen=True)
class LeanFiniteOriginCallTarget:
    target_id: int
    region_id: int
    summary_id: int

    def lean(self, context: str = "finite origin call target") -> str:
        return (
            "{ targetId := "
            f"{_nat(self.target_id, f'{context}.target_id')}, "
            f"regionId := {_nat(self.region_id, f'{context}.region_id')}, "
            f"summaryId := {_nat(self.summary_id, f'{context}.summary_id')} }}"
        )


@dataclass(frozen=True)
class LeanFiniteOriginCallDependency:
    dependency_id: int
    source_region_id: int
    continuation_region_id: int
    continuation_target_id: int
    internal_targets: tuple[LeanFiniteOriginCallTarget, ...]
    authority_module: str
    indirect_exit_authority_term: str

    def checked(self, context: str = "finite origin call dependency") -> None:
        _nat(self.dependency_id, f"{context}.dependency_id")
        _nat(self.source_region_id, f"{context}.source_region_id")
        _nat(self.continuation_region_id, f"{context}.continuation_region_id")
        _nat(self.continuation_target_id, f"{context}.continuation_target_id")
        _module(self.authority_module, f"{context}.authority_module")
        _qualified(
            self.indirect_exit_authority_term,
            f"{context}.indirect_exit_authority_term",
        )
        if not self.internal_targets:
            raise InternalDirectCallRegisterSummaryGenerationError(
                f"{context}.internal_targets must not be empty"
            )
        for index, target in enumerate(self.internal_targets):
            target.lean(f"{context}.internal_targets[{index}]")

    def lean(self, context: str = "finite origin call dependency") -> str:
        self.checked(context)
        targets = _lean_list([
            target.lean(f"{context}.internal_targets[{index}]")
            for index, target in enumerate(self.internal_targets)
        ])
        return (
            "{ id := "
            f"{_nat(self.dependency_id, f'{context}.dependency_id')}, "
            "sourceRegionId := "
            f"{_nat(self.source_region_id, f'{context}.source_region_id')}, "
            "continuationRegionId := "
            f"{_nat(self.continuation_region_id, f'{context}.continuation_region_id')}, "
            "continuationTargetId := "
            f"{_nat(self.continuation_target_id, f'{context}.continuation_target_id')}, "
            f"internalTargets := {targets} }}"
        )


@dataclass(frozen=True)
class LeanNestedSummaryDependency:
    dependency_id: int
    call_region_id: int
    continuation_region_id: int
    summary_id: int

    def lean(self, context: str = "nested dependency") -> str:
        return (
            "{ id := "
            f"{_nat(self.dependency_id, f'{context}.dependency_id')}, "
            "callRegionId := "
            f"{_nat(self.call_region_id, f'{context}.call_region_id')}, "
            "continuationRegionId := "
            f"{_nat(self.continuation_region_id, f'{context}.continuation_region_id')}, "
            "summaryId := "
            f"{_nat(self.summary_id, f'{context}.summary_id')} }}"
        )


@dataclass(frozen=True)
class LeanMachineImportDependency:
    dependency_id: int
    source_region_id: int
    continuation_region_id: int
    original_required: str
    candidate_required: str
    original_signatures: str
    candidate_signatures: str
    original_boundary: str
    candidate_boundary: str

    def lean(self, context: str = "machine import dependency") -> str:
        return (
            "{ id := "
            f"{_nat(self.dependency_id, f'{context}.dependency_id')}, "
            "sourceRegionId := "
            f"{_nat(self.source_region_id, f'{context}.source_region_id')}, "
            "continuationRegionId := "
            f"{_nat(self.continuation_region_id, f'{context}.continuation_region_id')}, "
            "originalRequired := "
            f"{_qualified(self.original_required, f'{context}.original_required')}, "
            "candidateRequired := "
            f"{_qualified(self.candidate_required, f'{context}.candidate_required')}, "
            "originalSignatures := "
            f"{_qualified(self.original_signatures, f'{context}.original_signatures')}, "
            "candidateSignatures := "
            f"{_qualified(self.candidate_signatures, f'{context}.candidate_signatures')}, "
            "originalBoundary := "
            f"{_qualified(self.original_boundary, f'{context}.original_boundary')}, "
            "candidateBoundary := "
            f"{_qualified(self.candidate_boundary, f'{context}.candidate_boundary')} }}"
        )


@dataclass(frozen=True)
class LeanMachineImportTailDependency:
    """One exact external tail reached through the live internal call frame."""

    dependency_id: int
    source_region_id: int
    signature_id: int
    argument_words: int
    original_required: str
    candidate_required: str
    original_signatures: str
    candidate_signatures: str

    def lean(self, context: str = "machine import tail dependency") -> str:
        return (
            "{ id := "
            f"{_nat(self.dependency_id, f'{context}.dependency_id')}, "
            "sourceRegionId := "
            f"{_nat(self.source_region_id, f'{context}.source_region_id')}, "
            "signatureId := "
            f"{_nat(self.signature_id, f'{context}.signature_id')}, "
            "argumentWords := "
            f"{_nat(self.argument_words, f'{context}.argument_words', u32=True)}, "
            "originalRequired := "
            f"{_qualified(self.original_required, f'{context}.original_required')}, "
            "candidateRequired := "
            f"{_qualified(self.candidate_required, f'{context}.candidate_required')}, "
            "originalSignatures := "
            f"{_qualified(self.original_signatures, f'{context}.original_signatures')}, "
            "candidateSignatures := "
            f"{_qualified(self.candidate_signatures, f'{context}.candidate_signatures')} }}"
        )


@dataclass(frozen=True)
class LeanMachineImportTerminalDependency:
    dependency_id: int
    source_region_id: int
    original_required: str
    candidate_required: str
    original_signatures: str
    candidate_signatures: str
    original_boundary: str
    candidate_boundary: str

    def lean(self, context: str = "machine import terminal dependency") -> str:
        return (
            "{ id := "
            f"{_nat(self.dependency_id, f'{context}.dependency_id')}, "
            "sourceRegionId := "
            f"{_nat(self.source_region_id, f'{context}.source_region_id')}, "
            "originalRequired := "
            f"{_qualified(self.original_required, f'{context}.original_required')}, "
            "candidateRequired := "
            f"{_qualified(self.candidate_required, f'{context}.candidate_required')}, "
            "originalSignatures := "
            f"{_qualified(self.original_signatures, f'{context}.original_signatures')}, "
            "candidateSignatures := "
            f"{_qualified(self.candidate_signatures, f'{context}.candidate_signatures')}, "
            "originalBoundary := "
            f"{_qualified(self.original_boundary, f'{context}.original_boundary')}, "
            "candidateBoundary := "
            f"{_qualified(self.candidate_boundary, f'{context}.candidate_boundary')} }}"
        )


@dataclass(frozen=True)
class LeanStackSaveRestoreFrameWitness:
    save_region_id: int
    restore_region_ids: tuple[int, ...]
    original_frame_bytes: int
    candidate_frame_bytes: int
    original_save_offset: int
    candidate_save_offset: int

    def lean(self, context: str = "stack frame witness") -> str:
        restore_ids = _lean_list([
            str(_nat(value, f"{context}.restore_region_ids[{index}]"))
            for index, value in enumerate(self.restore_region_ids)
        ])
        return (
            "{ saveRegionId := "
            f"{_nat(self.save_region_id, f'{context}.save_region_id')}, "
            f"restoreRegionIds := {restore_ids}, "
            "originalFrameBytes := "
            f"{_nat(self.original_frame_bytes, f'{context}.original_frame_bytes', u32=True)}, "
            "candidateFrameBytes := "
            f"{_nat(self.candidate_frame_bytes, f'{context}.candidate_frame_bytes', u32=True)}, "
            "originalSaveOffset := "
            f"{_nat(self.original_save_offset, f'{context}.original_save_offset', u32=True)}, "
            "candidateSaveOffset := "
            f"{_nat(self.candidate_save_offset, f'{context}.candidate_save_offset', u32=True)} }}"
        )


@dataclass(frozen=True)
class LeanStackFrameAnchorWitness:
    frame_entry_region_id: int
    register: str
    original_offset: int
    candidate_offset: int

    def lean(self, context: str = "stack frame anchor") -> str:
        return (
            "{ frameEntryRegionId := "
            f"{_nat(self.frame_entry_region_id, f'{context}.frame_entry_region_id')}, "
            f"register := .{_register(self.register, f'{context}.register')}, "
            "originalOffset := "
            f"{_nat(self.original_offset, f'{context}.original_offset', u32=True)}, "
            "candidateOffset := "
            f"{_nat(self.candidate_offset, f'{context}.candidate_offset', u32=True)} }}"
        )


@dataclass(frozen=True)
class LeanStackSaveRestoreWitness:
    register: str
    save_region_id: int
    restore_region_ids: tuple[int, ...]
    original_frame_bytes: int
    candidate_frame_bytes: int
    original_save_offset: int
    candidate_save_offset: int
    additional_frames: tuple[LeanStackSaveRestoreFrameWitness, ...] = ()
    protected_write_region_ids: tuple[int, ...] = ()
    protected_machine_import_dependency_ids: tuple[int, ...] = ()

    def lean(self, context: str = "stack witness") -> str:
        restore_ids = _lean_list([
            str(_nat(value, f"{context}.restore_region_ids[{index}]"))
            for index, value in enumerate(self.restore_region_ids)
        ])
        protected_write_ids = _lean_list([
            str(_nat(value, f"{context}.protected_write_region_ids[{index}]"))
            for index, value in enumerate(self.protected_write_region_ids)
        ])
        protected_import_ids = _lean_list([
            str(_nat(
                value,
                f"{context}.protected_machine_import_dependency_ids[{index}]",
            ))
            for index, value in enumerate(
                self.protected_machine_import_dependency_ids
            )
        ])
        additional_frames = _lean_list([
            frame.lean(f"{context}.additional_frames[{index}]")
            for index, frame in enumerate(self.additional_frames)
        ])
        return (
            "{ register := ."
            f"{_register(self.register, f'{context}.register')}, "
            "saveRegionId := "
            f"{_nat(self.save_region_id, f'{context}.save_region_id')}, "
            f"restoreRegionIds := {restore_ids}, "
            "originalFrameBytes := "
            f"{_nat(self.original_frame_bytes, f'{context}.original_frame_bytes', u32=True)}, "
            "candidateFrameBytes := "
            f"{_nat(self.candidate_frame_bytes, f'{context}.candidate_frame_bytes', u32=True)}, "
            "originalSaveOffset := "
            f"{_nat(self.original_save_offset, f'{context}.original_save_offset', u32=True)}, "
            "candidateSaveOffset := "
            f"{_nat(self.candidate_save_offset, f'{context}.candidate_save_offset', u32=True)}, "
            f"additionalFrames := {additional_frames}, "
            f"protectedWriteRegionIds := {protected_write_ids}, "
            f"protectedMachineImportDependencyIds := {protected_import_ids} }}"
        )


@dataclass(frozen=True)
class LeanStackEntryOffsetWitness:
    region_id: int
    original_offset: int
    candidate_offset: int

    def lean(self, context: str = "stack entry offset") -> str:
        return (
            "{ regionId := "
            f"{_nat(self.region_id, f'{context}.region_id')}, "
            "originalOffset := "
            f"{_nat(self.original_offset, f'{context}.original_offset', u32=True)}, "
            "candidateOffset := "
            f"{_nat(self.candidate_offset, f'{context}.candidate_offset', u32=True)} }}"
        )


@dataclass(frozen=True)
class LeanInternalDirectCallRegisterCertificate:
    summary_id: int
    dependency_depth: int
    caller: LeanExactRegionPair
    callsite: LeanExactRegionPair
    callee_entry: LeanExactRegionPair
    continuation: LeanExactRegionPair
    callee_regions: tuple[LeanExactRegionPair, ...]
    edges: tuple[LeanCalleeEdge, ...]
    returns: tuple[LeanReturnInventoryEntry, ...]
    requested_registers: tuple[str, ...]
    entry_kind: Literal["direct", "finite_origin_call"] = "direct"
    entry_dependency_id: int | None = None
    entry_target_id: int | None = None
    original_frame_bytes: int = 0
    candidate_frame_bytes: int = 0
    nested_dependencies: tuple[LeanNestedSummaryDependency, ...] = ()
    machine_import_dependencies: tuple[LeanMachineImportDependency, ...] = ()
    machine_import_tail_dependencies: tuple[
        LeanMachineImportTailDependency, ...
    ] = ()
    machine_import_terminal_dependencies: tuple[
        LeanMachineImportTerminalDependency, ...
    ] = ()
    finite_indirect_dependencies: tuple[LeanFiniteIndirectJumpDependency, ...] = ()
    finite_origin_call_dependencies: tuple[
        LeanFiniteOriginCallDependency, ...
    ] = ()
    finite_origin_tail_dependencies: tuple[
        LeanFiniteOriginTailDependency, ...
    ] = ()
    stack_frame_anchors: tuple[LeanStackFrameAnchorWitness, ...] = ()
    stack_witnesses: tuple[LeanStackSaveRestoreWitness, ...] = ()
    stack_entry_offsets: tuple[LeanStackEntryOffsetWitness, ...] = ()
    dynamic_stack_entry_region_ids: tuple[int, ...] = ()

    def lean(self, context: str = "certificate") -> str:
        regions = _lean_list([
            region.lean(f"{context}.callee_regions[{index}]")
            for index, region in enumerate(self.callee_regions)
        ])
        edges = _lean_list([
            edge.lean(f"{context}.edges[{index}]")
            for index, edge in enumerate(self.edges)
        ])
        returns = _lean_list([
            entry.lean(f"{context}.returns[{index}]")
            for index, entry in enumerate(self.returns)
        ])
        registers = _lean_list([
            f".{_register(register, f'{context}.requested_registers[{index}]')}"
            for index, register in enumerate(self.requested_registers)
        ])
        nested = _lean_list([
            dependency.lean(f"{context}.nested_dependencies[{index}]")
            for index, dependency in enumerate(self.nested_dependencies)
        ])
        machine = _lean_list([
            dependency.lean(f"{context}.machine_import_dependencies[{index}]")
            for index, dependency in enumerate(self.machine_import_dependencies)
        ])
        machine_tail = _lean_list([
            dependency.lean(
                f"{context}.machine_import_tail_dependencies[{index}]"
            )
            for index, dependency in enumerate(
                self.machine_import_tail_dependencies
            )
        ])
        machine_terminal = _lean_list([
            dependency.lean(
                f"{context}.machine_import_terminal_dependencies[{index}]"
            )
            for index, dependency in enumerate(
                self.machine_import_terminal_dependencies
            )
        ])
        finite_indirect = _lean_list([
            dependency.lean(f"{context}.finite_indirect_dependencies[{index}]")
            for index, dependency in enumerate(self.finite_indirect_dependencies)
        ])
        finite_origin_call = _lean_list([
            dependency.lean(
                f"{context}.finite_origin_call_dependencies[{index}]"
            )
            for index, dependency in enumerate(
                self.finite_origin_call_dependencies
            )
        ])
        finite_origin_tail = _lean_list([
            dependency.lean(
                f"{context}.finite_origin_tail_dependencies[{index}]"
            )
            for index, dependency in enumerate(
                self.finite_origin_tail_dependencies
            )
        ])
        stack_anchors = _lean_list([
            witness.lean(f"{context}.stack_frame_anchors[{index}]")
            for index, witness in enumerate(self.stack_frame_anchors)
        ])
        stack = _lean_list([
            witness.lean(f"{context}.stack_witnesses[{index}]")
            for index, witness in enumerate(self.stack_witnesses)
        ])
        stack_offsets = _lean_list([
            witness.lean(f"{context}.stack_entry_offsets[{index}]")
            for index, witness in enumerate(self.stack_entry_offsets)
        ])
        dynamic_stack_ids = _lean_list([
            str(_nat(
                region_id,
                f"{context}.dynamic_stack_entry_region_ids[{index}]",
            ))
            for index, region_id in enumerate(
                self.dynamic_stack_entry_region_ids
            )
        ])
        if self.entry_kind == "direct":
            if (
                self.entry_dependency_id is not None
                or self.entry_target_id is not None
            ):
                raise InternalDirectCallRegisterSummaryGenerationError(
                    f"{context} direct entry cannot name an authority dependency"
                )
            entry_kind = ".direct"
        elif self.entry_kind == "finite_origin_call":
            if (
                self.entry_dependency_id is None
                or self.entry_target_id is None
            ):
                raise InternalDirectCallRegisterSummaryGenerationError(
                    f"{context} finite-origin call entry requires dependency and target IDs"
                )
            entry_kind = (
                ".finiteOriginCall "
                f"{_nat(self.entry_dependency_id, f'{context}.entry_dependency_id')} "
                f"{_nat(self.entry_target_id, f'{context}.entry_target_id')}"
            )
        else:
            raise InternalDirectCallRegisterSummaryGenerationError(
                f"{context}.entry_kind is unsupported"
            )
        return " ".join((
            "{ summaryId := "
            f"{_nat(self.summary_id, f'{context}.summary_id')},",
            "dependencyDepth := "
            f"{_nat(self.dependency_depth, f'{context}.dependency_depth')},",
            f"caller := {self.caller.lean(f'{context}.caller')},",
            f"callsite := {self.callsite.lean(f'{context}.callsite')},",
            f"calleeEntry := {self.callee_entry.lean(f'{context}.callee_entry')},",
            f"continuation := {self.continuation.lean(f'{context}.continuation')},",
            f"calleeRegions := {regions},",
            f"edges := {edges},",
            f"returns := {returns},",
            f"requestedRegisters := {registers},",
            f"entryKind := {entry_kind},",
            "originalFrameBytes := "
            f"{_nat(self.original_frame_bytes, f'{context}.original_frame_bytes', u32=True)},",
            "candidateFrameBytes := "
            f"{_nat(self.candidate_frame_bytes, f'{context}.candidate_frame_bytes', u32=True)},",
            f"nestedDependencies := {nested},",
            f"machineImportDependencies := {machine},",
            f"machineImportTailDependencies := {machine_tail},",
            f"machineImportTerminalDependencies := {machine_terminal},",
            f"finiteIndirectDependencies := {finite_indirect},",
            f"finiteOriginCallDependencies := {finite_origin_call},",
            f"finiteOriginTailDependencies := {finite_origin_tail},",
            f"stackFrameAnchors := {stack_anchors},",
            f"stackWitnesses := {stack},",
            f"stackEntryOffsets := {stack_offsets},",
            f"dynamicStackEntryRegionIds := {dynamic_stack_ids} }}",
        ))


@dataclass(frozen=True)
class LeanInternalDirectCallRegisterSummaryTree:
    certificate: LeanInternalDirectCallRegisterCertificate
    nested: tuple["LeanInternalDirectCallRegisterSummaryTree", ...] = ()

    def lean(self, context: str = "summary") -> str:
        children = _lean_list([
            child.lean(f"{context}.nested[{index}]")
            for index, child in enumerate(self.nested)
        ])
        return f".node ({self.certificate.lean(f'{context}.certificate')}) {children}"

    def finite_origin_tail_dependencies(
        self,
    ) -> tuple[LeanFiniteOriginTailDependency, ...]:
        return (
            *self.certificate.finite_origin_tail_dependencies,
            *(
                dependency
                for child in self.nested
                for dependency in child.finite_origin_tail_dependencies()
            ),
        )

    def finite_origin_call_dependencies(
        self,
    ) -> tuple[LeanFiniteOriginCallDependency, ...]:
        return (
            *self.certificate.finite_origin_call_dependencies,
            *(
                dependency
                for child in self.nested
                for dependency in child.finite_origin_call_dependencies()
            ),
        )


@dataclass(frozen=True)
class _SharedSummaryNode:
    digest: str
    certificate_source: str
    child_digests: tuple[str, ...]
    tree: LeanInternalDirectCallRegisterSummaryTree


def _shared_summary_nodes(
    root: LeanInternalDirectCallRegisterSummaryTree,
) -> tuple[tuple[_SharedSummaryNode, ...], str]:
    """Hash-cons one recursive proposal into a deterministic summary DAG."""

    nodes_by_digest: dict[str, _SharedSummaryNode] = {}
    ordered: list[_SharedSummaryNode] = []

    def visit(tree: LeanInternalDirectCallRegisterSummaryTree) -> str:
        child_digests = tuple(visit(child) for child in tree.nested)
        certificate_source = tree.certificate.lean()
        digest_input = "\0".join((
            "stage-a-internal-direct-call-summary-node-v1",
            certificate_source,
            *child_digests,
        )).encode("utf-8")
        digest = hashlib.sha256(digest_input).hexdigest()
        node = _SharedSummaryNode(
            digest=digest,
            certificate_source=certificate_source,
            child_digests=child_digests,
            tree=tree,
        )
        prior = nodes_by_digest.get(digest)
        if prior is not None:
            if (
                prior.certificate_source != certificate_source
                or prior.child_digests != child_digests
            ):
                raise InternalDirectCallRegisterSummaryGenerationError(
                    "summary DAG hash collision names incompatible nodes"
                )
            return digest
        nodes_by_digest[digest] = node
        ordered.append(node)
        return digest

    root_digest = visit(root)
    return tuple(ordered), root_digest


def _summary_node_name(digest: str) -> str:
    return f"generatedSummaryNode{digest}"


def _summary_certificate_name(digest: str) -> str:
    return f"generatedSummaryCertificate{digest}"


def _summary_children_name(digest: str) -> str:
    return f"generatedSummaryChildren{digest}"


def _summary_node_checked_name(digest: str) -> str:
    return f"generatedSummaryNodeChecked{digest}"


def _register_preservation_declarations(
    certificate_name: str,
    certificate: LeanInternalDirectCallRegisterCertificate,
    bindings: "InternalDirectCallRegisterSummaryLeanBindings",
) -> tuple[str, ...]:
    declarations: list[str] = []
    stack_witness_by_register = {
        witness.register: index
        for index, witness in enumerate(certificate.stack_witnesses)
    }
    for register in certificate.requested_registers:
        checked_name = (
            f"{certificate_name}Register{register.upper()}PreservedChecked"
        )
        witness_index = stack_witness_by_register.get(register)
        if register != "esp" and witness_index is not None:
            witness_name = f"{certificate_name}StackWitness{witness_index:04d}"
            proof = (
                "  exact Certificate.registerPreservedChecked_of_stackWitness\n"
                f"    {certificate_name} {bindings.original_pe} "
                f"{bindings.candidate_pe}\n"
                f"    {bindings.original_imports} {bindings.candidate_imports}\n"
                f"    .{register} {witness_name} (by decide)\n"
                f"    {witness_name}Member (by rfl) {witness_name}Checked"
            )
        else:
            proof = "  decide"
        declarations.append(
            f"theorem {checked_name} :\n"
            f"    {certificate_name}.registerPreservedChecked\n"
            f"      {bindings.original_pe} {bindings.candidate_pe}\n"
            f"      {bindings.original_imports} {bindings.candidate_imports}\n"
            f"      .{register} = true := by\n"
            f"{proof}"
        )
    return tuple(declarations)


def _stack_witness_declarations(
    certificate_name: str,
    certificate: LeanInternalDirectCallRegisterCertificate,
    bindings: "InternalDirectCallRegisterSummaryLeanBindings",
) -> tuple[str, ...]:
    declarations: list[str] = []
    for index, witness in enumerate(certificate.stack_witnesses):
        witness_name = f"{certificate_name}StackWitness{index:04d}"
        declarations.append(
            f"def {witness_name} : StackSaveRestoreWitness :=\n"
            f"  {witness.lean(f'{certificate_name}.stack_witnesses[{index}]')}"
        )
        declarations.append(
            f"theorem {witness_name}Member :\n"
            f"    {witness_name} ∈ {certificate_name}.stackWitnesses := by\n"
            "  decide"
        )
        declarations.append(
            f"theorem {witness_name}Checked :\n"
            f"    {witness_name}.checked {certificate_name} "
            f"{bindings.original_pe} {bindings.candidate_pe} "
            f"{bindings.original_imports} {bindings.candidate_imports} = "
            "true := by\n"
            "  decide"
        )
    return tuple(declarations)


def _preservation_declarations(
    certificate_name: str,
    certificate: LeanInternalDirectCallRegisterCertificate,
    bindings: "InternalDirectCallRegisterSummaryLeanBindings",
) -> tuple[str, str]:
    requested_name = f"{certificate_name}RequestedRegisters"
    preservation_name = f"{certificate_name}PreservationChecked"
    requested = _lean_list([
        f".{register}" for register in certificate.requested_registers
    ])
    register_proofs = [
        f"{certificate_name}Register{register.upper()}PreservedChecked"
        for register in certificate.requested_registers
    ]
    alternatives = " | ".join("rfl" for _ in register_proofs)
    branches = "\n".join(
        f"  · exact {proof}" for proof in register_proofs
    )
    requested_projection = (
        f"theorem {requested_name} :\n"
        f"    {certificate_name}.requestedRegisters = {requested} := by\n"
        "  rfl"
    )
    preservation = (
        f"theorem {preservation_name} :\n"
        f"    {certificate_name}.preservationChecked\n"
        f"      {bindings.original_pe} {bindings.candidate_pe}\n"
        f"      {bindings.original_imports} {bindings.candidate_imports} = "
        "true := by\n"
        "  apply Certificate.preservationChecked_of_registers\n"
        "  intro register member\n"
        f"  rw [{requested_name}] at member\n"
        "  simp only [List.mem_cons, List.not_mem_nil, or_false] at member\n"
        f"  rcases member with {alternatives}\n"
        f"{branches}"
    )
    return requested_projection, preservation


def _shared_summary_declarations(
    nodes: tuple[_SharedSummaryNode, ...],
    bindings: "InternalDirectCallRegisterSummaryLeanBindings",
    *,
    prove_accepted: bool,
) -> str:
    declarations: list[str] = []
    for node in nodes:
        certificate = _summary_certificate_name(node.digest)
        children = _summary_children_name(node.digest)
        summary = _summary_node_name(node.digest)
        checked = _summary_node_checked_name(node.digest)
        child_rows = _lean_list([
            _summary_node_name(digest) for digest in node.child_digests
        ])
        declarations.extend((
            f"def {certificate} : Certificate :=\n"
            f"  {node.certificate_source}",
            f"def {children} : List SummaryTree :=\n"
            f"  {child_rows}",
            f"def {summary} : SummaryTree :=\n"
            f"  .node {certificate} {children}",
        ))
        if not prove_accepted:
            continue
        structure_checked = f"{certificate}StructureChecked"
        preservation_checked_name = f"{certificate}PreservationChecked"
        certificate_checked = f"{certificate}Checked"
        children_checked = f"{children}Checked"
        children_shallower = f"{children}Shallower"
        child_proofs = ", ".join(
            _summary_node_checked_name(digest)
            for digest in dict.fromkeys(node.child_digests)
        )
        child_simp = (
            f", {child_proofs}" if child_proofs else ""
        )
        register_preservation = _register_preservation_declarations(
            certificate,
            node.tree.certificate,
            bindings,
        )
        stack_witness_declarations = _stack_witness_declarations(
            certificate,
            node.tree.certificate,
            bindings,
        )
        preservation_declarations = _preservation_declarations(
            certificate,
            node.tree.certificate,
            bindings,
        )
        declarations.extend((
            f"theorem {structure_checked} :\n"
            f"    {certificate}.structureChecked\n"
            f"      {bindings.original_pe} {bindings.candidate_pe}\n"
            f"      {bindings.original_imports} {bindings.candidate_imports}\n"
            f"      {children} = true := by\n"
            "  decide",
            *stack_witness_declarations,
            *register_preservation,
            *preservation_declarations,
            f"theorem {certificate_checked} :\n"
            f"    {certificate}.checked\n"
            f"      {bindings.original_pe} {bindings.candidate_pe}\n"
            f"      {bindings.original_imports} {bindings.candidate_imports}\n"
            f"      {children} = true := by\n"
            "  exact Certificate.checked_of_structure_and_preservation\n"
            f"    {certificate} {bindings.original_pe} {bindings.candidate_pe}\n"
            f"    {bindings.original_imports} {bindings.candidate_imports}\n"
            f"    {children} {structure_checked} {preservation_checked_name}",
            f"theorem {children_checked} :\n"
            f"    {children}.all (fun child => child.checked\n"
            f"      {bindings.original_pe} {bindings.candidate_pe}\n"
            f"      {bindings.original_imports} {bindings.candidate_imports}) = "
            "true := by\n"
            f"  simp [{children}{child_simp}]",
            f"theorem {children_shallower} :\n"
            f"    {children}.all (fun child =>\n"
            "      child.certificate.dependencyDepth <\n"
            f"        {certificate}.dependencyDepth) = true := by\n"
            "  decide",
            f"theorem {checked} :\n"
            f"    {summary}.checked\n"
            f"      {bindings.original_pe} {bindings.candidate_pe}\n"
            f"      {bindings.original_imports} {bindings.candidate_imports} = "
            "true := by\n"
            "  exact SummaryTree.checked_node_of_certificate_and_children\n"
            f"    {certificate} {children}\n"
            f"    {bindings.original_pe} {bindings.candidate_pe}\n"
            f"    {bindings.original_imports} {bindings.candidate_imports}\n"
            f"    {certificate_checked} {children_checked}\n"
            f"    {children_shallower}",
        ))
    return "\n\n".join(declarations)


@dataclass(frozen=True)
class InternalDirectCallRegisterSummaryLeanBindings:
    original_pe: str
    candidate_pe: str
    original_imports: str
    candidate_imports: str
    imports: tuple[str, ...] = ()

    def checked(self) -> "InternalDirectCallRegisterSummaryLeanBindings":
        _qualified(self.original_pe, "bindings.original_pe")
        _qualified(self.candidate_pe, "bindings.candidate_pe")
        _qualified(self.original_imports, "bindings.original_imports")
        _qualified(self.candidate_imports, "bindings.candidate_imports")
        for index, module_name in enumerate(self.imports):
            _module(module_name, f"bindings.imports[{index}]")
        return self


@dataclass(frozen=True)
class InternalDirectCallRegisterSummaryLeanModule:
    module: str
    namespace: str
    source: str


@dataclass(frozen=True)
class InternalDirectCallRegisterSummaryLeanModuleDag:
    root_source: str
    root_node_module: str
    node_modules: tuple[InternalDirectCallRegisterSummaryLeanModule, ...]


def _dag_node_module_name(
    digest: str,
    bindings: InternalDirectCallRegisterSummaryLeanBindings,
) -> str:
    context = "\0".join((
        "stage-a-internal-direct-call-summary-node-module-v1",
        digest,
        bindings.original_pe,
        bindings.candidate_pe,
        bindings.original_imports,
        bindings.candidate_imports,
        *bindings.imports,
    ))
    context_digest = hashlib.sha256(context.encode("utf-8")).hexdigest()
    return (
        "StageA.GeneratedRelationalInternalDirectCallSummaryNode"
        f"{context_digest}"
    )


def _dag_node_namespace(module: str) -> str:
    return f"StageA.Generated.{module.removeprefix('StageA.')}"


def internal_direct_call_register_summary_module_dag(
    summary: LeanInternalDirectCallRegisterSummaryTree,
    bindings: InternalDirectCallRegisterSummaryLeanBindings,
    *,
    root_namespace: str,
) -> InternalDirectCallRegisterSummaryLeanModuleDag:
    """Emit one independently checkable Lean module per unique summary node."""

    bindings.checked()
    _qualified(root_namespace, "root_namespace")
    shared_nodes, root_digest = _shared_summary_nodes(summary)
    modules_by_digest = {
        node.digest: _dag_node_module_name(node.digest, bindings)
        for node in shared_nodes
    }
    generated_modules: list[InternalDirectCallRegisterSummaryLeanModule] = []
    for node in shared_nodes:
        module = modules_by_digest[node.digest]
        namespace = _dag_node_namespace(module)
        child_modules = tuple(
            modules_by_digest[digest] for digest in node.child_digests
        )
        child_namespaces = tuple(
            _dag_node_namespace(module_name) for module_name in child_modules
        )
        imports = "\n".join(
            f"import {module_name}"
            for module_name in dict.fromkeys((
                "StageA.RelationalInternalDirectCallRegisterSummary",
                *bindings.imports,
                *(
                    dependency.authority_module
                    for dependency in (
                        node.tree.certificate.finite_origin_tail_dependencies
                    )
                ),
                *child_modules,
            ))
        )
        children = _lean_list([
            f"{child_namespace}.generatedSummaryNode"
            for child_namespace in child_namespaces
        ])
        child_certificates = _lean_list([
            f"{child_namespace}.generatedSummaryCertificate"
            for child_namespace in child_namespaces
        ])
        child_checks = ", ".join(
            f"{child_namespace}.generatedSummaryNodeChecked"
            for child_namespace in dict.fromkeys(child_namespaces)
        )
        child_simp = f", {child_checks}" if child_checks else ""
        child_certificate_checks = ", ".join(
            f"{child_namespace}.generatedSummaryNodeCertificate"
            for child_namespace in dict.fromkeys(child_namespaces)
        )
        child_certificate_simp = (
            f", {child_certificate_checks}"
            if child_certificate_checks else ""
        )
        child_depth_checks = ", ".join(
            f"{child_namespace}.generatedSummaryNodeDepth"
            for child_namespace in dict.fromkeys(child_namespaces)
        )
        child_depth_simp = (
            f", {child_depth_checks}" if child_depth_checks else ""
        )
        register_preservation = "\n\n".join(
            _register_preservation_declarations(
                "generatedSummaryCertificate",
                node.tree.certificate,
                bindings,
            )
        )
        if register_preservation:
            register_preservation = f"\n\n{register_preservation}"
        stack_witness_declarations = "\n\n".join(
            _stack_witness_declarations(
                "generatedSummaryCertificate",
                node.tree.certificate,
                bindings,
            )
        )
        if stack_witness_declarations:
            stack_witness_declarations = f"\n\n{stack_witness_declarations}"
        preservation_declarations = "\n\n".join(
            _preservation_declarations(
                "generatedSummaryCertificate",
                node.tree.certificate,
                bindings,
            )
        )
        preservation_declarations = f"\n\n{preservation_declarations}"
        source = f"""{imports}

namespace {namespace}

open StageA.Formal StageA.Relational
open StageA.Relational.InternalDirectCallRegisterSummary

set_option maxRecDepth 1000000
set_option maxHeartbeats 0

def generatedSummaryCertificate : Certificate :=
  {node.certificate_source}

def generatedSummaryChildCertificates : List Certificate :=
  {child_certificates}

def generatedSummaryChildren : List SummaryTree :=
  {children}

@[irreducible] def generatedSummaryNode : SummaryTree :=
  .node generatedSummaryCertificate generatedSummaryChildren

theorem generatedSummaryNodeCertificate :
    generatedSummaryNode.certificate = generatedSummaryCertificate := by
  unfold generatedSummaryNode
  rfl

theorem generatedSummaryNodeDepth :
    generatedSummaryNode.certificate.dependencyDepth =
      generatedSummaryCertificate.dependencyDepth := by
  rw [generatedSummaryNodeCertificate]

theorem generatedSummaryCertificateCompactStructureChecked :
    generatedSummaryCertificate.structureCheckedWithChildCertificates
      {bindings.original_pe} {bindings.candidate_pe}
      {bindings.original_imports} {bindings.candidate_imports}
      generatedSummaryChildCertificates = true := by
  decide

theorem generatedSummaryChildrenCertificates :
    generatedSummaryChildren.map SummaryTree.certificate =
      generatedSummaryChildCertificates := by
  simp [generatedSummaryChildren, generatedSummaryChildCertificates{
      child_certificate_simp}]

theorem generatedSummaryCertificateStructureChecked :
    generatedSummaryCertificate.structureChecked
      {bindings.original_pe} {bindings.candidate_pe}
      {bindings.original_imports} {bindings.candidate_imports}
      generatedSummaryChildren = true := by
  unfold Certificate.structureChecked
  rw [generatedSummaryChildrenCertificates]
  exact generatedSummaryCertificateCompactStructureChecked
{stack_witness_declarations}
{register_preservation}
{preservation_declarations}

theorem generatedSummaryCertificateChecked :
    generatedSummaryCertificate.checked
      {bindings.original_pe} {bindings.candidate_pe}
      {bindings.original_imports} {bindings.candidate_imports}
      generatedSummaryChildren = true := by
  exact Certificate.checked_of_structure_and_preservation
    generatedSummaryCertificate {bindings.original_pe} {bindings.candidate_pe}
    {bindings.original_imports} {bindings.candidate_imports}
    generatedSummaryChildren generatedSummaryCertificateStructureChecked
    generatedSummaryCertificatePreservationChecked

theorem generatedSummaryChildrenChecked :
    generatedSummaryChildren.all (fun child => child.checked
      {bindings.original_pe} {bindings.candidate_pe}
      {bindings.original_imports} {bindings.candidate_imports}) = true := by
  simp [generatedSummaryChildren{child_simp}]

theorem generatedSummaryChildrenShallower :
    generatedSummaryChildren.all (fun child =>
      child.certificate.dependencyDepth <
        generatedSummaryCertificate.dependencyDepth) = true := by
  {"simp [generatedSummaryChildren" + child_depth_simp + "]\n  decide"
    if child_depth_checks else "simp [generatedSummaryChildren]"}

theorem generatedSummaryNodeChecked :
    generatedSummaryNode.checked
      {bindings.original_pe} {bindings.candidate_pe}
      {bindings.original_imports} {bindings.candidate_imports} = true := by
  unfold generatedSummaryNode
  exact SummaryTree.checked_node_of_certificate_and_children
    generatedSummaryCertificate generatedSummaryChildren
    {bindings.original_pe} {bindings.candidate_pe}
    {bindings.original_imports} {bindings.candidate_imports}
    generatedSummaryCertificateChecked generatedSummaryChildrenChecked
    generatedSummaryChildrenShallower

#print axioms generatedSummaryNodeChecked

end {namespace}
"""
        generated_modules.append(
            InternalDirectCallRegisterSummaryLeanModule(
                module=module,
                namespace=namespace,
                source=source,
            )
        )

    finite_origin_tail_owners: dict[int, _SharedSummaryNode] = {}
    finite_origin_call_owners: dict[int, _SharedSummaryNode] = {}
    tails_by_id: dict[int, LeanFiniteOriginTailDependency] = {}
    calls_by_id: dict[int, LeanFiniteOriginCallDependency] = {}
    for node in shared_nodes:
        for dependency in node.tree.certificate.finite_origin_tail_dependencies:
            prior = tails_by_id.get(dependency.dependency_id)
            if prior is not None and prior != dependency:
                raise InternalDirectCallRegisterSummaryGenerationError(
                    "one finite-origin tail dependency ID names incompatible "
                    "certificates across the summary DAG"
                )
            tails_by_id[dependency.dependency_id] = dependency
            finite_origin_tail_owners.setdefault(dependency.dependency_id, node)
        for dependency in node.tree.certificate.finite_origin_call_dependencies:
            prior = calls_by_id.get(dependency.dependency_id)
            if prior is not None and prior != dependency:
                raise InternalDirectCallRegisterSummaryGenerationError(
                    "one finite-origin call dependency ID names incompatible "
                    "certificates across the summary DAG"
                )
            calls_by_id[dependency.dependency_id] = dependency
            finite_origin_call_owners.setdefault(dependency.dependency_id, node)
    finite_origin_tails = tuple(tails_by_id.values())
    finite_origin_calls = tuple(calls_by_id.values())
    for index, dependency in enumerate(finite_origin_tails):
        dependency.checked(f"finite_origin_tail_dependencies[{index}]")
    for index, dependency in enumerate(finite_origin_calls):
        dependency.checked(f"finite_origin_call_dependencies[{index}]")

    root_module = modules_by_digest[root_digest]
    root_node_namespace = _dag_node_namespace(root_module)
    root_imports = "\n".join(
        f"import {module_name}"
        for module_name in dict.fromkeys((
            root_module,
            *(dependency.authority_module for dependency in finite_origin_calls),
            *(dependency.authority_module for dependency in finite_origin_tails),
        ))
    )
    finite_origin_tail_sources: list[str] = []
    for index, dependency in enumerate(finite_origin_tails):
        owner = finite_origin_tail_owners[dependency.dependency_id]
        owner_namespace = _dag_node_namespace(
            modules_by_digest[owner.digest]
        )
        finite_origin_tail_sources.append(
            "def generatedFiniteOriginTailRouteAuthority"
            f"{index:04d} :\n"
            "    StageA.Relational.CallableExternalIndirectExit."
            "CheckedCallableIndirectExitRouteAuthority\n"
            f"      {dependency.route_term} :=\n"
            f"  {dependency.route_authority_term}\n\n"
            "theorem generatedFiniteOriginTailRouteBound"
            f"{index:04d} :\n"
            f"    {owner_namespace}.generatedSummaryCertificate."
            "finiteOriginTailRouteBound\n"
            f"      {dependency.dependency_id} {dependency.route_term} = true := by\n"
            "  decide\n\n"
            "#print axioms generatedFiniteOriginTailRouteAuthority"
            f"{index:04d}\n"
            "#print axioms generatedFiniteOriginTailRouteBound"
            f"{index:04d}"
        )
    finite_origin_call_sources: list[str] = []
    for index, dependency in enumerate(finite_origin_calls):
        owner = finite_origin_call_owners[dependency.dependency_id]
        owner_namespace = _dag_node_namespace(
            modules_by_digest[owner.digest]
        )
        finite_origin_call_sources.append(
            "def generatedFiniteOriginCallAuthority"
            f"{index:04d} :=\n"
            f"  {dependency.indirect_exit_authority_term}\n\n"
            "theorem generatedFiniteOriginCallAuthorityBound"
            f"{index:04d} :\n"
            f"    {owner_namespace}.generatedSummaryCertificate."
            "finiteOriginCallAuthorityBound\n"
            f"      {owner_namespace}.generatedSummaryChildren\n"
            f"      {dependency.dependency_id}\n"
            "      generatedFiniteOriginCallAuthority"
            f"{index:04d}\n"
            f"      {bindings.original_pe} {bindings.candidate_pe}\n"
            f"      {bindings.original_imports} "
            f"{bindings.candidate_imports} = true := by\n"
            "  decide\n\n"
            "#print axioms generatedFiniteOriginCallAuthority"
            f"{index:04d}\n"
            "#print axioms generatedFiniteOriginCallAuthorityBound"
            f"{index:04d}"
        )
    authority_sources = "\n\n".join((
        *finite_origin_call_sources,
        *finite_origin_tail_sources,
    ))
    if authority_sources:
        authority_sources = f"\n\n{authority_sources}\n"
    root_source = f"""{root_imports}

namespace {root_namespace}

open StageA.Formal StageA.Relational
open StageA.Relational.InternalDirectCallRegisterSummary

def generatedInternalDirectCallRegisterSummary : SummaryTree :=
  {root_node_namespace}.generatedSummaryNode

theorem generatedInternalDirectCallRegisterSummaryChecked :
    generatedInternalDirectCallRegisterSummary.checked
      {bindings.original_pe} {bindings.candidate_pe}
      {bindings.original_imports} {bindings.candidate_imports} = true := by
  simpa [generatedInternalDirectCallRegisterSummary] using
    {root_node_namespace}.generatedSummaryNodeChecked

def generatedInternalDirectCallRegisterSummarySemanticIntegrationRequirements :
    SemanticIntegrationRequirements :=
  semanticIntegrationRequirements

def generatedInternalDirectCallRegisterSummaryStandaloneAcceptanceAuthority : Bool :=
  SemanticIntegrationRequirements.standaloneAcceptanceAuthority
    generatedInternalDirectCallRegisterSummarySemanticIntegrationRequirements

theorem generatedInternalDirectCallRegisterSummaryNotAcceptanceAuthority :
    generatedInternalDirectCallRegisterSummaryStandaloneAcceptanceAuthority = false := by
  simpa [generatedInternalDirectCallRegisterSummaryStandaloneAcceptanceAuthority,
    generatedInternalDirectCallRegisterSummarySemanticIntegrationRequirements] using
    semanticIntegrationRequirements_not_authority

def generatedInternalDirectCallRegisterSummaryStructuralEvidence :
    generatedInternalDirectCallRegisterSummary.StructuralCheckerEvidence
      {bindings.original_pe} {bindings.candidate_pe}
      {bindings.original_imports} {bindings.candidate_imports} :=
  SummaryTree.checked_structuralEvidence
    generatedInternalDirectCallRegisterSummary
    {bindings.original_pe} {bindings.candidate_pe}
    {bindings.original_imports} {bindings.candidate_imports}
    generatedInternalDirectCallRegisterSummaryChecked

#print axioms generatedInternalDirectCallRegisterSummaryStructuralEvidence
#print axioms generatedInternalDirectCallRegisterSummaryNotAcceptanceAuthority
{authority_sources}
end {root_namespace}
"""
    return InternalDirectCallRegisterSummaryLeanModuleDag(
        root_source=root_source,
        root_node_module=root_module,
        node_modules=tuple(generated_modules),
    )


def internal_direct_call_register_summary_source(
    summary: LeanInternalDirectCallRegisterSummaryTree,
    bindings: InternalDirectCallRegisterSummaryLeanBindings,
    *,
    expectation: Literal["accepted", "rejected"] = "accepted",
) -> str:
    """Serialize a proposal and ask Lean to decide the stated expectation."""
    if expectation not in {"accepted", "rejected"}:
        raise InternalDirectCallRegisterSummaryGenerationError(
            "expectation must be accepted or rejected"
        )
    bindings.checked()
    shared_nodes, root_digest = _shared_summary_nodes(summary)
    finite_origin_tail_owners: dict[int, _SharedSummaryNode] = {}
    finite_origin_call_owners: dict[int, _SharedSummaryNode] = {}
    for node in shared_nodes:
        for dependency in node.tree.certificate.finite_origin_tail_dependencies:
            finite_origin_tail_owners.setdefault(dependency.dependency_id, node)
        for dependency in node.tree.certificate.finite_origin_call_dependencies:
            finite_origin_call_owners.setdefault(dependency.dependency_id, node)
    all_finite_origin_tails = summary.finite_origin_tail_dependencies()
    all_finite_origin_calls = summary.finite_origin_call_dependencies()
    tails_by_id: dict[int, LeanFiniteOriginTailDependency] = {}
    for dependency in all_finite_origin_tails:
        prior = tails_by_id.get(dependency.dependency_id)
        if prior is not None and prior != dependency:
            raise InternalDirectCallRegisterSummaryGenerationError(
                "one finite-origin tail dependency ID names incompatible "
                "certificates across the summary tree"
            )
        tails_by_id[dependency.dependency_id] = dependency
    finite_origin_tails = tuple(tails_by_id.values())
    for index, dependency in enumerate(finite_origin_tails):
        dependency.checked(f"finite_origin_tail_dependencies[{index}]")
    calls_by_id: dict[int, LeanFiniteOriginCallDependency] = {}
    for dependency in all_finite_origin_calls:
        prior = calls_by_id.get(dependency.dependency_id)
        if prior is not None and prior != dependency:
            raise InternalDirectCallRegisterSummaryGenerationError(
                "one finite-origin call dependency ID names incompatible "
                "certificates across the summary tree"
            )
        calls_by_id[dependency.dependency_id] = dependency
    finite_origin_calls = tuple(calls_by_id.values())
    for index, dependency in enumerate(finite_origin_calls):
        dependency.checked(f"finite_origin_call_dependencies[{index}]")
    imports = [
        "import StageA.RelationalInternalDirectCallRegisterSummary",
        *[
            f"import {module_name}"
            for module_name in dict.fromkeys((
                *bindings.imports,
                *(dependency.authority_module for dependency in finite_origin_calls),
                *(dependency.authority_module for dependency in finite_origin_tails),
            ))
        ],
    ]
    expected = "true" if expectation == "accepted" else "false"
    shared_declarations = _shared_summary_declarations(
        shared_nodes,
        bindings,
        prove_accepted=expectation == "accepted",
    )
    root_summary = _summary_node_name(root_digest)
    root_checked = _summary_node_checked_name(root_digest)
    finite_origin_authorities = "\n\n".join(
        (
            "def generatedFiniteOriginTailRouteAuthority"
            f"{index:04d} :\n"
            "    StageA.Relational.CallableExternalIndirectExit."
            "CheckedCallableIndirectExitRouteAuthority\n"
            f"      {dependency.route_term} :=\n"
            f"  {dependency.route_authority_term}\n\n"
            "theorem generatedFiniteOriginTailRouteBound"
            f"{index:04d} :\n"
            f"    {_summary_certificate_name(finite_origin_tail_owners[dependency.dependency_id].digest)}."
            "finiteOriginTailRouteBound\n"
            f"      {dependency.dependency_id} {dependency.route_term} = true := by\n"
            "  decide\n\n"
            "#print axioms generatedFiniteOriginTailRouteAuthority"
            f"{index:04d}\n"
            "#print axioms generatedFiniteOriginTailRouteBound"
            f"{index:04d}"
        )
        for index, dependency in enumerate(finite_origin_tails)
    )
    finite_origin_call_authorities = "\n\n".join(
        (
            "def generatedFiniteOriginCallAuthority"
            f"{index:04d} :=\n"
            f"  {dependency.indirect_exit_authority_term}\n\n"
            "theorem generatedFiniteOriginCallAuthorityBound"
            f"{index:04d} :\n"
            f"    {_summary_certificate_name(finite_origin_call_owners[dependency.dependency_id].digest)}."
            "finiteOriginCallAuthorityBound\n"
            f"      {_summary_children_name(finite_origin_call_owners[dependency.dependency_id].digest)}\n"
            f"      {dependency.dependency_id}\n"
            "      generatedFiniteOriginCallAuthority"
            f"{index:04d}\n"
            f"      {bindings.original_pe} {bindings.candidate_pe}\n"
            f"      {bindings.original_imports} {bindings.candidate_imports} = true := by\n"
            "  decide\n\n"
            "#print axioms generatedFiniteOriginCallAuthority"
            f"{index:04d}\n"
            "#print axioms generatedFiniteOriginCallAuthorityBound"
            f"{index:04d}"
        )
        for index, dependency in enumerate(finite_origin_calls)
    )
    return f"""{chr(10).join(imports)}

namespace StageA.Generated.RelationalInternalDirectCallRegisterSummary

open StageA.Formal StageA.Relational
open StageA.Relational.InternalDirectCallRegisterSummary

{shared_declarations}

def generatedInternalDirectCallRegisterSummary : SummaryTree :=
  {root_summary}

def generatedInternalDirectCallRegisterSummaryChecked :
    generatedInternalDirectCallRegisterSummary.checked
      {bindings.original_pe} {bindings.candidate_pe}
      {bindings.original_imports} {bindings.candidate_imports} = {expected} := by
  """ + (
        "simpa [generatedInternalDirectCallRegisterSummary] using "
        f"{root_checked}"
        if expectation == "accepted"
        else "decide"
    ) + """

def generatedInternalDirectCallRegisterSummarySemanticIntegrationRequirements :
    SemanticIntegrationRequirements :=
  semanticIntegrationRequirements

def generatedInternalDirectCallRegisterSummaryStandaloneAcceptanceAuthority : Bool :=
  SemanticIntegrationRequirements.standaloneAcceptanceAuthority
    generatedInternalDirectCallRegisterSummarySemanticIntegrationRequirements

theorem generatedInternalDirectCallRegisterSummaryNotAcceptanceAuthority :
    generatedInternalDirectCallRegisterSummaryStandaloneAcceptanceAuthority = false :=
  by
    simpa [generatedInternalDirectCallRegisterSummaryStandaloneAcceptanceAuthority,
      generatedInternalDirectCallRegisterSummarySemanticIntegrationRequirements] using
      semanticIntegrationRequirements_not_authority

""" + (
        "def generatedInternalDirectCallRegisterSummaryStructuralEvidence :\n"
        "    generatedInternalDirectCallRegisterSummary.StructuralCheckerEvidence\n"
        f"      {bindings.original_pe} {bindings.candidate_pe}\n"
        f"      {bindings.original_imports} {bindings.candidate_imports} :=\n"
        "  SummaryTree.checked_structuralEvidence\n"
        "    generatedInternalDirectCallRegisterSummary\n"
        f"    {bindings.original_pe} {bindings.candidate_pe}\n"
        f"    {bindings.original_imports} {bindings.candidate_imports}\n"
        "    generatedInternalDirectCallRegisterSummaryChecked\n\n"
        "#print axioms generatedInternalDirectCallRegisterSummaryStructuralEvidence\n"
        "#print axioms generatedInternalDirectCallRegisterSummaryNotAcceptanceAuthority\n"
        if expectation == "accepted"
        else ""
    ) + (
        ("\n\n" + finite_origin_call_authorities + "\n")
        if finite_origin_call_authorities
        else "\n"
    ) + (
        ("\n\n" + finite_origin_authorities + "\n")
        if finite_origin_authorities
        else "\n"
    ) + "end StageA.Generated.RelationalInternalDirectCallRegisterSummary\n"


def write_internal_direct_call_register_summary(
    destination: Path,
    summary: LeanInternalDirectCallRegisterSummaryTree,
    bindings: InternalDirectCallRegisterSummaryLeanBindings,
    *,
    expectation: Literal["accepted", "rejected"] = "accepted",
) -> Path:
    """Write one generated module; no Python acceptance result is returned."""
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(
        internal_direct_call_register_summary_source(
            summary, bindings, expectation=expectation
        ),
        encoding="utf-8",
    )
    return destination


# Short aliases for consumers that do not need the Lean transport prefix.
ExactRegionPair = LeanExactRegionPair
CalleeEdge = LeanCalleeEdge
ReturnInventoryEntry = LeanReturnInventoryEntry
NestedSummaryDependency = LeanNestedSummaryDependency
MachineImportDependency = LeanMachineImportDependency
MachineImportTailDependency = LeanMachineImportTailDependency
MachineImportTerminalDependency = LeanMachineImportTerminalDependency
FiniteIndirectJumpDependency = LeanFiniteIndirectJumpDependency
FiniteOriginCallDependency = LeanFiniteOriginCallDependency
FiniteOriginCallTarget = LeanFiniteOriginCallTarget
FiniteOriginTailDependency = LeanFiniteOriginTailDependency
FiniteOriginTailTarget = LeanFiniteOriginTailTarget
StackFrameAnchorWitness = LeanStackFrameAnchorWitness
StackSaveRestoreFrameWitness = LeanStackSaveRestoreFrameWitness
StackSaveRestoreWitness = LeanStackSaveRestoreWitness
StackEntryOffsetWitness = LeanStackEntryOffsetWitness
InternalDirectCallRegisterCertificate = LeanInternalDirectCallRegisterCertificate
InternalDirectCallRegisterSummaryTree = LeanInternalDirectCallRegisterSummaryTree


__all__ = [
    "CalleeEdge",
    "ExactRegionPair",
    "FiniteIndirectJumpDependency",
    "FiniteOriginCallDependency",
    "FiniteOriginCallTarget",
    "FiniteOriginTailDependency",
    "FiniteOriginTailTarget",
    "INTERNAL_DIRECT_CALL_REGISTER_SUMMARY_LEAN_FILENAME",
    "InternalDirectCallRegisterCertificate",
    "InternalDirectCallRegisterSummaryGenerationError",
    "InternalDirectCallRegisterSummaryLeanBindings",
    "InternalDirectCallRegisterSummaryLeanModule",
    "InternalDirectCallRegisterSummaryLeanModuleDag",
    "InternalDirectCallRegisterSummaryTree",
    "LeanCalleeEdge",
    "LeanExactRegionPair",
    "LeanFiniteIndirectJumpDependency",
    "LeanFiniteOriginCallDependency",
    "LeanFiniteOriginCallTarget",
    "LeanFiniteOriginTailDependency",
    "LeanFiniteOriginTailTarget",
    "LeanInternalDirectCallRegisterCertificate",
    "LeanInternalDirectCallRegisterSummaryTree",
    "LeanMachineImportDependency",
    "LeanMachineImportTailDependency",
    "LeanMachineImportTerminalDependency",
    "LeanNestedSummaryDependency",
    "LeanReturnInventoryEntry",
    "LeanSpan",
    "LeanStackFrameAnchorWitness",
    "LeanStackSaveRestoreFrameWitness",
    "LeanStackSaveRestoreWitness",
    "LeanStackEntryOffsetWitness",
    "MachineImportDependency",
    "MachineImportTailDependency",
    "MachineImportTerminalDependency",
    "NestedSummaryDependency",
    "ReturnInventoryEntry",
    "StackFrameAnchorWitness",
    "StackSaveRestoreFrameWitness",
    "StackSaveRestoreWitness",
    "StackEntryOffsetWitness",
    "internal_direct_call_register_summary_source",
    "internal_direct_call_register_summary_module_dag",
    "write_internal_direct_call_register_summary",
]
