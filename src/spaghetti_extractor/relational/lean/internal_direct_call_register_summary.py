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


@dataclass(frozen=True)
class LeanCallerFrameWord:
    original_offset: int
    candidate_offset: int

    def lean(self, context: str = "caller frame word") -> str:
        original = _nat(
            self.original_offset,
            f"{context}.original_offset",
            u32=True,
        )
        candidate = _nat(
            self.candidate_offset,
            f"{context}.candidate_offset",
            u32=True,
        )
        if original > 65532 or candidate > 65532:
            raise InternalDirectCallRegisterSummaryGenerationError(
                f"{context} exceeds the checked frame-word offset bound"
            )
        return (
            "{ originalOffset := "
            f"{original}, candidateOffset := {candidate} }}"
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
class LeanGraphClosureNodeWitness:
    forward_rank: int
    forward_parent_region_index: int | None
    forward_parent_edge_index: int | None
    reverse_rank: int
    reverse_next_region_index: int | None
    reverse_next_edge_index: int | None

    @staticmethod
    def _option_nat(value: int | None, context: str) -> str:
        if value is None:
            return "none"
        return f"(some {_nat(value, context)})"

    def lean(self, context: str = "graph closure node witness") -> str:
        return " ".join((
            "{ forwardRank := "
            f"{_nat(self.forward_rank, f'{context}.forward_rank')},",
            "forwardParentRegionIndex := "
            f"{self._option_nat(self.forward_parent_region_index, f'{context}.forward_parent_region_index')},",
            "forwardParentEdgeIndex := "
            f"{self._option_nat(self.forward_parent_edge_index, f'{context}.forward_parent_edge_index')},",
            "reverseRank := "
            f"{_nat(self.reverse_rank, f'{context}.reverse_rank')},",
            "reverseNextRegionIndex := "
            f"{self._option_nat(self.reverse_next_region_index, f'{context}.reverse_next_region_index')},",
            "reverseNextEdgeIndex := "
            f"{self._option_nat(self.reverse_next_edge_index, f'{context}.reverse_next_edge_index')} }}",
        ))


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
    caller_frame_words: tuple[LeanCallerFrameWord, ...] = ()
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

    def graph_closure_witness(
        self,
        context: str = "certificate",
    ) -> tuple[LeanGraphClosureNodeWitness, ...]:
        if not self.callee_regions:
            raise InternalDirectCallRegisterSummaryGenerationError(
                f"{context}.callee_regions must not be empty"
            )

        region_index_by_id: dict[int, int] = {}
        for index, region in enumerate(self.callee_regions):
            prior = region_index_by_id.setdefault(region.region_id, index)
            if prior != index:
                raise InternalDirectCallRegisterSummaryGenerationError(
                    f"{context}.callee_regions contains duplicate region ID "
                    f"{region.region_id}"
                )

        entry_index = region_index_by_id.get(self.callee_entry.region_id)

        outgoing: list[list[tuple[int, int]]] = [
            [] for _ in self.callee_regions
        ]
        incoming: list[list[tuple[int, int]]] = [
            [] for _ in self.callee_regions
        ]
        for edge_index, edge in enumerate(self.edges):
            source_index = region_index_by_id.get(edge.source_region_id)
            target_index = region_index_by_id.get(edge.target_region_id)
            if source_index is None or target_index is None:
                # Preserve the malformed edge in the serialized certificate.
                # graphShapeChecked will reject it in Lean; it cannot
                # contribute to the proposed spanning witness.
                continue
            outgoing[source_index].append((target_index, edge_index))
            incoming[target_index].append((source_index, edge_index))

        forward_rank: list[int | None] = [None] * len(self.callee_regions)
        forward_parent_region: list[int | None] = [
            None
        ] * len(self.callee_regions)
        forward_parent_edge: list[int | None] = [
            None
        ] * len(self.callee_regions)
        forward_queue: list[int] = []
        if entry_index is not None:
            forward_rank[entry_index] = 0
            forward_queue.append(entry_index)
        for source_index in forward_queue:
            source_rank = forward_rank[source_index]
            assert source_rank is not None
            for target_index, edge_index in outgoing[source_index]:
                if forward_rank[target_index] is not None:
                    continue
                forward_rank[target_index] = source_rank + 1
                forward_parent_region[target_index] = source_index
                forward_parent_edge[target_index] = edge_index
                forward_queue.append(target_index)

        completion_ids = {
            entry.return_region_id for entry in self.returns
        }
        completion_ids.update(
            dependency.source_region_id
            for dependency in self.machine_import_terminal_dependencies
        )
        completion_indices = [
            region_index_by_id[region_id]
            for region_id in sorted(completion_ids)
            if region_id in region_index_by_id
        ]

        reverse_rank: list[int | None] = [None] * len(self.callee_regions)
        reverse_next_region: list[int | None] = [
            None
        ] * len(self.callee_regions)
        reverse_next_edge: list[int | None] = [
            None
        ] * len(self.callee_regions)
        reverse_queue: list[int] = []
        for completion_index in completion_indices:
            if reverse_rank[completion_index] is None:
                reverse_rank[completion_index] = 0
                reverse_queue.append(completion_index)
        for target_index in reverse_queue:
            target_rank = reverse_rank[target_index]
            assert target_rank is not None
            for source_index, edge_index in incoming[target_index]:
                if reverse_rank[source_index] is not None:
                    continue
                reverse_rank[source_index] = target_rank + 1
                reverse_next_region[source_index] = target_index
                reverse_next_edge[source_index] = edge_index
                reverse_queue.append(source_index)

        witnesses: list[LeanGraphClosureNodeWitness] = []
        for index in range(len(self.callee_regions)):
            node_forward_rank = forward_rank[index]
            node_reverse_rank = reverse_rank[index]
            witnesses.append(LeanGraphClosureNodeWitness(
                # Unwitnessed nodes deliberately serialize as rank-zero roots
                # without a parent/successor.  The Lean checker rejects those
                # unless they are the actual entry/completion.
                forward_rank=(
                    node_forward_rank
                    if node_forward_rank is not None
                    else 0
                ),
                forward_parent_region_index=forward_parent_region[index],
                forward_parent_edge_index=forward_parent_edge[index],
                reverse_rank=(
                    node_reverse_rank
                    if node_reverse_rank is not None
                    else 0
                ),
                reverse_next_region_index=reverse_next_region[index],
                reverse_next_edge_index=reverse_next_edge[index],
            ))
        return tuple(witnesses)

    def lean(
        self,
        context: str = "certificate",
        *,
        callee_regions_term: str | None = None,
    ) -> str:
        regions = (
            callee_regions_term
            if callee_regions_term is not None
            else _lean_list([
                region.lean(f"{context}.callee_regions[{index}]")
                for index, region in enumerate(self.callee_regions)
            ])
        )
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
        caller_frame_words = _lean_list([
            word.lean(f"{context}.caller_frame_words[{index}]")
            for index, word in enumerate(self.caller_frame_words)
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
        graph_closure_witness = _lean_list([
            witness.lean(f"{context}.graph_closure_witness[{index}]")
            for index, witness in enumerate(
                self.graph_closure_witness(context)
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
            f"callerFrameWords := {caller_frame_words},",
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
            f"dynamicStackEntryRegionIds := {dynamic_stack_ids},",
            "graphClosureWitness := "
            f"{{ nodes := {graph_closure_witness} }} }}",
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
    *,
    prechecked_registers: frozenset[str] = frozenset(),
) -> tuple[str, ...]:
    declarations: list[str] = []
    stack_witness_by_register = {
        witness.register: index
        for index, witness in enumerate(certificate.stack_witnesses)
    }
    for register in certificate.requested_registers:
        if register in prechecked_registers:
            continue
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
    resource_class: str = "light"
    estimated_memory_mb: int = 768


@dataclass(frozen=True)
class InternalDirectCallRegisterSummaryLeanModuleDag:
    root_source: str
    root_node_module: str
    node_modules: tuple[InternalDirectCallRegisterSummaryLeanModule, ...]
    artifact_modules: tuple[InternalDirectCallRegisterSummaryLeanModule, ...] = ()

    @property
    def all_modules(
        self,
    ) -> tuple[InternalDirectCallRegisterSummaryLeanModule, ...]:
        return (*self.artifact_modules, *self.node_modules)


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


def _dag_node_artifact_module_name(module: str, artifact: str) -> str:
    return f"{module}{artifact}"


def _control_inventory_resource(region_count: int) -> tuple[str, int]:
    """Classify PE-bound inventory checks by their full certificate context."""

    if region_count >= 256:
        return ("high-memory", 24576)
    if region_count >= 96:
        return ("large-memory", 16384)
    return ("medium", 4096)


def internal_direct_call_register_summary_module_dag(
    summary: LeanInternalDirectCallRegisterSummaryTree,
    bindings: InternalDirectCallRegisterSummaryLeanBindings,
    *,
    root_namespace: str,
) -> InternalDirectCallRegisterSummaryLeanModuleDag:
    """Emit one independently checkable Lean module per unique summary node."""

    control_pack_size = 32
    bindings.checked()
    _qualified(root_namespace, "root_namespace")
    shared_nodes, root_digest = _shared_summary_nodes(summary)
    modules_by_digest = {
        node.digest: _dag_node_module_name(node.digest, bindings)
        for node in shared_nodes
    }
    generated_modules: list[InternalDirectCallRegisterSummaryLeanModule] = []
    generated_artifact_modules: list[
        InternalDirectCallRegisterSummaryLeanModule
    ] = []
    for node in shared_nodes:
        module = modules_by_digest[node.digest]
        namespace = _dag_node_namespace(module)
        data_module = _dag_node_artifact_module_name(module, "Data")
        preservation_module = _dag_node_artifact_module_name(
            module, "Preservation"
        )
        family_modules = {
            "shape": _dag_node_artifact_module_name(
                module, "StructureShape"
            ),
            "decode": _dag_node_artifact_module_name(
                module, "StructureDecode"
            ),
            "control": _dag_node_artifact_module_name(
                module, "StructureControl"
            ),
            "dependencies": _dag_node_artifact_module_name(
                module, "StructureDependencies"
            ),
            "stack": _dag_node_artifact_module_name(
                module, "StructureStack"
            ),
        }
        region_count = len(node.tree.certificate.callee_regions)
        edge_count = len(node.tree.certificate.edges)
        dependency_count = sum((
            len(node.tree.certificate.nested_dependencies),
            len(node.tree.certificate.machine_import_dependencies),
            len(node.tree.certificate.machine_import_tail_dependencies),
            len(node.tree.certificate.machine_import_terminal_dependencies),
            len(node.tree.certificate.finite_indirect_dependencies),
            len(node.tree.certificate.finite_origin_call_dependencies),
            len(node.tree.certificate.finite_origin_tail_dependencies),
        ))
        split_control = region_count >= 32 or edge_count >= 64
        control_inventory_resource = _control_inventory_resource(region_count)
        region_parts = tuple(
            node.tree.certificate.callee_regions[start:start + control_pack_size]
            for start in range(0, region_count, control_pack_size)
        ) if split_control else ()
        region_part_names = tuple(
            f"generatedSummaryRegionPart{index:04d}"
            for index in range(len(region_parts))
        )
        graph_index_parts = tuple(
            tuple(range(start, min(start + control_pack_size, region_count)))
            for start in range(0, region_count, control_pack_size)
        ) if split_control else ()
        graph_index_part_names = tuple(
            f"generatedSummaryGraphClosureIndexPart{index:04d}"
            for index in range(len(graph_index_parts))
        )
        region_part_declarations = "\n\n".join(
            f"def {part_name} : List ExactRegionPair :=\n"
            f"  {_lean_list([
                region.lean(
                    'generatedSummaryCertificate.callee_regions'
                    f'[{part_index * control_pack_size + region_index}]'
                )
                for region_index, region in enumerate(part)
            ])}"
            for part_index, (part_name, part) in enumerate(
                zip(region_part_names, region_parts, strict=True)
            )
        )
        if region_part_declarations:
            region_part_declarations += "\n\n"
        graph_index_part_declarations = "\n\n".join(
            f"def {part_name} : List Nat :=\n"
            f"  {_lean_list([str(index) for index in part])}"
            for part_name, part in zip(
                graph_index_part_names, graph_index_parts, strict=True
            )
        )
        if graph_index_part_declarations:
            graph_index_part_declarations += "\n\n"
        region_parts_declaration = ""
        graph_index_parts_declaration = ""
        certificate_source = node.certificate_source
        if split_control:
            region_parts_declaration = (
                "def generatedSummaryRegionParts : "
                "List (List ExactRegionPair) :=\n"
                f"  {_lean_list(list(region_part_names))}\n\n"
            )
            graph_index_parts_declaration = (
                "def generatedSummaryGraphClosureIndexParts : "
                "List (List Nat) :=\n"
                f"  {_lean_list(list(graph_index_part_names))}\n\n"
            )
            certificate_source = node.tree.certificate.lean(
                callee_regions_term="generatedSummaryRegionParts.flatten",
            )
        child_modules = tuple(
            modules_by_digest[digest] for digest in node.child_digests
        )
        child_data_modules = tuple(
            _dag_node_artifact_module_name(child_module, "Data")
            for child_module in child_modules
        )
        child_namespaces = tuple(
            _dag_node_namespace(module_name) for module_name in child_modules
        )
        child_tree_terms = tuple(
            f"{child_namespace}.generatedSummaryNode"
            for child_namespace in child_namespaces
        )
        child_certificate_terms = tuple(
            f"{child_namespace}.generatedSummaryCertificate"
            for child_namespace in child_namespaces
        )
        split_children = len(child_modules) >= control_pack_size
        child_tree_parts = tuple(
            child_tree_terms[start:start + control_pack_size]
            for start in range(
                0, len(child_tree_terms), control_pack_size
            )
        ) if split_children else ()
        child_certificate_parts = tuple(
            child_certificate_terms[start:start + control_pack_size]
            for start in range(
                0, len(child_certificate_terms), control_pack_size
            )
        ) if split_children else ()
        child_tree_part_names = tuple(
            f"generatedSummaryChildrenPart{index:04d}"
            for index in range(len(child_tree_parts))
        )
        child_certificate_part_names = tuple(
            f"generatedSummaryChildCertificatesPart{index:04d}"
            for index in range(len(child_certificate_parts))
        )
        child_part_declarations = ""
        child_parts_declaration = ""
        if split_children:
            child_part_declarations = "\n\n".join(
                (
                    f"def {tree_part_name} : List SummaryTree :=\n"
                    f"  {_lean_list(list(tree_part))}\n\n"
                    f"def {certificate_part_name} : List Certificate :=\n"
                    f"  {_lean_list(list(certificate_part))}"
                )
                for (
                    tree_part_name,
                    certificate_part_name,
                    tree_part,
                    certificate_part,
                ) in zip(
                    child_tree_part_names,
                    child_certificate_part_names,
                    child_tree_parts,
                    child_certificate_parts,
                    strict=True,
                )
            )
            child_part_declarations += "\n\n"
            child_parts_declaration = (
                "def generatedSummaryChildrenParts : "
                "List (List SummaryTree) :=\n"
                f"  {_lean_list(list(child_tree_part_names))}\n\n"
                "def generatedSummaryChildCertificateParts : "
                "List (List Certificate) :=\n"
                f"  {_lean_list(list(child_certificate_part_names))}\n\n"
            )
        data_imports = "\n".join(
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
                *child_data_modules,
            ))
        )
        children = (
            "generatedSummaryChildrenParts.flatten"
            if split_children
            else _lean_list(list(child_tree_terms))
        )
        child_certificates = (
            "generatedSummaryChildCertificateParts.flatten"
            if split_children
            else _lean_list(list(child_certificate_terms))
        )
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
                prechecked_registers=(
                    frozenset(("esp",))
                    if split_control and
                    "esp" in node.tree.certificate.requested_registers
                    else frozenset()
                ),
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
        data_source = f"""{data_imports}

namespace {namespace}

open StageA.Formal StageA.Relational
open StageA.Relational.InternalDirectCallRegisterSummary

set_option maxRecDepth 1000000
set_option maxHeartbeats 0

{region_part_declarations}{region_parts_declaration}{graph_index_part_declarations}{graph_index_parts_declaration}{child_part_declarations}{child_parts_declaration}def generatedSummaryCertificate : Certificate :=
  {certificate_source}

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

end {namespace}
"""
        data_source_bytes = len(data_source.encode("utf-8"))
        if data_source_bytes >= 90 * 1024:
            data_resource = ("medium", 4096)
        elif data_source_bytes >= 22 * 1024:
            data_resource = ("medium", 2048)
        else:
            data_resource = ("light", 768)
        generated_artifact_modules.append(
            InternalDirectCallRegisterSummaryLeanModule(
                module=data_module,
                namespace=namespace,
                source=data_source,
                resource_class=data_resource[0],
                estimated_memory_mb=data_resource[1],
            )
        )

        family_specs = (
            (
                "shape",
                "generatedSummaryCertificateStructureShapeChecked",
                "generatedSummaryCertificate.structureShapeChecked",
                max(region_count, edge_count),
            ),
            (
                "decode",
                "generatedSummaryCertificateStructureDecodeChecked",
                "generatedSummaryCertificate.structureDecodeChecked\n"
                f"      {bindings.original_pe} {bindings.candidate_pe}\n"
                f"      {bindings.original_imports} "
                f"{bindings.candidate_imports}",
                region_count,
            ),
            (
                "control",
                "generatedSummaryCertificateStructureControlChecked",
                "generatedSummaryCertificate.structureControlChecked\n"
                f"      {bindings.original_pe} {bindings.candidate_pe}\n"
                f"      {bindings.original_imports} "
                f"{bindings.candidate_imports}",
                edge_count,
            ),
            (
                "dependencies",
                "generatedSummaryCertificateStructureDependenciesChecked",
                "generatedSummaryCertificate.structureDependenciesChecked\n"
                f"      {bindings.original_pe} {bindings.candidate_pe}\n"
                f"      {bindings.original_imports} "
                f"{bindings.candidate_imports}\n"
                "      generatedSummaryChildCertificates",
                dependency_count,
            ),
            (
                "stack",
                "generatedSummaryCertificateStructureStackChecked",
                "generatedSummaryCertificate.structureStackChecked\n"
                f"      {bindings.original_pe} {bindings.candidate_pe}\n"
                f"      {bindings.original_imports} "
                f"{bindings.candidate_imports}",
                region_count,
            ),
        )
        if split_control:
            family_specs = tuple(
                spec for spec in family_specs if spec[0] != "control"
            )

            graph_closed_module = _dag_node_artifact_module_name(
                module, "StructureGraphClosed"
            )
            graph_closed_theorem = (
                "generatedSummaryCertificateGraphClosedChecked"
            )
            graph_pack_modules: list[str] = []
            graph_pack_theorems: list[str] = []
            for part_index, part_name in enumerate(
                graph_index_part_names
            ):
                graph_pack_module = _dag_node_artifact_module_name(
                    module,
                    f"StructureGraphClosurePack{part_index:04d}",
                )
                graph_pack_theorem = (
                    "generatedSummaryGraphClosurePart"
                    f"{part_index:04d}Checked"
                )
                graph_pack_source = f"""import {data_module}

namespace {namespace}

open StageA.Formal StageA.Relational
open StageA.Relational.InternalDirectCallRegisterSummary

set_option maxRecDepth 1000000
set_option maxHeartbeats 0

theorem {graph_pack_theorem} :
    generatedSummaryCertificate.graphClosureWitness.partChecked
      generatedSummaryCertificate {part_name} = true := by
  decide

#print axioms {graph_pack_theorem}

end {namespace}
"""
                generated_artifact_modules.append(
                    InternalDirectCallRegisterSummaryLeanModule(
                        module=graph_pack_module,
                        namespace=namespace,
                        source=graph_pack_source,
                        resource_class="medium",
                        estimated_memory_mb=2048,
                    )
                )
                graph_pack_modules.append(graph_pack_module)
                graph_pack_theorems.append(graph_pack_theorem)

            graph_closed_imports = "\n".join(
                f"import {module_name}"
                for module_name in (
                    data_module,
                    *graph_pack_modules,
                )
            )
            graph_pack_simp = ", ".join(graph_pack_theorems)
            graph_closed_source = f"""{graph_closed_imports}

namespace {namespace}

open StageA.Formal StageA.Relational
open StageA.Relational.InternalDirectCallRegisterSummary

set_option maxRecDepth 1000000
set_option maxHeartbeats 0

theorem generatedSummaryGraphClosureWitnessLengthBound :
    generatedSummaryCertificate.graphClosureWitness.nodes.length =
      generatedSummaryCertificate.calleeRegions.length := by
  decide

theorem generatedSummaryGraphShapeChecked :
    generatedSummaryCertificate.graphShapeChecked = true := by
  decide

theorem generatedSummaryGraphClosureIndexPartsBound :
    generatedSummaryGraphClosureIndexParts.flatten =
      List.range generatedSummaryCertificate.calleeRegions.length := by
  decide

theorem generatedSummaryGraphClosurePartsChecked :
    generatedSummaryGraphClosureIndexParts.all (fun part =>
      generatedSummaryCertificate.graphClosureWitness.partChecked
        generatedSummaryCertificate part) = true := by
  simp [generatedSummaryGraphClosureIndexParts, {graph_pack_simp}]

theorem {graph_closed_theorem} :
    generatedSummaryCertificate.graphClosed = true := by
  unfold Certificate.graphClosed
  exact GraphClosureWitness.checked_of_parts
    generatedSummaryCertificate.graphClosureWitness
    generatedSummaryCertificate generatedSummaryGraphClosureIndexParts
    generatedSummaryGraphClosureWitnessLengthBound
    generatedSummaryGraphShapeChecked
    generatedSummaryGraphClosureIndexPartsBound
    generatedSummaryGraphClosurePartsChecked

#print axioms {graph_closed_theorem}

end {namespace}
"""
            generated_artifact_modules.append(
                InternalDirectCallRegisterSummaryLeanModule(
                    module=graph_closed_module,
                    namespace=namespace,
                    source=graph_closed_source,
                    resource_class="medium",
                    estimated_memory_mb=4096,
                )
            )

            control_pack_modules: list[str] = [graph_closed_module]
            original_pack_theorems: list[str] = []
            candidate_pack_theorems: list[str] = []
            for part_index, part_name in enumerate(region_part_names):
                pack_specs = (
                    (
                        "Original",
                        "generatedSummaryOriginalInventoryPart"
                        f"{part_index:04d}Checked",
                        "generatedSummaryCertificate.inventoryRegionsChecked\n"
                        f"      {bindings.original_pe} "
                        f"{bindings.original_imports} false\n"
                        f"      {part_name}",
                        original_pack_theorems,
                    ),
                    (
                        "Candidate",
                        "generatedSummaryCandidateInventoryPart"
                        f"{part_index:04d}Checked",
                        "generatedSummaryCertificate.inventoryRegionsChecked\n"
                        f"      {bindings.candidate_pe} "
                        f"{bindings.candidate_imports} true\n"
                        f"      {part_name}",
                        candidate_pack_theorems,
                    ),
                )
                for pack_kind, theorem_name, goal, theorem_names in pack_specs:
                    pack_resource = (
                        control_inventory_resource
                        if pack_kind in ("Original", "Candidate")
                        else ("medium", 4096)
                    )
                    pack_module = _dag_node_artifact_module_name(
                        module,
                        f"StructureControl{pack_kind}Pack{part_index:04d}",
                    )
                    pack_source = f"""import {data_module}

namespace {namespace}

open StageA.Formal StageA.Relational
open StageA.Relational.InternalDirectCallRegisterSummary

set_option maxRecDepth 1000000
set_option maxHeartbeats 0

theorem {theorem_name} :
    {goal} = true := by
  decide

#print axioms {theorem_name}

end {namespace}
"""
                    generated_artifact_modules.append(
                        InternalDirectCallRegisterSummaryLeanModule(
                            module=pack_module,
                            namespace=namespace,
                            source=pack_source,
                            resource_class=pack_resource[0],
                            estimated_memory_mb=pack_resource[1],
                        )
                    )
                    control_pack_modules.append(pack_module)
                    theorem_names.append(theorem_name)

            control_imports = "\n".join(
                f"import {module_name}"
                for module_name in (data_module, *control_pack_modules)
            )
            original_pack_simp = ", ".join(original_pack_theorems)
            candidate_pack_simp = ", ".join(candidate_pack_theorems)
            control_source = f"""{control_imports}

namespace {namespace}

open StageA.Formal StageA.Relational
open StageA.Relational.InternalDirectCallRegisterSummary

set_option maxRecDepth 1000000
set_option maxHeartbeats 0

theorem generatedSummaryRegionPartsBound :
    generatedSummaryRegionParts.flatten =
      generatedSummaryCertificate.calleeRegions := by
  rfl

theorem generatedSummaryOriginalInventoryPartsChecked :
    generatedSummaryRegionParts.all (fun part =>
      generatedSummaryCertificate.inventoryRegionsChecked
        {bindings.original_pe} {bindings.original_imports} false part) =
          true := by
  simp [generatedSummaryRegionParts, {original_pack_simp}]

theorem generatedSummaryCandidateInventoryPartsChecked :
    generatedSummaryRegionParts.all (fun part =>
      generatedSummaryCertificate.inventoryRegionsChecked
        {bindings.candidate_pe} {bindings.candidate_imports} true part) =
          true := by
  simp [generatedSummaryRegionParts, {candidate_pack_simp}]

theorem generatedSummaryCertificateStructureControlChecked :
    generatedSummaryCertificate.structureControlChecked
      {bindings.original_pe} {bindings.candidate_pe}
      {bindings.original_imports} {bindings.candidate_imports} = true := by
  exact Certificate.structureControlChecked_of_closed_graph_and_region_parts
    generatedSummaryCertificate
    {bindings.original_pe} {bindings.candidate_pe}
    {bindings.original_imports} {bindings.candidate_imports}
    generatedSummaryRegionParts generatedSummaryRegionPartsBound
    {graph_closed_theorem}
    generatedSummaryOriginalInventoryPartsChecked
    generatedSummaryCandidateInventoryPartsChecked

#print axioms generatedSummaryCertificateStructureControlChecked

end {namespace}
"""
            generated_artifact_modules.append(
                InternalDirectCallRegisterSummaryLeanModule(
                    module=family_modules["control"],
                    namespace=namespace,
                    source=control_source,
                    resource_class="light",
                    estimated_memory_mb=768,
                )
            )

        for family, theorem_name, goal, complexity in family_specs:
            family_source = f"""import {data_module}

namespace {namespace}

open StageA.Formal StageA.Relational
open StageA.Relational.InternalDirectCallRegisterSummary

set_option maxRecDepth 1000000
set_option maxHeartbeats 0

theorem {theorem_name} :
    {goal} = true := by
  decide

#print axioms {theorem_name}

end {namespace}
"""
            if family in {"shape", "control"} and complexity >= 256:
                family_resource = ("high-memory", 76800)
            elif complexity >= 256:
                family_resource = ("large-memory", 24576)
            elif complexity >= 64:
                family_resource = ("large-memory", 12288)
            elif complexity >= 16:
                family_resource = ("medium", 4096)
            else:
                family_resource = ("light", 768)
            generated_artifact_modules.append(
                InternalDirectCallRegisterSummaryLeanModule(
                    module=family_modules[family],
                    namespace=namespace,
                    source=family_source,
                    resource_class=family_resource[0],
                    estimated_memory_mb=family_resource[1],
                )
            )

        child_aggregate_module: str | None = None
        child_depth_proof = (
            "simp [generatedSummaryChildren"
            f"{child_depth_simp}]\n  decide"
            if child_depth_checks
            else "simp [generatedSummaryChildren]"
        )
        child_theorem_source = f"""
theorem generatedSummaryChildrenCertificates :
    generatedSummaryChildren.map SummaryTree.certificate =
      generatedSummaryChildCertificates := by
  simp [generatedSummaryChildren, generatedSummaryChildCertificates{
      child_certificate_simp}]

theorem generatedSummaryChildrenChecked :
    generatedSummaryChildren.all (fun child => child.checked
      {bindings.original_pe} {bindings.candidate_pe}
      {bindings.original_imports} {bindings.candidate_imports}) = true := by
  simp [generatedSummaryChildren{child_simp}]

theorem generatedSummaryChildrenShallower :
    generatedSummaryChildren.all (fun child =>
      child.certificate.dependencyDepth <
        generatedSummaryCertificate.dependencyDepth) = true := by
  {child_depth_proof}
"""
        if split_children:
            child_pack_modules: list[str] = []
            child_certificate_part_theorems: list[str] = []
            child_checked_part_theorems: list[str] = []
            child_depth_part_theorems: list[str] = []
            for part_index, (
                tree_part_name,
                certificate_part_name,
                part_namespaces,
            ) in enumerate(zip(
                child_tree_part_names,
                child_certificate_part_names,
                (
                    child_namespaces[
                        start:start + control_pack_size
                    ]
                    for start in range(
                        0, len(child_namespaces), control_pack_size
                    )
                ),
                strict=True,
            )):
                child_pack_module = _dag_node_artifact_module_name(
                    module, f"ChildrenPack{part_index:04d}"
                )
                certificates_theorem = (
                    "generatedSummaryChildrenPart"
                    f"{part_index:04d}Certificates"
                )
                checked_theorem = (
                    "generatedSummaryChildrenPart"
                    f"{part_index:04d}Checked"
                )
                depth_theorem = (
                    "generatedSummaryChildrenPart"
                    f"{part_index:04d}Shallower"
                )
                part_certificate_simp = ", ".join(
                    f"{child_namespace}.generatedSummaryNodeCertificate"
                    for child_namespace in dict.fromkeys(part_namespaces)
                )
                part_child_simp = ", ".join(
                    f"{child_namespace}.generatedSummaryNodeChecked"
                    for child_namespace in dict.fromkeys(part_namespaces)
                )
                part_depth_simp = ", ".join(
                    f"{child_namespace}.generatedSummaryNodeDepth"
                    for child_namespace in dict.fromkeys(part_namespaces)
                )
                part_child_modules = child_modules[
                    part_index * control_pack_size:
                    (part_index + 1) * control_pack_size
                ]
                child_pack_imports = "\n".join(
                    f"import {module_name}"
                    for module_name in dict.fromkeys((
                        data_module,
                        *part_child_modules,
                    ))
                )
                child_pack_source = f"""{child_pack_imports}

namespace {namespace}

open StageA.Formal StageA.Relational
open StageA.Relational.InternalDirectCallRegisterSummary

set_option maxRecDepth 1000000
set_option maxHeartbeats 0

theorem {certificates_theorem} :
    {tree_part_name}.map SummaryTree.certificate =
      {certificate_part_name} := by
  simp [{tree_part_name}, {certificate_part_name},
    {part_certificate_simp}]

theorem {checked_theorem} :
    {tree_part_name}.all (fun child => child.checked
      {bindings.original_pe} {bindings.candidate_pe}
      {bindings.original_imports} {bindings.candidate_imports}) = true := by
  simp [{tree_part_name}, {part_child_simp}]

theorem {depth_theorem} :
    {tree_part_name}.all (fun child =>
      child.certificate.dependencyDepth <
        generatedSummaryCertificate.dependencyDepth) = true := by
  simp [{tree_part_name}, {part_depth_simp}]
  decide

#print axioms {checked_theorem}

end {namespace}
"""
                generated_artifact_modules.append(
                    InternalDirectCallRegisterSummaryLeanModule(
                        module=child_pack_module,
                        namespace=namespace,
                        source=child_pack_source,
                        resource_class="medium",
                        estimated_memory_mb=4096,
                    )
                )
                child_pack_modules.append(child_pack_module)
                child_certificate_part_theorems.append(
                    certificates_theorem
                )
                child_checked_part_theorems.append(checked_theorem)
                child_depth_part_theorems.append(depth_theorem)

            child_aggregate_module = _dag_node_artifact_module_name(
                module, "ChildrenChecked"
            )
            child_aggregate_imports = "\n".join(
                f"import {module_name}"
                for module_name in (
                    data_module,
                    *child_pack_modules,
                )
            )
            child_certificate_pack_simp = ", ".join(
                child_certificate_part_theorems
            )
            child_checked_pack_simp = ", ".join(
                child_checked_part_theorems
            )
            child_depth_pack_simp = ", ".join(
                child_depth_part_theorems
            )
            child_aggregate_source = f"""{child_aggregate_imports}

namespace {namespace}

open StageA.Formal StageA.Relational
open StageA.Relational.InternalDirectCallRegisterSummary

set_option maxRecDepth 1000000
set_option maxHeartbeats 0

theorem generatedSummaryChildrenCertificates :
    generatedSummaryChildren.map SummaryTree.certificate =
      generatedSummaryChildCertificates := by
  simp [generatedSummaryChildren, generatedSummaryChildCertificates,
    generatedSummaryChildrenParts,
    generatedSummaryChildCertificateParts,
    {child_certificate_pack_simp}]

theorem generatedSummaryChildrenPartsChecked :
    generatedSummaryChildrenParts.all (fun part =>
      part.all (fun child => child.checked
        {bindings.original_pe} {bindings.candidate_pe}
        {bindings.original_imports} {bindings.candidate_imports})) = true := by
  simp [generatedSummaryChildrenParts, {child_checked_pack_simp}]

theorem generatedSummaryChildrenChecked :
    generatedSummaryChildren.all (fun child => child.checked
      {bindings.original_pe} {bindings.candidate_pe}
      {bindings.original_imports} {bindings.candidate_imports}) = true := by
  unfold generatedSummaryChildren
  exact listAll_flatten_of_parts generatedSummaryChildrenParts
    (fun child => child.checked
      {bindings.original_pe} {bindings.candidate_pe}
      {bindings.original_imports} {bindings.candidate_imports})
    generatedSummaryChildrenPartsChecked

theorem generatedSummaryChildrenPartsShallower :
    generatedSummaryChildrenParts.all (fun part =>
      part.all (fun child =>
        child.certificate.dependencyDepth <
          generatedSummaryCertificate.dependencyDepth)) = true := by
  simp [generatedSummaryChildrenParts, {child_depth_pack_simp}]

theorem generatedSummaryChildrenShallower :
    generatedSummaryChildren.all (fun child =>
      child.certificate.dependencyDepth <
        generatedSummaryCertificate.dependencyDepth) = true := by
  unfold generatedSummaryChildren
  exact listAll_flatten_of_parts generatedSummaryChildrenParts
    (fun child =>
      child.certificate.dependencyDepth <
        generatedSummaryCertificate.dependencyDepth)
    generatedSummaryChildrenPartsShallower

#print axioms generatedSummaryChildrenChecked

end {namespace}
"""
            generated_artifact_modules.append(
                InternalDirectCallRegisterSummaryLeanModule(
                    module=child_aggregate_module,
                    namespace=namespace,
                    source=child_aggregate_source,
                    resource_class="light",
                    estimated_memory_mb=768,
                )
            )
            child_theorem_source = ""

        preservation_witness_modules: list[str] = []
        if split_control and node.tree.certificate.stack_witnesses:
            stack_witness_declarations = ""
            for witness_index, witness in enumerate(
                node.tree.certificate.stack_witnesses
            ):
                witness_name = (
                    "generatedSummaryCertificateStackWitness"
                    f"{witness_index:04d}"
                )
                witness_base_module = _dag_node_artifact_module_name(
                    module,
                    f"PreservationWitness{witness_index:04d}Base",
                )
                witness_base_source = f"""import {data_module}

namespace {namespace}

open StageA.Formal StageA.Relational
open StageA.Relational.InternalDirectCallRegisterSummary

set_option maxRecDepth 1000000
set_option maxHeartbeats 0

def {witness_name} : StackSaveRestoreWitness :=
  {witness.lean(
      'generatedSummaryCertificate.stack_witnesses'
      f'[{witness_index}]'
  )}

theorem {witness_name}Member :
    {witness_name} ∈ generatedSummaryCertificate.stackWitnesses := by
  decide

theorem {witness_name}NonRegionalChecked :
    {witness_name}.nonRegionalChecked generatedSummaryCertificate
      {bindings.original_pe} {bindings.candidate_pe}
      {bindings.original_imports} {bindings.candidate_imports} = true := by
  decide

#print axioms {witness_name}NonRegionalChecked

end {namespace}
"""
                generated_artifact_modules.append(
                    InternalDirectCallRegisterSummaryLeanModule(
                        module=witness_base_module,
                        namespace=namespace,
                        source=witness_base_source,
                        resource_class="large-memory",
                        estimated_memory_mb=12288,
                    )
                )

                witness_pack_modules: list[str] = []
                original_part_theorems: list[str] = []
                candidate_part_theorems: list[str] = []
                for part_index, part_name in enumerate(region_part_names):
                    witness_pack_module = _dag_node_artifact_module_name(
                        module,
                        "PreservationWitness"
                        f"{witness_index:04d}Pack{part_index:04d}",
                    )
                    original_theorem = (
                        f"{witness_name}OriginalPart{part_index:04d}Checked"
                    )
                    candidate_theorem = (
                        f"{witness_name}CandidatePart{part_index:04d}Checked"
                    )
                    witness_pack_source = f"""import {witness_base_module}

namespace {namespace}

open StageA.Formal StageA.Relational
open StageA.Relational.InternalDirectCallRegisterSummary

set_option maxRecDepth 1000000
set_option maxHeartbeats 0

theorem {original_theorem} :
    stackWitnessRegionPartSideChecked generatedSummaryCertificate false
      {bindings.original_pe} {bindings.original_imports}
      {witness_name} {part_name} = true := by
  decide

theorem {candidate_theorem} :
    stackWitnessRegionPartSideChecked generatedSummaryCertificate true
      {bindings.candidate_pe} {bindings.candidate_imports}
      {witness_name} {part_name} = true := by
  decide

#print axioms {candidate_theorem}

end {namespace}
"""
                    generated_artifact_modules.append(
                        InternalDirectCallRegisterSummaryLeanModule(
                            module=witness_pack_module,
                            namespace=namespace,
                            source=witness_pack_source,
                            resource_class="large-memory",
                            estimated_memory_mb=8192,
                        )
                    )
                    witness_pack_modules.append(witness_pack_module)
                    original_part_theorems.append(original_theorem)
                    candidate_part_theorems.append(candidate_theorem)

                witness_checked_module = _dag_node_artifact_module_name(
                    module,
                    f"PreservationWitness{witness_index:04d}Checked",
                )
                witness_checked_imports = "\n".join(
                    f"import {module_name}"
                    for module_name in (
                        witness_base_module,
                        *witness_pack_modules,
                    )
                )
                original_part_simp = ", ".join(original_part_theorems)
                candidate_part_simp = ", ".join(candidate_part_theorems)
                witness_checked_source = f"""{witness_checked_imports}

namespace {namespace}

open StageA.Formal StageA.Relational
open StageA.Relational.InternalDirectCallRegisterSummary

set_option maxRecDepth 1000000
set_option maxHeartbeats 0

theorem {witness_name}OriginalPartsChecked :
    generatedSummaryRegionParts.all (fun part =>
      stackWitnessRegionPartSideChecked generatedSummaryCertificate false
        {bindings.original_pe} {bindings.original_imports}
        {witness_name} part) = true := by
  simp [generatedSummaryRegionParts, {original_part_simp}]

theorem {witness_name}CandidatePartsChecked :
    generatedSummaryRegionParts.all (fun part =>
      stackWitnessRegionPartSideChecked generatedSummaryCertificate true
        {bindings.candidate_pe} {bindings.candidate_imports}
        {witness_name} part) = true := by
  simp [generatedSummaryRegionParts, {candidate_part_simp}]

theorem {witness_name}OriginalRegionsChecked :
    stackWitnessRegionsSideChecked generatedSummaryCertificate false
      {bindings.original_pe} {bindings.original_imports}
      {witness_name} = true := by
  exact stackWitnessRegionsSideChecked_of_parts
    generatedSummaryCertificate false
    {bindings.original_pe} {bindings.original_imports}
    {witness_name} generatedSummaryRegionParts (by rfl)
    {witness_name}OriginalPartsChecked

theorem {witness_name}CandidateRegionsChecked :
    stackWitnessRegionsSideChecked generatedSummaryCertificate true
      {bindings.candidate_pe} {bindings.candidate_imports}
      {witness_name} = true := by
  exact stackWitnessRegionsSideChecked_of_parts
    generatedSummaryCertificate true
    {bindings.candidate_pe} {bindings.candidate_imports}
    {witness_name} generatedSummaryRegionParts (by rfl)
    {witness_name}CandidatePartsChecked

theorem {witness_name}Checked :
    {witness_name}.checked generatedSummaryCertificate
      {bindings.original_pe} {bindings.candidate_pe}
      {bindings.original_imports} {bindings.candidate_imports} = true := by
  exact StackSaveRestoreWitness.checked_of_region_parts
    {witness_name} generatedSummaryCertificate
    {bindings.original_pe} {bindings.candidate_pe}
    {bindings.original_imports} {bindings.candidate_imports}
    {witness_name}NonRegionalChecked
    {witness_name}OriginalRegionsChecked
    {witness_name}CandidateRegionsChecked

#print axioms {witness_name}Checked

end {namespace}
"""
                generated_artifact_modules.append(
                    InternalDirectCallRegisterSummaryLeanModule(
                        module=witness_checked_module,
                        namespace=namespace,
                        source=witness_checked_source,
                        resource_class="light",
                        estimated_memory_mb=768,
                    )
                )
                preservation_witness_modules.append(witness_checked_module)

        preservation_stack_pointer_module: str | None = None
        if (
            split_control
            and "esp" in node.tree.certificate.requested_registers
        ):
            stack_pointer_base_module = _dag_node_artifact_module_name(
                module, "PreservationStackPointerBase"
            )
            stack_pointer_base_source = f"""import {data_module}

namespace {namespace}

open StageA.Formal StageA.Relational
open StageA.Relational.InternalDirectCallRegisterSummary

set_option maxRecDepth 1000000
set_option maxHeartbeats 0

theorem generatedSummaryStackPointerOriginalInventoryChecked :
    generatedSummaryCertificate.stackPointerInventorySideChecked false =
      true := by
  decide

theorem generatedSummaryStackPointerCandidateInventoryChecked :
    generatedSummaryCertificate.stackPointerInventorySideChecked true =
      true := by
  decide

#print axioms generatedSummaryStackPointerCandidateInventoryChecked

end {namespace}
"""
            generated_artifact_modules.append(
                InternalDirectCallRegisterSummaryLeanModule(
                    module=stack_pointer_base_module,
                    namespace=namespace,
                    source=stack_pointer_base_source,
                    resource_class="medium",
                    estimated_memory_mb=4096,
                )
            )

            stack_pointer_pack_modules: list[str] = []
            stack_pointer_original_parts: list[str] = []
            stack_pointer_candidate_parts: list[str] = []
            for part_index, part_name in enumerate(region_part_names):
                stack_pointer_pack_module = _dag_node_artifact_module_name(
                    module,
                    f"PreservationStackPointerPack{part_index:04d}",
                )
                original_theorem = (
                    "generatedSummaryStackPointerOriginalPart"
                    f"{part_index:04d}Checked"
                )
                candidate_theorem = (
                    "generatedSummaryStackPointerCandidatePart"
                    f"{part_index:04d}Checked"
                )
                stack_pointer_pack_source = f"""import {stack_pointer_base_module}

namespace {namespace}

open StageA.Formal StageA.Relational
open StageA.Relational.InternalDirectCallRegisterSummary

set_option maxRecDepth 1000000
set_option maxHeartbeats 0

theorem {original_theorem} :
    generatedSummaryCertificate.stackPointerRegionPartSideChecked
      {bindings.original_pe} {bindings.original_imports} false
      {part_name} = true := by
  decide

theorem {candidate_theorem} :
    generatedSummaryCertificate.stackPointerRegionPartSideChecked
      {bindings.candidate_pe} {bindings.candidate_imports} true
      {part_name} = true := by
  decide

#print axioms {candidate_theorem}

end {namespace}
"""
                generated_artifact_modules.append(
                    InternalDirectCallRegisterSummaryLeanModule(
                        module=stack_pointer_pack_module,
                        namespace=namespace,
                        source=stack_pointer_pack_source,
                        resource_class="large-memory",
                        estimated_memory_mb=8192,
                    )
                )
                stack_pointer_pack_modules.append(stack_pointer_pack_module)
                stack_pointer_original_parts.append(original_theorem)
                stack_pointer_candidate_parts.append(candidate_theorem)

            preservation_stack_pointer_module = (
                _dag_node_artifact_module_name(
                    module, "PreservationStackPointerChecked"
                )
            )
            stack_pointer_checked_imports = "\n".join(
                f"import {module_name}"
                for module_name in (
                    stack_pointer_base_module,
                    *stack_pointer_pack_modules,
                )
            )
            stack_pointer_original_simp = ", ".join(
                stack_pointer_original_parts
            )
            stack_pointer_candidate_simp = ", ".join(
                stack_pointer_candidate_parts
            )
            stack_pointer_checked_source = f"""{stack_pointer_checked_imports}

namespace {namespace}

open StageA.Formal StageA.Relational
open StageA.Relational.InternalDirectCallRegisterSummary

set_option maxRecDepth 1000000
set_option maxHeartbeats 0

theorem generatedSummaryStackPointerOriginalPartsChecked :
    generatedSummaryRegionParts.all (fun part =>
      generatedSummaryCertificate.stackPointerRegionPartSideChecked
        {bindings.original_pe} {bindings.original_imports} false part) =
      true := by
  simp [generatedSummaryRegionParts, {stack_pointer_original_simp}]

theorem generatedSummaryStackPointerCandidatePartsChecked :
    generatedSummaryRegionParts.all (fun part =>
      generatedSummaryCertificate.stackPointerRegionPartSideChecked
        {bindings.candidate_pe} {bindings.candidate_imports} true part) =
      true := by
  simp [generatedSummaryRegionParts, {stack_pointer_candidate_simp}]

theorem generatedSummaryStackPointerOriginalRegionsChecked :
    generatedSummaryCertificate.stackPointerRegionsSideChecked
      {bindings.original_pe} {bindings.original_imports} false = true := by
  exact Certificate.stackPointerRegionsSideChecked_of_parts
    generatedSummaryCertificate
    {bindings.original_pe} {bindings.original_imports} false
    generatedSummaryRegionParts (by rfl)
    generatedSummaryStackPointerOriginalPartsChecked

theorem generatedSummaryStackPointerCandidateRegionsChecked :
    generatedSummaryCertificate.stackPointerRegionsSideChecked
      {bindings.candidate_pe} {bindings.candidate_imports} true = true := by
  exact Certificate.stackPointerRegionsSideChecked_of_parts
    generatedSummaryCertificate
    {bindings.candidate_pe} {bindings.candidate_imports} true
    generatedSummaryRegionParts (by rfl)
    generatedSummaryStackPointerCandidatePartsChecked

theorem generatedSummaryCertificateStackPointerPreservedChecked :
    generatedSummaryCertificate.stackPointerPreservedChecked
      {bindings.original_pe} {bindings.candidate_pe}
      {bindings.original_imports} {bindings.candidate_imports} = true := by
  exact Certificate.stackPointerPreservedChecked_of_region_parts
    generatedSummaryCertificate
    {bindings.original_pe} {bindings.candidate_pe}
    {bindings.original_imports} {bindings.candidate_imports}
    generatedSummaryStackPointerOriginalInventoryChecked
    generatedSummaryStackPointerCandidateInventoryChecked
    generatedSummaryStackPointerOriginalRegionsChecked
    generatedSummaryStackPointerCandidateRegionsChecked

theorem generatedSummaryCertificateRegisterESPPreservedChecked :
    generatedSummaryCertificate.registerPreservedChecked
      {bindings.original_pe} {bindings.candidate_pe}
      {bindings.original_imports} {bindings.candidate_imports}
      .esp = true := by
  simpa [Certificate.registerPreservedChecked] using
    generatedSummaryCertificateStackPointerPreservedChecked

#print axioms generatedSummaryCertificateRegisterESPPreservedChecked

end {namespace}
"""
            generated_artifact_modules.append(
                InternalDirectCallRegisterSummaryLeanModule(
                    module=preservation_stack_pointer_module,
                    namespace=namespace,
                    source=stack_pointer_checked_source,
                    resource_class="light",
                    estimated_memory_mb=768,
                )
            )

        preservation_imports = "\n".join(
            f"import {module_name}"
            for module_name in (
                data_module,
                *preservation_witness_modules,
                *(
                    (preservation_stack_pointer_module,)
                    if preservation_stack_pointer_module is not None
                    else ()
                ),
            )
        )
        preservation_source = f"""{preservation_imports}

namespace {namespace}

open StageA.Formal StageA.Relational
open StageA.Relational.InternalDirectCallRegisterSummary

set_option maxRecDepth 1000000
set_option maxHeartbeats 0
{stack_witness_declarations}
{register_preservation}
{preservation_declarations}

#print axioms generatedSummaryCertificatePreservationChecked

end {namespace}
"""
        preservation_complexity = max(
            region_count,
            sum(
                len(witness.protected_write_region_ids)
                for witness in node.tree.certificate.stack_witnesses
            ),
        )
        if preservation_complexity >= 128:
            preservation_resource = ("high-memory", 32768)
        elif preservation_complexity >= 32:
            preservation_resource = ("large-memory", 12288)
        else:
            preservation_resource = ("medium", 4096)
        generated_artifact_modules.append(
            InternalDirectCallRegisterSummaryLeanModule(
                module=preservation_module,
                namespace=namespace,
                source=preservation_source,
                resource_class=preservation_resource[0],
                estimated_memory_mb=preservation_resource[1],
            )
        )

        final_imports = "\n".join(
            f"import {module_name}"
            for module_name in (
                data_module,
                *family_modules.values(),
                preservation_module,
                *(
                    tuple(dict.fromkeys(child_modules))
                    if not split_children else ()
                ),
                *((child_aggregate_module,)
                  if child_aggregate_module is not None else ()),
            )
        )

        source = f"""{final_imports}

namespace {namespace}

open StageA.Formal StageA.Relational
open StageA.Relational.InternalDirectCallRegisterSummary

set_option maxRecDepth 1000000
set_option maxHeartbeats 0

theorem generatedSummaryCertificateCompactStructureChecked :
    generatedSummaryCertificate.structureCheckedWithChildCertificates
      {bindings.original_pe} {bindings.candidate_pe}
      {bindings.original_imports} {bindings.candidate_imports}
      generatedSummaryChildCertificates = true := by
  exact Certificate.structureCheckedWithChildCertificates_of_families
    generatedSummaryCertificate
    {bindings.original_pe} {bindings.candidate_pe}
    {bindings.original_imports} {bindings.candidate_imports}
    generatedSummaryChildCertificates
    generatedSummaryCertificateStructureShapeChecked
    generatedSummaryCertificateStructureDecodeChecked
    generatedSummaryCertificateStructureControlChecked
    generatedSummaryCertificateStructureDependenciesChecked
    generatedSummaryCertificateStructureStackChecked

{child_theorem_source}
theorem generatedSummaryCertificateStructureChecked :
    generatedSummaryCertificate.structureChecked
      {bindings.original_pe} {bindings.candidate_pe}
      {bindings.original_imports} {bindings.candidate_imports}
      generatedSummaryChildren = true := by
  unfold Certificate.structureChecked
  rw [generatedSummaryChildrenCertificates]
  exact generatedSummaryCertificateCompactStructureChecked

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
                resource_class=(
                    "medium" if len(child_modules) >= 4 else "light"
                ),
                estimated_memory_mb=(
                    4096 if len(child_modules) >= 4 else 768
                ),
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
            *((
                "StageA.RelationalInternalDirectCallAuthorityBinding",
            ) if finite_origin_calls else ()),
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
        dependency_name = (
            "generatedFiniteOriginCallDependency"
            f"{index:04d}"
        )
        authority_name = (
            "generatedFiniteOriginCallAuthority"
            f"{index:04d}"
        )
        component_prefix = (
            "generatedFiniteOriginCallAuthorityComponent"
            f"{index:04d}"
        )
        finite_origin_call_sources.append(
            f"def {dependency_name} : FiniteOriginCallDependency :=\n"
            f"  {dependency.lean()}\n\n"
            f"def {authority_name} :=\n"
            f"  {dependency.indirect_exit_authority_term}\n\n"
            f"theorem {component_prefix}Dependencies :\n"
            f"    {owner_namespace}.generatedSummaryCertificate."
            "finiteOriginCallDependencies.filter\n"
            f"      (fun candidate => candidate.id == "
            f"{dependency.dependency_id}) = [{dependency_name}] := by\n"
            "  decide\n\n"
            f"theorem {component_prefix}Shape :\n"
            f"    {dependency_name}.authorityShapeChecked "
            f"{authority_name}.certificate = true := by\n"
            "  decide\n\n"
            f"theorem {component_prefix}Targets :\n"
            f"    {dependency_name}.authorityTargetCertificatesCheckedFor\n"
            f"      {authority_name}\n"
            f"      ({owner_namespace}.generatedSummaryChildren.map "
            "SummaryTree.certificate) = true := by\n"
            f"  rw [{owner_namespace}.generatedSummaryChildrenCertificates]\n"
            "  set_option maxRecDepth 100000 in\n"
            "  decide\n\n"
            f"theorem {component_prefix}OriginalSide :\n"
            f"    {dependency_name}.authoritySideChecked "
            f"{authority_name}.certificate\n"
            f"      {bindings.original_pe} {bindings.original_imports} false\n"
            f"      {owner_namespace}.generatedSummaryCertificate."
            "calleeRegions = true := by\n"
            "  set_option maxRecDepth 100000 in\n"
            "  decide\n\n"
            f"theorem {component_prefix}CandidateSide :\n"
            f"    {dependency_name}.authoritySideChecked "
            f"{authority_name}.certificate\n"
            f"      {bindings.candidate_pe} {bindings.candidate_imports} true\n"
            f"      {owner_namespace}.generatedSummaryCertificate."
            "calleeRegions = true := by\n"
            "  set_option maxRecDepth 100000 in\n"
            "  decide\n\n"
            "theorem generatedFiniteOriginCallAuthorityBound"
            f"{index:04d} :\n"
            f"    {owner_namespace}.generatedSummaryCertificate."
            "finiteOriginCallAuthorityBound\n"
            f"      {owner_namespace}.generatedSummaryChildren\n"
            f"      {dependency.dependency_id}\n"
            f"      {authority_name}\n"
            f"      {bindings.original_pe} {bindings.candidate_pe}\n"
            f"      {bindings.original_imports} "
            f"{bindings.candidate_imports} = true := by\n"
            "  exact Certificate.finiteOriginCallAuthorityBound_of_components\n"
            f"    {owner_namespace}.generatedSummaryCertificate\n"
            f"    {owner_namespace}.generatedSummaryChildren\n"
            f"    {dependency.dependency_id} {authority_name}\n"
            f"    {bindings.original_pe} {bindings.candidate_pe}\n"
            f"    {bindings.original_imports} {bindings.candidate_imports}\n"
            f"    {dependency_name}\n"
            f"    {component_prefix}Dependencies\n"
            "    (by rfl) (by rfl) (by rfl) (by rfl)\n"
            f"    {component_prefix}Shape\n"
            f"    {component_prefix}Targets\n"
            f"    {component_prefix}OriginalSide\n"
            f"    {component_prefix}CandidateSide\n\n"
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
    root_stack_witness_sources: list[str] = []
    for index, _witness in enumerate(summary.certificate.stack_witnesses):
        alias = (
            "generatedInternalDirectCallRegisterSummaryStackWitness"
            f"{index:04d}"
        )
        source = (
            f"{root_node_namespace}.generatedSummaryCertificateStackWitness"
            f"{index:04d}"
        )
        root_stack_witness_sources.append(
            f"def {alias} : StackSaveRestoreWitness :=\n"
            f"  {source}\n\n"
            f"theorem {alias}Member :\n"
            f"    {alias} ∈ generatedInternalDirectCallRegisterSummary."
            "certificate.stackWitnesses := by\n"
            "  rw [generatedInternalDirectCallRegisterSummary,\n"
            f"    {root_node_namespace}.generatedSummaryNodeCertificate]\n"
            f"  exact {source}Member\n\n"
            f"theorem {alias}Checked :\n"
            f"    {alias}.checked\n"
            "      generatedInternalDirectCallRegisterSummary.certificate\n"
            f"      {bindings.original_pe} {bindings.candidate_pe}\n"
            f"      {bindings.original_imports} {bindings.candidate_imports} = "
            "true := by\n"
            "  rw [generatedInternalDirectCallRegisterSummary,\n"
            f"    {root_node_namespace}.generatedSummaryNodeCertificate]\n"
            f"  exact {source}Checked"
        )
    root_stack_witness_source = "\n\n".join(root_stack_witness_sources)
    if root_stack_witness_source:
        root_stack_witness_source = f"\n\n{root_stack_witness_source}\n"
    root_source = f"""{root_imports}

namespace {root_namespace}

open StageA.Formal StageA.Relational
open StageA.Relational.InternalDirectCallRegisterSummary

def generatedInternalDirectCallRegisterSummary : SummaryTree :=
  {root_node_namespace}.generatedSummaryNode

theorem generatedInternalDirectCallRegisterSummaryCertificateExact :
    generatedInternalDirectCallRegisterSummary.certificate =
      {root_node_namespace}.generatedSummaryCertificate := by
  simpa [generatedInternalDirectCallRegisterSummary] using
    {root_node_namespace}.generatedSummaryNodeCertificate

theorem generatedInternalDirectCallRegisterSummaryChecked :
    generatedInternalDirectCallRegisterSummary.checked
      {bindings.original_pe} {bindings.candidate_pe}
      {bindings.original_imports} {bindings.candidate_imports} = true := by
  simpa [generatedInternalDirectCallRegisterSummary] using
    {root_node_namespace}.generatedSummaryNodeChecked
{root_stack_witness_source}

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
        artifact_modules=tuple(generated_artifact_modules),
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
        *(
            ["import StageA.RelationalInternalDirectCallAuthorityBinding"]
            if finite_origin_calls
            else []
        ),
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
    def finite_origin_call_authority_source(
        index: int,
        dependency: LeanFiniteOriginCallDependency,
    ) -> str:
        owner = finite_origin_call_owners[dependency.dependency_id]
        certificate = _summary_certificate_name(owner.digest)
        children = _summary_children_name(owner.digest)
        dependency_name = f"generatedFiniteOriginCallDependency{index:04d}"
        authority_name = f"generatedFiniteOriginCallAuthority{index:04d}"
        component_prefix = (
            f"generatedFiniteOriginCallAuthorityComponent{index:04d}"
        )
        return (
            f"def {dependency_name} : FiniteOriginCallDependency :=\n"
            f"  {dependency.lean()}\n\n"
            f"def {authority_name} :=\n"
            f"  {dependency.indirect_exit_authority_term}\n\n"
            f"theorem {component_prefix}Dependencies :\n"
            f"    {certificate}.finiteOriginCallDependencies.filter\n"
            f"      (fun candidate => candidate.id == "
            f"{dependency.dependency_id}) = [{dependency_name}] := by\n"
            "  decide\n\n"
            f"theorem {component_prefix}Shape :\n"
            f"    {dependency_name}.authorityShapeChecked "
            f"{authority_name}.certificate = true := by\n"
            "  decide\n\n"
            f"theorem {component_prefix}Targets :\n"
            f"    {dependency_name}.authorityTargetCertificatesCheckedFor\n"
            f"      {authority_name}\n"
            f"      ({children}.map SummaryTree.certificate) = true := by\n"
            "  set_option maxRecDepth 100000 in\n"
            "  decide\n\n"
            f"theorem {component_prefix}OriginalSide :\n"
            f"    {dependency_name}.authoritySideChecked "
            f"{authority_name}.certificate\n"
            f"      {bindings.original_pe} {bindings.original_imports} false\n"
            f"      {certificate}.calleeRegions = true := by\n"
            "  set_option maxRecDepth 100000 in\n"
            "  decide\n\n"
            f"theorem {component_prefix}CandidateSide :\n"
            f"    {dependency_name}.authoritySideChecked "
            f"{authority_name}.certificate\n"
            f"      {bindings.candidate_pe} {bindings.candidate_imports} true\n"
            f"      {certificate}.calleeRegions = true := by\n"
            "  set_option maxRecDepth 100000 in\n"
            "  decide\n\n"
            "theorem generatedFiniteOriginCallAuthorityBound"
            f"{index:04d} :\n"
            f"    {certificate}.finiteOriginCallAuthorityBound\n"
            f"      {children}\n"
            f"      {dependency.dependency_id} {authority_name}\n"
            f"      {bindings.original_pe} {bindings.candidate_pe}\n"
            f"      {bindings.original_imports} "
            f"{bindings.candidate_imports} = true := by\n"
            "  exact Certificate.finiteOriginCallAuthorityBound_of_components\n"
            f"    {certificate} {children}\n"
            f"    {dependency.dependency_id} {authority_name}\n"
            f"    {bindings.original_pe} {bindings.candidate_pe}\n"
            f"    {bindings.original_imports} {bindings.candidate_imports}\n"
            f"    {dependency_name} {component_prefix}Dependencies\n"
            "    (by rfl) (by rfl) (by rfl) (by rfl)\n"
            f"    {component_prefix}Shape {component_prefix}Targets\n"
            f"    {component_prefix}OriginalSide "
            f"{component_prefix}CandidateSide\n\n"
            f"#print axioms {authority_name}\n"
            "#print axioms generatedFiniteOriginCallAuthorityBound"
            f"{index:04d}"
        )

    finite_origin_call_authorities = "\n\n".join(
        finite_origin_call_authority_source(index, dependency)
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
