"""Renderer-neutral executable transfer model and shared constants."""

from __future__ import annotations

from dataclasses import dataclass

from ..errors import ToolkitInputError
from .x87 import (
    TYPED_NATIVE_X87_PROGRAM_FORMAT,
    TypedX87Operation,
)


TRANSFER_DEFINEDNESS_USE_FIELDS = frozenset({
    "format",
    "status",
    "proof_authority",
    "state_machine_sha256",
    "definedness_evidence_sha256",
    "transfer_inventory_sha256",
    "evidence_slot_count",
    "unused_evidence_slot_count",
    "undefined_node_count",
    "slots",
    "metadata_sha256",
})

_REGISTERS = ("eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp")
_FLAGS = ("cf", "zf", "sf", "of", "pf", "df")
_REGISTER_INDEX = {name: index for index, name in enumerate(_REGISTERS)}
_FLAG_INDEX = {name: index for index, name in enumerate(_FLAGS)}
_AF_FLAG_INDEX = len(_FLAGS)
_REP_SCAS_OWNED_REGISTERS = ("edi", "ecx")
_REP_SCAS_OWNED_FLAGS = ("cf", "pf", "af", "zf", "sf", "of")
_X87_TYPED_PROGRAM_FORMAT = TYPED_NATIVE_X87_PROGRAM_FORMAT
_ORDINARY_CHECKED_DECODER = "SpaghettiExtractor.ISA.Formal.decodeInstructionExact"
_ORDINARY_CHECKED_EXECUTOR = "SpaghettiExtractor.ISA.Formal.executeInstruction"


class TransferPlanError(ToolkitInputError):
    """The semantic program cannot be lowered into the checked transfer model."""

    def __init__(
        self,
        message: str,
        *,
        code: str = "unsupported_transfer",
        next_action: str = (
            "repair the static analysis transfer or add generic checked transfer lowering"
        ),
    ) -> None:
        super().__init__(message)
        self.code = code
        self.next_action = next_action


@dataclass(frozen=True)
class _Node:
    op: str
    args: tuple[int, ...] = ()
    aux: int = 0
    immediate: int = 0
    identity: str | None = None


@dataclass(frozen=True)
class _Action:
    op: str
    args: tuple[int, ...] = ()
    aux: int = 0


@dataclass(frozen=True)
class _Call:
    kind: str
    instruction_rva: int
    call_index: int
    target_node: int | None
    target_rva: int
    return_rva: int
    dll: str | None
    symbol: str | None
    ordinal: int | None
    register_nodes: tuple[int, ...]
    flag_nodes: tuple[int, ...]
    argument_nodes: tuple[int, ...]
    stack_inputs: tuple[tuple[int, int, int], ...]
    native_exception_operations: tuple[str, ...] = ()


@dataclass(frozen=True)
class _ExceptionOccurrence:
    fault_index: int
    fault_sha256: str
    occurrence_kind: str
    effect_index: int
    operation: str
    call_id: int | None = None
    call_event_index: int | None = None


@dataclass(frozen=True)
class _TypedX87Program:
    contract_sha256: str
    image_base: int
    rva_start: int
    rva_end: int
    operation: TypedX87Operation
    checked_decoder: str
    checked_executor: str


@dataclass(frozen=True)
class _Transfer:
    identity: str
    contract_sha256: str
    instruction_bytes_sha256: str
    rva_start: int
    nodes: tuple[_Node, ...]
    x87_nodes: tuple[_Node, ...]
    actions: tuple[_Action, ...]
    calls: tuple[_Call, ...]
    x87_operations: tuple[_TypedX87Program, ...]
    exception_occurrences: tuple[_ExceptionOccurrence, ...] = ()
