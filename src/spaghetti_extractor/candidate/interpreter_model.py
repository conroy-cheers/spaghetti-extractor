"""Data model and shared constants for the Stage B interpreter."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from ..artifacts.formats import (
    INSTRUCTION_ORDERED_EFFECT_SCHEDULE_FORMAT,
    MACHINE_IR_FORMAT as _MACHINE_IR_FORMAT,
    NATIVE_X87_REPLAY_FORMAT as _X87_REPLAY_FORMAT,
    NATIVE_X87_REPLAY_PROGRAM_FORMAT as _X87_REPLAY_PROGRAM_FORMAT,
    STAGE_B_INTERPRETER_PACKAGE_FORMAT,
    STAGE_B_INTERPRETER_PROGRAM_FORMAT,
)
from ..pe32.stage_binary import StageAInputError
from .x87 import (
    TYPED_NATIVE_X87_PROGRAM_FORMAT,
    TypedX87Operation,
    X87_CHECKED_DECODER,
    X87_CHECKED_EXECUTOR,
)


STAGE_B_INTERPRETER_DEFINEDNESS_USE_FORMAT = (
    "stage-b-interpreter-definedness-use-v2"
)
STAGE_B_INTERPRETER_DEFINEDNESS_USE_FIELDS = frozenset({
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
_X87_REPLAY_MODEL = "native_exact_x87_command_replay_obligation_v1"
_X87_TYPED_PROGRAM_FORMAT = TYPED_NATIVE_X87_PROGRAM_FORMAT
_X87_CHECKED_DECODER = X87_CHECKED_DECODER
_X87_CHECKED_EXECUTOR = X87_CHECKED_EXECUTOR
_INSTRUCTION_EFFECT_SCHEDULE_FORMAT = (
    INSTRUCTION_ORDERED_EFFECT_SCHEDULE_FORMAT
)
_ORDINARY_CHECKED_DECODER = "StageA.Formal.decodeInstructionExact"
_ORDINARY_CHECKED_EXECUTOR = "StageA.Formal.executeInstruction"
_X87_PHYSICAL_FIELDS = (
    "stack", "tags", "control", "status", "pending_exception", "last_opcode",
    "instruction_pointer", "code_selector", "data_pointer", "data_selector",
)
_RAW_INSTRUCTION_FIELDS = frozenset({
    "bytes",
    "instruction_bytes",
    "opcode_bytes",
    "raw_bytes",
    "encoded_instruction",
})


class StageBInterpreterError(StageAInputError):
    """The semantic program cannot be lowered into the qualified interpreter."""

    def __init__(
        self,
        message: str,
        *,
        code: str = "unsupported_transfer",
        next_action: str = (
            "repair the Stage A transfer or add generic checked interpreter lowering"
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
