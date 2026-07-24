from __future__ import annotations

from collections.abc import Iterable
from pathlib import Path
from typing import Any

from ...stage_b_interpreter_backend import (
    _ACTIONS,
    _WORD_OPS,
    compile_stage_b_interpreter_program,
)
from ...stage_binary import StageAInputError


class RelationalInterpreterGenerationError(StageAInputError):
    """A Stage B program is outside the checked Lean interpreter subset."""


_SUPPORTED_WORD_OPS = (
    "const",
    "reg",
    "flag",
    "true",
    "false",
    "undefined_bv",
    "undefined_flag",
    "call_response",
    "call_flag",
    "load",
    "sub32",
    "ult32",
    "eq",
    "xor_bool",
    "eq_bool",
    "add32",
    "mul32",
    "xor32",
    "and32",
    "or32",
    "not32",
    "neg32",
    "shl32",
    "lshr32",
    "sar",
    "sign_extend",
    "ite",
    "msb",
    "not",
    "and_bool",
    "or_bool",
    "parity",
    "bool_to_bit",
    "add_overflow",
    "sub_overflow",
    "imul_low32",
    "mul_low32",
    "imul_high32",
    "mul_high32",
    "imul_overflow",
    "mul_carry",
    "udiv_quot32",
    "udiv_rem32",
    "udiv_valid32",
    "bsr_index",
    "tzcnt",
    "sbb_borrow",
    "sbb_overflow",
    "shift_cf",
    "shift_of",
)

_LEAN_WORD_OPS = (
    "constant",
    "register",
    "flag",
    "trueValue",
    "falseValue",
    "undefinedBv",
    "undefinedFlag",
    "callResponse",
    "callFlag",
    "load",
    "sub32",
    "ult32",
    "equal",
    "xorBool",
    "equalBool",
    "add32",
    "mul32",
    "xor32",
    "and32",
    "or32",
    "not32",
    "neg32",
    "shl32",
    "lshr32",
    "sar",
    "signExtend",
    "ite",
    "msb",
    "boolNot",
    "andBool",
    "orBool",
    "parity",
    "boolToBit",
    "addOverflow",
    "subOverflow",
    "imulLow32",
    "mulLow32",
    "imulHigh32",
    "mulHigh32",
    "imulOverflow",
    "mulCarry",
    "udivQuot32",
    "udivRem32",
    "udivValid32",
    "bsrIndex",
    "tzcnt",
    "sbbBorrow",
    "sbbOverflow",
    "shiftCf",
    "shiftOf",
)

_SUPPORTED_BODY_ACTIONS = frozenset(
    {
        "eval_word",
        "memory_write",
        "divide_if",
        "call",
        "rep_movsd",
        "set_reg",
        "set_flag",
        "sync_eflags",
    }
)
_OUTCOME_ACTIONS = frozenset(
    {
        "outcome_fallthrough",
        "outcome_jump",
        "outcome_branch",
        "outcome_return",
        "outcome_indirect",
        "outcome_external",
    }
)

_LEAN_REGISTERS = ("eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp")
_LEAN_FLAGS = ("cf", "zf", "sf", "ofl", "pf", "df")
_LEAN_WIDTHS = {1: "byte", 2: "word", 4: "dword"}
_LEAN_CALL_KINDS = {
    "external_call": "external",
    "internal_call": "internal",
    "indirect_call": "indirect",
}


def _is_u32(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and 0 <= value < 2**32


def _word_arity_valid(operation: str, arity: int) -> bool:
    zero = {
        "const", "reg", "flag", "true", "false", "call_response", "call_flag",
    }
    one = {"load", "not32", "neg32", "not", "bool_to_bit"}
    two = {
        "sub32", "ult32", "eq", "xor_bool", "eq_bool", "shl32",
        "lshr32", "sign_extend", "parity", "imul_low32", "mul_low32",
        "imul_high32", "mul_high32", "bsr_index", "tzcnt", "shift_cf",
    }
    three = {"sar", "ite", "udiv_quot32", "udiv_rem32", "udiv_valid32", "shift_of"}
    four = {"add_overflow", "sub_overflow", "mul_carry"}
    five = {"imul_overflow", "sbb_borrow", "sbb_overflow"}
    if operation in zero:
        return arity == 0
    if operation in {"undefined_bv", "undefined_flag"}:
        return arity <= 1
    if operation in one:
        return arity == 1
    if operation in two:
        return arity == 2
    if operation in three:
        return arity == 3
    if operation in four:
        return arity == 4
    if operation in five:
        return arity == 5
    if operation in {"add32", "mul32", "xor32", "and32", "or32"}:
        return 2 <= arity <= 4
    if operation == "msb":
        return 1 <= arity <= 2
    if operation in {"and_bool", "or_bool"}:
        return 1 <= arity <= 5
    return False


def _node_fields_valid(node: Any) -> bool:
    if not _is_u32(node.immediate):
        return False
    if node.op in {"reg", "call_response"}:
        return 0 <= node.aux < 8
    if node.op in {"flag", "call_flag"}:
        return 0 <= node.aux < 6
    if node.op == "load":
        return node.aux in _LEAN_WIDTHS
    if node.op in {"shift_cf", "shift_of"}:
        return node.aux // 256 < 3 and node.aux % 256 in {8, 16, 32}
    if node.op in {"const", "undefined_bv", "undefined_flag"}:
        return node.aux == 0
    return node.aux == 0 and node.immediate == 0


def _validate_action_shape(action: Any, context: str, index: int) -> None:
    expected = {
        "eval_word": 1,
        "memory_write": 2,
        "divide_if": 1,
        "call": 1,
        "rep_movsd": 4,
        "set_reg": 1,
        "set_flag": 1,
        "sync_eflags": 0,
        "outcome_fallthrough": 1,
        "outcome_jump": 1,
        "outcome_branch": 3,
        "outcome_return": 1,
        "outcome_indirect": 1,
        "outcome_external": 0,
    }
    if action.op not in expected or len(action.args) != expected[action.op]:
        raise RelationalInterpreterGenerationError(
            f"{context}: action {index} has an invalid arity"
        )
    if not _is_u32(action.aux) or not all(_is_u32(value) for value in action.args):
        raise RelationalInterpreterGenerationError(
            f"{context}: action {index} has a non-uint32 field"
        )
    aux_valid = (
        action.aux in _LEAN_WIDTHS
        if action.op == "memory_write"
        else 0 <= action.aux < 8
        if action.op == "set_reg"
        else 0 <= action.aux < 6
        if action.op == "set_flag"
        else action.aux == 0
    )
    if not aux_valid:
        raise RelationalInterpreterGenerationError(
            f"{context}: action {index} has an invalid auxiliary field"
        )


def _check_backend_opcode_tables() -> None:
    if tuple(_WORD_OPS[: len(_SUPPORTED_WORD_OPS)]) != _SUPPORTED_WORD_OPS:
        raise RelationalInterpreterGenerationError(
            "Stage B word-opcode numbering drifted from the Lean interpreter"
        )
    required_actions = {
        0: "eval_word",
        2: "memory_write",
        3: "divide_if",
        4: "call",
        5: "rep_movsd",
        6: "set_reg",
        7: "set_flag",
        18: "sync_eflags",
        19: "outcome_fallthrough",
        20: "outcome_jump",
        21: "outcome_branch",
        22: "outcome_return",
        23: "outcome_indirect",
        24: "outcome_external",
    }
    if any(
        index >= len(_ACTIONS) or _ACTIONS[index] != name
        for index, name in required_actions.items()
    ):
        raise RelationalInterpreterGenerationError(
            "Stage B action-opcode numbering drifted from the Lean interpreter"
        )


def _refs_ready(references: Iterable[int], ready: set[int]) -> bool:
    return all(reference in ready for reference in references)


def _call_references(call: Any) -> tuple[int, ...]:
    target = () if call.target_node is None else (call.target_node,)
    stack = tuple(item[2] for item in call.stack_inputs)
    return (
        target
        + tuple(call.register_nodes)
        + tuple(call.flag_nodes)
        + tuple(call.argument_nodes)
        + stack
    )


def _validate_transfer(transfer: Any) -> None:
    context = str(transfer.identity)
    if not context or not _is_u32(transfer.rva_start):
        raise RelationalInterpreterGenerationError(
            f"{context or '<unnamed>'}: transfer identity or source RVA is invalid"
        )
    for field, digest in (
        ("contract SHA-256", transfer.contract_sha256),
        ("instruction-bytes SHA-256", transfer.instruction_bytes_sha256),
    ):
        if not isinstance(digest, str) or len(digest) != 64 or any(
            character not in "0123456789abcdef" for character in digest
        ):
            raise RelationalInterpreterGenerationError(
                f"{context}: {field} is not a lowercase digest"
            )
    if transfer.x87_nodes:
        raise RelationalInterpreterGenerationError(
            f"{context}: x87 value operations are not supported by the Lean interpreter"
        )
    if len(transfer.nodes) > 1024:
        raise RelationalInterpreterGenerationError(
            f"{context}: word-node count exceeds the checked interpreter limit"
        )
    for index, node in enumerate(transfer.nodes):
        if node.op not in _SUPPORTED_WORD_OPS:
            raise RelationalInterpreterGenerationError(
                f"{context}: unsupported Lean word operation {node.op!r}"
            )
        if not _word_arity_valid(node.op, len(node.args)) or not _node_fields_valid(node):
            raise RelationalInterpreterGenerationError(
                f"{context}: word node {index} has an invalid opcode shape"
            )
        if not all(_is_u32(reference) for reference in node.args):
            raise RelationalInterpreterGenerationError(
                f"{context}: word node {index} has a non-uint32 reference"
            )
        if any(reference >= index for reference in node.args):
            raise RelationalInterpreterGenerationError(
                f"{context}: word node {index} has a non-backward reference"
            )

    call_event_indexes = [call.call_index for call in transfer.calls]
    if len(set(call_event_indexes)) != len(call_event_indexes):
        raise RelationalInterpreterGenerationError(
            f"{context}: call event indexes are ambiguous"
        )
    for index, call in enumerate(transfer.calls):
        if call.kind not in _LEAN_CALL_KINDS:
            raise RelationalInterpreterGenerationError(
                f"{context}: call {index} has unsupported kind {call.kind!r}"
            )
        if (call.kind == "indirect_call") != (call.target_node is not None):
            raise RelationalInterpreterGenerationError(
                f"{context}: call {index} has an invalid target-node shape"
            )
        numeric_fields = (
            call.instruction_rva,
            call.call_index,
            call.target_rva,
            call.return_rva,
        )
        if not all(_is_u32(value) for value in numeric_fields) or (
            call.ordinal is not None and not _is_u32(call.ordinal)
        ):
            raise RelationalInterpreterGenerationError(
                f"{context}: call {index} has a non-uint32 field"
            )
        if len(call.register_nodes) != 8 or len(call.flag_nodes) != 6:
            raise RelationalInterpreterGenerationError(
                f"{context}: call {index} lacks a complete register/flag input frame"
            )
        if len(call.argument_nodes) > 64 or len(call.stack_inputs) > 64:
            raise RelationalInterpreterGenerationError(
                f"{context}: call {index} exceeds the checked argument limit"
            )
        if any(width not in _LEAN_WIDTHS for _, width, _ in call.stack_inputs):
            raise RelationalInterpreterGenerationError(
                f"{context}: call {index} has an unsupported stack-input width"
            )
        if any(not _is_u32(offset) for offset, _, _ in call.stack_inputs):
            raise RelationalInterpreterGenerationError(
                f"{context}: call {index} has a non-uint32 stack offset"
            )
        if any(reference >= len(transfer.nodes) for reference in _call_references(call)):
            raise RelationalInterpreterGenerationError(
                f"{context}: call {index} references a missing word node"
            )

    if not transfer.actions or transfer.actions[-1].op not in _OUTCOME_ACTIONS:
        raise RelationalInterpreterGenerationError(
            f"{context}: program must end in one supported control outcome"
        )
    if any(action.op not in _SUPPORTED_BODY_ACTIONS for action in transfer.actions[:-1]):
        operation = next(
            action.op
            for action in transfer.actions[:-1]
            if action.op not in _SUPPORTED_BODY_ACTIONS
        )
        raise RelationalInterpreterGenerationError(
            f"{context}: unsupported Lean action {operation!r}"
        )
    for index, action in enumerate(transfer.actions):
        _validate_action_shape(action, context, index)

    ready: set[int] = set()
    used_calls: set[int] = set()
    last_call_event: int | None = None
    for action_index, action in enumerate(transfer.actions[:-1]):
        op = action.op
        args = tuple(action.args)
        if op == "eval_word":
            node_index = args[0]
            if node_index in ready or not 0 <= node_index < len(transfer.nodes):
                raise RelationalInterpreterGenerationError(
                    f"{context}: action {action_index} evaluates an invalid word node"
                )
            node = transfer.nodes[node_index]
            if not _refs_ready(node.args, ready):
                raise RelationalInterpreterGenerationError(
                    f"{context}: action {action_index} reads an unevaluated word node"
                )
            if node.op in {"call_response", "call_flag"} and (
                last_call_event != node.immediate
            ):
                raise RelationalInterpreterGenerationError(
                    f"{context}: action {action_index} reads stale call output"
                )
            ready.add(node_index)
        elif op == "call":
            call_index = args[0]
            if call_index in used_calls or not 0 <= call_index < len(transfer.calls):
                raise RelationalInterpreterGenerationError(
                    f"{context}: action {action_index} references an invalid call record"
                )
            call = transfer.calls[call_index]
            if not _refs_ready(_call_references(call), ready):
                raise RelationalInterpreterGenerationError(
                    f"{context}: action {action_index} uses an unevaluated call input"
                )
            used_calls.add(call_index)
            last_call_event = call.call_index
        else:
            value_references = {
                "memory_write": args,
                "divide_if": args,
                "rep_movsd": args,
                "set_reg": args,
                "set_flag": args,
                "sync_eflags": (),
            }[op]
            if not _refs_ready(value_references, ready):
                raise RelationalInterpreterGenerationError(
                    f"{context}: action {action_index} uses an unevaluated word node"
                )

    if used_calls != set(range(len(transfer.calls))):
        raise RelationalInterpreterGenerationError(
            f"{context}: not every call record is consumed exactly once"
        )
    if ready != set(range(len(transfer.nodes))):
        raise RelationalInterpreterGenerationError(
            f"{context}: not every word node is evaluated exactly once"
        )
    outcome = transfer.actions[-1]
    if outcome.op in {"outcome_branch", "outcome_return", "outcome_indirect"}:
        outcome_refs = (outcome.args[0],)
    else:
        outcome_refs = ()
    if not _refs_ready(outcome_refs, ready):
        raise RelationalInterpreterGenerationError(
            f"{context}: outcome uses an unevaluated word node"
        )


def _lean_string(value: str) -> str:
    pieces = ['"']
    escapes = {'"': '\\"', "\\": "\\\\", "\n": "\\n", "\r": "\\r", "\t": "\\t"}
    for character in value:
        if character in escapes:
            pieces.append(escapes[character])
        elif " " <= character <= "~":
            pieces.append(character)
        else:
            pieces.append(f"\\u{{{ord(character):x}}}")
    pieces.append('"')
    return "".join(pieces)


def _lean_option(value: object, render: Any) -> str:
    return "none" if value is None else f"(some {render(value)})"


def _lean_list(values: Iterable[object], render: Any = str) -> str:
    return "[" + ", ".join(render(value) for value in values) + "]"


def _raw_word_node(node: Any, *, inventory: tuple[str, ...]) -> str:
    return (
        "{ op := "
        + str(inventory.index(node.op))
        + ", arity := "
        + str(len(node.args))
        + ", aux := "
        + str(node.aux)
        + ", immediate := "
        + str(node.immediate)
        + ", args := "
        + _lean_list(node.args)
        + " }"
    )


def _semantic_word_node(node: Any) -> str:
    operation = _LEAN_WORD_OPS[_SUPPORTED_WORD_OPS.index(node.op)]
    return (
        "{ op := ."
        + operation
        + ", aux := "
        + str(node.aux)
        + ", immediate := "
        + str(node.immediate)
        + ", args := "
        + _lean_list(node.args)
        + " }"
    )


def _raw_stack_input(item: tuple[int, int, int]) -> str:
    offset, width, value = item
    return (
        f"{{ offset := {offset}, width := {width}, valueNode := {value} }}"
    )


def _semantic_stack_input(item: tuple[int, int, int]) -> str:
    offset, width, value = item
    return (
        f"{{ offset := {offset}, width := .{_LEAN_WIDTHS[width]}, "
        f"valueNode := {value} }}"
    )


def _call_fields(call: Any, *, semantic: bool) -> list[str]:
    if semantic:
        kind = "." + _LEAN_CALL_KINDS[call.kind]
        stack = _lean_list(call.stack_inputs, _semantic_stack_input)
    else:
        kind = str({"external_call": 0, "internal_call": 1, "indirect_call": 2}[call.kind])
        stack = _lean_list(call.stack_inputs, _raw_stack_input)
    return [
        f"kind := {kind}",
        f"instructionRva := {call.instruction_rva}",
        f"callIndex := {call.call_index}",
        f"targetNode := {_lean_option(call.target_node, str)}",
        f"targetRva := {call.target_rva}",
        f"returnRva := {call.return_rva}",
        f"dll := {_lean_option(call.dll, _lean_string)}",
        f"symbol := {_lean_option(call.symbol, _lean_string)}",
        f"ordinal := {_lean_option(call.ordinal, str)}",
        f"registerNodes := {_lean_list(call.register_nodes)}",
        f"flagNodes := {_lean_list(call.flag_nodes)}",
        f"argumentNodes := {_lean_list(call.argument_nodes)}",
        f"stackInputs := {stack}",
    ]


def _raw_call(call: Any) -> str:
    return "{ " + ", ".join(_call_fields(call, semantic=False)) + " }"


def _semantic_call(call: Any) -> str:
    return "{ " + ", ".join(_call_fields(call, semantic=True)) + " }"


def _raw_action(action: Any) -> str:
    return (
        f"{{ op := {_ACTIONS.index(action.op)}, arity := {len(action.args)}, "
        f"aux := {action.aux}, args := {_lean_list(action.args)} }}"
    )


def _semantic_action(action: Any) -> str:
    args = tuple(action.args)
    if action.op == "eval_word":
        return f".evalWord {args[0]}"
    if action.op == "memory_write":
        return f".memoryWrite {args[0]} {args[1]} .{_LEAN_WIDTHS[action.aux]}"
    if action.op == "divide_if":
        return f".divideIf {args[0]}"
    if action.op == "call":
        return f".call {args[0]}"
    if action.op == "rep_movsd":
        return f".repMovsd {args[0]} {args[1]} {args[2]} {args[3]}"
    if action.op == "set_reg":
        return f".setRegister .{_LEAN_REGISTERS[action.aux]} {args[0]}"
    if action.op == "set_flag":
        return f".setFlag .{_LEAN_FLAGS[action.aux]} {args[0]}"
    if action.op == "sync_eflags":
        return ".syncEflags"
    raise RelationalInterpreterGenerationError(
        f"unsupported Lean body action {action.op!r}"
    )


def _semantic_outcome(action: Any) -> str:
    args = tuple(action.args)
    if action.op == "outcome_fallthrough":
        return f".fallthrough {args[0]}"
    if action.op == "outcome_jump":
        return f".jump {args[0]}"
    if action.op == "outcome_branch":
        return f".branch {args[0]} {args[1]} {args[2]}"
    if action.op == "outcome_return":
        return f".returned {args[0]}"
    if action.op == "outcome_indirect":
        return f".indirectJump {args[0]}"
    if action.op == "outcome_external":
        return ".externalJump"
    raise RelationalInterpreterGenerationError(
        f"unsupported Lean outcome action {action.op!r}"
    )


def _render_transfer(index: int, transfer: Any) -> str:
    raw_name = f"semanticInterpreterProgramRecord{index}"
    transfer_name = f"semanticInterpreterTransfer{index}"
    export_name = f"semanticInterpreterExport{index}"
    raw_nodes = _lean_list(
        transfer.nodes,
        lambda node: _raw_word_node(node, inventory=_WORD_OPS),
    )
    semantic_nodes = _lean_list(transfer.nodes, _semantic_word_node)
    raw_calls = _lean_list(transfer.calls, _raw_call)
    semantic_calls = _lean_list(transfer.calls, _semantic_call)
    raw_actions = _lean_list(transfer.actions, _raw_action)
    semantic_body = _lean_list(transfer.actions[:-1], _semantic_action)
    semantic_outcome = _semantic_outcome(transfer.actions[-1])
    return f"""def {raw_name} : ProgramRecord := {{
  sourceRva := {transfer.rva_start}
  wordNodes := {raw_nodes}
  x87Nodes := []
  calls := {raw_calls}
  actions := {raw_actions}
}}

def {transfer_name} : SemanticTransfer := {{
  sourceRva := {transfer.rva_start}
  wordNodes := {semantic_nodes}
  calls := {semantic_calls}
  body := {semantic_body}
  outcome := {semantic_outcome}
}}

def {export_name} : ExportedSemanticTransfer := {{
  identity := {_lean_string(transfer.identity)}
  contractSha256 := {_lean_string(transfer.contract_sha256)}
  instructionBytesSha256 := {_lean_string(transfer.instruction_bytes_sha256)}
  transfer := {transfer_name}
}}

theorem {raw_name}Decoded :
    {raw_name}.decode = some {export_name}.transfer := by
  decide

theorem {raw_name}TransferChecked :
    {export_name}.transfer.checked = true := by
  decide

theorem {raw_name}Checked : {raw_name}.checked = true := by
  decide

theorem {raw_name}MacroStep
    (environment : Environment) (state : InterpreterMachine) :
    {raw_name}.interpret environment state =
      {export_name}.transfer.execute environment state :=
  {raw_name}.macroStep_exported_correspondence {export_name}
    {raw_name}Decoded {raw_name}TransferChecked environment state
"""


def relational_interpreter_program_source(transfers: Iterable[Any]) -> str:
    """Render checked Stage B records and their typed Lean transfer bindings."""

    _check_backend_opcode_tables()
    rows = tuple(transfers)
    if not rows:
        raise RelationalInterpreterGenerationError(
            "semantic interpreter program is empty"
        )
    for transfer in rows:
        _validate_transfer(transfer)
    rvas = [int(transfer.rva_start) for transfer in rows]
    if len(set(rvas)) != len(rvas):
        raise RelationalInterpreterGenerationError(
            "semantic interpreter program has duplicate source RVAs"
        )
    identities = [str(transfer.identity) for transfer in rows]
    if len(set(identities)) != len(identities):
        raise RelationalInterpreterGenerationError(
            "semantic interpreter program has duplicate transfer identities"
        )

    definitions = "\n".join(
        _render_transfer(index, transfer)
        for index, transfer in enumerate(rows)
    )
    record_names = ", ".join(
        f"semanticInterpreterProgramRecord{index}" for index in range(len(rows))
    )
    export_names = ", ".join(
        f"semanticInterpreterExport{index}" for index in range(len(rows))
    )
    return f"""import StageA.RelationalInterpreter

namespace StageA.GeneratedRelational

open StageA.Relational.Interpreter

{definitions}
def semanticInterpreterProgramRecords : List ProgramRecord :=
  [{record_names}]

def semanticInterpreterExports : List ExportedSemanticTransfer :=
  [{export_names}]

theorem semanticInterpreterProgramSourceRvasUnique :
    (semanticInterpreterProgramRecords.map (fun record => record.sourceRva)).Nodup := by
  decide

theorem semanticInterpreterProgramChecked :
    semanticInterpreterProgramRecords.all ProgramRecord.checked = true := by
  decide

end StageA.GeneratedRelational
"""


def relational_interpreter_source(state_machine: Path | str) -> str:
    """Compile one canonical Stage B state machine into Lean proof source."""

    transfers = compile_stage_b_interpreter_program(Path(state_machine))
    return relational_interpreter_program_source(transfers)


__all__ = [
    "RelationalInterpreterGenerationError",
    "relational_interpreter_program_source",
    "relational_interpreter_source",
]
