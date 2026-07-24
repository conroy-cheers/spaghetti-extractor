"""Plan a concrete, Lean-checked ABI for the compiled interpreter kernel.

Python cross-checks the kernel, data, and engine-layout inventories and proposes
addresses for an isolated invocation workspace.  It has no proof authority:
the emitted module calls ``buildConcreteKernelABI?``, which re-parses exact PE
bytes, imports, relocations, the engine layout, the program table, and the
compiled CFG in Lean.  Unsupported data produces ``none``.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Sequence

from ...errors import StageAInputError
from ...stage_b_engine_layout import (
    EngineField,
    EngineFieldKind,
    EngineFlag,
    EngineLayout,
    EngineRegister,
    parse_stage_b_engine_layout_payload,
)
from ...util import sha256_bytes, sha256_file, write_json
from .interpreter_kernel import INTERPRETER_KERNEL_PLAN_FORMAT
from .interpreter_kernel_data import INTERPRETER_KERNEL_DATA_FORMAT


INTERPRETER_KERNEL_ABI_FORMAT = (
    "stage-a-relational-interpreter-kernel-abi-plan-v1"
)
INTERPRETER_KERNEL_ABI_PLAN_FILENAME = "interpreter-kernel-abi-plan.json"
INTERPRETER_KERNEL_ABI_LEAN_FILENAME = (
    "GeneratedRelationalInterpreterKernelABI.lean"
)

_REQUIRED_ROLES = (
    "programLookup",
    "interpreterStep",
    "runFunction",
    "invokeCall",
)
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_LEAN_MODULE = re.compile(
    r"StageA\.[A-Za-z_][A-Za-z0-9_']*(?:\.[A-Za-z_][A-Za-z0-9_']*)*\Z"
)
_MIN_STACK_RESERVE = 4096
_UINT32_LIMIT = 1 << 32


class RelationalInterpreterKernelABIGenerationError(StageAInputError):
    """The available artifacts do not define the supported concrete ABI."""


@dataclass(frozen=True)
class KernelABIRoleEvidence:
    role: str
    function_index: int
    image_offset: int
    return_offsets: tuple[int, ...]

    def payload(self) -> dict[str, object]:
        return {
            "role": self.role,
            "function_index": self.function_index,
            "image_offset": self.image_offset,
            "return_offsets": list(self.return_offsets),
            "cdecl": _cdecl_payload(self.role),
            "frame": "exact-decoded-ebp-frame",
        }


@dataclass(frozen=True)
class InterpreterKernelABIPlan:
    kernel_plan_path: Path
    kernel_plan_sha256: str
    data_inventory_path: Path
    data_inventory_sha256: str
    engine_layout_path: Path
    engine_layout_sha256: str
    candidate_sha256: str
    engine_layout_offset: int
    engine_layout_size: int
    table_offset: int
    count_offset: int
    transfer_count: int
    engine_layout: EngineLayout
    workspace_start: int
    workspace_size: int
    stack_reserve: int
    roles: tuple[KernelABIRoleEvidence, ...]

    def payload(self) -> dict[str, object]:
        return {
            "format": INTERPRETER_KERNEL_ABI_FORMAT,
            "acceptance_authority": False,
            "candidate_pe_sha256": self.candidate_sha256,
            "inputs": {
                "kernel_plan": {
                    "path": self.kernel_plan_path.name,
                    "sha256": self.kernel_plan_sha256,
                },
                "data_inventory": {
                    "path": self.data_inventory_path.name,
                    "sha256": self.data_inventory_sha256,
                },
                "engine_layout": {
                    "path": self.engine_layout_path.name,
                    "sha256": self.engine_layout_sha256,
                },
            },
            "candidate_offsets": {
                "engine_layout": {
                    "start": self.engine_layout_offset,
                    "size": self.engine_layout_size,
                },
                "program_table": self.table_offset,
                "program_count": self.count_offset,
            },
            "program_records": self.transfer_count,
            "engine": {
                "state_size": self.engine_layout.state_size,
                "x87_slots": self.engine_layout.x87_slot_count,
                "fields": len(self.engine_layout.fields),
            },
            "invocation_workspace": {
                "start": self.workspace_start,
                "size": self.workspace_size,
                "stack_reserve_per_operation": self.stack_reserve,
            },
            "operations": [role.payload() for role in self.roles],
            "lean_builder": "buildConcreteKernelABI?",
            "failure_mode": "none",
            "proof_inputs": [
                "exact_candidate_pe_parse",
                "exact_import_and_relocation_parse",
                "exact_candidate_image_memory",
                "exact_program_table_and_count_memory",
                "exact_engine_layout_decode",
                "exact_compiled_kernel_cfg",
                "canonical_i386_cdecl_frames",
            ],
        }


def _object(value: object, context: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise RelationalInterpreterKernelABIGenerationError(
            f"{context} must be a JSON object"
        )
    return value


def _array(value: object, context: str) -> list[Any]:
    if not isinstance(value, list):
        raise RelationalInterpreterKernelABIGenerationError(
            f"{context} must be a JSON array"
        )
    return value


def _string(value: object, context: str) -> str:
    if not isinstance(value, str) or not value:
        raise RelationalInterpreterKernelABIGenerationError(
            f"{context} must be a non-empty string"
        )
    return value


def _nat(value: object, context: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise RelationalInterpreterKernelABIGenerationError(
            f"{context} must be a natural number"
        )
    return value


def _digest(value: object, context: str) -> str:
    text = _string(value, context)
    if _SHA256.fullmatch(text) is None:
        raise RelationalInterpreterKernelABIGenerationError(
            f"{context} must be a lowercase SHA-256 digest"
        )
    return text


def _read_json(path: Path, context: str) -> Mapping[str, Any]:
    try:
        return _object(json.loads(path.read_text(encoding="utf-8")), context)
    except (OSError, json.JSONDecodeError) as exc:
        raise RelationalInterpreterKernelABIGenerationError(
            f"unable to read {context}: {path}"
        ) from exc


def _regular_file(value: Path | str, context: str) -> Path:
    path = Path(value)
    if not path.is_file() or path.is_symlink():
        raise RelationalInterpreterKernelABIGenerationError(
            f"{context} is not a regular file: {path}"
        )
    return path


def _cdecl_payload(role: str) -> dict[str, object]:
    if role == "programLookup":
        return {
            "entry_stack_offsets": [4],
            "result": "eax-word",
            "return_stack_bytes": 4,
            "callee_saved": ["ebx", "esi", "edi", "ebp"],
        }
    if role == "interpreterStep":
        return {
            "entry_stack_offsets": [4, 8, 12, 16],
            "arguments": ["hidden-result", "runtime", "state", "source"],
            "result": "three-word-struct-and-eax-hidden-result-pointer",
            "return_stack_bytes": 4,
            "callee_saved": ["ebx", "esi", "edi", "ebp"],
        }
    if role == "runFunction":
        arguments = ["runtime", "source", "input", "output"]
    elif role == "invokeCall":
        arguments = ["runtime", "event", "input", "output"]
    else:
        raise RelationalInterpreterKernelABIGenerationError(
            f"unsupported kernel ABI role {role!r}"
        )
    return {
        "entry_stack_offsets": [4, 8, 12, 16],
        "arguments": arguments,
        "result": "eax-status",
        "return_stack_bytes": 4,
        "callee_saved": ["ebx", "esi", "edi", "ebp"],
    }


def _instruction_map(function: Mapping[str, Any]) -> dict[int, bytes]:
    result: dict[int, bytes] = {}
    for block_index, raw_block in enumerate(
        _array(function.get("blocks"), "kernel function blocks")
    ):
        block = _object(raw_block, f"kernel block {block_index}")
        for instruction_index, raw_instruction in enumerate(
            _array(
                block.get("instructions"),
                f"kernel block {block_index} instructions",
            )
        ):
            instruction = _object(
                raw_instruction,
                f"kernel block {block_index} instruction {instruction_index}",
            )
            offset = _nat(instruction.get("rva"), "kernel instruction offset")
            encoded = _string(instruction.get("bytes"), "kernel instruction bytes")
            try:
                data = bytes.fromhex(encoded)
            except ValueError as exc:
                raise RelationalInterpreterKernelABIGenerationError(
                    f"kernel instruction at {offset} has invalid hexadecimal bytes"
                ) from exc
            if not data or len(data) > 15 or offset in result:
                raise RelationalInterpreterKernelABIGenerationError(
                    f"kernel instruction inventory is invalid at {offset}"
                )
            result[offset] = data
    return result


def _role_evidence(
    functions: Sequence[object], role: str
) -> KernelABIRoleEvidence:
    matches = [
        (index, _object(value, f"kernel function {index}"))
        for index, value in enumerate(functions)
        if _object(value, f"kernel function {index}").get("role") == role
    ]
    if len(matches) != 1:
        raise RelationalInterpreterKernelABIGenerationError(
            f"kernel plan has {len(matches)} {role} functions"
        )
    index, function = matches[0]
    start = _nat(function.get("rva_start"), f"{role} function start")
    frame = _object(function.get("frame"), f"{role} frame")
    if frame.get("required") is not True:
        raise RelationalInterpreterKernelABIGenerationError(
            f"{role} does not use the required EBP frame"
        )
    if _nat(frame.get("push_rva"), f"{role} frame push") != start:
        raise RelationalInterpreterKernelABIGenerationError(
            f"{role} frame does not start at function entry"
        )
    setup = _nat(frame.get("setup_rva"), f"{role} frame setup")
    returns = tuple(
        _nat(value, f"{role} return offset")
        for value in _array(frame.get("return_rvas"), f"{role} returns")
    )
    teardowns = _array(frame.get("teardown_rvas"), f"{role} frame teardowns")
    if not returns or len(teardowns) != len(returns):
        raise RelationalInterpreterKernelABIGenerationError(
            f"{role} has an incomplete return/frame inventory"
        )
    instructions = _instruction_map(function)
    if instructions.get(start) != b"\x55" or instructions.get(setup) != b"\x89\xe5":
        raise RelationalInterpreterKernelABIGenerationError(
            f"{role} does not have the exact push-EBP/move-ESP frame prefix"
        )
    if any(instructions.get(offset) != b"\xc3" for offset in returns):
        raise RelationalInterpreterKernelABIGenerationError(
            f"{role} uses an unsupported cdecl return instruction"
        )
    return KernelABIRoleEvidence(role, index, start, returns)


def _required_engine_fields(slot_count: int) -> set[EngineField]:
    fields = {EngineField.register(register) for register in EngineRegister}
    fields.update(
        {
            EngineField(EngineFieldKind.EFLAGS),
            EngineField(EngineFieldKind.FS_BASE),
            EngineField(EngineFieldKind.X87_CONTROL),
            EngineField(EngineFieldKind.X87_STATUS),
            EngineField(EngineFieldKind.X87_PENDING_EXCEPTION),
            EngineField(EngineFieldKind.X87_LAST_OPCODE),
            EngineField(EngineFieldKind.X87_INSTRUCTION_POINTER),
            EngineField(EngineFieldKind.X87_CODE_SELECTOR),
            EngineField(EngineFieldKind.X87_DATA_POINTER),
            EngineField(EngineFieldKind.X87_DATA_SELECTOR),
            EngineField(EngineFieldKind.ORIGINAL_RVA),
        }
    )
    fields.update(EngineField.flag(flag) for flag in EngineFlag)
    fields.update(EngineField.x87_stack(index) for index in range(slot_count))
    fields.update(EngineField.x87_empty(index) for index in range(slot_count))
    fields.update(EngineField.x87_tag(index) for index in range(slot_count))
    return fields


def build_relational_interpreter_kernel_abi_plan(
    *,
    kernel_plan: Path | str,
    data_inventory: Path | str,
    engine_layout: Path | str,
    workspace_start: int = 0x70000000,
    stack_reserve: int = 0x10000,
) -> InterpreterKernelABIPlan:
    """Cross-check exact inventories and propose one canonical invocation arena."""

    kernel_path = _regular_file(kernel_plan, "kernel plan")
    data_path = _regular_file(data_inventory, "kernel data inventory")
    layout_path = _regular_file(engine_layout, "engine layout")
    kernel = _read_json(kernel_path, "kernel plan")
    data = _read_json(data_path, "kernel data inventory")

    if kernel.get("format") != INTERPRETER_KERNEL_PLAN_FORMAT:
        raise RelationalInterpreterKernelABIGenerationError(
            "unsupported interpreter kernel plan format"
        )
    if data.get("format") != INTERPRETER_KERNEL_DATA_FORMAT:
        raise RelationalInterpreterKernelABIGenerationError(
            "unsupported interpreter kernel data inventory format"
        )

    candidate = _object(kernel.get("candidate"), "kernel candidate")
    candidate_sha256 = _digest(candidate.get("pe_sha256"), "candidate digest")
    data_candidate_digest = _digest(
        data.get("candidate_sha256"), "data candidate digest"
    )
    if data_candidate_digest != candidate_sha256:
        raise RelationalInterpreterKernelABIGenerationError(
            "kernel and data inventories bind different candidate PEs"
        )

    raw_layout = layout_path.read_bytes()
    layout_digest = sha256_bytes(raw_layout)
    layout_inventory = _object(kernel.get("engine_layout"), "kernel engine layout")
    expected_layout_digest = _digest(
        layout_inventory.get("artifact_sha256"), "engine layout digest"
    )
    if expected_layout_digest != layout_digest:
        raise RelationalInterpreterKernelABIGenerationError(
            "engine-layout bytes differ from the kernel plan"
        )
    compiled_range = _object(
        layout_inventory.get("compiled_range"), "engine layout compiled range"
    )
    layout_offset = _nat(compiled_range.get("rva_start"), "engine layout offset")
    layout_size = _nat(compiled_range.get("size"), "engine layout size")
    if layout_size != len(raw_layout) or layout_offset % 4:
        raise RelationalInterpreterKernelABIGenerationError(
            "engine-layout range is truncated or unaligned"
        )

    try:
        parsed_layout = parse_stage_b_engine_layout_payload(raw_layout)
    except (TypeError, ValueError) as exc:
        raise RelationalInterpreterKernelABIGenerationError(
            "engine-layout bytes use an unsupported layout"
        ) from exc
    if parsed_layout.x87_slot_count != 8:
        raise RelationalInterpreterKernelABIGenerationError(
            "compiled interpreter ABI requires exactly eight x87 slots"
        )
    present = {entry.field for entry in parsed_layout.fields}
    missing = sorted(
        (field.name for field in _required_engine_fields(8) - present)
    )
    if missing:
        raise RelationalInterpreterKernelABIGenerationError(
            "engine layout is missing required fields: " + ", ".join(missing)
        )

    program = _object(kernel.get("program"), "kernel program")
    kernel_transfer_count = _nat(
        program.get("transfer_count"), "kernel transfer count"
    )
    counts = _object(data.get("counts"), "kernel data counts")
    transfer_count = _nat(counts.get("transfers"), "data transfer count")
    if transfer_count == 0 or transfer_count != kernel_transfer_count:
        raise RelationalInterpreterKernelABIGenerationError(
            "kernel and data transfer counts differ or are empty"
        )
    table_offset = _nat(data.get("table_rva"), "program table offset")
    count_offset = _nat(data.get("count_rva"), "program count offset")
    if table_offset % 4 or count_offset % 4:
        raise RelationalInterpreterKernelABIGenerationError(
            "program table/count offsets are not uint32-aligned"
        )

    functions = _array(kernel.get("kernel_functions"), "kernel functions")
    roles = tuple(_role_evidence(functions, role) for role in _REQUIRED_ROLES)

    if isinstance(workspace_start, bool) or not isinstance(workspace_start, int):
        raise RelationalInterpreterKernelABIGenerationError(
            "workspace start must be an integer"
        )
    if isinstance(stack_reserve, bool) or not isinstance(stack_reserve, int):
        raise RelationalInterpreterKernelABIGenerationError(
            "stack reserve must be an integer"
        )
    if workspace_start < 0 or workspace_start % 16:
        raise RelationalInterpreterKernelABIGenerationError(
            "workspace start must be a nonnegative 16-byte-aligned address"
        )
    if stack_reserve < _MIN_STACK_RESERVE:
        raise RelationalInterpreterKernelABIGenerationError(
            f"stack reserve must be at least {_MIN_STACK_RESERVE} bytes"
        )
    workspace_size = 64 + 2 * parsed_layout.state_size + 52 + 12 + 4 * stack_reserve
    if workspace_start + workspace_size > _UINT32_LIMIT:
        raise RelationalInterpreterKernelABIGenerationError(
            "invocation workspace wraps the 32-bit address space"
        )

    return InterpreterKernelABIPlan(
        kernel_plan_path=kernel_path,
        kernel_plan_sha256=sha256_file(kernel_path),
        data_inventory_path=data_path,
        data_inventory_sha256=sha256_file(data_path),
        engine_layout_path=layout_path,
        engine_layout_sha256=layout_digest,
        candidate_sha256=candidate_sha256,
        engine_layout_offset=layout_offset,
        engine_layout_size=layout_size,
        table_offset=table_offset,
        count_offset=count_offset,
        transfer_count=transfer_count,
        engine_layout=parsed_layout,
        workspace_start=workspace_start,
        workspace_size=workspace_size,
        stack_reserve=stack_reserve,
        roles=roles,
    )


def _lean_engine_field(field: EngineField) -> str:
    kind = field.kind
    if kind == EngineFieldKind.REGISTER:
        return f".register .{EngineRegister(field.index).name.lower()}"
    if kind == EngineFieldKind.FLAG:
        return f".flag {field.index}"
    if kind == EngineFieldKind.X87_STACK:
        return f".x87Stack {field.index}"
    if kind == EngineFieldKind.X87_EMPTY:
        return f".x87Empty {field.index}"
    if kind == EngineFieldKind.X87_TAG:
        return f".x87Tag {field.index}"
    names = {
        EngineFieldKind.EFLAGS: ".eflags",
        EngineFieldKind.FS_BASE: ".fsBase",
        EngineFieldKind.ORIGINAL_RVA: ".originalRva",
        EngineFieldKind.X87_CONTROL: ".x87Control",
        EngineFieldKind.X87_STATUS: ".x87Status",
        EngineFieldKind.X87_PENDING_EXCEPTION: ".x87PendingException",
        EngineFieldKind.X87_LAST_OPCODE: ".x87LastOpcode",
        EngineFieldKind.X87_INSTRUCTION_POINTER: ".x87InstructionPointer",
        EngineFieldKind.X87_CODE_SELECTOR: ".x87CodeSelector",
        EngineFieldKind.X87_DATA_POINTER: ".x87DataPointer",
        EngineFieldKind.X87_DATA_SELECTOR: ".x87DataSelector",
    }
    try:
        return names[kind]
    except KeyError as exc:
        raise RelationalInterpreterKernelABIGenerationError(
            f"unsupported engine field {field.name}"
        ) from exc


def _lean_layout(layout: EngineLayout) -> str:
    fields = ",\n    ".join(
        "{ field := "
        f"{_lean_engine_field(entry.field)}, offset := {entry.offset}, "
        "alignment := 1 }"
        for entry in layout.fields
    )
    return (
        "{\n"
        f"  stateSize := {layout.state_size}\n"
        f"  x87StackSlots := {layout.x87_slot_count}\n"
        f"  fields := [\n    {fields}\n  ]\n"
        "}"
    )


def _validate_module(value: str, context: str) -> str:
    if _LEAN_MODULE.fullmatch(value) is None:
        raise RelationalInterpreterKernelABIGenerationError(
            f"{context} is not a valid StageA Lean module"
        )
    return value


def relational_interpreter_kernel_abi_source(
    plan: InterpreterKernelABIPlan,
    *,
    kernel_module: str = "StageA.GeneratedRelational.InterpreterKernel",
    data_module: str = "StageA.GeneratedInterpreterKernelDataBundle",
) -> str:
    """Emit a non-authoritative, fail-closed concrete ABI instantiation."""

    kernel_import = _validate_module(kernel_module, "kernel module")
    data_import = _validate_module(data_module, "data module")
    return f"""import StageA.RelationalInterpreterKernelABI
import {kernel_import}
import {data_import}

namespace StageA.GeneratedRelational.InterpreterKernelABI

open StageA.Formal StageA.Relational
open StageA.Relational.Engine
open StageA.Relational.InterpreterKernel
open StageA.Relational.InterpreterKernelABI
open StageA.GeneratedRelational.InterpreterKernel
open StageA.GeneratedRelational.InterpreterKernelData

def generatedInterpreterEngineLayout : EngineLayout :=
  {_lean_layout(plan.engine_layout)}

def generatedInterpreterKernelABIParameters : KernelABIParameters := {{
  engineLayoutSpan := {{
    start := {plan.engine_layout_offset}
    size := {plan.engine_layout_size}
  }}
  writableWorkspace := {{
    start := {plan.workspace_start}
    size := {plan.workspace_size}
  }}
  stackReserve := {plan.stack_reserve}
}}

def generatedConcreteInterpreterKernelABI? :=
  buildConcreteKernelABI?
    generatedInterpreterKernelCandidatePe
    generatedInterpreterKernelImports
    generatedInterpreterKernelRelocations
    generatedInterpreterKernelTableRva
    generatedInterpreterKernelCountRva
    semanticInterpreterProgramRecords
    generatedCompiledKernelProgram
    generatedInterpreterEngineLayout
    generatedInterpreterKernelABIParameters
    generatedInterpreterKernelDataCertificate

/-- This is an actual `KernelABIRelation` only when every exact Lean checker
succeeds.  Unsupported candidate bytes, relocations, CFGs, data tables, engine
layouts, or address plans produce `none`. -/
def generatedInterpreterKernelABIRelation? : Option KernelABIRelation :=
  generatedConcreteInterpreterKernelABI?.map ConcreteKernelABI.relation

def GeneratedInterpreterKernelABIRelationGoal : Prop :=
  generatedInterpreterKernelABIRelation?.isSome = true

/-- Kernel-reduced evidence that the exact candidate PE, program table,
compiled CFG, engine layout, relocation inventory, and workspace proposal
jointly define the supported interpreter ABI. -/
theorem generatedInterpreterKernelABIRelationChecked :
    GeneratedInterpreterKernelABIRelationGoal := by
  decide +kernel

theorem generatedConcreteInterpreterKernelABIChecked :
    generatedConcreteInterpreterKernelABI?.isSome = true := by
  simpa [generatedInterpreterKernelABIRelation?] using
    generatedInterpreterKernelABIRelationChecked

/-- Preserve the complete checked ABI certificate.  Operation proofs consume
this value directly instead of independently replaying the PE, table, layout,
and workspace reductions. -/
def generatedConcreteInterpreterKernelABI :=
  generatedConcreteInterpreterKernelABI?.get
    generatedConcreteInterpreterKernelABIChecked

/-- The whole-program relation is definitionally the projection of the shared
concrete certificate used by every operation proof. -/
def generatedInterpreterKernelABIRelation : KernelABIRelation :=
  generatedConcreteInterpreterKernelABI.relation

#print axioms generatedInterpreterKernelABIRelationChecked
#print axioms generatedConcreteInterpreterKernelABIChecked

end StageA.GeneratedRelational.InterpreterKernelABI
"""


def write_relational_interpreter_kernel_abi_bundle(
    *,
    out: Path | str,
    kernel_module: str = "StageA.GeneratedRelational.InterpreterKernel",
    data_module: str = "StageA.GeneratedInterpreterKernelDataBundle",
    **kwargs: Any,
) -> InterpreterKernelABIPlan:
    destination = Path(out)
    destination.mkdir(parents=True, exist_ok=True)
    plan = build_relational_interpreter_kernel_abi_plan(**kwargs)
    write_json(destination / INTERPRETER_KERNEL_ABI_PLAN_FILENAME, plan.payload())
    source = relational_interpreter_kernel_abi_source(
        plan, kernel_module=kernel_module, data_module=data_module
    )
    (destination / INTERPRETER_KERNEL_ABI_LEAN_FILENAME).write_text(
        source, encoding="utf-8"
    )
    return plan


def abi_plan_payload_sha256(plan: InterpreterKernelABIPlan) -> str:
    """Stable digest helper for callers that bind the proposal as an artifact."""

    encoded = json.dumps(
        plan.payload(), sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()
