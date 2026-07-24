"""Generate the reflected ``programLookup`` template proof goal.

The planner cross-checks the exact kernel and data inventories for
``programLookup``.  Its output has no semantic authority: generated Lean must
still construct ``KernelFunctionSummary`` and the concrete ABI relation.  The
generic Lean module derives the operation simulation from those checked inputs.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path
from typing import Any, Mapping

from ...errors import StageAInputError
from ...util import sha256_file, write_json
from .interpreter_kernel import INTERPRETER_KERNEL_PLAN_FORMAT
from .interpreter_kernel_data import INTERPRETER_KERNEL_DATA_FORMAT


INTERPRETER_KERNEL_SUMMARY_FORMAT = (
    "stage-a-relational-interpreter-kernel-function-summary-plan-v1"
)
INTERPRETER_KERNEL_SUMMARY_PLAN_FILENAME = "interpreter-kernel-summary-plan.json"
INTERPRETER_KERNEL_SUMMARY_LEAN_FILENAME = (
    "GeneratedRelationalInterpreterKernelSummary.lean"
)

_PROGRAM_LOOKUP_ROLE = "programLookup"
_INTERPRETER_KERNEL_DATA_LEGACY_FORMAT = (
    "stage-a-interpreter-kernel-data-inventory-v1"
)
_PROGRAM_LOOKUP_TEMPLATE_SIZE = 161
_PROGRAM_LOOKUP_TEMPLATE_BLOCKS = (
    (0, (89,), (0, 1, 3, 6, 13, 18, 21)),
    (
        23,
        (83, 72),
        (23, 26, 29, 31, 33, 36, 38, 41, 44, 46, 49, 51, 54, 59, 61, 64, 67, 70),
    ),
    (72, (89,), (72, 75, 78, 81)),
    (83, (89,), (83, 86)),
    (89, (23, 97), (89, 92, 95)),
    (97, (152, 107), (97, 102, 105)),
    (107, (152, 132), (107, 110, 112, 115, 117, 120, 125, 127, 130)),
    (132, (157,), (132, 135, 137, 140, 142, 145, 150)),
    (152, (157,), (152,)),
    (157, (), (157, 158, 160)),
)
_PROGRAM_LOOKUP_TEMPLATE_HEX = (
    "5589e583ec10c745fc00000000a1{count}8945f8eb42"
    "8b45f82b45fcd1e889c28b45fc01d08945f48b55f489d0c1e00201d0c1e003"
    "05{table}8b008945f08b45f03b4508730b"
    "8b45f483c0018945fceb06"
    "8b45f48945f8"
    "8b45fc3b45f872b6"
    "a1{count}3945fc732d"
    "8b55fc89d0c1e00201d0c1e00305{table}8b003945087514"
    "8b55fc89d0c1e00201d0c1e00305{table}eb05"
    "b800000000"
    "c931d2c3"
)
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_LEAN_MODULE = re.compile(
    r"StageA\.[A-Za-z_][A-Za-z0-9_']*(?:\.[A-Za-z_][A-Za-z0-9_']*)*\Z"
)


class RelationalInterpreterKernelSummaryGenerationError(StageAInputError):
    """Kernel and data artifacts cannot support a fail-closed summary goal."""


@dataclass(frozen=True)
class InterpreterKernelLookupTemplatePlan:
    """Exact code/CFG certificate inputs available from the kernel plan alone."""

    kernel_plan_path: Path
    kernel_plan_sha256: str
    candidate_sha256: str
    function_index: int
    function_entry_rva: int
    function_end_rva: int
    function_sha256: str
    block_count: int
    instruction_rvas: tuple[int, ...]
    transfer_count: int
    table_rva: int
    count_rva: int
    image_base: int
    table_absolute_address: int
    count_absolute_address: int

    @property
    def generated_function_name(self) -> str:
        return f"generatedKernelFunction{self.function_index:04d}"

    def payload(self) -> dict[str, Any]:
        return {
            "acceptance_authority": False,
            "operation": _PROGRAM_LOOKUP_ROLE,
            "candidate_pe_sha256": self.candidate_sha256,
            "input": {
                "path": self.kernel_plan_path.name,
                "sha256": self.kernel_plan_sha256,
            },
            "function": {
                "index": self.function_index,
                "generated_name": self.generated_function_name,
                "rva_start": self.function_entry_rva,
                "rva_end": self.function_end_rva,
                "sha256": self.function_sha256,
                "blocks": self.block_count,
                "instructions": len(self.instruction_rvas),
                "instruction_rvas": list(self.instruction_rvas),
            },
            "data_parameters": {
                "image_base": self.image_base,
                "table_rva": self.table_rva,
                "count_rva": self.count_rva,
                "table_absolute_address": self.table_absolute_address,
                "count_absolute_address": self.count_absolute_address,
                "transfer_count": self.transfer_count,
                "source": "exact-kernel-compiled-ranges-and-operands",
                "loaded_memory_certificate_required": True,
            },
        }


@dataclass(frozen=True)
class InterpreterKernelFunctionSummaryPlan:
    kernel_plan_path: Path
    kernel_plan_sha256: str
    data_inventory_path: Path
    data_inventory_sha256: str
    candidate_sha256: str
    function_index: int
    function_entry_rva: int
    function_end_rva: int
    function_sha256: str
    block_count: int
    instruction_rvas: tuple[int, ...]
    transfer_count: int
    table_rva: int
    count_rva: int
    image_base: int
    table_absolute_address: int
    count_absolute_address: int

    @property
    def generated_function_name(self) -> str:
        return f"generatedKernelFunction{self.function_index:04d}"

    def payload(self) -> dict[str, Any]:
        return {
            "format": INTERPRETER_KERNEL_SUMMARY_FORMAT,
            "acceptance_authority": False,
            "operation": _PROGRAM_LOOKUP_ROLE,
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
            },
            "function": {
                "index": self.function_index,
                "generated_name": self.generated_function_name,
                "rva_start": self.function_entry_rva,
                "rva_end": self.function_end_rva,
                "sha256": self.function_sha256,
                "blocks": self.block_count,
                "instructions": len(self.instruction_rvas),
                "instruction_rvas": list(self.instruction_rvas),
            },
            "data": {
                "image_base": self.image_base,
                "table_rva": self.table_rva,
                "count_rva": self.count_rva,
                "table_absolute_address": self.table_absolute_address,
                "count_absolute_address": self.count_absolute_address,
                "transfer_count": self.transfer_count,
                "relocations": "parsed-from-candidate-pe",
                "records": "decoded-from-candidate-pe",
            },
            "lean_goal": "GeneratedProgramLookupKernelFunctionSummaryGoal",
            "required_proof_fields": [
                "exact_candidate_pe_parse",
                "exact_function_bytes",
                "exact_decoded_instruction_sequence",
                "exact_relocations_and_program_table",
                "abi_request_establishes_entry_invariant",
                "low_le_high_le_transfer_count",
                "rank_high_sub_low_strictly_decreases",
                "exact_lookup_result",
                "abi_eax_return_value",
                "memory_frame",
                "reflected_template_execution",
            ],
            "template": {
                "id": "pe32-o0-cdecl-lower-bound-v1",
                "function_bytes": _PROGRAM_LOOKUP_TEMPLATE_SIZE,
                "blocks": len(_PROGRAM_LOOKUP_TEMPLATE_BLOCKS),
                "instructions": sum(
                    len(instructions)
                    for _, _, instructions in _PROGRAM_LOOKUP_TEMPLATE_BLOCKS
                ),
                "parameter_fields": [
                    "image_base",
                    "table_rva",
                    "count_rva",
                ],
            },
        }


def _object(value: object, context: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise RelationalInterpreterKernelSummaryGenerationError(
            f"{context} must be a JSON object"
        )
    return value


def _array(value: object, context: str) -> list[Any]:
    if not isinstance(value, list):
        raise RelationalInterpreterKernelSummaryGenerationError(
            f"{context} must be a JSON array"
        )
    return value


def _string(value: object, context: str) -> str:
    if not isinstance(value, str) or not value:
        raise RelationalInterpreterKernelSummaryGenerationError(
            f"{context} must be a non-empty string"
        )
    return value


def _nat(value: object, context: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise RelationalInterpreterKernelSummaryGenerationError(
            f"{context} must be a natural number"
        )
    return value


def _hex_sha256(value: object, context: str) -> str:
    text = _string(value, context)
    if _SHA256.fullmatch(text) is None:
        raise RelationalInterpreterKernelSummaryGenerationError(
            f"{context} must be a lowercase SHA-256 digest"
        )
    return text


def _read_json(path: Path, context: str) -> Mapping[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RelationalInterpreterKernelSummaryGenerationError(
            f"unable to read {context}: {path}"
        ) from exc
    return _object(value, context)


def _validate_instruction_inventory(
    function: Mapping[str, Any],
    *,
    function_start: int,
    function_end: int,
) -> tuple[int, tuple[int, ...], bytes]:
    blocks = _array(function.get("blocks"), "programLookup blocks")
    if not blocks:
        raise RelationalInterpreterKernelSummaryGenerationError(
            "programLookup has no checked CFG blocks"
        )

    instruction_rvas: list[int] = []
    function_bytes = bytearray(function_end - function_start)
    occupied = [False] * len(function_bytes)
    block_entries: set[int] = set()
    for block_index, raw_block in enumerate(blocks):
        block = _object(raw_block, f"programLookup block {block_index}")
        entry = _nat(block.get("entry_rva"), f"programLookup block {block_index} entry")
        if entry in block_entries:
            raise RelationalInterpreterKernelSummaryGenerationError(
                f"programLookup has duplicate block entry {entry}"
            )
        block_entries.add(entry)
        instructions = _array(
            block.get("instructions"),
            f"programLookup block {block_index} instructions",
        )
        if not instructions:
            raise RelationalInterpreterKernelSummaryGenerationError(
                f"programLookup block {block_index} has no instructions"
            )
        first_rva: int | None = None
        for instruction_index, raw_instruction in enumerate(instructions):
            instruction = _object(
                raw_instruction,
                f"programLookup block {block_index} instruction {instruction_index}",
            )
            rva = _nat(
                instruction.get("rva"),
                f"programLookup instruction {instruction_index} RVA",
            )
            encoded = _string(
                instruction.get("bytes"),
                f"programLookup instruction {instruction_index} bytes",
            )
            try:
                instruction_bytes = bytes.fromhex(encoded)
            except ValueError as exc:
                raise RelationalInterpreterKernelSummaryGenerationError(
                    f"programLookup instruction at {rva} has invalid hex bytes"
                ) from exc
            if not instruction_bytes or len(instruction_bytes) > 15:
                raise RelationalInterpreterKernelSummaryGenerationError(
                    f"programLookup instruction at {rva} has invalid x86 length"
                )
            if rva < function_start or rva + len(instruction_bytes) > function_end:
                raise RelationalInterpreterKernelSummaryGenerationError(
                    f"programLookup instruction at {rva} lies outside its function"
                )
            if first_rva is None:
                first_rva = rva
            instruction_rvas.append(rva)
            offset = rva - function_start
            for byte_offset, byte in enumerate(instruction_bytes):
                position = offset + byte_offset
                if occupied[position]:
                    raise RelationalInterpreterKernelSummaryGenerationError(
                        f"programLookup has overlapping instruction byte {position}"
                    )
                occupied[position] = True
                function_bytes[position] = byte
        if first_rva != entry:
            raise RelationalInterpreterKernelSummaryGenerationError(
                f"programLookup block {block_index} does not start at its entry"
            )

    if len(set(instruction_rvas)) != len(instruction_rvas):
        raise RelationalInterpreterKernelSummaryGenerationError(
            "programLookup has duplicate instruction RVAs"
        )
    if function_start not in block_entries:
        raise RelationalInterpreterKernelSummaryGenerationError(
            "programLookup function entry is absent from its CFG"
        )
    if _array(function.get("x87_frames", []), "programLookup x87 frames"):
        raise RelationalInterpreterKernelSummaryGenerationError(
            "programLookup contains x87 frame protocol instructions"
        )
    if not all(occupied):
        raise RelationalInterpreterKernelSummaryGenerationError(
            "programLookup instruction inventory does not cover its exact bytes"
        )
    return len(blocks), tuple(instruction_rvas), bytes(function_bytes)


def _u32_little_endian(value: int) -> bytes:
    if value < 0 or value >= 2**32:
        raise RelationalInterpreterKernelSummaryGenerationError(
            "programLookup template address does not fit in PE32"
        )
    return value.to_bytes(4, "little")


def _program_lookup_template_bytes(count_absolute: int, table_absolute: int) -> bytes:
    return bytes.fromhex(
        _PROGRAM_LOOKUP_TEMPLATE_HEX.format(
            count=_u32_little_endian(count_absolute).hex(),
            table=_u32_little_endian(table_absolute).hex(),
        )
    )


def _validate_program_lookup_template(
    function: Mapping[str, Any],
    *,
    function_start: int,
    function_bytes: bytes,
    table_rva: int,
    count_rva: int,
) -> tuple[int, int, int]:
    if len(function_bytes) != _PROGRAM_LOOKUP_TEMPLATE_SIZE:
        raise RelationalInterpreterKernelSummaryGenerationError(
            "programLookup is not the 161-byte reflected binary-search template"
        )
    blocks = _array(function.get("blocks"), "programLookup blocks")
    observed_blocks: list[tuple[int, tuple[int, ...], tuple[int, ...]]] = []
    for index, raw_block in enumerate(blocks):
        block = _object(raw_block, f"programLookup block {index}")
        entry = _nat(block.get("entry_rva"), f"programLookup block {index} entry")
        successors = tuple(
            _nat(value, f"programLookup block {index} successor") - function_start
            for value in _array(
                block.get("successors"), f"programLookup block {index} successors"
            )
        )
        instructions = tuple(
            _nat(
                _object(value, f"programLookup block {index} instruction").get("rva"),
                f"programLookup block {index} instruction RVA",
            )
            - function_start
            for value in _array(
                block.get("instructions"),
                f"programLookup block {index} instructions",
            )
        )
        observed_blocks.append((entry - function_start, successors, instructions))
    if tuple(observed_blocks) != _PROGRAM_LOOKUP_TEMPLATE_BLOCKS:
        raise RelationalInterpreterKernelSummaryGenerationError(
            "programLookup decoded CFG does not match the reflected binary-search template"
        )

    count_absolute = int.from_bytes(function_bytes[14:18], "little")
    table_absolute = int.from_bytes(function_bytes[55:59], "little")
    if function_bytes[98:102] != _u32_little_endian(count_absolute):
        raise RelationalInterpreterKernelSummaryGenerationError(
            "programLookup count operands disagree"
        )
    table_bytes = _u32_little_endian(table_absolute)
    if function_bytes[121:125] != table_bytes or function_bytes[146:150] != table_bytes:
        raise RelationalInterpreterKernelSummaryGenerationError(
            "programLookup table operands disagree"
        )
    if count_absolute < count_rva or table_absolute < table_rva:
        raise RelationalInterpreterKernelSummaryGenerationError(
            "programLookup data operands precede their PE RVAs"
        )
    count_image_base = count_absolute - count_rva
    table_image_base = table_absolute - table_rva
    if count_image_base != table_image_base:
        raise RelationalInterpreterKernelSummaryGenerationError(
            "programLookup data operands imply different PE image bases"
        )
    expected = _program_lookup_template_bytes(count_absolute, table_absolute)
    if function_bytes != expected:
        raise RelationalInterpreterKernelSummaryGenerationError(
            "programLookup bytes do not match the reflected binary-search template"
        )
    return count_image_base, table_absolute, count_absolute


def _single_compiled_range(
    program: Mapping[str, Any], role: str
) -> tuple[int, int]:
    ranges = _array(program.get("compiled_ranges"), "kernel compiled ranges")
    matches = [
        _object(value, f"kernel compiled range {index}")
        for index, value in enumerate(ranges)
        if _object(value, f"kernel compiled range {index}").get("role") == role
    ]
    if len(matches) != 1:
        raise RelationalInterpreterKernelSummaryGenerationError(
            f"kernel plan has {len(matches)} {role} compiled ranges"
        )
    compiled_range = matches[0]
    start = _nat(compiled_range.get("rva_start"), f"{role} start RVA")
    end = _nat(compiled_range.get("rva_end"), f"{role} end RVA")
    size = _nat(compiled_range.get("size"), f"{role} size")
    if start >= end or end - start != size:
        raise RelationalInterpreterKernelSummaryGenerationError(
            f"{role} span and size disagree"
        )
    return start, end


def build_relational_interpreter_kernel_lookup_template_plan(
    kernel_plan: Path | str,
) -> InterpreterKernelLookupTemplatePlan:
    """Validate the reflected code template without inventing table contents.

    This is intentionally weaker than ``build_relational_interpreter_kernel_summary_plan``:
    the kernel plan fixes code, CFG, count, and table locations, but a matching data
    inventory is still required before Lean can build ``ProgramTableCertificate``.
    """

    kernel_path = Path(kernel_plan)
    kernel = _read_json(kernel_path, "interpreter kernel plan")
    if kernel.get("format") != INTERPRETER_KERNEL_PLAN_FORMAT:
        raise RelationalInterpreterKernelSummaryGenerationError(
            "unsupported interpreter kernel plan format"
        )

    candidate = _object(kernel.get("candidate"), "kernel candidate")
    candidate_sha256 = _hex_sha256(
        candidate.get("pe_sha256"), "kernel candidate SHA-256"
    )
    _nat(candidate.get("size"), "kernel candidate size")

    functions = _array(kernel.get("kernel_functions"), "kernel functions")
    matches = [
        (index, _object(value, f"kernel function {index}"))
        for index, value in enumerate(functions)
        if _object(value, f"kernel function {index}").get("role")
        == _PROGRAM_LOOKUP_ROLE
    ]
    if len(matches) != 1:
        raise RelationalInterpreterKernelSummaryGenerationError(
            f"kernel plan has {len(matches)} programLookup functions"
        )
    function_index, function = matches[0]
    start = _nat(function.get("rva_start"), "programLookup start RVA")
    end = _nat(function.get("rva_end"), "programLookup end RVA")
    size = _nat(function.get("size"), "programLookup size")
    if start >= end or end - start != size:
        raise RelationalInterpreterKernelSummaryGenerationError(
            "programLookup span and size disagree"
        )

    issues = _array(kernel.get("issues", []), "kernel issues")
    lookup_issues: list[Mapping[str, Any]] = []
    for index, value in enumerate(issues):
        issue = _object(value, f"kernel issue {index}")
        issue_start_value = issue.get("rva_start")
        issue_end_value = issue.get("rva_end")
        overlaps = False
        if issue_start_value is not None:
            issue_start = _nat(issue_start_value, f"kernel issue {index} start RVA")
            issue_end = (
                issue_start + 1
                if issue_end_value is None
                else _nat(issue_end_value, f"kernel issue {index} end RVA")
            )
            overlaps = issue_start < end and start < issue_end
        if issue.get("function_role") == _PROGRAM_LOOKUP_ROLE or overlaps:
            lookup_issues.append(issue)
    if lookup_issues:
        codes = ", ".join(
            str(issue.get("code", "unknown")) for issue in lookup_issues
        )
        raise RelationalInterpreterKernelSummaryGenerationError(
            f"programLookup has unresolved kernel issues: {codes}"
        )

    function_sha256 = _hex_sha256(
        function.get("sha256"), "programLookup SHA-256"
    )
    block_count, instruction_rvas, function_bytes = _validate_instruction_inventory(
        function,
        function_start=start,
        function_end=end,
    )
    if sha256(function_bytes).hexdigest() != function_sha256:
        raise RelationalInterpreterKernelSummaryGenerationError(
            "programLookup SHA-256 does not match its exact instruction bytes"
        )

    program = _object(kernel.get("program"), "kernel program")
    transfer_count = _nat(program.get("transfer_count"), "kernel transfer count")
    table_rva, table_end = _single_compiled_range(
        program, "program_transfer_table"
    )
    count_rva, count_end = _single_compiled_range(
        program, "program_transfer_count"
    )
    if table_rva % 4 != 0 or count_rva % 4 != 0:
        raise RelationalInterpreterKernelSummaryGenerationError(
            "program table and count RVAs must be 4-byte aligned"
        )
    if table_end != count_rva or count_end - count_rva != 4:
        raise RelationalInterpreterKernelSummaryGenerationError(
            "program table/count compiled ranges are not contiguous"
        )
    if table_end - table_rva != transfer_count * 40:
        raise RelationalInterpreterKernelSummaryGenerationError(
            "program table compiled range does not contain 40-byte transfer records"
        )
    image_base, table_absolute, count_absolute = _validate_program_lookup_template(
        function,
        function_start=start,
        function_bytes=function_bytes,
        table_rva=table_rva,
        count_rva=count_rva,
    )

    return InterpreterKernelLookupTemplatePlan(
        kernel_plan_path=kernel_path,
        kernel_plan_sha256=sha256_file(kernel_path),
        candidate_sha256=candidate_sha256,
        function_index=function_index,
        function_entry_rva=start,
        function_end_rva=end,
        function_sha256=function_sha256,
        block_count=block_count,
        instruction_rvas=instruction_rvas,
        transfer_count=transfer_count,
        table_rva=table_rva,
        count_rva=count_rva,
        image_base=image_base,
        table_absolute_address=table_absolute,
        count_absolute_address=count_absolute,
    )


def build_relational_interpreter_kernel_summary_plan(
    kernel_plan: Path | str,
    data_inventory: Path | str,
) -> InterpreterKernelFunctionSummaryPlan:
    kernel_path = Path(kernel_plan)
    data_path = Path(data_inventory)
    kernel = _read_json(kernel_path, "interpreter kernel plan")
    data = _read_json(data_path, "interpreter kernel data inventory")

    if kernel.get("format") != INTERPRETER_KERNEL_PLAN_FORMAT:
        raise RelationalInterpreterKernelSummaryGenerationError(
            "unsupported interpreter kernel plan format"
        )
    data_format = data.get("format")
    if data_format not in {
        INTERPRETER_KERNEL_DATA_FORMAT,
        _INTERPRETER_KERNEL_DATA_LEGACY_FORMAT,
    }:
        raise RelationalInterpreterKernelSummaryGenerationError(
            "unsupported interpreter kernel data inventory format"
        )

    kernel_candidate = _object(kernel.get("candidate"), "kernel candidate")
    kernel_sha256 = _hex_sha256(
        kernel_candidate.get("pe_sha256"), "kernel candidate SHA-256"
    )
    kernel_candidate_size = _nat(
        kernel_candidate.get("size"), "kernel candidate size"
    )
    data_sha256 = _hex_sha256(
        data.get("candidate_sha256"), "data candidate SHA-256"
    )
    if kernel_sha256 != data_sha256:
        raise RelationalInterpreterKernelSummaryGenerationError(
            "kernel and data inventories describe different candidate PE bytes"
        )
    data_candidate_size_value = data.get("candidate_bytes")
    if data_candidate_size_value is None:
        if data_format != _INTERPRETER_KERNEL_DATA_LEGACY_FORMAT:
            raise RelationalInterpreterKernelSummaryGenerationError(
                "data candidate size is absent"
            )
    else:
        data_candidate_size = _nat(
            data_candidate_size_value, "data candidate size"
        )
        if kernel_candidate_size != data_candidate_size:
            raise RelationalInterpreterKernelSummaryGenerationError(
                "kernel and data inventories disagree on candidate PE size"
            )

    functions = _array(kernel.get("kernel_functions"), "kernel functions")
    matches = [
        (index, _object(value, f"kernel function {index}"))
        for index, value in enumerate(functions)
        if _object(value, f"kernel function {index}").get("role")
        == _PROGRAM_LOOKUP_ROLE
    ]
    if len(matches) != 1:
        raise RelationalInterpreterKernelSummaryGenerationError(
            f"kernel plan has {len(matches)} programLookup functions"
        )
    function_index, function = matches[0]

    start = _nat(function.get("rva_start"), "programLookup start RVA")
    end = _nat(function.get("rva_end"), "programLookup end RVA")
    size = _nat(function.get("size"), "programLookup size")
    if start >= end or end - start != size:
        raise RelationalInterpreterKernelSummaryGenerationError(
            "programLookup span and size disagree"
        )

    issues = _array(kernel.get("issues", []), "kernel issues")
    lookup_issues: list[Mapping[str, Any]] = []
    for index, value in enumerate(issues):
        issue = _object(value, f"kernel issue {index}")
        issue_start_value = issue.get("rva_start")
        issue_end_value = issue.get("rva_end")
        overlaps = False
        if issue_start_value is not None:
            issue_start = _nat(issue_start_value, f"kernel issue {index} start RVA")
            issue_end = (
                issue_start + 1
                if issue_end_value is None
                else _nat(issue_end_value, f"kernel issue {index} end RVA")
            )
            overlaps = issue_start < end and start < issue_end
        if issue.get("function_role") == _PROGRAM_LOOKUP_ROLE or overlaps:
            lookup_issues.append(issue)
    if lookup_issues:
        codes = ", ".join(
            str(issue.get("code", "unknown")) for issue in lookup_issues
        )
        raise RelationalInterpreterKernelSummaryGenerationError(
            f"programLookup has unresolved kernel issues: {codes}"
        )

    function_sha256 = _hex_sha256(
        function.get("sha256"), "programLookup SHA-256"
    )
    block_count, instruction_rvas, function_bytes = _validate_instruction_inventory(
        function,
        function_start=start,
        function_end=end,
    )
    if sha256(function_bytes).hexdigest() != function_sha256:
        raise RelationalInterpreterKernelSummaryGenerationError(
            "programLookup SHA-256 does not match its exact instruction bytes"
        )

    kernel_program = _object(kernel.get("program"), "kernel program")
    kernel_transfer_count = _nat(
        kernel_program.get("transfer_count"), "kernel transfer count"
    )
    counts = _object(data.get("counts"), "data counts")
    data_transfer_count = _nat(counts.get("transfers"), "data transfer count")
    if kernel_transfer_count != data_transfer_count:
        raise RelationalInterpreterKernelSummaryGenerationError(
            "kernel and data inventories disagree on transfer count"
        )

    table_rva = _nat(data.get("table_rva"), "program table RVA")
    count_rva = _nat(data.get("count_rva"), "program count RVA")
    if table_rva % 4 != 0 or count_rva % 4 != 0:
        raise RelationalInterpreterKernelSummaryGenerationError(
            "program table and count RVAs must be 4-byte aligned"
        )
    image_base, table_absolute, count_absolute = _validate_program_lookup_template(
        function,
        function_start=start,
        function_bytes=function_bytes,
        table_rva=table_rva,
        count_rva=count_rva,
    )

    return InterpreterKernelFunctionSummaryPlan(
        kernel_plan_path=kernel_path,
        kernel_plan_sha256=sha256_file(kernel_path),
        data_inventory_path=data_path,
        data_inventory_sha256=sha256_file(data_path),
        candidate_sha256=kernel_sha256,
        function_index=function_index,
        function_entry_rva=start,
        function_end_rva=end,
        function_sha256=function_sha256,
        block_count=block_count,
        instruction_rvas=instruction_rvas,
        transfer_count=kernel_transfer_count,
        table_rva=table_rva,
        count_rva=count_rva,
        image_base=image_base,
        table_absolute_address=table_absolute,
        count_absolute_address=count_absolute,
    )


def _validate_module_name(module: str, context: str) -> None:
    if _LEAN_MODULE.fullmatch(module) is None:
        raise RelationalInterpreterKernelSummaryGenerationError(
            f"{context} must be a qualified StageA Lean module"
        )


def relational_interpreter_kernel_summary_source(
    plan: InterpreterKernelFunctionSummaryPlan,
    *,
    kernel_module: str = "StageA.GeneratedRelationalInterpreterKernel",
    data_module: str = "StageA.GeneratedInterpreterKernelDataBundle",
) -> str:
    _validate_module_name(kernel_module, "kernel_module")
    _validate_module_name(data_module, "data_module")
    function_name = plan.generated_function_name
    return f"""import StageA.RelationalInterpreterKernelSummary
import {kernel_module}
import {data_module}

namespace StageA.GeneratedRelational.InterpreterKernelSummary

open StageA.Formal StageA.Relational
open StageA.Relational.InterpreterKernel
open StageA.Relational.InterpreterKernelLoop
open StageA.Relational.InterpreterKernelSummary
open StageA.GeneratedRelational.InterpreterKernel
open StageA.GeneratedRelational.InterpreterKernelData

/-! Generated parameters only select exact PE-backed artifacts.  The inventory
JSON has no acceptance authority: Lean rechecks the exact bytes, decoded CFG,
PE parse, relocation-backed table, loaded entry memory, ABI result, and frame. -/
def generatedProgramLookupTemplateParameters :
    ProgramLookupTemplateParameters := {{
  entryRva := {plan.function_entry_rva}
  tableRva := {plan.table_rva}
  countRva := {plan.count_rva}
}}

def GeneratedProgramLookupTemplateReflectionGoal : Prop :=
  exists reflection,
    reflectProgramLookupTemplate? generatedInterpreterKernelCandidatePe
      {function_name} = some reflection

def GeneratedProgramLookupTemplateCheckedGoal : Prop :=
  programLookupTemplateChecked generatedCompiledKernelProgram
    generatedInterpreterKernelCandidatePe generatedInterpreterKernelImports
    {function_name} generatedProgramLookupTemplateParameters = true

def generatedProgramLookupTemplateCertificate
    (reflection : ReflectedProgramLookupTemplate)
    (reflected : reflectProgramLookupTemplate?
      generatedInterpreterKernelCandidatePe {function_name} = some reflection)
    (checked : GeneratedProgramLookupTemplateCheckedGoal) :
    ProgramLookupTemplateCertificate generatedCompiledKernelProgram
      generatedInterpreterKernelCandidatePe generatedInterpreterKernelImports
      {function_name} := {{
  parameters := generatedProgramLookupTemplateParameters
  reflection
  reflected
  checked
}}

def GeneratedProgramLookupKernelFunctionSummaryGoal
    (abi : KernelABIRelation) : Prop :=
  Nonempty (KernelFunctionSummary generatedCompiledKernelProgram
    generatedInterpreterKernelCandidatePe generatedInterpreterKernelImports
    abi generatedInterpreterKernelRelocations
    generatedInterpreterKernelTableRva generatedInterpreterKernelCountRva
    semanticInterpreterProgramRecords {function_name})

noncomputable def GeneratedProgramLookupExecutionSummary
    {{abi : KernelABIRelation}}
    (summary : KernelFunctionSummary generatedCompiledKernelProgram
      generatedInterpreterKernelCandidatePe generatedInterpreterKernelImports
      abi generatedInterpreterKernelRelocations
      generatedInterpreterKernelTableRva generatedInterpreterKernelCountRva
      semanticInterpreterProgramRecords {function_name})
    {{sourceRva : Nat}} {{before : MachineState}}
    (entry : ProgramLookupConcreteEntry generatedInterpreterKernelCandidatePe
      abi semanticInterpreterProgramRecords
      summary.dataCertificate.transferCount sourceRva before
      summary.templateCertificate) :
    ProgramLookupExecutionSummary generatedInterpreterKernelCandidatePe abi
      semanticInterpreterProgramRecords summary.dataCertificate.transferCount
      sourceRva before summary.templateCertificate summary.concreteABI :=
  summary.templateCertificate.executionSummary summary.concreteABI entry
    summary.blockExecutionComposes summary.sourceRvasSorted

theorem GeneratedProgramLookupRefinesUsingReflectedTemplate
    {{abi : KernelABIRelation}}
    (summary : KernelFunctionSummary generatedCompiledKernelProgram
      generatedInterpreterKernelCandidatePe generatedInterpreterKernelImports
      abi generatedInterpreterKernelRelocations
      generatedInterpreterKernelTableRva generatedInterpreterKernelCountRva
      semanticInterpreterProgramRecords {function_name}) :
    KernelOperationRefinesUsing generatedCompiledKernelProgram abi
      (ProgramLookupTemplateDispatches generatedInterpreterKernelCandidatePe
        semanticInterpreterProgramRecords summary.dataCertificate.transferCount
        summary.templateCertificate) .programLookup :=
  summary.programLookupRefinesUsingTemplate

#print axioms GeneratedProgramLookupRefinesUsingReflectedTemplate

end StageA.GeneratedRelational.InterpreterKernelSummary
"""


def write_relational_interpreter_kernel_summary_bundle(
    *,
    kernel_plan: Path | str,
    data_inventory: Path | str,
    out: Path | str,
    kernel_module: str = "StageA.GeneratedRelationalInterpreterKernel",
    data_module: str = "StageA.GeneratedInterpreterKernelDataBundle",
) -> InterpreterKernelFunctionSummaryPlan:
    output = Path(out)
    output.mkdir(parents=True, exist_ok=True)
    plan = build_relational_interpreter_kernel_summary_plan(
        kernel_plan,
        data_inventory,
    )
    write_json(output / INTERPRETER_KERNEL_SUMMARY_PLAN_FILENAME, plan.payload())
    (output / INTERPRETER_KERNEL_SUMMARY_LEAN_FILENAME).write_text(
        relational_interpreter_kernel_summary_source(
            plan,
            kernel_module=kernel_module,
            data_module=data_module,
        ),
        encoding="utf-8",
    )
    return plan


__all__ = [
    "INTERPRETER_KERNEL_SUMMARY_FORMAT",
    "INTERPRETER_KERNEL_SUMMARY_LEAN_FILENAME",
    "INTERPRETER_KERNEL_SUMMARY_PLAN_FILENAME",
    "InterpreterKernelFunctionSummaryPlan",
    "InterpreterKernelLookupTemplatePlan",
    "RelationalInterpreterKernelSummaryGenerationError",
    "build_relational_interpreter_kernel_lookup_template_plan",
    "build_relational_interpreter_kernel_summary_plan",
    "relational_interpreter_kernel_summary_source",
    "write_relational_interpreter_kernel_summary_bundle",
]
