from __future__ import annotations

import os
import re
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

from ..stage_binary import StageAInputError
from .semantic import (
    AdjustStack,
    AssignRegister,
    Branch,
    CompareRegister,
    CompareStack,
    ExternalCall,
    InternalCall,
    Jump,
    Nop,
    RegisterArithmetic,
    Return,
    ScalarValue,
    SemanticBlock,
    SemanticProgram,
    StackArithmetic,
    StoreStack,
    ValueKind,
)


@dataclass(frozen=True)
class AssemblyLoweringVariant:
    id: str
    nop_before_external_symbols: tuple[str, ...] = ()
    invert_branch_blocks: tuple[str, ...] = ()
    nop_before_blocks: tuple[str, ...] = ()
    align_blocks: tuple[str, ...] = ()
    split_blocks: tuple[str, ...] = ()
    bridge_jump_blocks: tuple[str, ...] = ()
    reversible_spill_blocks: tuple[str, ...] = ()
    reassign_eax_arithmetic_blocks: tuple[str, ...] = ()
    lea_arithmetic_blocks: tuple[str, ...] = ()
    fallthrough_branch_blocks: tuple[str, ...] = ()
    block_order: tuple[str, ...] = ()


@dataclass(frozen=True)
class LinkedPE32:
    source: Path
    object: Path
    binary: Path
    linker_map: Path
    compiler: str
    compiler_version: str
    linker_version: str


def lower_semantic_program_to_gnu_assembly(
    program: SemanticProgram,
    *,
    variant: AssemblyLoweringVariant,
) -> str:
    ordered_blocks = _ordered_blocks(program, variant)
    known_block_ids = {block.id for block in program.blocks}
    referenced_variant_blocks = {
        block_id
        for values in (
            variant.invert_branch_blocks,
            variant.nop_before_blocks,
            variant.align_blocks,
            variant.split_blocks,
            variant.bridge_jump_blocks,
            variant.reversible_spill_blocks,
            variant.reassign_eax_arithmetic_blocks,
            variant.lea_arithmetic_blocks,
            variant.fallthrough_branch_blocks,
        )
        for block_id in values
    }
    unknown_variant_blocks = sorted(referenced_variant_blocks - known_block_ids)
    if unknown_variant_blocks:
        raise StageAInputError(
            f"lowering variant names unknown blocks {unknown_variant_blocks}"
        )
    block_symbols = {
        block.id: (
            "_mainCRTStartup" if block.id == program.entry else _asm_symbol(block.id)
        )
        for block in program.blocks
    }
    object_symbols = {item.id: _asm_symbol(item.id) for item in program.static_objects}
    imports = sorted({
        block.terminator.decorated_symbol
        for block in program.blocks
        if isinstance(block.terminator, ExternalCall)
    })
    lines = ["    .intel_syntax noprefix", ""]
    for section, directive in (("read_only", '.section .rdata,"dr"'), ("writable", ".section .data")):
        selected = [item for item in program.static_objects if item.section == section]
        if not selected:
            continue
        lines.append(f"    {directive}")
        for item in selected:
            lines.extend((
                f"    .balign {item.alignment}",
                f"{object_symbols[item.id]}:",
                _assembly_bytes(item.data),
            ))
        lines.append("")
    lines.extend(("    .text", f"    .globl {block_symbols[program.entry]}"))
    for block in ordered_blocks:
        if block.id != program.entry:
            lines.append(f"    .globl {block_symbols[block.id]}")
    for imported in imports:
        lines.append(f'    .extern "{imported}"')
    lines.append("")
    for block_index, block in enumerate(ordered_blocks):
        if block.id in set(variant.align_blocks):
            lines.append("    .balign 16, 0x90")
        lines.append(f"{block_symbols[block.id]}:")
        if block.id in set(variant.nop_before_blocks):
            lines.append("    nop")
        if block.id in set(variant.reversible_spill_blocks):
            lines.extend((
                "    lea esp, [esp - 4]",
                "    xchg ebx, DWORD PTR [esp]",
                "    xchg ebx, DWORD PTR [esp]",
                "    lea esp, [esp + 4]",
            ))
        for operation_index, operation in enumerate(block.operations):
            lines.extend(_lower_operation(
                operation,
                object_symbols=object_symbols,
                reassign_eax=(
                    block.id in set(variant.reassign_eax_arithmetic_blocks)
                ),
                use_lea=(block.id in set(variant.lea_arithmetic_blocks)),
            ))
            if (
                block.id in set(variant.split_blocks)
                and operation_index + 1 == max(1, len(block.operations) // 2)
            ):
                split = f".L{_asm_symbol(block.id).lstrip('_')}_split"
                lines.extend((f"    jmp {split}", f"{split}:"))
        if block.id in set(variant.bridge_jump_blocks):
            bridge = f".L{_asm_symbol(block.id).lstrip('_')}_bridge"
            lines.extend((f"    jmp {bridge}", f"{bridge}:"))
        terminator = block.terminator
        if isinstance(terminator, Jump):
            lines.append(f"    jmp {block_symbols[terminator.target]}")
        elif isinstance(terminator, Branch):
            condition = "je" if terminator.condition == "zero" else "jne"
            if block.id in set(variant.invert_branch_blocks):
                condition = "jne" if condition == "je" else "je"
                lines.append(f"    {condition} {block_symbols[terminator.false_target]}")
                fallthrough = terminator.true_target
            else:
                lines.append(f"    {condition} {block_symbols[terminator.true_target]}")
                fallthrough = terminator.false_target
            next_id = _next_block_id_from_order(ordered_blocks, block_index)
            if block.id in set(variant.fallthrough_branch_blocks):
                if next_id != fallthrough:
                    raise StageAInputError(
                        f"branch block {block.id!r} declares fallthrough to "
                        f"{fallthrough!r}, but the next lowered block is {next_id!r}"
                    )
            else:
                lines.append(f"    jmp {block_symbols[fallthrough]}")
        elif isinstance(terminator, InternalCall):
            lines.append(f"    call {block_symbols[terminator.target]}")
            if _next_block_id_from_order(ordered_blocks, block_index) != terminator.continuation:
                lines.append(f"    jmp {block_symbols[terminator.continuation]}")
        elif isinstance(terminator, Return):
            lines.append("    ret")
        else:
            if terminator.symbol in set(variant.nop_before_external_symbols):
                lines.append("    nop")
            lines.append(f'    call "{terminator.decorated_symbol}"')
            if terminator.continuation is not None:
                next_id = _next_block_id_from_order(ordered_blocks, block_index)
                if next_id != terminator.continuation:
                    lines.append(f"    jmp {block_symbols[terminator.continuation]}")
            elif terminator.disposition == "terminates":
                # Give the architectural return address a real cutpoint.  The
                # environment contract proves this path unreachable, while a
                # contract-violating return remains defined and fail closed.
                fallback = f".L{_asm_symbol(block.id).lstrip('_')}_unexpected_return"
                lines.extend((f"{fallback}:", f"    jmp {fallback}"))
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def lower_semantic_program_to_llvm_msvc_assembly(
    program: SemanticProgram,
    *,
    variant: AssemblyLoweringVariant,
) -> str:
    """Emit Intel assembly accepted by clang's i686 MSVC target."""

    return lower_semantic_program_to_gnu_assembly(
        program,
        variant=variant,
    ).replace("OFFSET FLAT:", "offset ")


def build_gnu_pe32(
    *,
    source: Path,
    binary: Path,
    linker_map: Path,
    compiler: str = "i686-w64-mingw32-gcc",
) -> LinkedPE32:
    executable = shutil.which(compiler)
    if executable is None:
        raise StageAInputError(f"PE32 compiler is not available: {compiler}")
    source = Path(source)
    binary = Path(binary)
    linker_map = Path(linker_map)
    if source.parent.resolve() != binary.parent.resolve() or source.parent.resolve() != linker_map.parent.resolve():
        raise StageAInputError("PE32 source, object, binary, and map must share a build directory")
    binary.parent.mkdir(parents=True, exist_ok=True)
    object_path = binary.with_suffix(".o")
    compile_command = [
        executable,
        "-x",
        "assembler",
        "-g0",
        "-c",
        source.name,
        "-o",
        object_path.name,
    ]
    link_command = [
        executable,
        "-nostdlib",
        "-Wl,--exclude-all-symbols",
        "-Wl,--subsystem,console",
        "-Wl,-e,_mainCRTStartup",
        "-Wl,--disable-dynamicbase",
        "-Wl,--image-base,0x400000",
        "-Wl,--section-alignment,0x1000",
        "-Wl,--file-alignment,0x400",
        f"-Wl,-Map,{linker_map.name}",
        "-o",
        binary.name,
        object_path.name,
        "-lkernel32",
    ]
    environment = {
        **os.environ,
        "LC_ALL": "C",
        "SOURCE_DATE_EPOCH": "1",
        "ZERO_AR_DATE": "1",
    }
    for phase, command in (("assembly", compile_command), ("link", link_command)):
        process = subprocess.run(
            command,
            cwd=source.parent,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=environment,
            check=False,
        )
        if process.returncode != 0:
            raise StageAInputError(
                f"PE32 {phase} failed:\n"
                + process.stdout[-2000:]
                + process.stderr[-8000:]
            )
    if not object_path.is_file() or not binary.is_file() or not linker_map.is_file():
        raise StageAInputError("PE32 toolchain omitted the object, binary, or linker map")
    compiler_version = _tool_output([executable, "-dumpfullversion", "-dumpversion"])
    linker_version = _tool_output([executable, "-Wl,--version"], first_line=True)
    return LinkedPE32(
        source=source,
        object=object_path,
        binary=binary,
        linker_map=linker_map,
        compiler=executable,
        compiler_version=compiler_version,
        linker_version=linker_version,
    )


def build_llvm_msvc_pe32(
    *,
    source: Path,
    binary: Path,
    linker_map: Path,
    clang_cl: str = "clang-cl",
    linker: str = "lld-link",
    mingw_gcc: str = "i686-w64-mingw32-gcc",
) -> LinkedPE32:
    clang_cl_executable = shutil.which(clang_cl)
    linker_executable = shutil.which(linker)
    mingw_executable = shutil.which(mingw_gcc)
    missing = [
        name
        for name, executable in (
            (clang_cl, clang_cl_executable),
            (linker, linker_executable),
            (mingw_gcc, mingw_executable),
        )
        if executable is None
    ]
    if missing:
        raise StageAInputError(
            "PE32 LLVM/MSVC-compatible toolchain is unavailable: "
            + ", ".join(missing)
        )
    assert clang_cl_executable is not None
    assert linker_executable is not None
    assert mingw_executable is not None
    clang_executable = Path(clang_cl_executable).with_name("clang")
    if not clang_executable.is_file():
        raise StageAInputError(
            f"clang-cl companion assembler is unavailable: {clang_executable}"
        )
    source = Path(source)
    binary = Path(binary)
    linker_map = Path(linker_map)
    if source.parent.resolve() != binary.parent.resolve() or source.parent.resolve() != linker_map.parent.resolve():
        raise StageAInputError("PE32 source, object, binary, and map must share a build directory")
    binary.parent.mkdir(parents=True, exist_ok=True)
    object_path = binary.with_suffix(".obj")
    kernel32_path = Path(
        _tool_output([mingw_executable, "-print-file-name=libkernel32.a"])
    )
    if not kernel32_path.is_file():
        raise StageAInputError(
            f"MinGW kernel32 import library is unavailable: {kernel32_path}"
        )
    compile_command = [
        str(clang_executable),
        "--target=i686-pc-windows-msvc",
        "-c",
        "-x",
        "assembler",
        source.name,
        "-o",
        object_path.name,
    ]
    link_command = [
        linker_executable,
        "/machine:x86",
        "/subsystem:console",
        "/entry:mainCRTStartup",
        "/base:0x400000",
        "/fixed",
        "/safeseh:no",
        "/nodefaultlib",
        "/align:4096",
        "/filealign:1024",
        "/timestamp:1",
        f"/out:{binary.name}",
        f"/map:{linker_map.name}",
        object_path.name,
        str(kernel32_path),
    ]
    environment = {
        **os.environ,
        "LC_ALL": "C",
        "SOURCE_DATE_EPOCH": "1",
        "ZERO_AR_DATE": "1",
    }
    for phase, command in (("assembly", compile_command), ("link", link_command)):
        process = subprocess.run(
            command,
            cwd=source.parent,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=environment,
            check=False,
        )
        if process.returncode != 0:
            raise StageAInputError(
                f"PE32 LLVM/MSVC-compatible {phase} failed:\n"
                + process.stdout[-2000:]
                + process.stderr[-8000:]
            )
    if not object_path.is_file() or not binary.is_file() or not linker_map.is_file():
        raise StageAInputError(
            "PE32 LLVM/MSVC-compatible toolchain omitted the object, binary, or linker map"
        )
    return LinkedPE32(
        source=source,
        object=object_path,
        binary=binary,
        linker_map=linker_map,
        compiler=clang_cl_executable,
        compiler_version=_tool_output(
            [clang_cl_executable, "--version"], first_line=True
        ),
        linker_version=_tool_output([linker_executable, "--version"], first_line=True),
    )


def _lower_operation(
    operation: (
        AdjustStack | StoreStack | Nop | StackArithmetic | CompareStack
        | AssignRegister | RegisterArithmetic | CompareRegister
    ),
    *,
    object_symbols: dict[str, str],
    reassign_eax: bool = False,
    use_lea: bool = False,
) -> list[str]:
    if isinstance(operation, AdjustStack):
        instruction = "sub" if operation.bytes > 0 else "add"
        return [f"    {instruction} esp, {abs(operation.bytes)}"]
    if isinstance(operation, Nop):
        return ["    nop"]
    if isinstance(operation, StackArithmetic):
        immediate = _assembly_word(operation.immediate)
        return [
            f"    {operation.operator} DWORD PTR {_stack_address(operation.offset)}, {immediate}"
        ]
    if isinstance(operation, CompareStack):
        return [
            f"    cmp DWORD PTR {_stack_address(operation.offset)}, "
            f"{_assembly_word(operation.immediate)}"
        ]
    if isinstance(operation, AssignRegister):
        return [
            f"    mov {operation.register}, "
            f"{_assembly_value(operation.value, object_symbols=object_symbols)}"
        ]
    if isinstance(operation, RegisterArithmetic):
        if reassign_eax and operation.register == "eax":
            return [
                "    xchg eax, edx",
                f"    {operation.operator} edx, {_assembly_word(operation.immediate)}",
                "    xchg eax, edx",
            ]
        if use_lea and operation.register == "eax" and operation.operator in {"add", "sub"}:
            opcode = "0x05" if operation.operator == "add" else "0x2d"
            return [
                f"    .byte {opcode}",
                f"    .long {operation.immediate & 0xFFFFFFFF}",
            ]
        return [
            f"    {operation.operator} {operation.register}, "
            f"{_assembly_word(operation.immediate)}"
        ]
    if isinstance(operation, CompareRegister):
        return [
            f"    cmp {operation.register}, {_assembly_word(operation.immediate)}"
        ]
    value = _assembly_value(operation.value, object_symbols=object_symbols)
    address = _stack_address(operation.offset)
    return [f"    mov DWORD PTR {address}, {value}"]


def _assembly_value(value: ScalarValue, *, object_symbols: dict[str, str]) -> str:
    if value.kind is ValueKind.CONSTANT:
        raw = int(value.value)
        return str(raw if raw < 2**31 else raw - 2**32)
    if value.kind is ValueKind.REGISTER:
        return str(value.value)
    return f"OFFSET FLAT:{object_symbols[str(value.value)]}"


def _assembly_bytes(data: bytes) -> str:
    return "    .byte " + ", ".join(f"0x{value:02x}" for value in data)


def _asm_symbol(identifier: str) -> str:
    normalized = re.sub(r"[^A-Za-z0-9_]", "_", identifier)
    return f"_rt_{normalized}"


def _stack_address(offset: int) -> str:
    if offset == 0:
        return "[esp]"
    operator = "+" if offset > 0 else "-"
    return f"[esp {operator} {abs(offset)}]"


def _assembly_word(value: int) -> str:
    return str(value if value < 2**31 else value - 2**32)


def _next_block_id(program: SemanticProgram, block_id: str) -> str | None:
    index = next(
        index for index, block in enumerate(program.blocks) if block.id == block_id
    )
    return program.blocks[index + 1].id if index + 1 < len(program.blocks) else None


def _ordered_blocks(
    program: SemanticProgram, variant: AssemblyLoweringVariant,
) -> tuple[SemanticBlock, ...]:
    if not variant.block_order:
        return program.blocks
    expected = {block.id for block in program.blocks}
    supplied = tuple(variant.block_order)
    if len(supplied) != len(set(supplied)) or set(supplied) != expected:
        raise StageAInputError(
            "lowering variant block_order must be a permutation of all blocks"
        )
    by_id = {block.id: block for block in program.blocks}
    return tuple(by_id[block_id] for block_id in supplied)


def _next_block_id_from_order(
    blocks: tuple[SemanticBlock, ...], index: int,
) -> str | None:
    if index + 1 >= len(blocks):
        return None
    return str(blocks[index + 1].id)


def _tool_output(command: list[str], *, first_line: bool = False) -> str:
    process = subprocess.run(
        command,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )
    if process.returncode != 0 or not process.stdout.strip():
        raise StageAInputError(f"cannot identify PE32 toolchain: {' '.join(command)}")
    output = process.stdout.strip()
    return output.splitlines()[0] if first_line else output
