"""Bounded Unicorn evidence backend for PE32 ISA conformance cases.

Unicorn is an untrusted concrete oracle.  Results from this module can veto or
qualify an ISA model, but they cannot qualify a reconstructed candidate.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
import struct
from typing import Any

import capstone
from capstone import x86_const as capstone_x86

from .isa_conformance import (
    BackendDescriptor,
    BackendKind,
    BackendObservation,
    ControlClass,
    ExpectedOutcome,
    FaultClass,
    FSState,
    GPR_NAMES,
    GPRState,
    ISAConformanceCorpus,
    ISAConformanceError,
    ISAConformanceReport,
    InstructionTestCase,
    MachineState,
    ObservationStatus,
    ObservedMemoryRegion,
    ReportCounts,
    ReportQualification,
    ReportTrust,
    X87State,
    isa_conformance_corpus_sha256,
)

try:
    import unicorn as _unicorn
    from unicorn import x86_const as _unicorn_x86
except (ImportError, OSError) as _unicorn_import_exception:
    _unicorn = None
    _unicorn_x86 = None
    _UNICORN_IMPORT_DETAIL = str(_unicorn_import_exception)
else:
    _UNICORN_IMPORT_DETAIL = ""


UNICORN_BACKEND_ID = "unicorn-x86-32-batch-v2"
UNICORN_CPU_PROFILES = {
    "haswell": "UC_CPU_X86_HASWELL",
    # Unicorn has no Pentium Pro model. Pentium II is the nearest
    # architectural superset; pe32-i686-v1 excludes MMX and later forms.
    "i686": "UC_CPU_X86_PENTIUM2",
}
PAGE_SIZE = 0x1000
MAX_MAPPED_BYTES = 16 * 1024 * 1024
MAX_OBSERVED_BYTES = 1024 * 1024
MAX_REPEAT_ITERATIONS = 65536
_HARNESS_GDT_PAGE = 0x1000
_HARNESS_TRANSITION_PAGE = 0x2000
_HARNESS_TRANSITION_STACK_PAGE = 0x3000
_HARNESS_END = 0x4000
_KERNEL_CODE_SELECTOR = 0x08
_KERNEL_DATA_SELECTOR = 0x10
_USER_CODE_SELECTOR = 0x1B
_USER_DATA_SELECTOR = 0x23
_USER_CODE_INDEX = _USER_CODE_SELECTOR >> 3
_USER_DATA_INDEX = _USER_DATA_SELECTOR >> 3
_GDT_ENTRY_LIMIT = PAGE_SIZE // 8
_FORBIDDEN_USER_EFLAGS = (3 << 12) | (1 << 14) | (1 << 17)

_PERMISSION_BITS = {"r": 1, "w": 2, "x": 4}
_CANONICAL_X87_SCALARS = (0x037F, 0, 0xFFFF, 0, 0, 0)
_X87_CORE_REGISTER_NAMES = {
    "fpcw",
    "fpsw",
    "fptag",
    *(f"fp{index}" for index in range(8)),
    *(f"st({index})" for index in range(8)),
}
_X87_REQUIRED_UNICORN_REGISTERS = (
    "FPCW",
    "FPSW",
    "FPTAG",
    "FIP",
    "FDP",
    "FOP",
    *(f"FP{index}" for index in range(8)),
)
_SYSTEM_MNEMONICS = {
    "clts",
    "cpuid",
    "getsec",
    "hlt",
    "in",
    "insb",
    "insd",
    "insw",
    "invd",
    "invept",
    "invlpg",
    "invpcid",
    "invvpid",
    "lgdt",
    "lidt",
    "lldt",
    "lmsw",
    "ltr",
    "monitor",
    "mwait",
    "out",
    "outsb",
    "outsd",
    "outsw",
    "rdmsr",
    "rdpmc",
    "rdrand",
    "rdseed",
    "rdtsc",
    "rdtscp",
    "rsm",
    "sgdt",
    "sidt",
    "sldt",
    "smsw",
    "str",
    "swapgs",
    "syscall",
    "sysenter",
    "sysexit",
    "sysret",
    "ud0",
    "ud1",
    "ud2",
    "vmcall",
    "vmclear",
    "vmlaunch",
    "vmload",
    "vmmcall",
    "vmptrld",
    "vmptrst",
    "vmread",
    "vmresume",
    "vmrun",
    "vmsave",
    "vmwrite",
    "vmxoff",
    "vmxon",
    "wbinvd",
    "wrmsr",
    "xgetbv",
    "xsetbv",
}
_FAR_OR_SEGMENT_MNEMONICS = {
    "callf",
    "iret",
    "iretd",
    "iretw",
    "jmpf",
    "lcall",
    "ljmp",
    "retf",
    "retfd",
    "retfw",
}
_MODELED_REGISTER_NAMES = {
    "eax",
    "ax",
    "al",
    "ah",
    "ebx",
    "bx",
    "bl",
    "bh",
    "ecx",
    "cx",
    "cl",
    "ch",
    "edx",
    "dx",
    "dl",
    "dh",
    "esi",
    "si",
    "edi",
    "di",
    "ebp",
    "bp",
    "esp",
    "sp",
    "eip",
    "ip",
    "eflags",
    "flags",
    "fs",
    "cs",
    "ds",
    "es",
    "ss",
}
_SEGMENT_REGISTERS = {"cs", "ds", "es", "fs", "gs", "ss"}


@dataclass(frozen=True)
class _DecodedCase:
    instruction: Any
    control: ControlClass


@dataclass(frozen=True)
class _AccessRange:
    start: int
    end: int
    permissions: str

    def permits(self, address: int, size: int, permission: str) -> bool:
        end = address + size
        return (
            size > 0
            and end <= 2**32
            and self.start <= address
            and end <= self.end
            and permission in self.permissions
        )


def unicorn_available() -> bool:
    """Return whether the optional Unicorn Python binding imported cleanly."""
    return _unicorn is not None and _unicorn_x86 is not None


def unicorn_backend_descriptor() -> BackendDescriptor:
    version = getattr(_unicorn, "__version__", "unavailable")
    return BackendDescriptor(
        id=UNICORN_BACKEND_ID,
        kind=BackendKind.EMULATOR,
        version=str(version),
    )


def _unsupported(case: InstructionTestCase, detail: str) -> BackendObservation:
    return BackendObservation(
        case_id=case.id,
        status=ObservationStatus.UNSUPPORTED,
        final_state=None,
        memory=None,
        actual=None,
        detail=detail,
    )


def _error(case: InstructionTestCase, detail: str) -> BackendObservation:
    return BackendObservation(
        case_id=case.id,
        status=ObservationStatus.ERROR,
        final_state=None,
        memory=None,
        actual=None,
        detail=detail,
    )


def _complete_observation(
    case: InstructionTestCase,
    *,
    final_state: MachineState | None,
    memory: tuple[ObservedMemoryRegion, ...] | None,
    control: ControlClass,
    fault: FaultClass,
) -> BackendObservation:
    provisional = BackendObservation(
        case_id=case.id,
        status=ObservationStatus.MATCH,
        final_state=final_state,
        memory=memory,
        actual=ExpectedOutcome(control=control, fault=fault),
        detail="",
    )
    matches = case.matches(provisional)
    return replace(
        provisional,
        status=(ObservationStatus.MATCH if matches else ObservationStatus.MISMATCH),
        detail=(
            ""
            if matches
            else "masked Unicorn observation differs from expected outcome"
        ),
    )


def _all_zero(values: tuple[bytes, ...]) -> bool:
    return all(not any(value) for value in values)


def _x87_input_is_canonical(state: MachineState) -> bool:
    x87 = state.x87
    return (
        (
            x87.control_word,
            x87.status_word,
            x87.tag_word,
            x87.last_opcode,
            x87.instruction_pointer,
            x87.data_pointer,
        )
        == _CANONICAL_X87_SCALARS
        and _all_zero(x87.registers)
    )


def _x87_core_outputs_are_unobserved(case: InstructionTestCase) -> bool:
    mask = case.defined_outputs.x87
    return (
        mask.control_word == 0
        and mask.status_word == 0
        and mask.tag_word == 0
        and _all_zero(mask.registers)
    )


def _instruction_uses_unmodeled_registers(
    instruction: Any, *, allow_x87: bool
) -> str | None:
    try:
        read_registers, written_registers = instruction.regs_access()
    except capstone.CsError as exc:
        return f"Capstone could not classify register access: {exc}"
    names = {
        instruction.reg_name(register)
        for register in (*read_registers, *written_registers)
    }
    names.discard("")
    modeled = _MODELED_REGISTER_NAMES
    if allow_x87:
        modeled = modeled | _X87_CORE_REGISTER_NAMES
    unsupported = sorted(names - modeled)
    if unsupported:
        return "instruction uses unmodeled register state: " + ", ".join(unsupported)
    for operand in instruction.operands:
        if operand.type != capstone_x86.X86_OP_REG:
            continue
        name = instruction.reg_name(operand.reg)
        if name in _SEGMENT_REGISTERS:
            return f"instruction explicitly accesses unmodeled segment register {name}"
    return None


def _classify_control(instruction: Any) -> ControlClass:
    if instruction.group(capstone.CS_GRP_CALL):
        if (
            instruction.operands
            and instruction.operands[0].type == capstone_x86.X86_OP_IMM
        ):
            return ControlClass.DIRECT_CALL
        return ControlClass.INDIRECT_CALL
    if instruction.group(capstone.CS_GRP_RET):
        return ControlClass.RETURN
    if instruction.group(capstone.CS_GRP_JUMP):
        if (
            instruction.operands
            and instruction.operands[0].type == capstone_x86.X86_OP_IMM
        ):
            return ControlClass.DIRECT_BRANCH
        return ControlClass.INDIRECT_BRANCH
    if instruction.group(capstone.CS_GRP_INT) or instruction.group(
        capstone.CS_GRP_IRET
    ):
        return ControlClass.INTERRUPT
    if instruction.mnemonic.lower() == "hlt":
        return ControlClass.HALT
    return ControlClass.FALLTHROUGH


def _decode_case(case: InstructionTestCase) -> _DecodedCase | str:
    decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    decoder.detail = True
    instructions = list(
        decoder.disasm(case.instruction_bytes, case.initial_state.eip, count=1)
    )
    if not instructions:
        return "Capstone rejected the instruction bytes"
    instruction = instructions[0]
    if instruction.size != len(case.instruction_bytes):
        return "instruction_bytes must contain exactly one complete instruction"
    mnemonic = instruction.mnemonic.lower()
    if 0x65 in instruction.prefix:
        return "GS segment overrides are outside the bounded Unicorn profile"
    if instruction.group(capstone.CS_GRP_PRIVILEGE):
        return "privileged/system instructions are outside the bounded Unicorn profile"
    if mnemonic in _SYSTEM_MNEMONICS:
        return f"system instruction {mnemonic} is outside the bounded Unicorn profile"
    if mnemonic in _FAR_OR_SEGMENT_MNEMONICS:
        return f"far/segment control instruction {mnemonic} is unsupported"
    register_issue = _instruction_uses_unmodeled_registers(
        instruction,
        allow_x87=(
            instruction.group(capstone_x86.X86_GRP_FPU)
            or mnemonic.startswith("f")
        ),
    )
    if register_issue is not None:
        return register_issue
    control = _classify_control(instruction)
    if control in {ControlClass.INTERRUPT, ControlClass.HALT}:
        return (
            "interrupt, callback, and halt transitions require an "
            "external-state model"
        )
    return _DecodedCase(instruction=instruction, control=control)


def _validate_user_fs(case: InstructionTestCase) -> str | None:
    fs = case.initial_state.fs
    if fs.selector == 0:
        if fs.base != 0:
            return "a null FS selector cannot carry a nonzero hidden base"
        return None
    if fs.selector & 0x4:
        return "LDT-backed FS selectors are outside the bounded Unicorn profile"
    if fs.selector & 0x3 != 0x3:
        return "PE32 user-mode FS selectors must have RPL=3"
    index = fs.selector >> 3
    if index >= _GDT_ENTRY_LIMIT:
        return "FS selector exceeds the bounded one-page GDT"
    if index in {_USER_CODE_INDEX, _USER_DATA_INDEX}:
        return "FS selector aliases a fixed CPL3 harness descriptor"
    return None


def _case_memory_read(
    case: InstructionTestCase, address: int, size: int
) -> bytes | None:
    if size <= 0 or address + size > 2**32:
        return None
    for region in case.memory:
        if (
            "r" in region.permissions
            and region.address <= address
            and address + size <= region.address + len(region.data)
        ):
            offset = address - region.address
            return region.data[offset : offset + size]
    return None


def _gpr_value(case: InstructionTestCase, name: str) -> int | None:
    if name not in GPR_NAMES:
        return None
    return int(getattr(case.initial_state.gprs, name)) & 0xFFFFFFFF


def _memory_operand_address(
    case: InstructionTestCase, instruction: Any, operand: Any
) -> int | None:
    memory = operand.mem
    base = 0
    if memory.base:
        base_name = instruction.reg_name(memory.base)
        base_value = _gpr_value(case, base_name)
        if base_value is None:
            return None
        base = base_value
    index = 0
    if memory.index:
        index_name = instruction.reg_name(memory.index)
        index_value = _gpr_value(case, index_name)
        if index_value is None:
            return None
        index = index_value
    segment_base = 0
    if memory.segment:
        segment_name = instruction.reg_name(memory.segment)
        if segment_name != "fs":
            return None
        segment_base = case.initial_state.fs.base
    return (
        segment_base + base + index * int(memory.scale) + int(memory.disp)
    ) & 0xFFFFFFFF


def _decoded_control_target(
    case: InstructionTestCase, decoded: _DecodedCase
) -> int | None:
    instruction = decoded.instruction
    if decoded.control is ControlClass.RETURN:
        raw = _case_memory_read(case, case.initial_state.gprs.esp, 4)
        return None if raw is None else int.from_bytes(raw, "little")
    if not instruction.operands:
        return None
    operand = instruction.operands[0]
    if operand.type == capstone_x86.X86_OP_IMM:
        return int(operand.imm) & 0xFFFFFFFF
    if operand.type == capstone_x86.X86_OP_REG:
        return _gpr_value(case, instruction.reg_name(operand.reg))
    if operand.type == capstone_x86.X86_OP_MEM:
        address = _memory_operand_address(case, instruction, operand)
        if address is None:
            return None
        raw = _case_memory_read(case, address, 4)
        return None if raw is None else int.from_bytes(raw, "little")
    return None


def _is_repeat_instruction(decoded: _DecodedCase) -> bool:
    mnemonic = decoded.instruction.mnemonic.lower()
    return mnemonic.startswith(("rep ", "repe ", "repne "))


def _control_landing_addresses(
    case: InstructionTestCase, decoded: _DecodedCase
) -> tuple[int, ...] | str:
    if case.expected.control in {ControlClass.FALLTHROUGH, ControlClass.FAULT}:
        return ()
    addresses: set[int] = set()
    if case.expected.final_state is not None:
        addresses.add(case.expected.final_state.eip)
    decoded_target = _decoded_control_target(case, decoded)
    if decoded_target is not None:
        addresses.add(decoded_target)
    if not addresses:
        return "control-transfer destination cannot be provisioned fail-closed"
    return tuple(sorted(addresses))


def _preflight(case: InstructionTestCase) -> _DecodedCase | str:
    if case.profile.architecture != "x86":
        return "Unicorn backend supports only x86"
    if case.profile.execution_mode != "protected-32":
        return "Unicorn backend supports only protected 32-bit execution"
    if case.profile.environment != "pe32":
        return "Unicorn backend supports only the PE32 environment profile"
    if case.profile.cpu not in UNICORN_CPU_PROFILES:
        return (
            f"unsupported CPU profile {case.profile.cpu!r}; expected one of "
            f"{sorted(UNICORN_CPU_PROFILES)!r}"
        )
    if case.profile.features:
        return "feature overrides are unsupported; use a fixed CPU profile"
    fs_issue = _validate_user_fs(case)
    if fs_issue is not None:
        return fs_issue
    if case.initial_state.eflags & _FORBIDDEN_USER_EFLAGS:
        return (
            "PE32 CPL3 cases require IOPL=0, NT=0, and VM=0 in the initial "
            "EFLAGS state"
        )
    mapped_bytes = sum(len(region.data) for region in case.memory)
    if mapped_bytes > MAX_MAPPED_BYTES:
        return f"declared memory exceeds the {MAX_MAPPED_BYTES}-byte backend bound"
    observed_bytes = sum(len(mask.mask) for mask in case.defined_outputs.memory)
    if observed_bytes > MAX_OBSERVED_BYTES:
        return f"observed memory exceeds the {MAX_OBSERVED_BYTES}-byte backend bound"
    decoded = _decode_case(case)
    if isinstance(decoded, str):
        return decoded
    return decoded


def _page_start(address: int) -> int:
    return address & ~(PAGE_SIZE - 1)


def _pages_for(address: int, length: int) -> range:
    first = _page_start(address)
    last = _page_start(address + length - 1)
    return range(first, last + PAGE_SIZE, PAGE_SIZE)


def _permission_bits(permissions: str) -> int:
    bits = 0
    for permission in permissions:
        bits |= _PERMISSION_BITS[permission]
    return bits


def _unicorn_protection(bits: int) -> int:
    assert _unicorn is not None
    protection = 0
    if bits & _PERMISSION_BITS["r"]:
        protection |= _unicorn.UC_PROT_READ
    if bits & _PERMISSION_BITS["w"]:
        protection |= _unicorn.UC_PROT_WRITE
    if bits & _PERMISSION_BITS["x"]:
        protection |= _unicorn.UC_PROT_EXEC
    return protection


def _memory_plan(
    case: InstructionTestCase,
    decoded: _DecodedCase,
) -> tuple[dict[int, int], tuple[_AccessRange, ...], str | None]:
    code_start = case.initial_state.eip
    code_end = code_start + len(case.instruction_bytes)
    ranges = [
        _AccessRange(code_start, code_end, "rx"),
        *(
            _AccessRange(
                region.address,
                region.address + len(region.data),
                region.permissions,
            )
            for region in case.memory
        ),
    ]
    for row in ranges:
        if row.start < _HARNESS_END and _HARNESS_GDT_PAGE < row.end:
            return {}, (), "declared execution state overlaps the CPL3 harness"
    for region in case.memory:
        overlap_start = max(code_start, region.address)
        overlap_end = min(code_end, region.address + len(region.data))
        if overlap_start >= overlap_end:
            continue
        code_slice = case.instruction_bytes[
            overlap_start - code_start : overlap_end - code_start
        ]
        memory_slice = region.data[
            overlap_start - region.address : overlap_end - region.address
        ]
        if code_slice != memory_slice:
            return {}, (), "instruction bytes conflict with declared memory"
        if "x" not in region.permissions:
            return (
                {},
                (),
                "declared memory overlapping the instruction is not executable",
            )
    for mask in case.defined_outputs.memory:
        if not any(
            row.start <= mask.address
            and mask.address + len(mask.mask) <= row.end
            for row in ranges
        ):
            return {}, (), "requested memory observation is outside declared mappings"
    page_permissions: dict[int, int] = {}
    for row in ranges:
        for page in _pages_for(row.start, row.end - row.start):
            page_permissions[page] = page_permissions.get(page, 0) | _permission_bits(
                row.permissions
            )
    landings = _control_landing_addresses(case, decoded)
    if isinstance(landings, str):
        return {}, (), landings
    for landing in landings:
        landing_page = _page_start(landing)
        page_permissions[landing_page] = (
            page_permissions.get(landing_page, 0) | _permission_bits("rx")
        )
        ranges.append(_AccessRange(landing_page, landing_page + PAGE_SIZE, "rx"))
    for page in (
        _HARNESS_GDT_PAGE,
        _HARNESS_TRANSITION_PAGE,
        _HARNESS_TRANSITION_STACK_PAGE,
    ):
        page_permissions[page] = _permission_bits("rwx")
    if len(page_permissions) * PAGE_SIZE > MAX_MAPPED_BYTES + 4 * PAGE_SIZE:
        return {}, (), "page-rounded mappings exceed the bounded backend limit"
    return page_permissions, tuple(ranges), None


def _access_is_permitted(
    ranges: tuple[_AccessRange, ...],
    address: int,
    size: int,
    permission: str,
) -> bool:
    return any(row.permits(address, size, permission) for row in ranges)


def _fault_from_vector(vector: int) -> FaultClass | None:
    return {
        0: FaultClass.DIVIDE_ERROR,
        1: FaultClass.DEBUG,
        3: FaultClass.BREAKPOINT,
        4: FaultClass.OVERFLOW,
        5: FaultClass.BOUNDS,
        6: FaultClass.INVALID_OPCODE,
        7: FaultClass.DEVICE_NOT_AVAILABLE,
        8: FaultClass.DOUBLE_FAULT,
        10: FaultClass.INVALID_TSS,
        11: FaultClass.SEGMENT_NOT_PRESENT,
        12: FaultClass.STACK_SEGMENT,
        13: FaultClass.GENERAL_PROTECTION,
        14: FaultClass.PAGE_FAULT,
        16: FaultClass.X87_FLOATING_POINT,
        17: FaultClass.ALIGNMENT_CHECK,
        18: FaultClass.MACHINE_CHECK,
        19: FaultClass.SIMD_FLOATING_POINT,
    }.get(vector)


def _page_fault_error_numbers() -> set[int]:
    if _unicorn is None:
        return set()
    return {
        value
        for name in (
            "UC_ERR_READ_UNMAPPED",
            "UC_ERR_WRITE_UNMAPPED",
            "UC_ERR_FETCH_UNMAPPED",
            "UC_ERR_READ_PROT",
            "UC_ERR_WRITE_PROT",
            "UC_ERR_FETCH_PROT",
        )
        if isinstance((value := getattr(_unicorn, name, None)), int)
    }


def _register_inventory() -> dict[str, int]:
    assert _unicorn_x86 is not None
    return {
        register: getattr(_unicorn_x86, f"UC_X86_REG_{register.upper()}")
        for register in GPR_NAMES
    }


def _x87_register_inventory() -> dict[str, int] | None:
    if _unicorn_x86 is None:
        return None
    inventory: dict[str, int] = {}
    for register in _X87_REQUIRED_UNICORN_REGISTERS:
        value = getattr(_unicorn_x86, f"UC_X86_REG_{register}", None)
        if not isinstance(value, int):
            return None
        inventory[register] = value
    return inventory


def _x87_word_to_unicorn(value: bytes) -> tuple[int, int]:
    return (
        int.from_bytes(value[:8], "little"),
        int.from_bytes(value[8:], "little"),
    )


def _x87_word_from_unicorn(value: Any) -> bytes:
    if (
        not isinstance(value, tuple)
        or len(value) != 2
        or any(not isinstance(part, int) for part in value)
    ):
        raise ValueError(
            "Unicorn FP register reads must return a (mantissa, exponent) tuple"
        )
    mantissa, exponent = value
    if not 0 <= mantissa < 2**64 or not 0 <= exponent < 2**16:
        raise ValueError("Unicorn FP register read is outside the 80-bit range")
    return mantissa.to_bytes(8, "little") + exponent.to_bytes(2, "little")


def _x87_top(status_word: int) -> int:
    return (status_word >> 11) & 0x7


def _read_x87_core(engine: Any) -> X87State:
    inventory = _x87_register_inventory()
    if inventory is None:
        raise ValueError(
            "Unicorn binding does not expose the required x87 register set"
        )
    control_word = int(engine.reg_read(inventory["FPCW"])) & 0xFFFF
    status_word = int(engine.reg_read(inventory["FPSW"])) & 0xFFFF
    tag_word = int(engine.reg_read(inventory["FPTAG"])) & 0xFFFF
    physical = tuple(
        _x87_word_from_unicorn(engine.reg_read(inventory[f"FP{index}"]))
        for index in range(8)
    )
    top = _x87_top(status_word)
    logical = tuple(physical[(top + index) & 0x7] for index in range(8))
    return X87State(
        control_word=control_word,
        status_word=status_word,
        tag_word=tag_word,
        last_opcode=int(engine.reg_read(inventory["FOP"])) & 0x7FF,
        instruction_pointer=(
            int(engine.reg_read(inventory["FIP"])) & 0xFFFFFFFF
        ),
        data_pointer=int(engine.reg_read(inventory["FDP"])) & 0xFFFFFFFF,
        registers=logical,
    )


def _write_x87_core(engine: Any, state: X87State) -> None:
    inventory = _x87_register_inventory()
    if inventory is None:
        raise ValueError(
            "Unicorn binding does not expose the required x87 register set"
        )
    top = _x87_top(state.status_word)
    physical = [bytes(10) for _ in range(8)]
    for logical_index, value in enumerate(state.registers):
        physical[(top + logical_index) & 0x7] = value
    engine.reg_write(inventory["FPCW"], state.control_word)
    engine.reg_write(inventory["FPSW"], state.status_word)
    engine.reg_write(inventory["FIP"], state.instruction_pointer)
    engine.reg_write(inventory["FDP"], state.data_pointer)
    engine.reg_write(inventory["FOP"], state.last_opcode)
    for index, value in enumerate(physical):
        engine.reg_write(inventory[f"FP{index}"], _x87_word_to_unicorn(value))
    # Unicorn reconstructs non-empty tag classes from the physical FP value.
    engine.reg_write(inventory["FPTAG"], state.tag_word)


def _probe_x87_register_api(engine: Any) -> str | None:
    inventory = _x87_register_inventory()
    if inventory is None:
        missing = [
            name
            for name in _X87_REQUIRED_UNICORN_REGISTERS
            if _unicorn_x86 is None
            or not isinstance(
                getattr(_unicorn_x86, f"UC_X86_REG_{name}", None), int
            )
        ]
        return "missing Unicorn x87 register constants: " + ", ".join(missing)
    probe_registers = tuple(
        (
            0x8000000000000000 | index,
            0x3FFF,
        )
        for index in range(8)
    )
    try:
        engine.reg_write(inventory["FPCW"], 0x027F)
        engine.reg_write(inventory["FPSW"], 3 << 11)
        engine.reg_write(inventory["FIP"], 0x12345678)
        engine.reg_write(inventory["FDP"], 0x9ABCDEF0)
        engine.reg_write(inventory["FOP"], 0x5A5)
        for index, value in enumerate(probe_registers):
            engine.reg_write(inventory[f"FP{index}"], value)
        engine.reg_write(inventory["FPTAG"], 0)
        observed = (
            int(engine.reg_read(inventory["FPCW"])) & 0xFFFF,
            int(engine.reg_read(inventory["FPSW"])) & 0xFFFF,
            int(engine.reg_read(inventory["FPTAG"])) & 0xFFFF,
            int(engine.reg_read(inventory["FIP"])) & 0xFFFFFFFF,
            int(engine.reg_read(inventory["FDP"])) & 0xFFFFFFFF,
            int(engine.reg_read(inventory["FOP"])) & 0x7FF,
            tuple(
                engine.reg_read(inventory[f"FP{index}"])
                for index in range(8)
            ),
        )
    except Exception as exc:
        return f"Unicorn x87 register round-trip raised {type(exc).__name__}: {exc}"
    expected = (
        0x027F,
        3 << 11,
        0,
        0x12345678,
        0x9ABCDEF0,
        0x5A5,
        probe_registers,
    )
    if observed != expected:
        return (
            "Unicorn x87 register round-trip was not exact: "
            f"expected {expected!r}, observed {observed!r}"
        )
    return None


def unicorn_x87_capability_detail(cpu_profile: str = "haswell") -> str:
    """Return an empty string only when Unicorn exactly round-trips x87 core state."""
    if not unicorn_available():
        detail = "Unicorn Python binding is unavailable"
        if _UNICORN_IMPORT_DETAIL:
            detail += f": {_UNICORN_IMPORT_DETAIL}"
        return detail
    try:
        engine = _new_engine(cpu_profile)
    except Exception as exc:
        return f"Unicorn CPU setup is unsupported: {exc}"
    return _probe_x87_register_api(engine) or ""


def _new_engine(cpu_profile: str) -> Any:
    assert _unicorn is not None and _unicorn_x86 is not None
    engine = _unicorn.Uc(_unicorn.UC_ARCH_X86, _unicorn.UC_MODE_32)
    if not hasattr(engine, "ctl_set_cpu_model"):
        raise RuntimeError("Unicorn binding cannot select a CPU model")
    model_name = UNICORN_CPU_PROFILES.get(cpu_profile)
    if model_name is None:
        raise RuntimeError(f"unsupported Unicorn CPU profile {cpu_profile!r}")
    model = getattr(_unicorn_x86, model_name, None)
    if model is None:
        raise RuntimeError(
            f"Unicorn binding does not expose CPU model {model_name}"
        )
    engine.ctl_set_cpu_model(model)
    return engine


def _segment_descriptor(
    *, base: int, limit: int, access: int, flags: int
) -> bytes:
    value = (
        (limit & 0xFFFF)
        | ((base & 0xFFFFFF) << 16)
        | ((access & 0xFF) << 40)
        | (((limit >> 16) & 0xF) << 48)
        | ((flags & 0xF) << 52)
        | (((base >> 24) & 0xFF) << 56)
    )
    return struct.pack("<Q", value)


def _gdt_for_case(case: InstructionTestCase) -> bytes:
    fs = case.initial_state.fs
    fs_index = fs.selector >> 3 if fs.selector else 0
    entry_count = max(5, fs_index + 1)
    entries = [bytes(8) for _ in range(entry_count)]
    entries[1] = _segment_descriptor(
        base=0, limit=0xFFFFF, access=0x9A, flags=0xC
    )
    entries[2] = _segment_descriptor(
        base=0, limit=0xFFFFF, access=0x92, flags=0xC
    )
    entries[_USER_CODE_INDEX] = _segment_descriptor(
        base=0, limit=0xFFFFF, access=0xFA, flags=0xC
    )
    entries[_USER_DATA_INDEX] = _segment_descriptor(
        base=0, limit=0xFFFFF, access=0xF2, flags=0xC
    )
    if fs.selector:
        entries[fs_index] = _segment_descriptor(
            base=fs.base, limit=0xFFFFF, access=0xF2, flags=0xC
        )
    return b"".join(entries)


def _initialize_cpl3(engine: Any, case: InstructionTestCase) -> None:
    assert _unicorn_x86 is not None
    gdt = _gdt_for_case(case)
    transition_eip = _HARNESS_TRANSITION_PAGE
    transition_esp = _HARNESS_END - 5 * 4
    engine.mem_write(_HARNESS_GDT_PAGE, gdt)
    engine.mem_write(transition_eip, b"\xCF")
    engine.mem_write(
        transition_esp,
        struct.pack(
            "<IIIII",
            case.initial_state.eip,
            _USER_CODE_SELECTOR,
            case.initial_state.eflags,
            case.initial_state.gprs.esp,
            _USER_DATA_SELECTOR,
        ),
    )
    engine.reg_write(
        _unicorn_x86.UC_X86_REG_GDTR,
        (0, _HARNESS_GDT_PAGE, len(gdt) - 1, 0),
    )
    for register, selector in (
        (_unicorn_x86.UC_X86_REG_DS, _KERNEL_DATA_SELECTOR),
        (_unicorn_x86.UC_X86_REG_ES, _KERNEL_DATA_SELECTOR),
        (_unicorn_x86.UC_X86_REG_SS, _KERNEL_DATA_SELECTOR),
        (_unicorn_x86.UC_X86_REG_CS, _KERNEL_CODE_SELECTOR),
    ):
        engine.reg_write(register, selector)
    engine.reg_write(_unicorn_x86.UC_X86_REG_ESP, transition_esp)
    engine.reg_write(_unicorn_x86.UC_X86_REG_EIP, transition_eip)
    engine.emu_start(transition_eip, transition_eip + 1, count=1)
    for register in (
        _unicorn_x86.UC_X86_REG_DS,
        _unicorn_x86.UC_X86_REG_ES,
    ):
        engine.reg_write(register, _USER_DATA_SELECTOR)
    engine.reg_write(
        _unicorn_x86.UC_X86_REG_FS, case.initial_state.fs.selector
    )
    observed = (
        int(engine.reg_read(_unicorn_x86.UC_X86_REG_CS)) & 0xFFFF,
        int(engine.reg_read(_unicorn_x86.UC_X86_REG_SS)) & 0xFFFF,
        int(engine.reg_read(_unicorn_x86.UC_X86_REG_FS)) & 0xFFFF,
        int(engine.reg_read(_unicorn_x86.UC_X86_REG_FS_BASE)) & 0xFFFFFFFF,
    )
    expected = (
        _USER_CODE_SELECTOR,
        _USER_DATA_SELECTOR,
        case.initial_state.fs.selector,
        case.initial_state.fs.base,
    )
    if observed != expected:
        raise ValueError(
            "Unicorn CPL3/FS setup did not round-trip exactly: "
            f"expected {expected!r}, observed {observed!r}"
        )


def _initialize_engine(
    engine: Any,
    case: InstructionTestCase,
    page_permissions: dict[int, int],
    *,
    initialize_x87: bool,
) -> None:
    assert _unicorn is not None and _unicorn_x86 is not None
    for page, permissions in sorted(page_permissions.items()):
        engine.mem_map(page, PAGE_SIZE, _unicorn.UC_PROT_ALL)
        engine.mem_protect(page, PAGE_SIZE, _unicorn_protection(permissions))
    for region in case.memory:
        engine.mem_write(region.address, region.data)
    engine.mem_write(case.initial_state.eip, case.instruction_bytes)
    _initialize_cpl3(engine, case)
    for register, unicorn_register in _register_inventory().items():
        engine.reg_write(
            unicorn_register, getattr(case.initial_state.gprs, register)
        )
    engine.reg_write(_unicorn_x86.UC_X86_REG_EIP, case.initial_state.eip)
    engine.reg_write(_unicorn_x86.UC_X86_REG_EFLAGS, case.initial_state.eflags)
    observed_eflags = (
        int(engine.reg_read(_unicorn_x86.UC_X86_REG_EFLAGS)) & 0xFFFFFFFF
    )
    if observed_eflags != case.initial_state.eflags:
        raise ValueError(
            "requested CPL3 EFLAGS state does not round-trip exactly through "
            f"Unicorn: expected 0x{case.initial_state.eflags:08x}, observed "
            f"0x{observed_eflags:08x}"
        )
    if initialize_x87:
        _write_x87_core(engine, case.initial_state.x87)
        observed = _read_x87_core(engine)
        if observed != case.initial_state.x87:
            raise ValueError(
                "requested x87 core state does not round-trip exactly through "
                f"Unicorn: expected {case.initial_state.x87!r}, observed "
                f"{observed!r}"
            )


def _read_final_state(
    engine: Any, case: InstructionTestCase, *, observe_x87: bool
) -> MachineState:
    assert _unicorn_x86 is not None
    gprs = {
        register: int(engine.reg_read(unicorn_register)) & 0xFFFFFFFF
        for register, unicorn_register in _register_inventory().items()
    }
    return MachineState(
        gprs=GPRState(**gprs),
        eip=int(engine.reg_read(_unicorn_x86.UC_X86_REG_EIP)) & 0xFFFFFFFF,
        eflags=int(engine.reg_read(_unicorn_x86.UC_X86_REG_EFLAGS)) & 0xFFFFFFFF,
        fs=FSState(
            selector=int(engine.reg_read(_unicorn_x86.UC_X86_REG_FS)) & 0xFFFF,
            base=(
                int(engine.reg_read(_unicorn_x86.UC_X86_REG_FS_BASE))
                & 0xFFFFFFFF
            ),
        ),
        x87=(
            _read_x87_core(engine)
            if observe_x87
            else case.initial_state.x87
        ),
    )


def _read_observed_memory(
    engine: Any, case: InstructionTestCase
) -> tuple[ObservedMemoryRegion, ...]:
    return tuple(
        ObservedMemoryRegion(
            address=mask.address,
            data=bytes(engine.mem_read(mask.address, len(mask.mask))),
        )
        for mask in case.defined_outputs.memory
    )


def run_unicorn_case(case: InstructionTestCase) -> BackendObservation:
    """Execute exactly one instruction in a fresh Unicorn engine."""
    if not isinstance(case, InstructionTestCase):
        raise ISAConformanceError("case must be an InstructionTestCase")
    try:
        case.to_payload()
    except ISAConformanceError as exc:
        return _error(case, f"invalid typed case supplied to backend: {exc}")
    preflight = _preflight(case)
    if isinstance(preflight, str):
        return _unsupported(case, preflight)
    requires_x87 = (
        preflight.instruction.group(capstone_x86.X86_GRP_FPU)
        or preflight.instruction.mnemonic.lower().startswith("f")
        or not _x87_input_is_canonical(case.initial_state)
        or not _x87_core_outputs_are_unobserved(case)
    )
    if not unicorn_available():
        detail = "Unicorn Python binding is unavailable"
        if _UNICORN_IMPORT_DETAIL:
            detail += f": {_UNICORN_IMPORT_DETAIL}"
        return _unsupported(case, detail)
    page_permissions, access_ranges, memory_issue = _memory_plan(case, preflight)
    if memory_issue is not None:
        return _unsupported(case, memory_issue)
    try:
        engine = _new_engine(case.profile.cpu)
    except Exception as exc:
        return _unsupported(case, f"Unicorn CPU setup is unsupported: {exc}")
    if requires_x87:
        x87_issue = _probe_x87_register_api(engine)
        if x87_issue is not None:
            return _unsupported(
                case,
                f"Unicorn x87 register API is unsupported: {x87_issue}",
            )
    try:
        _initialize_engine(
            engine,
            case,
            page_permissions,
            initialize_x87=requires_x87,
        )
    except _unicorn.UcError as exc:
        return _unsupported(case, f"Unicorn cannot represent the memory layout: {exc}")
    except ValueError as exc:
        return _unsupported(case, f"Unicorn cannot represent the x87 state: {exc}")
    except Exception as exc:
        return _error(case, f"Unicorn harness initialization failed: {exc}")

    access_violation: list[str] = []
    interrupt_vectors: list[int] = []
    repeat_steps = [0]
    repeat_bound_exceeded = [False]
    # Unicorn reports one same-EIP code hook per iteration plus a final hook
    # that retires the completed REP instruction and advances EIP.
    # A large initial count does not imply a long execution: REPE/REPNE scans
    # and compares may stop after the first iteration. Let Unicorn execute such
    # cases, but stop and fail closed if the actual same-EIP hook count reaches
    # the bounded campaign budget.
    repeat_hook_limit = min(
        MAX_REPEAT_ITERATIONS,
        max(1, case.initial_state.gprs.ecx + 1),
    )
    assert _unicorn is not None
    access_permissions = {
        _unicorn.UC_MEM_READ: "r",
        _unicorn.UC_MEM_WRITE: "w",
        _unicorn.UC_MEM_FETCH: "x",
    }

    def check_access(
        hooked_engine: Any,
        access: int,
        address: int,
        size: int,
        _value: int,
        _user_data: Any,
    ) -> None:
        permission = access_permissions.get(access)
        if permission is None or _access_is_permitted(
            access_ranges, address, size, permission
        ):
            return
        access_violation.append(
            f"{permission} access at 0x{address:08x} size {size} is outside "
            "declared byte ranges or permissions"
        )
        hooked_engine.emu_stop()

    def record_interrupt(
        hooked_engine: Any, vector: int, _user_data: Any
    ) -> None:
        interrupt_vectors.append(int(vector))
        hooked_engine.emu_stop()

    def finish_repeat_instruction(
        hooked_engine: Any,
        address: int,
        _size: int,
        _user_data: Any,
    ) -> None:
        if address != case.initial_state.eip:
            hooked_engine.emu_stop()
            return
        if repeat_steps[0] >= repeat_hook_limit:
            repeat_bound_exceeded[0] = True
            hooked_engine.emu_stop()
            return
        repeat_steps[0] += 1

    try:
        engine.hook_add(
            _unicorn.UC_HOOK_MEM_READ
            | _unicorn.UC_HOOK_MEM_WRITE
            | _unicorn.UC_HOOK_MEM_FETCH,
            check_access,
        )
        engine.hook_add(_unicorn.UC_HOOK_INTR, record_interrupt)
        if _is_repeat_instruction(preflight):
            engine.hook_add(_unicorn.UC_HOOK_CODE, finish_repeat_instruction)
            engine.emu_start(case.initial_state.eip, 0xFFFFFFFF)
        else:
            control_target = _decoded_control_target(case, preflight)
            stop_address = (
                control_target
                if control_target is not None
                and control_target != case.initial_state.eip
                else case.initial_state.eip + len(case.instruction_bytes)
            )
            engine.emu_start(
                case.initial_state.eip,
                stop_address,
                count=1,
            )
    except _unicorn.UcError as exc:
        if access_violation:
            return _complete_observation(
                case,
                final_state=None,
                memory=None,
                control=ControlClass.FAULT,
                fault=FaultClass.PAGE_FAULT,
            )
        if interrupt_vectors:
            fault = _fault_from_vector(interrupt_vectors[0])
            if fault is not None:
                return _complete_observation(
                    case,
                    final_state=None,
                    memory=None,
                    control=ControlClass.FAULT,
                    fault=fault,
                )
        if getattr(exc, "errno", None) in _page_fault_error_numbers():
            return _complete_observation(
                case,
                final_state=None,
                memory=None,
                control=ControlClass.FAULT,
                fault=FaultClass.PAGE_FAULT,
            )
        return _unsupported(
            case,
            "Unicorn raised an architectural condition whose fault class is "
            f"not distinguishable: {exc}",
        )
    except Exception as exc:
        return _error(case, f"Unicorn harness execution failed: {exc}")

    if repeat_bound_exceeded[0]:
        return _unsupported(
            case,
            "Unicorn repeat execution exceeded its checked iteration bound",
        )
    if access_violation:
        return _complete_observation(
            case,
            final_state=None,
            memory=None,
            control=ControlClass.FAULT,
            fault=FaultClass.PAGE_FAULT,
        )
    if interrupt_vectors:
        if len(interrupt_vectors) != 1:
            return _unsupported(case, "Unicorn reported multiple interrupt vectors")
        fault = _fault_from_vector(interrupt_vectors[0])
        if fault is None:
            return _unsupported(
                case,
                f"Unicorn interrupt vector {interrupt_vectors[0]} has no fault mapping",
            )
        return _complete_observation(
            case,
            final_state=None,
            memory=None,
            control=ControlClass.FAULT,
            fault=fault,
        )
    try:
        final_state = _read_final_state(
            engine,
            case,
            observe_x87=requires_x87,
        )
        memory = _read_observed_memory(engine, case)
    except Exception as exc:
        return _error(case, f"Unicorn harness observation failed: {exc}")
    return _complete_observation(
        case,
        final_state=final_state,
        memory=memory,
        control=preflight.control,
        fault=FaultClass.NONE,
    )


def run_unicorn_corpus(corpus: ISAConformanceCorpus) -> ISAConformanceReport:
    """Run a corpus with one fresh Unicorn engine per instruction case."""
    if not isinstance(corpus, ISAConformanceCorpus):
        raise ISAConformanceError("corpus must be an ISAConformanceCorpus")
    input_sha256 = isa_conformance_corpus_sha256(corpus)
    observations = tuple(run_unicorn_case(case) for case in corpus.cases)
    counts = ReportCounts(
        cases=len(observations),
        matched=sum(row.status is ObservationStatus.MATCH for row in observations),
        mismatched=sum(
            row.status is ObservationStatus.MISMATCH for row in observations
        ),
        unsupported=sum(
            row.status is ObservationStatus.UNSUPPORTED for row in observations
        ),
        errors=sum(row.status is ObservationStatus.ERROR for row in observations),
    )
    if counts.mismatched:
        qualification = ReportQualification.VETOED
    elif counts.unsupported or counts.errors:
        qualification = ReportQualification.UNQUALIFIED
    else:
        qualification = ReportQualification.QUALIFIED
    report = ISAConformanceReport(
        corpus_id=corpus.id,
        input_sha256=input_sha256,
        backend=unicorn_backend_descriptor(),
        qualification=qualification,
        observations=observations,
        counts=counts,
        trust=ReportTrust(),
    )
    report.to_payload(corpus=corpus)
    return report


__all__ = [
    "MAX_MAPPED_BYTES",
    "MAX_OBSERVED_BYTES",
    "UNICORN_BACKEND_ID",
    "UNICORN_CPU_PROFILES",
    "run_unicorn_case",
    "run_unicorn_corpus",
    "unicorn_available",
    "unicorn_backend_descriptor",
]
