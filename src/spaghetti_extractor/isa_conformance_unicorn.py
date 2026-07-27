"""Bounded Unicorn evidence backend for PE32 ISA conformance cases.

Unicorn is an untrusted concrete oracle.  Results from this module can veto or
qualify an ISA model, but they cannot close any Stage A proof obligation.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
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

_PERMISSION_BITS = {"r": 1, "w": 2, "x": 4}
_CANONICAL_X87_SCALARS = (0x037F, 0, 0xFFFF, 0, 0, 0)
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


def _x87_outputs_are_unobserved(case: InstructionTestCase) -> bool:
    mask = case.defined_outputs.x87
    return (
        mask.control_word == 0
        and mask.status_word == 0
        and mask.tag_word == 0
        and mask.last_opcode == 0
        and mask.instruction_pointer == 0
        and mask.data_pointer == 0
        and _all_zero(mask.registers)
    )


def _fs_outputs_are_unobserved(case: InstructionTestCase) -> bool:
    return (
        case.defined_outputs.fs.selector == 0
        and case.defined_outputs.fs.base == 0
    )


def _instruction_uses_unmodeled_registers(instruction: Any) -> str | None:
    try:
        read_registers, written_registers = instruction.regs_access()
    except capstone.CsError as exc:
        return f"Capstone could not classify register access: {exc}"
    names = {
        instruction.reg_name(register)
        for register in (*read_registers, *written_registers)
    }
    names.discard("")
    unsupported = sorted(names - _MODELED_REGISTER_NAMES)
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
    if 0x64 in instruction.prefix or 0x65 in instruction.prefix:
        return "FS/GS segment overrides are outside the bounded Unicorn profile"
    if instruction.group(capstone_x86.X86_GRP_FPU):
        return "x87 instructions are outside the bounded Unicorn profile"
    if instruction.group(capstone.CS_GRP_PRIVILEGE):
        return "privileged/system instructions are outside the bounded Unicorn profile"
    if mnemonic in _SYSTEM_MNEMONICS:
        return f"system instruction {mnemonic} is outside the bounded Unicorn profile"
    if mnemonic in _FAR_OR_SEGMENT_MNEMONICS:
        return f"far/segment control instruction {mnemonic} is unsupported"
    register_issue = _instruction_uses_unmodeled_registers(instruction)
    if register_issue is not None:
        return register_issue
    control = _classify_control(instruction)
    if control in {ControlClass.INTERRUPT, ControlClass.HALT}:
        return (
            "interrupt, callback, and halt transitions require an "
            "external-state model"
        )
    return _DecodedCase(instruction=instruction, control=control)


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
    if case.initial_state.fs.selector != 0 or case.initial_state.fs.base != 0:
        return "non-flat FS selector/base state is not representable by this backend"
    if not _fs_outputs_are_unobserved(case):
        return "FS output masks are unsupported by this backend"
    if not _x87_input_is_canonical(case.initial_state):
        return "non-canonical x87 input state is unsupported by this backend"
    if not _x87_outputs_are_unobserved(case):
        return "x87 output masks are unsupported by this backend"
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
    if len(page_permissions) * PAGE_SIZE > MAX_MAPPED_BYTES + 2 * PAGE_SIZE:
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


def _initialize_engine(
    engine: Any,
    case: InstructionTestCase,
    page_permissions: dict[int, int],
) -> None:
    assert _unicorn is not None and _unicorn_x86 is not None
    for page, permissions in sorted(page_permissions.items()):
        engine.mem_map(page, PAGE_SIZE, _unicorn.UC_PROT_ALL)
        engine.mem_protect(page, PAGE_SIZE, _unicorn_protection(permissions))
    for region in case.memory:
        engine.mem_write(region.address, region.data)
    engine.mem_write(case.initial_state.eip, case.instruction_bytes)
    for register, unicorn_register in _register_inventory().items():
        engine.reg_write(
            unicorn_register, getattr(case.initial_state.gprs, register)
        )
    engine.reg_write(_unicorn_x86.UC_X86_REG_EIP, case.initial_state.eip)
    engine.reg_write(_unicorn_x86.UC_X86_REG_EFLAGS, case.initial_state.eflags)


def _read_final_state(engine: Any, case: InstructionTestCase) -> MachineState:
    assert _unicorn_x86 is not None
    gprs = {
        register: int(engine.reg_read(unicorn_register)) & 0xFFFFFFFF
        for register, unicorn_register in _register_inventory().items()
    }
    return MachineState(
        gprs=GPRState(**gprs),
        eip=int(engine.reg_read(_unicorn_x86.UC_X86_REG_EIP)) & 0xFFFFFFFF,
        eflags=int(engine.reg_read(_unicorn_x86.UC_X86_REG_EFLAGS)) & 0xFFFFFFFF,
        fs=case.initial_state.fs,
        x87=case.initial_state.x87,
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
    if not unicorn_available():
        detail = "Unicorn Python binding is unavailable"
        if _UNICORN_IMPORT_DETAIL:
            detail += f": {_UNICORN_IMPORT_DETAIL}"
        return _unsupported(case, detail)
    page_permissions, access_ranges, memory_issue = _memory_plan(case)
    if memory_issue is not None:
        return _unsupported(case, memory_issue)
    try:
        engine = _new_engine(case.profile.cpu)
    except Exception as exc:
        return _unsupported(case, f"Unicorn CPU setup is unsupported: {exc}")
    try:
        _initialize_engine(engine, case, page_permissions)
    except _unicorn.UcError as exc:
        return _unsupported(case, f"Unicorn cannot represent the memory layout: {exc}")
    except Exception as exc:
        return _error(case, f"Unicorn harness initialization failed: {exc}")

    access_violation: list[str] = []
    interrupt_vectors: list[int] = []
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

    try:
        engine.hook_add(
            _unicorn.UC_HOOK_MEM_READ
            | _unicorn.UC_HOOK_MEM_WRITE
            | _unicorn.UC_HOOK_MEM_FETCH,
            check_access,
        )
        engine.hook_add(_unicorn.UC_HOOK_INTR, record_interrupt)
        engine.emu_start(
            case.initial_state.eip,
            case.initial_state.eip + len(case.instruction_bytes),
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
        final_state = _read_final_state(engine, case)
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
