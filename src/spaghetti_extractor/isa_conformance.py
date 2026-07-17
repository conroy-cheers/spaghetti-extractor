"""Strict, evidence-only models for x86 PE32 ISA conformance corpora.

This module deliberately has no execution-backend dependencies.  A report can
record conformance evidence or veto a backend, but it is never proof authority
for Stage A and can never claim to close a Stage A proof.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from enum import Enum
import hashlib
import json
from typing import Any


ISA_CONFORMANCE_CORPUS_FORMAT = "stage-a-isa-conformance-corpus-v1"
ISA_CONFORMANCE_REPORT_FORMAT = "stage-a-isa-conformance-report-v2"
ISA_CONFORMANCE_TRUST_ROLE = "isa_conformance_evidence_only"
GPR_NAMES = ("eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp")
X87_REGISTER_COUNT = 8
X87_REGISTER_BYTES = 10
MAX_X86_INSTRUCTION_BYTES = 15
_ADDRESS_SPACE_SIZE = 2**32
_MEMORY_PERMISSIONS = {"r", "rw", "rx", "rwx"}


class ISAConformanceError(ValueError):
    """Raised when a corpus or report fails closed schema validation."""


class ControlClass(str, Enum):
    FALLTHROUGH = "fallthrough"
    DIRECT_BRANCH = "direct_branch"
    INDIRECT_BRANCH = "indirect_branch"
    DIRECT_CALL = "direct_call"
    INDIRECT_CALL = "indirect_call"
    RETURN = "return"
    INTERRUPT = "interrupt"
    HALT = "halt"
    FAULT = "fault"


class FaultClass(str, Enum):
    NONE = "none"
    DIVIDE_ERROR = "divide_error"
    DEBUG = "debug"
    BREAKPOINT = "breakpoint"
    OVERFLOW = "overflow"
    BOUNDS = "bounds"
    INVALID_OPCODE = "invalid_opcode"
    DEVICE_NOT_AVAILABLE = "device_not_available"
    DOUBLE_FAULT = "double_fault"
    INVALID_TSS = "invalid_tss"
    SEGMENT_NOT_PRESENT = "segment_not_present"
    STACK_SEGMENT = "stack_segment"
    GENERAL_PROTECTION = "general_protection"
    PAGE_FAULT = "page_fault"
    X87_FLOATING_POINT = "x87_floating_point"
    ALIGNMENT_CHECK = "alignment_check"
    MACHINE_CHECK = "machine_check"
    SIMD_FLOATING_POINT = "simd_floating_point"


class BackendKind(str, Enum):
    ORACLE = "oracle"
    EMULATOR = "emulator"
    HARDWARE = "hardware"
    SEMANTIC_MODEL = "semantic_model"
    IMPLEMENTATION = "implementation"


class ObservationStatus(str, Enum):
    MATCH = "match"
    MISMATCH = "mismatch"
    UNSUPPORTED = "unsupported"
    ERROR = "error"


class ReportQualification(str, Enum):
    QUALIFIED = "qualified"
    UNQUALIFIED = "unqualified"
    VETOED = "vetoed"


@dataclass(frozen=True)
class CPUProfile:
    cpu: str
    features: tuple[str, ...]
    architecture: str = "x86"
    execution_mode: str = "protected-32"
    environment: str = "pe32"


@dataclass(frozen=True)
class GPRState:
    eax: int
    ebx: int
    ecx: int
    edx: int
    esi: int
    edi: int
    ebp: int
    esp: int


@dataclass(frozen=True)
class FSState:
    selector: int
    base: int


@dataclass(frozen=True)
class X87State:
    control_word: int
    status_word: int
    tag_word: int
    last_opcode: int
    instruction_pointer: int
    data_pointer: int
    registers: tuple[bytes, ...]


@dataclass(frozen=True)
class MachineState:
    gprs: GPRState
    eip: int
    eflags: int
    fs: FSState
    x87: X87State


@dataclass(frozen=True)
class MappedMemoryRegion:
    address: int
    data: bytes
    permissions: str


@dataclass(frozen=True)
class FSMask:
    selector: int
    base: int


@dataclass(frozen=True)
class X87Mask:
    control_word: int
    status_word: int
    tag_word: int
    last_opcode: int
    instruction_pointer: int
    data_pointer: int
    registers: tuple[bytes, ...]


@dataclass(frozen=True)
class MemoryMask:
    address: int
    mask: bytes


@dataclass(frozen=True)
class DefinedOutputMasks:
    gprs: GPRState
    eip: int
    eflags: int
    fs: FSMask
    x87: X87Mask
    memory: tuple[MemoryMask, ...]


@dataclass(frozen=True)
class ExpectedOutcome:
    control: ControlClass
    fault: FaultClass


@dataclass(frozen=True)
class CaseExpectation:
    final_state: MachineState | None
    memory: tuple[ObservedMemoryRegion, ...] | None
    control: ControlClass
    fault: FaultClass


@dataclass(frozen=True)
class InstructionTestCase:
    id: str
    instruction_bytes: bytes
    profile: CPUProfile
    image_base: int
    initial_state: MachineState
    memory: tuple[MappedMemoryRegion, ...]
    defined_outputs: DefinedOutputMasks
    expected: CaseExpectation

    @classmethod
    def parse(cls, value: Any) -> "InstructionTestCase":
        return _parse_test_case(value, "instruction test case")

    def to_payload(self) -> dict[str, Any]:
        return _validated_payload(
            self,
            _test_case_payload,
            lambda value: _parse_test_case(value, "instruction test case"),
            "instruction test case",
        )

    def matches(self, observation: "BackendObservation") -> bool:
        """Mechanically compare a complete observation under this case's masks."""
        return observation_matches_case(self, observation)


@dataclass(frozen=True)
class ISAConformanceCorpus:
    id: str
    cases: tuple[InstructionTestCase, ...]
    format: str = ISA_CONFORMANCE_CORPUS_FORMAT

    @classmethod
    def parse(cls, value: Any) -> "ISAConformanceCorpus":
        return parse_isa_conformance_corpus(value)

    def to_payload(self) -> dict[str, Any]:
        return serialize_isa_conformance_corpus(self)


@dataclass(frozen=True)
class BackendDescriptor:
    id: str
    kind: BackendKind
    version: str


@dataclass(frozen=True)
class ObservedMemoryRegion:
    address: int
    data: bytes


@dataclass(frozen=True)
class BackendObservation:
    case_id: str
    status: ObservationStatus
    final_state: MachineState | None
    memory: tuple[ObservedMemoryRegion, ...] | None
    actual: ExpectedOutcome | None
    detail: str

    @classmethod
    def parse(cls, value: Any) -> "BackendObservation":
        return _parse_observation(value, "backend observation")

    def to_payload(self) -> dict[str, Any]:
        return _validated_payload(
            self,
            _observation_payload,
            lambda value: _parse_observation(value, "backend observation"),
            "backend observation",
        )


@dataclass(frozen=True)
class ReportCounts:
    cases: int
    matched: int
    mismatched: int
    unsupported: int
    errors: int


@dataclass(frozen=True)
class ReportTrust:
    role: str = ISA_CONFORMANCE_TRUST_ROLE
    proof_authority: bool = False
    closes_stage_a_proof: bool = False


@dataclass(frozen=True)
class ISAConformanceReport:
    corpus_id: str
    input_sha256: str
    backend: BackendDescriptor
    qualification: ReportQualification
    observations: tuple[BackendObservation, ...]
    counts: ReportCounts
    trust: ReportTrust
    format: str = ISA_CONFORMANCE_REPORT_FORMAT

    @classmethod
    def parse(
        cls,
        value: Any,
        *,
        corpus: ISAConformanceCorpus | None = None,
    ) -> "ISAConformanceReport":
        return parse_isa_conformance_report(value, corpus=corpus)

    def to_payload(
        self,
        *,
        corpus: ISAConformanceCorpus | None = None,
    ) -> dict[str, Any]:
        return serialize_isa_conformance_report(self, corpus=corpus)


def _object(value: Any, context: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise ISAConformanceError(f"{context} must be an object")
    return value


def _objects(value: Any, context: str) -> list[Mapping[str, Any]]:
    if not isinstance(value, list) or any(
        not isinstance(item, Mapping) for item in value
    ):
        raise ISAConformanceError(f"{context} must be a list of objects")
    return list(value)


def _exact_fields(
    payload: Mapping[str, Any], fields: set[str], context: str
) -> None:
    missing = fields - set(payload)
    unknown = set(payload) - fields
    if not missing and not unknown:
        return
    details: list[str] = []
    if missing:
        details.append(
            "missing fields " + repr(sorted(missing, key=lambda item: str(item)))
        )
    if unknown:
        details.append(
            "unknown fields " + repr(sorted(unknown, key=lambda item: str(item)))
        )
    raise ISAConformanceError(f"{context} has " + " and ".join(details))


def _string(value: Any, context: str, *, allow_empty: bool = False) -> str:
    if not isinstance(value, str):
        raise ISAConformanceError(f"{context} must be a string")
    if not allow_empty and (not value or value.strip() != value):
        raise ISAConformanceError(
            f"{context} must be a non-empty string without surrounding whitespace"
        )
    return value


def _sha256(value: Any, context: str) -> str:
    digest = _string(value, context)
    if len(digest) != 64 or any(
        character not in "0123456789abcdef" for character in digest
    ):
        raise ISAConformanceError(f"{context} must be a lowercase SHA-256 digest")
    return digest


def _uint(value: Any, bits: int, context: str) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or not 0 <= value < 2**bits
    ):
        raise ISAConformanceError(f"{context} must be an unsigned {bits}-bit integer")
    return value


def _count(value: Any, context: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ISAConformanceError(f"{context} must be a non-negative integer")
    return value


def _byte_sequence(
    value: Any,
    context: str,
    *,
    allow_empty: bool,
    exact_length: int | None = None,
) -> bytes:
    if not isinstance(value, list):
        raise ISAConformanceError(f"{context} must be a list of byte values")
    if not allow_empty and not value:
        raise ISAConformanceError(f"{context} must not be empty")
    if exact_length is not None and len(value) != exact_length:
        raise ISAConformanceError(
            f"{context} must contain exactly {exact_length} bytes"
        )
    result = bytearray()
    for index, item in enumerate(value):
        if isinstance(item, bool) or not isinstance(item, int) or not 0 <= item <= 255:
            raise ISAConformanceError(
                f"{context}[{index}] must be an integer in the byte range 0..255"
            )
        result.append(item)
    return bytes(result)


def _enum(enum_type: type[Enum], value: Any, context: str) -> Any:
    try:
        return enum_type(value)
    except (TypeError, ValueError) as exc:
        raise ISAConformanceError(f"{context} is unsupported") from exc


def _range_end(address: int, length: int, context: str) -> int:
    end = address + length
    if end > _ADDRESS_SPACE_SIZE:
        raise ISAConformanceError(f"{context} extends beyond the PE32 address space")
    return end


def _reject_overlaps(
    ranges: list[tuple[int, int]], context: str
) -> None:
    ordered = sorted(ranges)
    for previous, current in zip(ordered, ordered[1:]):
        if current[0] < previous[1]:
            raise ISAConformanceError(f"{context} contains overlapping ranges")


def _parse_profile(value: Any, context: str) -> CPUProfile:
    payload = _object(value, context)
    _exact_fields(
        payload,
        {"architecture", "cpu", "execution_mode", "environment", "features"},
        context,
    )
    if payload.get("architecture") != "x86":
        raise ISAConformanceError(f"{context}.architecture must be x86")
    if payload.get("execution_mode") != "protected-32":
        raise ISAConformanceError(
            f"{context}.execution_mode must be protected-32"
        )
    if payload.get("environment") != "pe32":
        raise ISAConformanceError(f"{context}.environment must be pe32")
    cpu = _string(payload.get("cpu"), f"{context}.cpu")
    raw_features = payload.get("features")
    if not isinstance(raw_features, list):
        raise ISAConformanceError(f"{context}.features must be a list")
    features = tuple(
        _string(item, f"{context}.features[{index}]")
        for index, item in enumerate(raw_features)
    )
    if list(features) != sorted(set(features)):
        raise ISAConformanceError(
            f"{context}.features must be unique and canonically ordered"
        )
    return CPUProfile(cpu=cpu, features=features)


def _parse_gprs(value: Any, context: str) -> GPRState:
    payload = _object(value, context)
    _exact_fields(payload, set(GPR_NAMES), context)
    return GPRState(
        **{
            register: _uint(payload.get(register), 32, f"{context}.{register}")
            for register in GPR_NAMES
        }
    )


def _parse_fs(value: Any, context: str) -> FSState:
    payload = _object(value, context)
    _exact_fields(payload, {"selector", "base"}, context)
    return FSState(
        selector=_uint(payload.get("selector"), 16, f"{context}.selector"),
        base=_uint(payload.get("base"), 32, f"{context}.base"),
    )


def _parse_fs_mask(value: Any, context: str) -> FSMask:
    payload = _object(value, context)
    _exact_fields(payload, {"selector", "base"}, context)
    return FSMask(
        selector=_uint(payload.get("selector"), 16, f"{context}.selector"),
        base=_uint(payload.get("base"), 32, f"{context}.base"),
    )


def _parse_x87_registers(value: Any, context: str) -> tuple[bytes, ...]:
    if not isinstance(value, list) or len(value) != X87_REGISTER_COUNT:
        raise ISAConformanceError(
            f"{context} must contain exactly {X87_REGISTER_COUNT} registers"
        )
    return tuple(
        _byte_sequence(
            register,
            f"{context}[{index}]",
            allow_empty=False,
            exact_length=X87_REGISTER_BYTES,
        )
        for index, register in enumerate(value)
    )


_X87_FIELDS = {
    "control_word",
    "status_word",
    "tag_word",
    "last_opcode",
    "instruction_pointer",
    "data_pointer",
    "registers",
}


def _parse_x87(value: Any, context: str) -> X87State:
    payload = _object(value, context)
    _exact_fields(payload, _X87_FIELDS, context)
    return X87State(
        control_word=_uint(payload.get("control_word"), 16, f"{context}.control_word"),
        status_word=_uint(payload.get("status_word"), 16, f"{context}.status_word"),
        tag_word=_uint(payload.get("tag_word"), 16, f"{context}.tag_word"),
        last_opcode=_uint(payload.get("last_opcode"), 11, f"{context}.last_opcode"),
        instruction_pointer=_uint(
            payload.get("instruction_pointer"), 32, f"{context}.instruction_pointer"
        ),
        data_pointer=_uint(
            payload.get("data_pointer"), 32, f"{context}.data_pointer"
        ),
        registers=_parse_x87_registers(
            payload.get("registers"), f"{context}.registers"
        ),
    )


def _parse_x87_mask(value: Any, context: str) -> X87Mask:
    payload = _object(value, context)
    _exact_fields(payload, _X87_FIELDS, context)
    return X87Mask(
        control_word=_uint(payload.get("control_word"), 16, f"{context}.control_word"),
        status_word=_uint(payload.get("status_word"), 16, f"{context}.status_word"),
        tag_word=_uint(payload.get("tag_word"), 16, f"{context}.tag_word"),
        last_opcode=_uint(payload.get("last_opcode"), 11, f"{context}.last_opcode"),
        instruction_pointer=_uint(
            payload.get("instruction_pointer"), 32, f"{context}.instruction_pointer"
        ),
        data_pointer=_uint(
            payload.get("data_pointer"), 32, f"{context}.data_pointer"
        ),
        registers=_parse_x87_registers(
            payload.get("registers"), f"{context}.registers"
        ),
    )


def _parse_machine_state(value: Any, context: str) -> MachineState:
    payload = _object(value, context)
    _exact_fields(payload, {"gprs", "eip", "eflags", "fs", "x87"}, context)
    return MachineState(
        gprs=_parse_gprs(payload.get("gprs"), f"{context}.gprs"),
        eip=_uint(payload.get("eip"), 32, f"{context}.eip"),
        eflags=_uint(payload.get("eflags"), 32, f"{context}.eflags"),
        fs=_parse_fs(payload.get("fs"), f"{context}.fs"),
        x87=_parse_x87(payload.get("x87"), f"{context}.x87"),
    )


def _parse_mapped_memory(value: Any, context: str) -> tuple[MappedMemoryRegion, ...]:
    rows = _objects(value, context)
    result: list[MappedMemoryRegion] = []
    ranges: list[tuple[int, int]] = []
    for index, row in enumerate(rows):
        row_context = f"{context}[{index}]"
        _exact_fields(row, {"address", "bytes", "permissions"}, row_context)
        address = _uint(row.get("address"), 32, f"{row_context}.address")
        data = _byte_sequence(
            row.get("bytes"), f"{row_context}.bytes", allow_empty=False
        )
        permissions = _string(row.get("permissions"), f"{row_context}.permissions")
        if permissions not in _MEMORY_PERMISSIONS:
            raise ISAConformanceError(
                f"{row_context}.permissions must be one of "
                f"{sorted(_MEMORY_PERMISSIONS)}"
            )
        ranges.append((address, _range_end(address, len(data), row_context)))
        result.append(MappedMemoryRegion(address, data, permissions))
    _reject_overlaps(ranges, context)
    return tuple(result)


def _parse_memory_masks(value: Any, context: str) -> tuple[MemoryMask, ...]:
    rows = _objects(value, context)
    result: list[MemoryMask] = []
    ranges: list[tuple[int, int]] = []
    for index, row in enumerate(rows):
        row_context = f"{context}[{index}]"
        _exact_fields(row, {"address", "mask"}, row_context)
        address = _uint(row.get("address"), 32, f"{row_context}.address")
        mask = _byte_sequence(
            row.get("mask"), f"{row_context}.mask", allow_empty=False
        )
        ranges.append((address, _range_end(address, len(mask), row_context)))
        result.append(MemoryMask(address, mask))
    _reject_overlaps(ranges, context)
    return tuple(result)


def _parse_defined_outputs(value: Any, context: str) -> DefinedOutputMasks:
    payload = _object(value, context)
    _exact_fields(
        payload, {"gprs", "eip", "eflags", "fs", "x87", "memory"}, context
    )
    return DefinedOutputMasks(
        gprs=_parse_gprs(payload.get("gprs"), f"{context}.gprs"),
        eip=_uint(payload.get("eip"), 32, f"{context}.eip"),
        eflags=_uint(payload.get("eflags"), 32, f"{context}.eflags"),
        fs=_parse_fs_mask(payload.get("fs"), f"{context}.fs"),
        x87=_parse_x87_mask(payload.get("x87"), f"{context}.x87"),
        memory=_parse_memory_masks(payload.get("memory"), f"{context}.memory"),
    )


def _parse_outcome(value: Any, context: str) -> ExpectedOutcome:
    payload = _object(value, context)
    _exact_fields(payload, {"control", "fault"}, context)
    control = _enum(ControlClass, payload.get("control"), f"{context}.control")
    fault = _enum(FaultClass, payload.get("fault"), f"{context}.fault")
    if (control is ControlClass.FAULT) != (fault is not FaultClass.NONE):
        raise ISAConformanceError(
            f"{context} must use control=fault exactly when a fault class is present"
        )
    return ExpectedOutcome(control=control, fault=fault)


def _parse_test_case(value: Any, context: str) -> InstructionTestCase:
    payload = _object(value, context)
    _exact_fields(
        payload,
        {
            "id",
            "instruction_bytes",
            "profile",
            "image_base",
            "initial_state",
            "memory",
            "defined_outputs",
            "expected",
        },
        context,
    )
    case_id = _string(payload.get("id"), f"{context}.id")
    instruction_bytes = _byte_sequence(
        payload.get("instruction_bytes"),
        f"{context}.instruction_bytes",
        allow_empty=False,
    )
    if len(instruction_bytes) > MAX_X86_INSTRUCTION_BYTES:
        raise ISAConformanceError(
            f"{context}.instruction_bytes exceeds the x86 15-byte limit"
        )
    initial_state = _parse_machine_state(
        payload.get("initial_state"), f"{context}.initial_state"
    )
    image_base = _uint(payload.get("image_base"), 32, f"{context}.image_base")
    if initial_state.eip < image_base:
        raise ISAConformanceError(
            f"{context}.initial_state.eip must not precede image_base"
        )
    _range_end(initial_state.eip, len(instruction_bytes), f"{context}.instruction")
    test_case = InstructionTestCase(
        id=case_id,
        instruction_bytes=instruction_bytes,
        profile=_parse_profile(payload.get("profile"), f"{context}.profile"),
        image_base=image_base,
        initial_state=initial_state,
        memory=_parse_mapped_memory(payload.get("memory"), f"{context}.memory"),
        defined_outputs=_parse_defined_outputs(
            payload.get("defined_outputs"), f"{context}.defined_outputs"
        ),
        expected=_parse_case_expectation(
            payload.get("expected"), f"{context}.expected"
        ),
    )
    _validate_case_expectation(test_case, context)
    return test_case


def parse_isa_conformance_corpus(value: Any) -> ISAConformanceCorpus:
    """Parse a complete, versioned corpus and reject every ambiguous field."""
    payload = _object(value, "ISA conformance corpus")
    _exact_fields(payload, {"format", "id", "cases"}, "ISA conformance corpus")
    if payload.get("format") != ISA_CONFORMANCE_CORPUS_FORMAT:
        raise ISAConformanceError("unsupported ISA conformance corpus format")
    corpus_id = _string(payload.get("id"), "ISA conformance corpus.id")
    cases = tuple(
        _parse_test_case(row, f"ISA conformance corpus.cases[{index}]")
        for index, row in enumerate(
            _objects(payload.get("cases"), "ISA conformance corpus.cases")
        )
    )
    if not cases:
        raise ISAConformanceError("ISA conformance corpus.cases must not be empty")
    case_ids = [case.id for case in cases]
    if len(case_ids) != len(set(case_ids)):
        raise ISAConformanceError("ISA conformance corpus contains duplicate case IDs")
    return ISAConformanceCorpus(id=corpus_id, cases=cases)


def canonical_isa_conformance_corpus_input(corpus: ISAConformanceCorpus) -> bytes:
    """Return the canonical full-corpus bytes consumed by execution backends."""
    if not isinstance(corpus, ISAConformanceCorpus):
        raise ISAConformanceError("corpus must be an ISAConformanceCorpus")
    encoded = json.dumps(
        corpus.to_payload(),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("ascii")
    return encoded + b"\n"


def isa_conformance_corpus_sha256(corpus: ISAConformanceCorpus) -> str:
    """Identify every byte of a canonical ISA conformance corpus input."""
    return hashlib.sha256(canonical_isa_conformance_corpus_input(corpus)).hexdigest()


def _parse_backend(value: Any, context: str) -> BackendDescriptor:
    payload = _object(value, context)
    _exact_fields(payload, {"id", "kind", "version"}, context)
    return BackendDescriptor(
        id=_string(payload.get("id"), f"{context}.id"),
        kind=_enum(BackendKind, payload.get("kind"), f"{context}.kind"),
        version=_string(payload.get("version"), f"{context}.version"),
    )


def _parse_observed_memory(
    value: Any, context: str
) -> tuple[ObservedMemoryRegion, ...]:
    rows = _objects(value, context)
    result: list[ObservedMemoryRegion] = []
    ranges: list[tuple[int, int]] = []
    for index, row in enumerate(rows):
        row_context = f"{context}[{index}]"
        _exact_fields(row, {"address", "bytes"}, row_context)
        address = _uint(row.get("address"), 32, f"{row_context}.address")
        data = _byte_sequence(
            row.get("bytes"), f"{row_context}.bytes", allow_empty=False
        )
        ranges.append((address, _range_end(address, len(data), row_context)))
        result.append(ObservedMemoryRegion(address, data))
    _reject_overlaps(ranges, context)
    return tuple(result)


def _parse_case_expectation(value: Any, context: str) -> CaseExpectation:
    payload = _object(value, context)
    _exact_fields(payload, {"final_state", "memory", "control", "fault"}, context)
    outcome = _parse_outcome(
        {"control": payload.get("control"), "fault": payload.get("fault")},
        context,
    )
    raw_final_state = payload.get("final_state")
    raw_memory = payload.get("memory")
    return CaseExpectation(
        final_state=(
            _parse_machine_state(raw_final_state, f"{context}.final_state")
            if raw_final_state is not None
            else None
        ),
        memory=(
            _parse_observed_memory(raw_memory, f"{context}.memory")
            if raw_memory is not None
            else None
        ),
        control=outcome.control,
        fault=outcome.fault,
    )


def _machine_masks_are_zero(masks: DefinedOutputMasks) -> bool:
    gprs_zero = all(getattr(masks.gprs, register) == 0 for register in GPR_NAMES)
    x87_scalars_zero = all(
        value == 0
        for value in (
            masks.x87.control_word,
            masks.x87.status_word,
            masks.x87.tag_word,
            masks.x87.last_opcode,
            masks.x87.instruction_pointer,
            masks.x87.data_pointer,
        )
    )
    return (
        gprs_zero
        and masks.eip == 0
        and masks.eflags == 0
        and masks.fs.selector == 0
        and masks.fs.base == 0
        and x87_scalars_zero
        and all(not any(register) for register in masks.x87.registers)
    )


def _memory_inventory(
    regions: tuple[ObservedMemoryRegion, ...],
) -> list[tuple[int, int]]:
    return sorted((region.address, len(region.data)) for region in regions)


def _mask_inventory(masks: tuple[MemoryMask, ...]) -> list[tuple[int, int]]:
    return sorted((region.address, len(region.mask)) for region in masks)


def _validate_case_expectation(case: InstructionTestCase, context: str) -> None:
    state_is_null = case.expected.final_state is None
    memory_is_null = case.expected.memory is None
    if state_is_null != memory_is_null:
        raise ISAConformanceError(
            f"{context} expected final_state and memory must both be null or both "
            "be present"
        )
    if case.expected.fault is FaultClass.NONE and state_is_null:
        raise ISAConformanceError(
            f"{context} non-fault expectation requires final state and memory"
        )
    if state_is_null:
        if not _machine_masks_are_zero(case.defined_outputs):
            raise ISAConformanceError(
                f"{context} null expected final state requires zero state masks"
            )
        if case.defined_outputs.memory:
            raise ISAConformanceError(
                f"{context} null expected memory requires no memory masks"
            )
        return
    assert case.expected.memory is not None
    if _memory_inventory(case.expected.memory) != _mask_inventory(
        case.defined_outputs.memory
    ):
        raise ISAConformanceError(
            f"{context} expected memory must exactly match the memory-mask inventory"
        )


def _masked_word_matches(expected: int, observed: int, mask: int) -> bool:
    return ((expected ^ observed) & mask) == 0


def _masked_bytes_match(expected: bytes, observed: bytes, mask: bytes) -> bool:
    return len(expected) == len(observed) == len(mask) and all(
        ((expected_byte ^ observed_byte) & mask_byte) == 0
        for expected_byte, observed_byte, mask_byte in zip(expected, observed, mask)
    )


def _machine_state_matches(
    expected: MachineState,
    observed: MachineState,
    masks: DefinedOutputMasks,
) -> bool:
    if any(
        not _masked_word_matches(
            getattr(expected.gprs, register),
            getattr(observed.gprs, register),
            getattr(masks.gprs, register),
        )
        for register in GPR_NAMES
    ):
        return False
    scalar_words = (
        (expected.eip, observed.eip, masks.eip),
        (expected.eflags, observed.eflags, masks.eflags),
        (expected.fs.selector, observed.fs.selector, masks.fs.selector),
        (expected.fs.base, observed.fs.base, masks.fs.base),
        (
            expected.x87.control_word,
            observed.x87.control_word,
            masks.x87.control_word,
        ),
        (
            expected.x87.status_word,
            observed.x87.status_word,
            masks.x87.status_word,
        ),
        (expected.x87.tag_word, observed.x87.tag_word, masks.x87.tag_word),
        (
            expected.x87.last_opcode,
            observed.x87.last_opcode,
            masks.x87.last_opcode,
        ),
        (
            expected.x87.instruction_pointer,
            observed.x87.instruction_pointer,
            masks.x87.instruction_pointer,
        ),
        (
            expected.x87.data_pointer,
            observed.x87.data_pointer,
            masks.x87.data_pointer,
        ),
    )
    if any(
        not _masked_word_matches(expected_word, observed_word, mask)
        for expected_word, observed_word, mask in scalar_words
    ):
        return False
    return all(
        _masked_bytes_match(expected_register, observed_register, mask)
        for expected_register, observed_register, mask in zip(
            expected.x87.registers,
            observed.x87.registers,
            masks.x87.registers,
        )
    )


def _observed_memory_matches(
    expected: tuple[ObservedMemoryRegion, ...],
    observed: tuple[ObservedMemoryRegion, ...],
    masks: tuple[MemoryMask, ...],
) -> bool:
    if _memory_inventory(expected) != _memory_inventory(observed):
        return False
    expected_by_address = {region.address: region.data for region in expected}
    observed_by_address = {region.address: region.data for region in observed}
    return all(
        _masked_bytes_match(
            expected_by_address[mask.address],
            observed_by_address[mask.address],
            mask.mask,
        )
        for mask in masks
    )


def observation_matches_case(
    case: InstructionTestCase,
    observation: BackendObservation,
) -> bool:
    """Return the masked, mechanical result for one complete observation."""
    if not isinstance(case, InstructionTestCase):
        raise ISAConformanceError("case must be an InstructionTestCase")
    if not isinstance(observation, BackendObservation):
        raise ISAConformanceError("observation must be a BackendObservation")
    if observation.status not in {
        ObservationStatus.MATCH,
        ObservationStatus.MISMATCH,
    }:
        raise ISAConformanceError(
            "only complete match or mismatch observations can be compared"
        )
    if observation.case_id != case.id or observation.actual is None:
        return False
    if (
        observation.actual.control is not case.expected.control
        or observation.actual.fault is not case.expected.fault
    ):
        return False
    if case.expected.final_state is None:
        return observation.final_state is None and observation.memory is None
    if observation.final_state is None or observation.memory is None:
        return False
    assert case.expected.memory is not None
    return _machine_state_matches(
        case.expected.final_state,
        observation.final_state,
        case.defined_outputs,
    ) and _observed_memory_matches(
        case.expected.memory,
        observation.memory,
        case.defined_outputs.memory,
    )


def _parse_observation(value: Any, context: str) -> BackendObservation:
    payload = _object(value, context)
    _exact_fields(
        payload,
        {"case_id", "status", "final_state", "memory", "actual", "detail"},
        context,
    )
    case_id = _string(payload.get("case_id"), f"{context}.case_id")
    status = _enum(ObservationStatus, payload.get("status"), f"{context}.status")
    detail = _string(payload.get("detail"), f"{context}.detail", allow_empty=True)
    if status in {ObservationStatus.MATCH, ObservationStatus.MISMATCH}:
        if payload.get("actual") is None:
            raise ISAConformanceError(
                f"{context}.actual is required for a complete observation"
            )
        actual = _parse_outcome(payload.get("actual"), f"{context}.actual")
        state_is_null = payload.get("final_state") is None
        memory_is_null = payload.get("memory") is None
        if state_is_null != memory_is_null:
            raise ISAConformanceError(
                f"{context}.final_state and memory must both be null or both be present"
            )
        if actual.fault is FaultClass.NONE and state_is_null:
            raise ISAConformanceError(
                f"{context} non-fault observation requires final state and memory"
            )
        return BackendObservation(
            case_id=case_id,
            status=status,
            final_state=(
                _parse_machine_state(
                    payload.get("final_state"), f"{context}.final_state"
                )
                if not state_is_null
                else None
            ),
            memory=(
                _parse_observed_memory(
                    payload.get("memory"), f"{context}.memory"
                )
                if not memory_is_null
                else None
            ),
            actual=actual,
            detail=detail,
        )
    if any(
        payload.get(field) is not None
        for field in ("final_state", "memory", "actual")
    ):
        raise ISAConformanceError(
            f"{context} must use null outputs for unsupported or error status"
        )
    if not detail:
        raise ISAConformanceError(
            f"{context}.detail must explain unsupported or error status"
        )
    return BackendObservation(
        case_id=case_id,
        status=status,
        final_state=None,
        memory=None,
        actual=None,
        detail=detail,
    )


def _parse_counts(value: Any, context: str) -> ReportCounts:
    payload = _object(value, context)
    fields = {"cases", "matched", "mismatched", "unsupported", "errors"}
    _exact_fields(payload, fields, context)
    return ReportCounts(
        cases=_count(payload.get("cases"), f"{context}.cases"),
        matched=_count(payload.get("matched"), f"{context}.matched"),
        mismatched=_count(payload.get("mismatched"), f"{context}.mismatched"),
        unsupported=_count(payload.get("unsupported"), f"{context}.unsupported"),
        errors=_count(payload.get("errors"), f"{context}.errors"),
    )


def _expected_counts(observations: tuple[BackendObservation, ...]) -> ReportCounts:
    return ReportCounts(
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


def _expected_qualification(
    observations: tuple[BackendObservation, ...]
) -> ReportQualification:
    if any(row.status is ObservationStatus.MISMATCH for row in observations):
        return ReportQualification.VETOED
    if any(row.status is not ObservationStatus.MATCH for row in observations):
        return ReportQualification.UNQUALIFIED
    return ReportQualification.QUALIFIED


def _parse_trust(value: Any, context: str, backend_kind: BackendKind) -> ReportTrust:
    payload = _object(value, context)
    _exact_fields(
        payload, {"role", "proof_authority", "closes_stage_a_proof"}, context
    )
    if payload.get("role") != ISA_CONFORMANCE_TRUST_ROLE:
        raise ISAConformanceError(f"{context}.role is unsupported")
    if payload.get("proof_authority") is not False:
        if backend_kind is BackendKind.ORACLE:
            raise ISAConformanceError("oracle report cannot claim proof authority")
        raise ISAConformanceError("ISA conformance report cannot claim proof authority")
    if payload.get("closes_stage_a_proof") is not False:
        if backend_kind is BackendKind.ORACLE:
            raise ISAConformanceError("oracle report cannot close a Stage A proof")
        raise ISAConformanceError("ISA conformance report cannot close a Stage A proof")
    return ReportTrust()


def parse_isa_conformance_report(
    value: Any,
    *,
    corpus: ISAConformanceCorpus | None = None,
) -> ISAConformanceReport:
    """Parse an aggregate report while preserving its evidence-only trust role."""
    if corpus is not None and not isinstance(corpus, ISAConformanceCorpus):
        raise ISAConformanceError("corpus must be an ISAConformanceCorpus")
    payload = _object(value, "ISA conformance report")
    _exact_fields(
        payload,
        {
            "format",
            "corpus_id",
            "input_sha256",
            "backend",
            "qualification",
            "observations",
            "counts",
            "trust",
        },
        "ISA conformance report",
    )
    if payload.get("format") != ISA_CONFORMANCE_REPORT_FORMAT:
        raise ISAConformanceError("unsupported ISA conformance report format")
    corpus_id = _string(payload.get("corpus_id"), "ISA conformance report.corpus_id")
    input_sha256 = _sha256(
        payload.get("input_sha256"), "ISA conformance report.input_sha256"
    )
    backend = _parse_backend(payload.get("backend"), "ISA conformance report.backend")
    observations = tuple(
        _parse_observation(row, f"ISA conformance report.observations[{index}]")
        for index, row in enumerate(
            _objects(
                payload.get("observations"), "ISA conformance report.observations"
            )
        )
    )
    if not observations:
        raise ISAConformanceError(
            "ISA conformance report.observations must not be empty"
        )
    observation_ids = [row.case_id for row in observations]
    if len(observation_ids) != len(set(observation_ids)):
        raise ISAConformanceError("ISA conformance report contains duplicate case IDs")
    counts = _parse_counts(payload.get("counts"), "ISA conformance report.counts")
    if counts != _expected_counts(observations):
        raise ISAConformanceError(
            "ISA conformance report.counts do not match its observations"
        )
    qualification = _enum(
        ReportQualification,
        payload.get("qualification"),
        "ISA conformance report.qualification",
    )
    trust = _parse_trust(
        payload.get("trust"), "ISA conformance report.trust", backend.kind
    )
    complete_observations = tuple(
        observation
        for observation in observations
        if observation.status
        in {ObservationStatus.MATCH, ObservationStatus.MISMATCH}
    )
    if corpus is None:
        if complete_observations:
            raise ISAConformanceError(
                "corpus is required to verify match or mismatch observations"
            )
    else:
        if corpus_id != corpus.id:
            raise ISAConformanceError("ISA conformance report names the wrong corpus")
        if input_sha256 != isa_conformance_corpus_sha256(corpus):
            raise ISAConformanceError(
                "ISA conformance report.input_sha256 does not match the canonical corpus input"
            )
        case_ids = {case.id for case in corpus.cases}
        if set(observation_ids) != case_ids:
            raise ISAConformanceError(
                "ISA conformance report must contain exactly one observation per case"
            )
        cases_by_id = {case.id: case for case in corpus.cases}
        for observation in complete_observations:
            mechanically_matches = observation_matches_case(
                cases_by_id[observation.case_id], observation
            )
            claims_match = observation.status is ObservationStatus.MATCH
            if claims_match != mechanically_matches:
                raise ISAConformanceError(
                    f"observation {observation.case_id!r} status contradicts "
                    "the corpus expectation"
                )
    if qualification is not _expected_qualification(observations):
        raise ISAConformanceError(
            "ISA conformance report.qualification does not match verified results"
        )
    return ISAConformanceReport(
        corpus_id=corpus_id,
        input_sha256=input_sha256,
        backend=backend,
        qualification=qualification,
        observations=observations,
        counts=counts,
        trust=trust,
    )


def _profile_payload(profile: CPUProfile) -> dict[str, Any]:
    return {
        "architecture": profile.architecture,
        "cpu": profile.cpu,
        "execution_mode": profile.execution_mode,
        "environment": profile.environment,
        "features": list(profile.features),
    }


def _gprs_payload(gprs: GPRState) -> dict[str, Any]:
    return {register: getattr(gprs, register) for register in GPR_NAMES}


def _fs_payload(fs: FSState | FSMask) -> dict[str, Any]:
    return {"selector": fs.selector, "base": fs.base}


def _x87_payload(x87: X87State | X87Mask) -> dict[str, Any]:
    return {
        "control_word": x87.control_word,
        "status_word": x87.status_word,
        "tag_word": x87.tag_word,
        "last_opcode": x87.last_opcode,
        "instruction_pointer": x87.instruction_pointer,
        "data_pointer": x87.data_pointer,
        "registers": [list(register) for register in x87.registers],
    }


def _machine_state_payload(state: MachineState) -> dict[str, Any]:
    return {
        "gprs": _gprs_payload(state.gprs),
        "eip": state.eip,
        "eflags": state.eflags,
        "fs": _fs_payload(state.fs),
        "x87": _x87_payload(state.x87),
    }


def _defined_outputs_payload(masks: DefinedOutputMasks) -> dict[str, Any]:
    return {
        "gprs": _gprs_payload(masks.gprs),
        "eip": masks.eip,
        "eflags": masks.eflags,
        "fs": _fs_payload(masks.fs),
        "x87": _x87_payload(masks.x87),
        "memory": [
            {"address": region.address, "mask": list(region.mask)}
            for region in masks.memory
        ],
    }


def _outcome_payload(outcome: ExpectedOutcome) -> dict[str, Any]:
    return {"control": outcome.control.value, "fault": outcome.fault.value}


def _observed_memory_payload(
    memory: tuple[ObservedMemoryRegion, ...],
) -> list[dict[str, Any]]:
    return [
        {"address": region.address, "bytes": list(region.data)}
        for region in memory
    ]


def _case_expectation_payload(expected: CaseExpectation) -> dict[str, Any]:
    return {
        "final_state": (
            _machine_state_payload(expected.final_state)
            if expected.final_state is not None
            else None
        ),
        "memory": (
            _observed_memory_payload(expected.memory)
            if expected.memory is not None
            else None
        ),
        "control": expected.control.value,
        "fault": expected.fault.value,
    }


def _test_case_payload(case: InstructionTestCase) -> dict[str, Any]:
    return {
        "id": case.id,
        "instruction_bytes": list(case.instruction_bytes),
        "profile": _profile_payload(case.profile),
        "image_base": case.image_base,
        "initial_state": _machine_state_payload(case.initial_state),
        "memory": [
            {
                "address": region.address,
                "bytes": list(region.data),
                "permissions": region.permissions,
            }
            for region in case.memory
        ],
        "defined_outputs": _defined_outputs_payload(case.defined_outputs),
        "expected": _case_expectation_payload(case.expected),
    }


def _observation_payload(observation: BackendObservation) -> dict[str, Any]:
    return {
        "case_id": observation.case_id,
        "status": observation.status.value,
        "final_state": (
            _machine_state_payload(observation.final_state)
            if observation.final_state is not None
            else None
        ),
        "memory": (
            _observed_memory_payload(observation.memory)
            if observation.memory is not None
            else None
        ),
        "actual": (
            _outcome_payload(observation.actual)
            if observation.actual is not None
            else None
        ),
        "detail": observation.detail,
    }


def _validated_payload(
    instance: Any,
    payload_builder: Any,
    parser: Any,
    context: str,
) -> dict[str, Any]:
    try:
        payload = payload_builder(instance)
    except (AttributeError, TypeError, ValueError) as exc:
        raise ISAConformanceError(f"{context} is not a valid typed instance") from exc
    if parser(payload) != instance:
        raise ISAConformanceError(f"{context} is not a valid typed instance")
    return payload


def serialize_isa_conformance_corpus(
    corpus: ISAConformanceCorpus,
) -> dict[str, Any]:
    """Serialize and revalidate a typed corpus."""
    if not isinstance(corpus, ISAConformanceCorpus):
        raise ISAConformanceError("corpus must be an ISAConformanceCorpus")

    def payload_builder(value: ISAConformanceCorpus) -> dict[str, Any]:
        return {
            "format": value.format,
            "id": value.id,
            "cases": [_test_case_payload(case) for case in value.cases],
        }

    return _validated_payload(
        corpus,
        payload_builder,
        parse_isa_conformance_corpus,
        "ISA conformance corpus",
    )


def serialize_isa_conformance_report(
    report: ISAConformanceReport,
    *,
    corpus: ISAConformanceCorpus | None = None,
) -> dict[str, Any]:
    """Serialize and revalidate an evidence-only aggregate report."""
    if not isinstance(report, ISAConformanceReport):
        raise ISAConformanceError("report must be an ISAConformanceReport")

    def payload_builder(value: ISAConformanceReport) -> dict[str, Any]:
        return {
            "format": value.format,
            "corpus_id": value.corpus_id,
            "input_sha256": value.input_sha256,
            "backend": {
                "id": value.backend.id,
                "kind": value.backend.kind.value,
                "version": value.backend.version,
            },
            "qualification": value.qualification.value,
            "observations": [
                _observation_payload(observation)
                for observation in value.observations
            ],
            "counts": {
                "cases": value.counts.cases,
                "matched": value.counts.matched,
                "mismatched": value.counts.mismatched,
                "unsupported": value.counts.unsupported,
                "errors": value.counts.errors,
            },
            "trust": {
                "role": value.trust.role,
                "proof_authority": value.trust.proof_authority,
                "closes_stage_a_proof": value.trust.closes_stage_a_proof,
            },
        }

    return _validated_payload(
        report,
        payload_builder,
        lambda payload: parse_isa_conformance_report(payload, corpus=corpus),
        "ISA conformance report",
    )


# Concise aliases for callers that already know they are in this module.
parse_corpus = parse_isa_conformance_corpus
serialize_corpus = serialize_isa_conformance_corpus
parse_report = parse_isa_conformance_report
serialize_report = serialize_isa_conformance_report


__all__ = [
    "BackendDescriptor",
    "BackendKind",
    "BackendObservation",
    "CPUProfile",
    "CaseExpectation",
    "ControlClass",
    "DefinedOutputMasks",
    "ExpectedOutcome",
    "FSMask",
    "FSState",
    "FaultClass",
    "GPRState",
    "ISA_CONFORMANCE_CORPUS_FORMAT",
    "ISA_CONFORMANCE_REPORT_FORMAT",
    "ISA_CONFORMANCE_TRUST_ROLE",
    "ISAConformanceCorpus",
    "ISAConformanceError",
    "ISAConformanceReport",
    "InstructionTestCase",
    "MachineState",
    "MappedMemoryRegion",
    "MemoryMask",
    "ObservationStatus",
    "ObservedMemoryRegion",
    "ReportCounts",
    "ReportQualification",
    "ReportTrust",
    "X87Mask",
    "X87State",
    "canonical_isa_conformance_corpus_input",
    "isa_conformance_corpus_sha256",
    "observation_matches_case",
    "parse_corpus",
    "parse_isa_conformance_corpus",
    "parse_isa_conformance_report",
    "parse_report",
    "serialize_corpus",
    "serialize_isa_conformance_corpus",
    "serialize_isa_conformance_report",
    "serialize_report",
]
