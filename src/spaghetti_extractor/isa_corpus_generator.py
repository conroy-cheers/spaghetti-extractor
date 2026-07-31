"""Deterministic, effect-class-driven inputs for ISA oracle campaigns.

Generated cases intentionally omit expected final machine states.  Metadata is
an untrusted source of encodings, state-shape constraints, and defined-output
masks; Bochs, Unicorn, hardware, and the Lean evaluator must independently
produce observations before a conformance corpus can be qualified.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, replace
from enum import Enum
import hashlib
import json
from typing import Any

from . import isa_conformance as conformance
from .isa_catalog import (
    AccessMode,
    AddressExpression,
    AddressSegment,
    BranchEffect,
    BranchOutcome,
    DivideEffect,
    EffectClass,
    FixedControlTarget,
    InputPredicate,
    ISA_PROFILE_ID,
    ISAFormCatalog,
    ISAFormCatalogEntry,
    MemoryControlTarget,
    MemoryEffect,
    NoOpEffect,
    PredicateKind,
    RegisterControlTarget,
    RegisterEffect,
    RegisterLocation,
    StateComponent,
    StateEffect,
    X87Effect,
    XEDInstructionCatalog,
    isa_form_catalog_sha256,
)
from .isa_conformance import (
    BackendObservation,
    CaseExpectation,
    CPUProfile,
    ControlClass,
    DefinedOutputMasks,
    ExpectedOutcome,
    FSMask,
    FSState,
    FaultClass,
    GPR_NAMES,
    GPRState,
    ISAConformanceCorpus,
    ISAConformanceError,
    ISAConformanceReport,
    InstructionTestCase,
    MachineState,
    MappedMemoryRegion,
    MemoryMask,
    ObservationStatus,
    ObservedMemoryRegion,
    X87Mask,
    X87State,
)


STRUCTURAL_COVERAGE_CELL_FORMAT = "stage-a-isa-structural-coverage-cell-v1"
BOUNDARY_MACHINE_STATE_CASE_FORMAT = "stage-a-isa-boundary-state-case-v1"
GENERATED_ISA_CORPUS_FORMAT = "stage-a-generated-isa-corpus-v1"

IMAGE_BASE = 0x00400000
TEST_EIP = 0x00401000
DATA_BASE = 0x00600000
# Keep the synthetic FS window inside the shared 16 MiB executor address
# space. The profile validates segmented addressing, not a particular Windows
# TEB address.
FS_BASE = 0x00800000
STACK_POINTER = 0x70001000
DYNAMIC_TARGET_EIP = TEST_EIP + 0x100
SHARED_MEMORY_MIN = 0x00010000
SHARED_MEMORY_END = 0x01000000
MAX_SHARED_MEMORY_REGIONS = 32
MAX_SHARED_MEMORY_BYTES = 65536


class ISACorpusGenerationError(ISAConformanceError):
    """Raised when generic metadata cannot safely instantiate a case."""


class CoverageScenario(str, Enum):
    NOOP_BASELINE = "noop_baseline"
    REGISTER_ZERO = "register_zero"
    REGISTER_ONE = "register_one"
    REGISTER_MAX_UNSIGNED = "register_max_unsigned"
    REGISTER_SIGN_BIT = "register_sign_bit"
    REGISTER_ALTERNATING = "register_alternating"
    MEMORY_ALIGNED_ZERO = "memory_aligned_zero"
    MEMORY_ALIGNED_MAX = "memory_aligned_max"
    MEMORY_PAGE_EDGE = "memory_page_edge"
    MEMORY_CONDITION_FALSE = "memory_condition_false"
    STATE_BASELINE = "state_baseline"
    BRANCH_TAKEN = "branch_taken"
    BRANCH_NOT_TAKEN = "branch_not_taken"
    DIVIDE_SUCCESS = "divide_success"
    DIVIDE_BY_ZERO = "divide_by_zero"
    DIVIDE_QUOTIENT_OVERFLOW = "divide_quotient_overflow"
    X87_ZERO = "x87_zero"
    X87_NORMAL = "x87_normal"
    X87_INFINITY = "x87_infinity"
    X87_NAN = "x87_nan"


@dataclass(frozen=True)
class StructuralCoverageCell:
    form_id: str
    effect_id: str
    effect_class: EffectClass
    scenario: CoverageScenario
    width_bits: int | None
    required_features: tuple[str, ...]
    format: str = STRUCTURAL_COVERAGE_CELL_FORMAT

    @property
    def id(self) -> str:
        return (
            f"{self.form_id}/{self.effect_id}/{self.effect_class.value}/"
            f"{self.scenario.value}"
        )


@dataclass(frozen=True)
class BoundaryMachineStateCase:
    id: str
    form_id: str
    instruction_bytes: bytes
    profile: CPUProfile
    image_base: int
    initial_state: MachineState
    memory: tuple[MappedMemoryRegion, ...]
    defined_outputs: DefinedOutputMasks
    expected: ExpectedOutcome
    coverage_cell: StructuralCoverageCell
    format: str = BOUNDARY_MACHINE_STATE_CASE_FORMAT

    @classmethod
    def parse(cls, value: Any) -> "BoundaryMachineStateCase":
        return parse_boundary_machine_state_case(value)

    def to_payload(self) -> dict[str, Any]:
        return serialize_boundary_machine_state_case(self)


@dataclass(frozen=True)
class GeneratedISACorpus:
    id: str
    catalog_sha256: str
    seed: int
    cases: tuple[BoundaryMachineStateCase, ...]
    profile: str = ISA_PROFILE_ID
    format: str = GENERATED_ISA_CORPUS_FORMAT

    @classmethod
    def parse(cls, value: Any) -> "GeneratedISACorpus":
        return parse_generated_isa_corpus(value)

    def to_payload(self) -> dict[str, Any]:
        return serialize_generated_isa_corpus(self)


@dataclass(frozen=True)
class ExecutorCorpusAdapter:
    generated_corpus_sha256: str
    corpus: ISAConformanceCorpus
    neutral_expectations: bool = True


@dataclass(frozen=True)
class RawBackendCaseObservation:
    case_id: str
    complete: bool
    final_state: MachineState | None
    memory: tuple[ObservedMemoryRegion, ...] | None
    actual: ExpectedOutcome | None
    detail: str


@dataclass(frozen=True)
class RawBackendObservationSet:
    backend_id: str
    generated_corpus_sha256: str
    observations: tuple[RawBackendCaseObservation, ...]
    proof_authority: bool = False


class RawConsensusStatus(str, Enum):
    AGREED = "agreed"
    DISAGREED = "disagreed"
    INCOMPLETE = "incomplete"


@dataclass(frozen=True)
class RawConsensusCase:
    case_id: str
    status: RawConsensusStatus
    backends: tuple[str, ...]


@dataclass(frozen=True)
class RawObservationConsensus:
    generated_corpus_sha256: str
    cases: tuple[RawConsensusCase, ...]
    proof_authority: bool = False


def _object(value: Any, context: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise ISAConformanceError(f"{context} must be an object")
    return value


def _exact_fields(
    payload: Mapping[str, Any], expected: set[str], context: str
) -> None:
    missing = expected - set(payload)
    unknown = set(payload) - expected
    if not missing and not unknown:
        return
    details: list[str] = []
    if missing:
        details.append(f"missing fields {sorted(missing)!r}")
    if unknown:
        details.append(f"unknown fields {sorted(unknown, key=str)!r}")
    raise ISAConformanceError(f"{context} has " + " and ".join(details))


def _string(value: Any, context: str) -> str:
    if not isinstance(value, str) or not value or value.strip() != value:
        raise ISAConformanceError(
            f"{context} must be a non-empty string without surrounding whitespace"
        )
    return value


def _sha256(value: Any, context: str) -> str:
    digest = _string(value, context)
    if len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest):
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


def _enum(enum_type: type[Enum], value: Any, context: str) -> Any:
    try:
        return enum_type(value)
    except (TypeError, ValueError) as exc:
        raise ISAConformanceError(f"{context} is unsupported") from exc


def _cell_payload(cell: StructuralCoverageCell) -> dict[str, Any]:
    return {
        "format": cell.format,
        "form_id": cell.form_id,
        "effect_id": cell.effect_id,
        "effect_class": cell.effect_class.value,
        "scenario": cell.scenario.value,
        "width_bits": cell.width_bits,
        "required_features": list(cell.required_features),
    }


def parse_structural_coverage_cell(value: Any) -> StructuralCoverageCell:
    payload = _object(value, "structural coverage cell")
    _exact_fields(
        payload,
        {
            "format",
            "form_id",
            "effect_id",
            "effect_class",
            "scenario",
            "width_bits",
            "required_features",
        },
        "structural coverage cell",
    )
    if payload.get("format") != STRUCTURAL_COVERAGE_CELL_FORMAT:
        raise ISAConformanceError("unsupported structural coverage cell format")
    effect_class = _enum(
        EffectClass, payload.get("effect_class"), "structural coverage cell.effect_class"
    )
    scenario = _enum(
        CoverageScenario, payload.get("scenario"), "structural coverage cell.scenario"
    )
    if not scenario.value.startswith(effect_class.value + "_"):
        raise ISAConformanceError(
            "structural coverage cell scenario does not match its effect class"
        )
    raw_width = payload.get("width_bits")
    width = (
        None
        if raw_width is None
        else _uint(raw_width, 16, "structural coverage cell.width_bits")
    )
    if effect_class in {EffectClass.REGISTER, EffectClass.DIVIDE}:
        if width not in {8, 16, 32}:
            raise ISAConformanceError(
                "structural coverage cell requires an 8, 16, or 32-bit width"
            )
    elif effect_class is EffectClass.MEMORY:
        if width is None or width < 8 or width % 8:
            raise ISAConformanceError(
                "memory structural coverage cells require a byte-aligned width"
            )
    elif effect_class is EffectClass.X87:
        if width != 80:
            raise ISAConformanceError(
                "x87 structural coverage cells require width_bits=80"
            )
    elif width is not None:
        raise ISAConformanceError(
            "non-data structural coverage cells require width_bits=null"
        )
    raw_features = payload.get("required_features")
    if not isinstance(raw_features, list):
        raise ISAConformanceError(
            "structural coverage cell.required_features must be a list"
        )
    required_features = tuple(
        _string(
            feature,
            f"structural coverage cell.required_features[{index}]",
        )
        for index, feature in enumerate(raw_features)
    )
    if list(required_features) != sorted(set(required_features)):
        raise ISAConformanceError(
            "structural coverage cell.required_features must be unique and "
            "canonically ordered"
        )
    return StructuralCoverageCell(
        form_id=_string(payload.get("form_id"), "structural coverage cell.form_id"),
        effect_id=_string(
            payload.get("effect_id"), "structural coverage cell.effect_id"
        ),
        effect_class=effect_class,
        scenario=scenario,
        width_bits=width,
        required_features=required_features,
    )


def _stable_word(material: bytes, label: str) -> int:
    return int.from_bytes(
        hashlib.sha256(material + b"\0" + label.encode("ascii")).digest()[:4],
        "little",
    )


def _initial_x87(value: bytes | None = None, inputs: int = 0) -> X87State:
    if value is None:
        registers = (bytes(10),) * 8
        tag_word = 0xFFFF
    else:
        registers = tuple(value if index < inputs else bytes(10) for index in range(8))
        if value == bytes(10):
            tag = 0b01
        elif value[-2:] == b"\xff\x7f":
            tag = 0b10
        else:
            tag = 0b00
        tag_word = 0
        for index in range(8):
            tag_word |= (tag if index < inputs else 0b11) << (2 * index)
    return X87State(
        control_word=0x037F,
        status_word=0,
        tag_word=tag_word,
        last_opcode=0,
        instruction_pointer=0,
        data_pointer=0,
        registers=registers,
    )


_X87_VALUES = {
    CoverageScenario.X87_ZERO: bytes(10),
    CoverageScenario.X87_NORMAL: bytes.fromhex("0000000000000080ff3f"),
    CoverageScenario.X87_INFINITY: bytes.fromhex("0000000000000080ff7f"),
    CoverageScenario.X87_NAN: bytes.fromhex("00000000000000c0ff7f"),
}


def _base_state(entry: ISAFormCatalogEntry, seed: int) -> MachineState:
    material = (
        seed.to_bytes(8, "little")
        + entry.form_id.encode("utf-8")
        + entry.instruction_bytes
    )
    values = {
        register: _stable_word(material, register) for register in GPR_NAMES
    }
    values["esp"] = STACK_POINTER
    values["ebp"] = STACK_POINTER + 0x1000
    uses_fs = any(
        (
            isinstance(effect, MemoryEffect)
            and effect.address.segment is AddressSegment.FS
        )
        or (
            isinstance(effect, StateEffect)
            and effect.state is StateComponent.FS
            and effect.access in {AccessMode.READ, AccessMode.READ_WRITE}
        )
        for effect in entry.effects
    )
    return MachineState(
        gprs=GPRState(**values),
        eip=TEST_EIP,
        eflags=0x202,
        fs=(
            FSState(selector=0x3B, base=FS_BASE)
            if uses_fs
            else FSState(selector=0, base=0)
        ),
        x87=_initial_x87(),
    )


def _low_mask(width_bits: int) -> int:
    return (1 << width_bits) - 1


class _RegisterAssignments:
    def __init__(self, initial: GPRState):
        self.initial = {
            register: getattr(initial, register) for register in GPR_NAMES
        }
        self.constraints: dict[str, tuple[int, int, tuple[str, ...]]] = {}

    def constrain(
        self,
        location: RegisterLocation,
        width_bits: int,
        value: int,
        reason: str,
    ) -> None:
        mask = _low_mask(width_bits) << location.lsb
        shifted_value = (value & _low_mask(width_bits)) << location.lsb
        self.constrain_mask(location.register, mask, shifted_value, reason)

    def constrain_mask(
        self, register: str, mask: int, value: int, reason: str
    ) -> None:
        mask &= 0xFFFFFFFF
        value &= mask
        if mask == 0:
            raise ISACorpusGenerationError(
                f"empty state constraint for {register}: {reason}"
            )
        prior_mask, prior_value, prior_reasons = self.constraints.get(
            register, (0, 0, ())
        )
        overlap = prior_mask & mask
        if (prior_value ^ value) & overlap:
            raise ISACorpusGenerationError(
                f"conflicting state constraints for {register}: "
                f"{prior_reasons[-1]} versus {reason}"
            )
        self.constraints[register] = (
            prior_mask | mask,
            (prior_value & ~mask) | value,
            prior_reasons + (reason,),
        )

    def set_default(
        self,
        location: RegisterLocation,
        width_bits: int,
        value: int,
        reason: str,
    ) -> None:
        mask = _low_mask(width_bits) << location.lsb
        prior_mask, _, _ = self.constraints.get(location.register, (0, 0, ()))
        if prior_mask & mask:
            return
        self.constrain(location, width_bits, value, reason)

    def constrained_mask(self, register: str) -> int:
        return self.constraints.get(register, (0, 0, ()))[0]

    def reasons(self, register: str) -> tuple[str, ...]:
        return self.constraints.get(register, (0, 0, ()))[2]

    def value(self, register: str) -> int:
        mask, value, _ = self.constraints.get(register, (0, 0, ()))
        return (self.initial[register] & ~mask) | value

    def constrain_full_compatible(
        self, register: str, preferred: int, reason: str
    ) -> int:
        mask, value, _ = self.constraints.get(register, (0, 0, ()))
        compatible = ((preferred & ~mask) | value) & 0xFFFFFFFF
        self.constrain_mask(register, 0xFFFFFFFF, compatible, reason)
        return compatible

    def finish(self) -> GPRState:
        values = dict(self.initial)
        for register, (mask, value, _) in sorted(self.constraints.items()):
            values[register] = (values[register] & ~mask) | value
        return GPRState(**values)


class _WordAssignments:
    def __init__(self, initial: int, name: str):
        self.initial = initial & 0xFFFFFFFF
        self.name = name
        self.mask = 0
        self.value = 0
        self.reasons: tuple[str, ...] = ()

    def constrain(self, mask: int, value: int, reason: str) -> None:
        mask &= 0xFFFFFFFF
        value &= mask
        if mask == 0:
            raise ISACorpusGenerationError(
                f"empty state constraint for {self.name}: {reason}"
            )
        if (self.value ^ value) & (self.mask & mask):
            raise ISACorpusGenerationError(
                f"conflicting state constraints for {self.name}: "
                f"{self.reasons[-1]} versus {reason}"
            )
        self.value = (self.value & ~mask) | value
        self.mask |= mask
        self.reasons += (reason,)

    def finish(self) -> int:
        return (self.initial & ~self.mask) | self.value


def _register_scenarios() -> tuple[CoverageScenario, ...]:
    return (
        CoverageScenario.REGISTER_ZERO,
        CoverageScenario.REGISTER_ONE,
        CoverageScenario.REGISTER_MAX_UNSIGNED,
        CoverageScenario.REGISTER_SIGN_BIT,
        CoverageScenario.REGISTER_ALTERNATING,
    )


def _scenario_value(scenario: CoverageScenario, width_bits: int) -> int:
    if scenario is CoverageScenario.REGISTER_ZERO:
        return 0
    if scenario is CoverageScenario.REGISTER_ONE:
        return 1
    if scenario is CoverageScenario.REGISTER_MAX_UNSIGNED:
        return _low_mask(width_bits)
    if scenario is CoverageScenario.REGISTER_SIGN_BIT:
        return 1 << (width_bits - 1)
    if scenario is CoverageScenario.REGISTER_ALTERNATING:
        return int("aa" * (width_bits // 8), 16)
    raise AssertionError("not a register scenario")


def _register_locations_overlap(
    left: RegisterLocation,
    left_width: int,
    right: RegisterLocation,
    right_width: int,
) -> bool:
    return (
        left.register == right.register
        and left.lsb < right.lsb + right_width
        and right.lsb < left.lsb + left_width
    )


def _coupled_register_inputs(
    entry: ISAFormCatalogEntry,
) -> tuple[tuple[RegisterLocation, int], ...]:
    coupled: list[tuple[RegisterLocation, int]] = []
    for effect in entry.effects:
        if (
            isinstance(effect, MemoryEffect)
            and effect.condition is not None
            and effect.condition.kind is PredicateKind.REGISTER
        ):
            assert effect.condition.location is not None
            coupled.append(
                (effect.condition.location, effect.condition.width_bits)
            )
        elif isinstance(effect, BranchEffect):
            coupled.extend(
                (outcome.target.location, 32)
                for outcome in effect.outcomes
                if isinstance(outcome.target, RegisterControlTarget)
            )
        elif isinstance(effect, DivideEffect):
            coupled.extend(
                (
                    (effect.dividend_high, effect.width_bits),
                    (effect.dividend_low, effect.width_bits),
                )
            )
            if isinstance(effect.divisor, RegisterLocation):
                coupled.append((effect.divisor, effect.width_bits))
    return tuple(coupled)


def _memory_scenarios(
    effect: MemoryEffect | None = None,
) -> tuple[CoverageScenario, ...]:
    scenarios: tuple[CoverageScenario, ...] = (
        CoverageScenario.MEMORY_ALIGNED_ZERO,
        CoverageScenario.MEMORY_ALIGNED_MAX,
        CoverageScenario.MEMORY_PAGE_EDGE,
    )
    if (
        effect is not None
        and effect.address.base is None
        and effect.address.index is None
    ):
        scenarios = scenarios[:2]
    if effect is not None and effect.condition is not None:
        scenarios += (CoverageScenario.MEMORY_CONDITION_FALSE,)
    return scenarios


def _divide_scenarios() -> tuple[CoverageScenario, ...]:
    return (
        CoverageScenario.DIVIDE_SUCCESS,
        CoverageScenario.DIVIDE_BY_ZERO,
        CoverageScenario.DIVIDE_QUOTIENT_OVERFLOW,
    )


def _x87_scenarios() -> tuple[CoverageScenario, ...]:
    return tuple(_X87_VALUES)


def _branch_scenario(outcome: BranchOutcome) -> CoverageScenario:
    return (
        CoverageScenario.BRANCH_TAKEN
        if outcome.scenario.value == "taken"
        else CoverageScenario.BRANCH_NOT_TAKEN
    )


def _cells(entry: ISAFormCatalogEntry) -> tuple[StructuralCoverageCell, ...]:
    result: list[StructuralCoverageCell] = []
    for effect in entry.effects:
        if isinstance(effect, NoOpEffect):
            scenarios = (CoverageScenario.NOOP_BASELINE,)
            width = None
        elif isinstance(effect, RegisterEffect):
            scenarios = (
                _register_scenarios()
                if effect.reads
                else (CoverageScenario.REGISTER_ZERO,)
            )
            width: int | None = effect.width_bits
        elif isinstance(effect, StateEffect):
            scenarios = (CoverageScenario.STATE_BASELINE,)
            width = None
        elif isinstance(effect, MemoryEffect):
            scenarios = _memory_scenarios(effect)
            width = effect.width_bits
        elif isinstance(effect, BranchEffect):
            scenarios = tuple(_branch_scenario(outcome) for outcome in effect.outcomes)
            width = None
        elif isinstance(effect, DivideEffect):
            scenarios = _divide_scenarios()
            width = effect.width_bits
        elif isinstance(effect, X87Effect):
            scenarios = _x87_scenarios()
            width = 80
        else:
            raise ISACorpusGenerationError(
                f"unsupported effect class for {entry.form_id}"
            )
        result.extend(
            StructuralCoverageCell(
                form_id=entry.form_id,
                effect_id=effect.id,
                effect_class=effect.effect_class,
                scenario=scenario,
                width_bits=width,
                required_features=entry.required_features,
            )
            for scenario in scenarios
        )
    return tuple(result)


def _target_memory_address(effect_index: int, scenario: CoverageScenario, size: int) -> int:
    region_base = DATA_BASE + effect_index * 0x2000
    if scenario is CoverageScenario.MEMORY_PAGE_EDGE:
        return region_base + 0x1000 - size
    return region_base + 0x40


def _address_value(
    assignments: _RegisterAssignments,
    address: AddressExpression,
) -> int:
    segment_base = FS_BASE if address.segment is AddressSegment.FS else 0
    base = 0 if address.base is None else assignments.value(address.base)
    index = 0 if address.index is None else assignments.value(address.index)
    return (
        segment_base
        + base
        + index * address.scale
        + address.displacement
    ) & 0xFFFFFFFF


def _apply_address_constraints(
    assignments: _RegisterAssignments,
    address: AddressExpression,
    preferred: int,
    reason: str,
) -> int:
    segment_base = FS_BASE if address.segment is AddressSegment.FS else 0
    fixed = (segment_base + address.displacement) & 0xFFFFFFFF
    base_full = (
        address.base is not None
        and assignments.constrained_mask(address.base) == 0xFFFFFFFF
    )
    index_full = (
        address.index is not None
        and assignments.constrained_mask(address.index) == 0xFFFFFFFF
    )

    if address.base is not None and not base_full:
        index_value = 0
        if address.index is not None:
            if index_full:
                index_value = assignments.value(address.index)
            else:
                index_value = assignments.constrain_full_compatible(
                    address.index, 0, f"{reason} address index"
                )
        desired_base = (
            preferred - fixed - index_value * address.scale
        ) & 0xFFFFFFFF
        assignments.constrain_full_compatible(
            address.base, desired_base, f"{reason} address base"
        )
    elif address.index is not None and not index_full:
        base_value = (
            0 if address.base is None else assignments.value(address.base)
        )
        delta = (preferred - fixed - base_value) & 0xFFFFFFFF
        if delta % address.scale:
            delta = (delta + address.scale - delta % address.scale) & 0xFFFFFFFF
        assignments.constrain_full_compatible(
            address.index,
            delta // address.scale,
            f"{reason} address index",
        )

    actual = _address_value(assignments, address)
    if actual != preferred:
        semantic_full_registers = [
            register
            for register in (address.base, address.index)
            if register is not None
            and assignments.constrained_mask(register) == 0xFFFFFFFF
            and not any(
                "address" in constraint_reason
                for constraint_reason in assignments.reasons(register)
            )
        ]
        if semantic_full_registers:
            raise ISACorpusGenerationError(
                "conflicting state constraints for memory address "
                + ", ".join(sorted(semantic_full_registers))
            )
    return actual


def _apply_predicate(
    assignments: _RegisterAssignments,
    eflags: _WordAssignments,
    predicate: InputPredicate,
    *,
    satisfied: bool,
    reason: str,
) -> None:
    value = (
        predicate.value
        if satisfied
        else predicate.value ^ (predicate.mask & -predicate.mask)
    )
    if predicate.kind is PredicateKind.EFLAGS:
        eflags.constrain(predicate.mask, value, reason)
        return
    if predicate.location is None:
        raise ISACorpusGenerationError(
            f"{reason} register predicate has no location"
        )
    shifted_mask = predicate.mask << predicate.location.lsb
    shifted_value = value << predicate.location.lsb
    assignments.constrain_mask(
        predicate.location.register,
        shifted_mask,
        shifted_value,
        reason,
    )


def _apply_divide_constraints(
    assignments: _RegisterAssignments,
    effect: DivideEffect,
    scenario: CoverageScenario,
) -> tuple[ExpectedOutcome, int]:
    width = effect.width_bits
    if scenario is CoverageScenario.DIVIDE_SUCCESS:
        high, low, divisor = (
            (0, 9, _low_mask(width) - 2)
            if effect.signed
            else (0, 9, 3)
        )
        outcome = ExpectedOutcome(ControlClass.FALLTHROUGH, FaultClass.NONE)
    elif scenario is CoverageScenario.DIVIDE_BY_ZERO:
        high, low, divisor = (0, 9, 0)
        outcome = ExpectedOutcome(ControlClass.FAULT, FaultClass.DIVIDE_ERROR)
    elif scenario is CoverageScenario.DIVIDE_QUOTIENT_OVERFLOW:
        if effect.signed:
            high, low, divisor = (_low_mask(width), 1 << (width - 1), _low_mask(width))
        else:
            high, low, divisor = (1, 0, 1)
        outcome = ExpectedOutcome(ControlClass.FAULT, FaultClass.DIVIDE_ERROR)
    else:
        raise AssertionError("not a divide scenario")
    assignments.constrain(
        effect.dividend_high, width, high, f"{effect.id} dividend high"
    )
    assignments.constrain(
        effect.dividend_low, width, low, f"{effect.id} dividend low"
    )
    if isinstance(effect.divisor, RegisterLocation):
        assignments.constrain(
            effect.divisor, width, divisor, f"{effect.id} divisor"
        )
    return outcome, divisor


def _defined_outputs(
    entry: ISAFormCatalogEntry,
    memory_masks: tuple[MemoryMask, ...],
    *,
    faulting: bool,
) -> DefinedOutputMasks:
    if faulting:
        return DefinedOutputMasks(
            gprs=GPRState(**{register: 0 for register in GPR_NAMES}),
            eip=0,
            eflags=0,
            fs=FSMask(0, 0),
            x87=X87Mask(
                control_word=0,
                status_word=0,
                tag_word=0,
                last_opcode=0,
                instruction_pointer=0,
                data_pointer=0,
                registers=(bytes(10),) * 8,
            ),
            memory=(),
        )
    return replace(entry.defined_outputs, memory=memory_masks)


@dataclass(frozen=True)
class _MemoryRequest:
    id: str
    width_bits: int
    access: AccessMode
    address: AddressExpression
    scenario: CoverageScenario
    data: bytes | None
    structural_target: bool


def _build_case(
    entry: ISAFormCatalogEntry,
    cell: StructuralCoverageCell,
    *,
    seed: int,
) -> BoundaryMachineStateCase:
    state = _base_state(entry, seed)
    assignments = _RegisterAssignments(state.gprs)
    eflags_assignments = _WordAssignments(state.eflags, "eflags")
    target_effect = next(effect for effect in entry.effects if effect.id == cell.effect_id)

    if isinstance(target_effect, RegisterEffect):
        value = _scenario_value(cell.scenario, target_effect.width_bits)
        coupled_inputs = _coupled_register_inputs(entry)
        for location in target_effect.reads:
            if any(
                _register_locations_overlap(
                    location,
                    target_effect.width_bits,
                    coupled,
                    coupled_width,
                )
                for coupled, coupled_width in coupled_inputs
            ):
                continue
            assignments.constrain(
                location,
                target_effect.width_bits,
                value,
                f"{target_effect.id} {cell.scenario.value}",
            )

    divide_outcome: ExpectedOutcome | None = None
    divide_memory: list[tuple[DivideEffect, int]] = []
    for effect in entry.effects:
        if not isinstance(effect, DivideEffect):
            continue
        scenario = (
            cell.scenario
            if effect is target_effect
            else CoverageScenario.DIVIDE_SUCCESS
        )
        divide_outcome, divisor = _apply_divide_constraints(
            assignments, effect, scenario
        )
        if isinstance(effect.divisor, AddressExpression):
            divide_memory.append((effect, divisor))

    branch_outcome: ExpectedOutcome | None = None
    branch_memory: list[tuple[BranchEffect, MemoryControlTarget]] = []
    for effect in entry.effects:
        if not isinstance(effect, BranchEffect):
            continue
        desired = (
            cell.scenario
            if effect is target_effect
            else _branch_scenario(effect.outcomes[0])
        )
        outcome = next(
            row for row in effect.outcomes if _branch_scenario(row) is desired
        )
        if outcome.eflags_mask:
            eflags_assignments.constrain(
                outcome.eflags_mask,
                outcome.eflags_value,
                f"{effect.id} {desired.value}",
            )
        branch_outcome = ExpectedOutcome(outcome.control, FaultClass.NONE)
        if isinstance(outcome.target, RegisterControlTarget):
            assignments.constrain(
                outcome.target.location,
                32,
                DYNAMIC_TARGET_EIP,
                f"{effect.id} dynamic control target",
            )
        elif isinstance(outcome.target, MemoryControlTarget):
            branch_memory.append((effect, outcome.target))

    memory_requests: list[_MemoryRequest] = []
    inactive_predicate = (
        target_effect.condition
        if (
            isinstance(target_effect, MemoryEffect)
            and target_effect.condition is not None
            and cell.scenario is CoverageScenario.MEMORY_CONDITION_FALSE
        )
        else None
    )
    for effect in entry.effects:
        if not isinstance(effect, MemoryEffect):
            continue
        scenario = (
            cell.scenario
            if effect is target_effect
            else CoverageScenario.MEMORY_ALIGNED_ZERO
        )
        active = not (
            effect.condition is not None
            and effect.condition == inactive_predicate
        )
        if effect.condition is not None:
            _apply_predicate(
                assignments,
                eflags_assignments,
                effect.condition,
                satisfied=active,
                reason=f"{effect.id} memory condition",
            )
        memory_requests.append(
            _MemoryRequest(
                id=effect.id,
                width_bits=effect.width_bits,
                # A false semantic effect can still cause a speculative or
                # architecturally unconditional source read (notably CMOVcc).
                # Provision readable backing without claiming a write.
                access=(effect.access if active else AccessMode.READ),
                address=effect.address,
                scenario=scenario,
                data=None,
                structural_target=effect is target_effect,
            )
        )
    for effect, divisor in divide_memory:
        memory_requests.append(
            _MemoryRequest(
                id=f"{effect.id}/divisor",
                width_bits=effect.width_bits,
                access=AccessMode.READ,
                address=effect.divisor,
                scenario=CoverageScenario.MEMORY_ALIGNED_ZERO,
                data=divisor.to_bytes(effect.width_bits // 8, "little"),
                structural_target=False,
            )
        )
    for effect, target in branch_memory:
        memory_requests.append(
            _MemoryRequest(
                id=f"{effect.id}/target",
                width_bits=32,
                access=AccessMode.READ,
                address=target.address,
                scenario=CoverageScenario.MEMORY_ALIGNED_ZERO,
                data=DYNAMIC_TARGET_EIP.to_bytes(4, "little"),
                structural_target=False,
            )
        )

    memory_rows: list[MappedMemoryRegion] = []
    memory_masks: list[MemoryMask] = []
    memory_ranges: list[tuple[int, int, str]] = []
    request_ids = [request.id for request in memory_requests]
    if len(request_ids) != len(set(request_ids)):
        raise ISACorpusGenerationError(
            "generated memory footprint contains duplicate request IDs"
        )
    if len(memory_requests) > MAX_SHARED_MEMORY_REGIONS:
        raise ISACorpusGenerationError(
            "generated memory footprint exceeds the shared executor region limit"
        )
    if sum(request.width_bits // 8 for request in memory_requests) > (
        MAX_SHARED_MEMORY_BYTES
    ):
        raise ISACorpusGenerationError(
            "generated memory footprint exceeds the shared executor byte limit"
        )
    ordered_requests = sorted(
        memory_requests, key=lambda request: (not request.structural_target, request.id)
    )
    for request_index, request in enumerate(ordered_requests):
        size = request.width_bits // 8
        preferred = _target_memory_address(
            request_index, request.scenario, size
        )
        address = _apply_address_constraints(
            assignments, request.address, preferred, request.id
        )
        if (
            request.scenario is CoverageScenario.MEMORY_PAGE_EDGE
            and address % 0x1000 != 0
            and (address + size) % 0x1000 != 0
        ):
            raise ISACorpusGenerationError(
                f"{request.id} page-edge constraint conflicts with shared state"
            )
        end = address + size
        if end > 2**32:
            raise ISACorpusGenerationError(
                f"{request.id} generated memory range wraps the PE32 address space"
            )
        if address < SHARED_MEMORY_MIN or end > SHARED_MEMORY_END:
            raise ISACorpusGenerationError(
                f"{request.id} generated memory range is outside the shared "
                "executor address window"
            )
        instruction_end = TEST_EIP + len(entry.instruction_bytes)
        if address < instruction_end and TEST_EIP < end:
            raise ISACorpusGenerationError(
                f"{request.id} generated memory overlaps the instruction"
            )
        for prior_start, prior_end, prior_id in memory_ranges:
            if address < prior_end and prior_start < end:
                raise ISACorpusGenerationError(
                    f"generated memory effects {prior_id} and {request.id} overlap"
                )
        memory_ranges.append((address, end, request.id))
        if request.data is not None:
            data = request.data
        else:
            fill = (
                0xFF
                if request.scenario is CoverageScenario.MEMORY_ALIGNED_MAX
                else (request_index * 37 + seed) & 0xFF
                if request.scenario is CoverageScenario.MEMORY_PAGE_EDGE
                else 0
            )
            data = bytes([fill]) * size
        permissions = "r" if request.access is AccessMode.READ else "rw"
        memory_rows.append(MappedMemoryRegion(address, data, permissions))
        if request.access in {AccessMode.WRITE, AccessMode.READ_WRITE}:
            memory_masks.append(MemoryMask(address, bytes([0xFF]) * size))

    for effect in entry.effects:
        if not isinstance(effect, RegisterEffect) or effect is target_effect:
            continue
        for location in effect.reads:
            assignments.set_default(
                location, effect.width_bits, 1, f"{effect.id} baseline"
            )

    x87 = state.x87
    for effect in entry.effects:
        if not isinstance(effect, X87Effect):
            continue
        scenario = (
            cell.scenario if effect is target_effect else CoverageScenario.X87_NORMAL
        )
        x87 = _initial_x87(_X87_VALUES[scenario], effect.stack_inputs)

    state = replace(
        state,
        gprs=assignments.finish(),
        eflags=eflags_assignments.finish(),
        x87=x87,
    )
    expected = (
        divide_outcome
        if divide_outcome is not None and divide_outcome.fault is not FaultClass.NONE
        else branch_outcome
        or divide_outcome
        or ExpectedOutcome(ControlClass.FALLTHROUGH, FaultClass.NONE)
    )
    provisional = BoundaryMachineStateCase(
        id="pending",
        form_id=entry.form_id,
        instruction_bytes=entry.instruction_bytes,
        profile=CPUProfile(
            cpu="i686",
            features=(),
        ),
        image_base=IMAGE_BASE,
        initial_state=state,
        memory=tuple(sorted(memory_rows, key=lambda row: row.address)),
        defined_outputs=_defined_outputs(
            entry,
            tuple(sorted(memory_masks, key=lambda row: row.address)),
            faulting=expected.fault is not FaultClass.NONE,
        ),
        expected=expected,
        coverage_cell=cell,
    )
    return replace(provisional, id=_case_id(provisional))


def _case_payload(case: BoundaryMachineStateCase, *, include_id: bool) -> dict[str, Any]:
    payload = {
        "format": case.format,
        "form_id": case.form_id,
        "instruction_bytes": list(case.instruction_bytes),
        "profile": conformance._profile_payload(case.profile),
        "image_base": case.image_base,
        "initial_state": conformance._machine_state_payload(case.initial_state),
        "memory": [
            {
                "address": region.address,
                "bytes": list(region.data),
                "permissions": region.permissions,
            }
            for region in case.memory
        ],
        "defined_outputs": conformance._defined_outputs_payload(
            case.defined_outputs
        ),
        "expected": conformance._outcome_payload(case.expected),
        "coverage_cell": _cell_payload(case.coverage_cell),
    }
    if include_id:
        return {"id": case.id, **payload}
    return payload


def _case_id(case: BoundaryMachineStateCase) -> str:
    encoded = json.dumps(
        _case_payload(case, include_id=False),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("ascii")
    return "case-" + hashlib.sha256(encoded).hexdigest()


def parse_boundary_machine_state_case(value: Any) -> BoundaryMachineStateCase:
    payload = _object(value, "boundary machine-state case")
    _exact_fields(
        payload,
        {
            "format",
            "id",
            "form_id",
            "instruction_bytes",
            "profile",
            "image_base",
            "initial_state",
            "memory",
            "defined_outputs",
            "expected",
            "coverage_cell",
        },
        "boundary machine-state case",
    )
    if payload.get("format") != BOUNDARY_MACHINE_STATE_CASE_FORMAT:
        raise ISAConformanceError("unsupported boundary machine-state case format")
    raw_bytes = payload.get("instruction_bytes")
    if not isinstance(raw_bytes, list) or not raw_bytes:
        raise ISAConformanceError(
            "boundary machine-state case.instruction_bytes must not be empty"
        )
    instruction_bytes = bytes(
        _uint(value, 8, f"boundary machine-state case.instruction_bytes[{index}]")
        for index, value in enumerate(raw_bytes)
    )
    if len(instruction_bytes) > 15:
        raise ISAConformanceError(
            "boundary machine-state case.instruction_bytes exceeds 15 bytes"
        )
    cell = parse_structural_coverage_cell(payload.get("coverage_cell"))
    case = BoundaryMachineStateCase(
        id=_string(payload.get("id"), "boundary machine-state case.id"),
        form_id=_string(
            payload.get("form_id"), "boundary machine-state case.form_id"
        ),
        instruction_bytes=instruction_bytes,
        profile=conformance._parse_profile(
            payload.get("profile"), "boundary machine-state case.profile"
        ),
        image_base=_uint(
            payload.get("image_base"), 32, "boundary machine-state case.image_base"
        ),
        initial_state=conformance._parse_machine_state(
            payload.get("initial_state"),
            "boundary machine-state case.initial_state",
        ),
        memory=conformance._parse_mapped_memory(
            payload.get("memory"), "boundary machine-state case.memory"
        ),
        defined_outputs=conformance._parse_defined_outputs(
            payload.get("defined_outputs"),
            "boundary machine-state case.defined_outputs",
        ),
        expected=conformance._parse_outcome(
            payload.get("expected"), "boundary machine-state case.expected"
        ),
        coverage_cell=cell,
    )
    if case.form_id != cell.form_id:
        raise ISAConformanceError(
            "boundary machine-state case and coverage cell name different forms"
        )
    if case.profile.cpu != "i686" or case.profile.features:
        raise ISAConformanceError(
            "boundary machine-state case requires the fixed pe32-i686-v1 CPU profile"
        )
    if case.initial_state.eip < case.image_base:
        raise ISAConformanceError(
            "boundary machine-state case initial EIP precedes image base"
        )
    if case.id != _case_id(case):
        raise ISAConformanceError(
            "boundary machine-state case ID does not match canonical case content"
        )
    mapped = {
        (region.address, len(region.data))
        for region in case.memory
        if "w" in region.permissions
    }
    masked = {
        (region.address, len(region.mask)) for region in case.defined_outputs.memory
    }
    if not masked <= mapped:
        raise ISAConformanceError(
            "boundary machine-state case masks memory that is not writable and mapped"
        )
    return case


def serialize_boundary_machine_state_case(
    case: BoundaryMachineStateCase,
) -> dict[str, Any]:
    if not isinstance(case, BoundaryMachineStateCase):
        raise ISAConformanceError("case must be a BoundaryMachineStateCase")
    payload = _case_payload(case, include_id=True)
    if parse_boundary_machine_state_case(payload) != case:
        raise ISAConformanceError("case is not a valid typed instance")
    return payload


def _corpus_id(catalog_sha256: str, seed: int, cases: tuple[BoundaryMachineStateCase, ...]) -> str:
    payload = {
        "catalog_sha256": catalog_sha256,
        "seed": seed,
        "case_ids": [case.id for case in cases],
    }
    encoded = json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("ascii")
    return "generated-" + hashlib.sha256(encoded).hexdigest()


def generate_boundary_isa_corpus(
    catalog: ISAFormCatalog | XEDInstructionCatalog,
    *,
    seed: int = 0,
) -> GeneratedISACorpus:
    """Generate deterministic cases solely from reviewed generic effect classes."""
    if isinstance(catalog, XEDInstructionCatalog):
        raise ISACorpusGenerationError(
            "raw XED templates require concrete encodings and generic effect "
            "descriptors before corpus generation"
        )
    if not isinstance(catalog, ISAFormCatalog):
        raise ISAConformanceError("catalog must be an ISAFormCatalog")
    if isinstance(seed, bool) or not isinstance(seed, int) or not 0 <= seed < 2**64:
        raise ISAConformanceError("seed must be an unsigned 64-bit integer")
    cases = tuple(
        sorted(
            (
                _build_case(entry, cell, seed=seed)
                for entry in catalog.entries
                for cell in _cells(entry)
            ),
            key=lambda case: case.coverage_cell.id,
        )
    )
    catalog_digest = isa_form_catalog_sha256(catalog)
    return GeneratedISACorpus(
        id=_corpus_id(catalog_digest, seed, cases),
        catalog_sha256=catalog_digest,
        seed=seed,
        cases=cases,
    )


def parse_generated_isa_corpus(value: Any) -> GeneratedISACorpus:
    payload = _object(value, "generated ISA corpus")
    _exact_fields(
        payload,
        {"format", "profile", "id", "catalog_sha256", "seed", "cases"},
        "generated ISA corpus",
    )
    if payload.get("format") != GENERATED_ISA_CORPUS_FORMAT:
        raise ISAConformanceError("unsupported generated ISA corpus format")
    if payload.get("profile") != ISA_PROFILE_ID:
        raise ISAConformanceError(
            f"generated ISA corpus.profile must be {ISA_PROFILE_ID}"
        )
    raw_cases = payload.get("cases")
    if not isinstance(raw_cases, list):
        raise ISAConformanceError("generated ISA corpus.cases must be a list")
    cases = tuple(
        parse_boundary_machine_state_case(row) for row in raw_cases
    )
    if not cases:
        raise ISAConformanceError("generated ISA corpus.cases must not be empty")
    cell_ids = [case.coverage_cell.id for case in cases]
    if cell_ids != sorted(set(cell_ids)):
        raise ISAConformanceError(
            "generated ISA corpus cases must have unique canonical coverage cells"
        )
    digest = _sha256(
        payload.get("catalog_sha256"), "generated ISA corpus.catalog_sha256"
    )
    seed = _uint(payload.get("seed"), 64, "generated ISA corpus.seed")
    corpus = GeneratedISACorpus(
        id=_string(payload.get("id"), "generated ISA corpus.id"),
        catalog_sha256=digest,
        seed=seed,
        cases=cases,
    )
    if corpus.id != _corpus_id(digest, seed, cases):
        raise ISAConformanceError(
            "generated ISA corpus ID does not match canonical corpus content"
        )
    return corpus


def serialize_generated_isa_corpus(corpus: GeneratedISACorpus) -> dict[str, Any]:
    if not isinstance(corpus, GeneratedISACorpus):
        raise ISAConformanceError("corpus must be a GeneratedISACorpus")
    payload = {
        "format": corpus.format,
        "profile": corpus.profile,
        "id": corpus.id,
        "catalog_sha256": corpus.catalog_sha256,
        "seed": corpus.seed,
        "cases": [
            serialize_boundary_machine_state_case(case) for case in corpus.cases
        ],
    }
    if parse_generated_isa_corpus(payload) != corpus:
        raise ISAConformanceError("corpus is not a valid typed instance")
    return payload


def canonical_generated_isa_corpus_input(corpus: GeneratedISACorpus) -> bytes:
    return (
        json.dumps(
            serialize_generated_isa_corpus(corpus),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("ascii")
        + b"\n"
    )


def generated_isa_corpus_sha256(corpus: GeneratedISACorpus) -> str:
    return hashlib.sha256(canonical_generated_isa_corpus_input(corpus)).hexdigest()


def _neutral_memory_expectation(
    case: BoundaryMachineStateCase,
) -> tuple[ObservedMemoryRegion, ...]:
    result: list[ObservedMemoryRegion] = []
    for mask in case.defined_outputs.memory:
        source = next(
            (
                region
                for region in case.memory
                if region.address <= mask.address
                and mask.address + len(mask.mask)
                <= region.address + len(region.data)
            ),
            None,
        )
        if source is None:
            raise ISACorpusGenerationError(
                f"{case.id} output mask is not contained in mapped memory"
            )
        offset = mask.address - source.address
        result.append(
            ObservedMemoryRegion(
                address=mask.address,
                data=source.data[offset : offset + len(mask.mask)],
            )
        )
    return tuple(result)


def generated_corpus_executor_input(
    generated: GeneratedISACorpus,
) -> ExecutorCorpusAdapter:
    """Adapt differential inputs to current runners with non-authoritative expectations."""
    if not isinstance(generated, GeneratedISACorpus):
        raise ISAConformanceError("generated must be a GeneratedISACorpus")
    digest = generated_isa_corpus_sha256(generated)
    cases: list[InstructionTestCase] = []
    for generated_case in generated.cases:
        faulting = generated_case.expected.fault is not FaultClass.NONE
        cases.append(
            InstructionTestCase(
                id=generated_case.id,
                instruction_bytes=generated_case.instruction_bytes,
                profile=generated_case.profile,
                image_base=generated_case.image_base,
                initial_state=generated_case.initial_state,
                memory=generated_case.memory,
                defined_outputs=generated_case.defined_outputs,
                expected=CaseExpectation(
                    final_state=None if faulting else generated_case.initial_state,
                    memory=(
                        None
                        if faulting
                        else _neutral_memory_expectation(generated_case)
                    ),
                    control=generated_case.expected.control,
                    fault=generated_case.expected.fault,
                ),
            )
        )
    corpus = ISAConformanceCorpus(
        id="generated-executor-" + digest,
        cases=tuple(cases),
    )
    # Existing runner entry points validate through this serializer.
    conformance.serialize_isa_conformance_corpus(corpus)
    return ExecutorCorpusAdapter(
        generated_corpus_sha256=digest,
        corpus=corpus,
    )


def extract_raw_executor_observations(
    generated: GeneratedISACorpus,
    report: ISAConformanceReport,
) -> RawBackendObservationSet:
    """Preserve runner actuals while discarding neutral expectation status."""
    adapter = generated_corpus_executor_input(generated)
    if not isinstance(report, ISAConformanceReport):
        raise ISAConformanceError("report must be an ISAConformanceReport")
    conformance.serialize_isa_conformance_report(report, corpus=adapter.corpus)
    observations = tuple(
        RawBackendCaseObservation(
            case_id=observation.case_id,
            complete=(
                observation.status
                in {ObservationStatus.MATCH, ObservationStatus.MISMATCH}
                and observation.actual is not None
            ),
            final_state=observation.final_state,
            memory=observation.memory,
            actual=observation.actual,
            detail=observation.detail,
        )
        for observation in report.observations
    )
    return RawBackendObservationSet(
        backend_id=report.backend.id,
        generated_corpus_sha256=adapter.generated_corpus_sha256,
        observations=observations,
    )


def _raw_memory_agrees(
    masks: tuple[MemoryMask, ...],
    left: tuple[ObservedMemoryRegion, ...],
    right: tuple[ObservedMemoryRegion, ...],
) -> bool:
    left_by_range = {
        (region.address, len(region.data)): region.data for region in left
    }
    right_by_range = {
        (region.address, len(region.data)): region.data for region in right
    }
    expected_ranges = {(mask.address, len(mask.mask)) for mask in masks}
    if set(left_by_range) != expected_ranges or set(right_by_range) != expected_ranges:
        return False
    return all(
        conformance._masked_bytes_match(
            left_by_range[(mask.address, len(mask.mask))],
            right_by_range[(mask.address, len(mask.mask))],
            mask.mask,
        )
        for mask in masks
    )


def _raw_case_agrees(
    case: BoundaryMachineStateCase,
    left: RawBackendCaseObservation,
    right: RawBackendCaseObservation,
) -> bool:
    if not left.complete or not right.complete or left.actual != right.actual:
        return False
    if left.final_state is None or right.final_state is None:
        return (
            left.final_state is None
            and right.final_state is None
            and left.memory is None
            and right.memory is None
            and left.actual is not None
            and left.actual.fault is not FaultClass.NONE
        )
    if left.memory is None or right.memory is None:
        return False
    return conformance._machine_state_matches(
        left.final_state, right.final_state, case.defined_outputs
    ) and _raw_memory_agrees(
        case.defined_outputs.memory, left.memory, right.memory
    )


def compare_raw_executor_observations(
    generated: GeneratedISACorpus,
    *reports: ISAConformanceReport,
) -> RawObservationConsensus:
    """Compare backend actuals pointwise; neutral match statuses are irrelevant."""
    if len(reports) < 2:
        raise ISAConformanceError("raw consensus requires at least two backends")
    extracted = tuple(
        extract_raw_executor_observations(generated, report) for report in reports
    )
    backend_ids = tuple(item.backend_id for item in extracted)
    if len(backend_ids) != len(set(backend_ids)):
        raise ISAConformanceError("raw consensus requires unique backend IDs")
    cases_by_id = {case.id: case for case in generated.cases}
    result: list[RawConsensusCase] = []
    for case_id in (case.id for case in generated.cases):
        observations = tuple(
            next(row for row in item.observations if row.case_id == case_id)
            for item in extracted
        )
        if any(not row.complete for row in observations):
            status = RawConsensusStatus.INCOMPLETE
        elif all(
            _raw_case_agrees(cases_by_id[case_id], observations[0], row)
            for row in observations[1:]
        ):
            status = RawConsensusStatus.AGREED
        else:
            status = RawConsensusStatus.DISAGREED
        result.append(
            RawConsensusCase(case_id=case_id, status=status, backends=backend_ids)
        )
    return RawObservationConsensus(
        generated_corpus_sha256=generated_isa_corpus_sha256(generated),
        cases=tuple(result),
    )


__all__ = [
    "BOUNDARY_MACHINE_STATE_CASE_FORMAT",
    "GENERATED_ISA_CORPUS_FORMAT",
    "STRUCTURAL_COVERAGE_CELL_FORMAT",
    "BoundaryMachineStateCase",
    "CoverageScenario",
    "GeneratedISACorpus",
    "ExecutorCorpusAdapter",
    "ISACorpusGenerationError",
    "RawBackendCaseObservation",
    "RawBackendObservationSet",
    "RawConsensusCase",
    "RawConsensusStatus",
    "RawObservationConsensus",
    "StructuralCoverageCell",
    "canonical_generated_isa_corpus_input",
    "compare_raw_executor_observations",
    "extract_raw_executor_observations",
    "generate_boundary_isa_corpus",
    "generated_corpus_executor_input",
    "generated_isa_corpus_sha256",
    "parse_boundary_machine_state_case",
    "parse_generated_isa_corpus",
    "parse_structural_coverage_cell",
    "serialize_boundary_machine_state_case",
    "serialize_generated_isa_corpus",
]
