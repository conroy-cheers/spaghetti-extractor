"""Reviewed policy for exact-side ISA semantic coverage classification.

The registry is deliberately independent of instruction discovery.  Exact side
ISA artifacts supply Lean-decoded semantic-form strings and bytes; this module
only records which constructor families have been reviewed for a concrete CPU
profile and how much semantic authority the current runtime provides.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from enum import Enum
from typing import Any
import re

from ..stage_binary import StageAInputError


SEMANTIC_COVERAGE_REGISTRY_FORMAT = (
    "stage-a-relational-side-semantic-coverage-registry-v1"
)
DEFAULT_CPU_PROFILE_ID = "pe32-i686-v1"
DEFAULT_REGISTRY_ID = "stage-a-checked-runtime-semantic-coverage-v1"
RUNTIME_HANDLER_PRECEDENCE = (
    "x87-frame",
    "x87-command",
    "ordinary",
    "unsupported",
)

_PROFILE_FIELDS = {
    "id",
    "architecture",
    "cpu",
    "execution_mode",
    "environment",
    "features",
}
_REGISTRY_FIELDS = {
    "format",
    "id",
    "runtime_handler_precedence",
    "cpu_profiles",
    "entries",
}
_ENTRY_FIELDS = {
    "id",
    "constructor",
    "runtime_handler",
    "qualification",
    "qualification_id",
    "cpu_profile_ids",
    "required_features",
    "rationale",
}
_CONSTRUCTOR_RE = re.compile(r"[A-Za-z][A-Za-z0-9]*")


class RuntimeHandler(str, Enum):
    ORDINARY = "ordinary"
    X87_FRAME = "x87-frame"
    X87_COMMAND = "x87-command"
    UNSUPPORTED = "unsupported"


class SemanticQualification(str, Enum):
    QUALIFIED = "qualified"
    RELATIONAL_PARAMETRIC = "relational-parametric"
    STATE_PARTIAL = "state-partial"
    KNOWN_INCORRECT = "known-incorrect"
    PROFILE_AMBIGUOUS = "profile-ambiguous"
    UNSUPPORTED = "unsupported"


class ExactFormShape(str, Enum):
    PURE_REGISTER = "pure-register"
    PURE_STATE = "pure-state"
    MEMORY = "memory"
    STRING_MEMORY = "string-memory"
    CONTROL = "control"
    X87_FRAME = "x87-frame"
    X87_COMMAND = "x87-command"
    UNKNOWN = "unknown"


class SemanticDimensionStatus(str, Enum):
    SUPPORTED = "supported"
    COMPLETE = "complete"
    NOT_APPLICABLE = "not-applicable"
    REQUIRES_PROOF = "requires-proof"
    PARAMETRIC = "parametric"
    PARTIAL = "partial"
    KNOWN_INCORRECT = "known-incorrect"
    PROFILE_AMBIGUOUS = "profile-ambiguous"
    UNSUPPORTED = "unsupported"


def _object(value: Any, context: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise StageAInputError(f"{context} must be an object")
    return value


def _exact_fields(
    value: Mapping[str, Any], expected: set[str], context: str
) -> None:
    if set(value) != expected:
        raise StageAInputError(f"{context} fields are malformed")


def _string(value: Any, context: str) -> str:
    if (
        not isinstance(value, str)
        or not value
        or value.strip() != value
        or any(ord(character) < 0x20 for character in value)
    ):
        raise StageAInputError(f"{context} must be a nonempty printable string")
    return value


def _ordered_strings(
    value: Any, context: str, *, nonempty: bool = False
) -> tuple[str, ...]:
    if not isinstance(value, list):
        raise StageAInputError(f"{context} must be a list")
    result = tuple(
        _string(item, f"{context}[{index}]")
        for index, item in enumerate(value)
    )
    if result != tuple(sorted(set(result))) or (nonempty and not result):
        raise StageAInputError(
            f"{context} must be unique and canonically ordered"
        )
    return result


@dataclass(frozen=True)
class CPUProfile:
    id: str
    architecture: str
    cpu: str
    execution_mode: str
    environment: str
    features: tuple[str, ...]

    @classmethod
    def parse(cls, value: Any) -> "CPUProfile":
        payload = _object(value, "semantic coverage CPU profile")
        _exact_fields(payload, _PROFILE_FIELDS, "semantic coverage CPU profile")
        return cls(
            id=_string(payload["id"], "semantic coverage CPU profile id"),
            architecture=_string(
                payload["architecture"],
                "semantic coverage CPU profile architecture",
            ),
            cpu=_string(payload["cpu"], "semantic coverage CPU"),
            execution_mode=_string(
                payload["execution_mode"],
                "semantic coverage CPU execution mode",
            ),
            environment=_string(
                payload["environment"],
                "semantic coverage CPU environment",
            ),
            features=_ordered_strings(
                payload["features"], "semantic coverage CPU features"
            ),
        )

    def to_payload(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "architecture": self.architecture,
            "cpu": self.cpu,
            "execution_mode": self.execution_mode,
            "environment": self.environment,
            "features": list(self.features),
        }


DEFAULT_CPU_PROFILE = CPUProfile(
    id=DEFAULT_CPU_PROFILE_ID,
    architecture="x86",
    cpu="i686",
    execution_mode="protected-32",
    environment="pe32",
    features=("x87",),
)


@dataclass(frozen=True)
class RegistryEntry:
    id: str
    constructor: str
    runtime_handler: RuntimeHandler
    qualification: SemanticQualification
    qualification_id: str
    cpu_profile_ids: tuple[str, ...]
    required_features: tuple[str, ...]
    rationale: str

    @classmethod
    def parse(cls, value: Any, context: str) -> "RegistryEntry":
        payload = _object(value, context)
        _exact_fields(payload, _ENTRY_FIELDS, context)
        constructor = _string(
            payload["constructor"], f"{context}.constructor"
        )
        if _CONSTRUCTOR_RE.fullmatch(constructor) is None:
            raise StageAInputError(f"{context}.constructor is malformed")
        try:
            runtime_handler = RuntimeHandler(payload["runtime_handler"])
        except (TypeError, ValueError) as exc:
            raise StageAInputError(
                f"{context}.runtime_handler is invalid"
            ) from exc
        try:
            qualification = SemanticQualification(payload["qualification"])
        except (TypeError, ValueError) as exc:
            raise StageAInputError(
                f"{context}.qualification is invalid"
            ) from exc
        if (
            runtime_handler is RuntimeHandler.UNSUPPORTED
            and qualification is not SemanticQualification.UNSUPPORTED
        ):
            raise StageAInputError(
                f"{context} cannot qualify an unsupported runtime handler"
            )
        return cls(
            id=_string(payload["id"], f"{context}.id"),
            constructor=constructor,
            runtime_handler=runtime_handler,
            qualification=qualification,
            qualification_id=_string(
                payload["qualification_id"], f"{context}.qualification_id"
            ),
            cpu_profile_ids=_ordered_strings(
                payload["cpu_profile_ids"],
                f"{context}.cpu_profile_ids",
                nonempty=True,
            ),
            required_features=_ordered_strings(
                payload["required_features"],
                f"{context}.required_features",
            ),
            rationale=_string(payload["rationale"], f"{context}.rationale"),
        )

    def to_payload(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "constructor": self.constructor,
            "runtime_handler": self.runtime_handler.value,
            "qualification": self.qualification.value,
            "qualification_id": self.qualification_id,
            "cpu_profile_ids": list(self.cpu_profile_ids),
            "required_features": list(self.required_features),
            "rationale": self.rationale,
        }


@dataclass(frozen=True)
class SemanticCoverageRegistry:
    id: str
    cpu_profiles: tuple[CPUProfile, ...]
    entries: tuple[RegistryEntry, ...]

    @property
    def cpu_profile_ids(self) -> tuple[str, ...]:
        return tuple(profile.id for profile in self.cpu_profiles)

    @classmethod
    def parse(cls, value: Any) -> "SemanticCoverageRegistry":
        payload = _object(value, "semantic coverage registry")
        _exact_fields(payload, _REGISTRY_FIELDS, "semantic coverage registry")
        if payload["format"] != SEMANTIC_COVERAGE_REGISTRY_FORMAT:
            raise StageAInputError(
                "unsupported semantic coverage registry format"
            )
        if payload["runtime_handler_precedence"] != list(
            RUNTIME_HANDLER_PRECEDENCE
        ):
            raise StageAInputError(
                "semantic coverage runtime handler precedence mismatch"
            )
        raw_profiles = payload["cpu_profiles"]
        if not isinstance(raw_profiles, list) or not raw_profiles:
            raise StageAInputError(
                "semantic coverage registry CPU profiles must be a nonempty list"
            )
        cpu_profiles = tuple(
            CPUProfile.parse(profile) for profile in raw_profiles
        )
        cpu_profile_ids = tuple(profile.id for profile in cpu_profiles)
        if cpu_profile_ids != tuple(sorted(set(cpu_profile_ids))):
            raise StageAInputError(
                "semantic coverage registry CPU profile ids must be unique "
                "and ordered"
            )
        raw_entries = payload["entries"]
        if not isinstance(raw_entries, list) or not raw_entries:
            raise StageAInputError(
                "semantic coverage registry entries must be a nonempty list"
            )
        entries = tuple(
            RegistryEntry.parse(
                entry, f"semantic coverage registry entry {index}"
            )
            for index, entry in enumerate(raw_entries)
        )
        entry_ids = tuple(entry.id for entry in entries)
        constructors = tuple(entry.constructor for entry in entries)
        qualification_ids = tuple(entry.qualification_id for entry in entries)
        if entry_ids != tuple(sorted(set(entry_ids))):
            raise StageAInputError(
                "semantic coverage registry entry ids must be unique and ordered"
            )
        if len(constructors) != len(set(constructors)):
            raise StageAInputError(
                "semantic coverage registry constructors must be unique"
            )
        if len(qualification_ids) != len(set(qualification_ids)):
            raise StageAInputError(
                "semantic coverage qualification ids must be unique"
            )
        if any(
            not set(entry.cpu_profile_ids).issubset(cpu_profile_ids)
            for entry in entries
        ):
            raise StageAInputError(
                "semantic coverage entry references an unknown CPU profile"
            )
        return cls(
            id=_string(payload["id"], "semantic coverage registry id"),
            cpu_profiles=cpu_profiles,
            entries=entries,
        )

    def to_payload(self) -> dict[str, Any]:
        return {
            "format": SEMANTIC_COVERAGE_REGISTRY_FORMAT,
            "id": self.id,
            "runtime_handler_precedence": list(RUNTIME_HANDLER_PRECEDENCE),
            "cpu_profiles": [
                profile.to_payload() for profile in self.cpu_profiles
            ],
            "entries": [entry.to_payload() for entry in self.entries],
        }

    def entry_for(self, constructor: str) -> RegistryEntry | None:
        return next(
            (
                entry
                for entry in self.entries
                if entry.constructor == constructor
            ),
            None,
        )

    def cpu_profile_for(self, profile_id: str) -> CPUProfile | None:
        return next(
            (
                profile
                for profile in self.cpu_profiles
                if profile.id == profile_id
            ),
            None,
        )


_INSTRUCTION_CONSTRUCTORS = (
    "addZero",
    "atomicCompareExchange",
    "binary",
    "binary8",
    "binaryCarry",
    "binaryWidth",
    "bitScan",
    "bitTestRegister",
    "branchCondition",
    "branchEqual",
    "callImport",
    "callIndirect",
    "callRel32",
    "clearDirection",
    "cmpImm",
    "conditionalMove",
    "convertDwordToQuad",
    "convertWordToDword",
    "divideSigned",
    "divideUnsigned",
    "doubleShift",
    "exchange",
    "jumpImport",
    "jumpIndirect",
    "jumpRel32",
    "jumpRel8",
    "lea",
    "leaAddress",
    "leave",
    "load32",
    "movFromOperand",
    "movFromOperand8",
    "movFromOperandWidth",
    "movFs32",
    "movImmediate",
    "movImmediate8",
    "movImmediateWidth",
    "movRegImm",
    "movRegReg",
    "movSignExtend",
    "movSignExtend8",
    "movSignExtend8ToWord",
    "movToOperand",
    "movToOperand8",
    "movToOperandWidth",
    "movZeroExtend",
    "moveDwords",
    "multiplyFull",
    "multiplyLow",
    "nop",
    "popAll",
    "popFlags",
    "popReg",
    "pushAll",
    "pushFlags",
    "pushOperand",
    "pushReg",
    "ret",
    "retPop",
    "setCondition",
    "shift",
    "shift8",
    "shiftWidth",
    "store32",
    "storeDwords",
    "subZero",
    "unary",
    "x87BinaryMemory",
    "x87BinaryStack",
    "x87CompareStack",
    "x87CompareMemory",
    "x87Examine",
    "x87Exchange",
    "x87Initialize",
    "x87LoadConstant",
    "x87LoadControl",
    "x87LoadMemory",
    "x87LoadStack",
    "x87RestoreState",
    "x87SaveState",
    "x87StoreControl",
    "x87StoreMemory",
    "x87StoreStack",
    "x87StoreStatusAx",
    "x87Unary",
    "x87Wait",
    "zeroReg",
)

_QUALIFIED_CONSTRUCTORS = {
    "clearDirection",
    "convertDwordToQuad",
    "convertWordToDword",
    "lea",
    "leaAddress",
    "movRegImm",
    "movRegReg",
    "nop",
    "zeroReg",
}
EXACT_FORM_QUALIFIABLE_CONSTRUCTORS = frozenset(
    {
        "bitScan",
        "doubleShift",
        "shift",
        "shift8",
        "shiftWidth",
    }
)
_RELATIONAL_PARAMETRIC_CONSTRUCTORS = {
    "callImport",
    "callIndirect",
    "jumpImport",
    "jumpIndirect",
}
_X87_FRAME_CONSTRUCTORS = {"x87RestoreState", "x87SaveState"}
_X87_COMMAND_CONSTRUCTORS = {
    "x87BinaryMemory",
    "x87BinaryStack",
    "x87CompareStack",
    "x87CompareMemory",
    "x87Examine",
    "x87Exchange",
    "x87Initialize",
    "x87LoadConstant",
    "x87LoadControl",
    "x87LoadMemory",
    "x87LoadStack",
    "x87StoreControl",
    "x87StoreMemory",
    "x87StoreStack",
    "x87StoreStatusAx",
    "x87Unary",
    "x87Wait",
}


def _default_entry(constructor: str) -> RegistryEntry:
    if constructor in _X87_FRAME_CONSTRUCTORS:
        handler = RuntimeHandler.X87_FRAME
        qualification = SemanticQualification.STATE_PARTIAL
        rationale = (
            "exact 108-byte frame semantics omit segmentation and paging faults"
        )
    elif constructor in _X87_COMMAND_CONSTRUCTORS:
        handler = RuntimeHandler.X87_COMMAND
        qualification = SemanticQualification.RELATIONAL_PARAMETRIC
        rationale = (
            "x87 numeric behavior is an explicit shared Semantics parameter"
        )
    elif constructor in _RELATIONAL_PARAMETRIC_CONSTRUCTORS:
        handler = RuntimeHandler.ORDINARY
        qualification = SemanticQualification.RELATIONAL_PARAMETRIC
        rationale = (
            "control behavior requires a separately related target or environment"
        )
    elif constructor in _QUALIFIED_CONSTRUCTORS:
        handler = RuntimeHandler.ORDINARY
        qualification = SemanticQualification.QUALIFIED
        rationale = "reviewed total register or control-state transition"
    else:
        handler = RuntimeHandler.ORDINARY
        qualification = SemanticQualification.STATE_PARTIAL
        rationale = (
            "the checked semantics leaves architectural state or fault behavior partial"
        )
    slug = re.sub(r"([a-z0-9])([A-Z])", r"\1-\2", constructor).lower()
    return RegistryEntry(
        id=f"semcov-form-{slug}-v1",
        constructor=constructor,
        runtime_handler=handler,
        qualification=qualification,
        qualification_id=f"semcov-q-{qualification.value}-{slug}-v1",
        cpu_profile_ids=(DEFAULT_CPU_PROFILE_ID,),
        required_features=(
            ("x87",)
            if constructor
            in _X87_FRAME_CONSTRUCTORS | _X87_COMMAND_CONSTRUCTORS
            else ()
        ),
        rationale=rationale,
    )


DEFAULT_SEMANTIC_COVERAGE_REGISTRY = SemanticCoverageRegistry.parse(
    {
        "format": SEMANTIC_COVERAGE_REGISTRY_FORMAT,
        "id": DEFAULT_REGISTRY_ID,
        "runtime_handler_precedence": list(RUNTIME_HANDLER_PRECEDENCE),
        "cpu_profiles": [DEFAULT_CPU_PROFILE.to_payload()],
        "entries": [
            entry.to_payload()
            for entry in sorted(
                (
                    _default_entry(constructor)
                    for constructor in _INSTRUCTION_CONSTRUCTORS
                ),
                key=lambda entry: entry.id,
            )
        ],
    }
)


__all__ = [
    "CPUProfile",
    "DEFAULT_CPU_PROFILE",
    "DEFAULT_CPU_PROFILE_ID",
    "DEFAULT_REGISTRY_ID",
    "DEFAULT_SEMANTIC_COVERAGE_REGISTRY",
    "EXACT_FORM_QUALIFIABLE_CONSTRUCTORS",
    "ExactFormShape",
    "RUNTIME_HANDLER_PRECEDENCE",
    "RegistryEntry",
    "RuntimeHandler",
    "SEMANTIC_COVERAGE_REGISTRY_FORMAT",
    "SemanticCoverageRegistry",
    "SemanticDimensionStatus",
    "SemanticQualification",
]
