"""Finite immutable lattice facts for interprocedural fixed points.

The domains in this module do not use ``None`` as an abstract value.  Absence,
finite knowledge, unbounded knowledge, exact facts, and conflicts all have
distinct runtime types.
"""

from __future__ import annotations

import dataclasses
import enum
import math
from collections.abc import Callable, Hashable, Iterable, Mapping
from dataclasses import dataclass
from typing import Any, Generic, TypeVar, cast


ValueT = TypeVar("ValueT", bound=Hashable)
CleanupT = TypeVar("CleanupT")
ResultT = TypeVar("ResultT")
ExactT = TypeVar("ExactT")
LabelT = TypeVar("LabelT", bound=Hashable)


def _stable_token(value: object) -> tuple[object, ...]:
    if value is None:
        return ("none",)
    if isinstance(value, bool):
        return ("bool", int(value))
    if isinstance(value, int):
        return ("int", value)
    if isinstance(value, float):
        if math.isnan(value):
            return ("float", "nan")
        if math.isinf(value):
            return ("float", "inf" if value > 0 else "-inf")
        return ("float", value.hex())
    if isinstance(value, str):
        return ("str", value)
    if isinstance(value, bytes):
        return ("bytes", value.hex())
    if isinstance(value, enum.Enum):
        return (
            "enum",
            type(value).__module__,
            type(value).__qualname__,
            _stable_token(value.value),
        )
    if isinstance(value, (tuple, list)):
        return ("sequence", *(_stable_token(item) for item in value))
    if isinstance(value, (set, frozenset)):
        return ("set", *sorted(_stable_token(item) for item in value))
    if isinstance(value, Mapping):
        return (
            "mapping",
            *sorted(
                (_stable_token(key), _stable_token(item))
                for key, item in value.items()
            ),
        )
    if dataclasses.is_dataclass(value) and not isinstance(value, type):
        return (
            "dataclass",
            type(value).__module__,
            type(value).__qualname__,
            *(
                (field.name, _stable_token(getattr(value, field.name)))
                for field in dataclasses.fields(value)
            ),
        )
    raise TypeError(
        f"no deterministic projection for {type(value).__qualname__}; "
        "supply a projector"
    )


def deterministic_projection(value: object) -> Any:
    """Project common immutable values into a deterministic JSON-safe shape."""

    if value is None or isinstance(value, (bool, int, str)):
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError("non-finite floats are not JSON-safe")
        return value
    if isinstance(value, bytes):
        return value.hex()
    if isinstance(value, enum.Enum):
        return deterministic_projection(value.value)
    if isinstance(value, (tuple, list)):
        return [deterministic_projection(item) for item in value]
    if isinstance(value, (set, frozenset)):
        projected = [deterministic_projection(item) for item in value]
        return sorted(projected, key=_stable_token)
    if isinstance(value, Mapping):
        if all(isinstance(key, str) for key in value):
            return {
                key: deterministic_projection(value[key])
                for key in sorted(cast(Iterable[str], value))
            }
        pairs = [
            [deterministic_projection(key), deterministic_projection(item)]
            for key, item in value.items()
        ]
        return sorted(pairs, key=_stable_token)
    if dataclasses.is_dataclass(value) and not isinstance(value, type):
        return {
            field.name: deterministic_projection(getattr(value, field.name))
            for field in dataclasses.fields(value)
        }
    raise TypeError(
        f"no deterministic projection for {type(value).__qualname__}; "
        "supply a projector"
    )


class MayValue(Generic[ValueT]):
    """Base class for the explicit bottom/finite/top may-value lattice."""

    @property
    def complete(self) -> bool:
        return not isinstance(self, Top)

    def join(
        self, other: MayValue[ValueT], *, maximum: int
    ) -> MayValue[ValueT]:
        return bounded_may_join(self, other, maximum=maximum)

    def leq(self, other: MayValue[ValueT]) -> bool:
        return may_leq(self, other)

    def project(
        self, projector: Callable[[ValueT], Any] = deterministic_projection
    ) -> dict[str, Any]:
        return project_may_value(self, projector=projector)

    def to_projection(
        self, projector: Callable[[ValueT], Any] = deterministic_projection
    ) -> dict[str, Any]:
        return self.project(projector)


@dataclass(frozen=True)
class Bottom(MayValue[ValueT]):
    """No may-value contribution has been observed."""


@dataclass(frozen=True)
class Finite(MayValue[ValueT]):
    """A non-empty, explicitly finite set of possible values."""

    values: frozenset[ValueT]

    def __post_init__(self) -> None:
        object.__setattr__(self, "values", frozenset(self.values))
        if not self.values:
            raise ValueError("an empty finite set is Bottom, not Finite")

    @classmethod
    def of(cls, values: Iterable[ValueT]) -> MayValue[ValueT]:
        materialized = frozenset(values)
        return cls(materialized) if materialized else Bottom()


@dataclass(frozen=True)
class Top(MayValue[ValueT]):
    """Unbounded or overflowed may-values; projections are incomplete."""


def finite(values: Iterable[ValueT]) -> MayValue[ValueT]:
    """Canonicalize an iterable to Bottom or a non-empty Finite value."""

    return Finite.of(values)


def bounded_may_join(
    left: MayValue[ValueT],
    right: MayValue[ValueT],
    *,
    maximum: int,
) -> MayValue[ValueT]:
    """Join may-values, promoting a finite overflow to explicit Top."""

    if isinstance(maximum, bool) or maximum <= 0:
        raise ValueError("maximum must be positive")
    if isinstance(left, Top) or isinstance(right, Top):
        return Top()
    values = frozenset(
        (left.values if isinstance(left, Finite) else frozenset())
        | (right.values if isinstance(right, Finite) else frozenset())
    )
    if len(values) > maximum:
        return Top()
    return Finite(values) if values else Bottom()


def may_leq(left: MayValue[ValueT], right: MayValue[ValueT]) -> bool:
    if isinstance(left, Bottom) or isinstance(right, Top):
        return True
    if isinstance(left, Top):
        return isinstance(right, Top)
    if isinstance(right, Bottom):
        return False
    if not isinstance(left, Finite) or not isinstance(right, Finite):
        raise TypeError("unsupported may-value lattice variant")
    return left.values <= right.values


def project_may_value(
    value: MayValue[ValueT],
    *,
    projector: Callable[[ValueT], Any] = deterministic_projection,
) -> dict[str, Any]:
    if isinstance(value, Bottom):
        return {"kind": "bottom", "complete": True}
    if isinstance(value, Top):
        return {"kind": "top", "complete": False}
    if not isinstance(value, Finite):
        raise TypeError("unsupported may-value lattice variant")
    projected = [projector(item) for item in value.values]
    return {
        "kind": "finite",
        "complete": True,
        "values": sorted(projected, key=_stable_token),
    }


@dataclass(frozen=True)
class MustPreservedRegisters:
    """Registers preserved on every observed path; combination is meet."""

    registers: frozenset[str]

    def __post_init__(self) -> None:
        normalized = frozenset(str(register).lower() for register in self.registers)
        if any(not register for register in normalized):
            raise ValueError("register names must be non-empty")
        object.__setattr__(self, "registers", normalized)

    def meet(self, other: MustPreservedRegisters) -> MustPreservedRegisters:
        return MustPreservedRegisters(self.registers & other.registers)

    def join(self, other: MustPreservedRegisters) -> MustPreservedRegisters:
        """Information-order join, equal to must-property set intersection."""

        return self.meet(other)

    def leq(self, other: MustPreservedRegisters) -> bool:
        return self.registers >= other.registers

    def project(self) -> dict[str, Any]:
        return {"kind": "must", "registers": sorted(self.registers)}

    to_projection = project


class ExactOrConflict(Generic[ExactT]):
    """Base class for no-fact, one-exact-fact, or conflicting facts."""

    @property
    def complete(self) -> bool:
        return not isinstance(self, Conflict)

    def join(self, other: ExactOrConflict[ExactT]) -> ExactOrConflict[ExactT]:
        return exact_join(self, other)

    def leq(self, other: ExactOrConflict[ExactT]) -> bool:
        return exact_leq(self, other)

    def project(
        self, projector: Callable[[ExactT], Any] = deterministic_projection
    ) -> dict[str, Any]:
        return project_exact(self, projector=projector)

    def to_projection(
        self, projector: Callable[[ExactT], Any] = deterministic_projection
    ) -> dict[str, Any]:
        return self.project(projector)


@dataclass(frozen=True)
class NoExactValue(ExactOrConflict[ExactT]):
    """No exact contribution has been observed."""


@dataclass(frozen=True)
class Exact(ExactOrConflict[ExactT]):
    value: ExactT


@dataclass(frozen=True)
class Conflict(ExactOrConflict[ExactT]):
    """At least two incompatible exact contributions were observed."""


def exact_join(
    left: ExactOrConflict[ExactT], right: ExactOrConflict[ExactT]
) -> ExactOrConflict[ExactT]:
    if isinstance(left, Conflict) or isinstance(right, Conflict):
        return Conflict()
    if isinstance(left, NoExactValue):
        return right
    if isinstance(right, NoExactValue):
        return left
    if not isinstance(left, Exact) or not isinstance(right, Exact):
        raise TypeError("unsupported exact lattice variant")
    return left if left.value == right.value else Conflict()


def exact_leq(
    left: ExactOrConflict[ExactT], right: ExactOrConflict[ExactT]
) -> bool:
    if isinstance(left, NoExactValue) or isinstance(right, Conflict):
        return True
    if isinstance(left, Conflict):
        return isinstance(right, Conflict)
    if isinstance(right, NoExactValue):
        return False
    if not isinstance(left, Exact) or not isinstance(right, Exact):
        raise TypeError("unsupported exact lattice variant")
    return left.value == right.value


def project_exact(
    value: ExactOrConflict[ExactT],
    *,
    projector: Callable[[ExactT], Any] = deterministic_projection,
) -> dict[str, Any]:
    if isinstance(value, NoExactValue):
        return {"kind": "bottom", "complete": True}
    if isinstance(value, Conflict):
        return {"kind": "conflict", "complete": False}
    if not isinstance(value, Exact):
        raise TypeError("unsupported exact lattice variant")
    return {
        "kind": "exact",
        "complete": True,
        "value": projector(value.value),
    }


@dataclass(frozen=True)
class ReturnBehavior:
    """Monotone observations of returning and non-returning paths."""

    may_return: bool = False
    may_not_return: bool = False
    incomplete: bool = False

    def __post_init__(self) -> None:
        if not all(
            isinstance(value, bool)
            for value in (self.may_return, self.may_not_return, self.incomplete)
        ):
            raise TypeError("return behavior fields must be bool")

    @classmethod
    def unknown(cls) -> ReturnBehavior:
        return cls(may_return=True, may_not_return=True, incomplete=True)

    def join(self, other: ReturnBehavior) -> ReturnBehavior:
        return ReturnBehavior(
            may_return=self.may_return or other.may_return,
            may_not_return=self.may_not_return or other.may_not_return,
            incomplete=self.incomplete or other.incomplete,
        )

    def leq(self, other: ReturnBehavior) -> bool:
        return (
            (not self.may_return or other.may_return)
            and (not self.may_not_return or other.may_not_return)
            and (not self.incomplete or other.incomplete)
        )

    def project(self) -> dict[str, Any]:
        return {
            "status": "incomplete" if self.incomplete else "complete",
            "may_return": self.may_return,
            "may_not_return": self.may_not_return,
        }

    to_projection = project


@dataclass(frozen=True)
class Taint(Generic[LabelT]):
    """A monotone set of stable taint labels."""

    labels: frozenset[LabelT] = frozenset()

    def __post_init__(self) -> None:
        object.__setattr__(self, "labels", frozenset(self.labels))

    @property
    def tainted(self) -> bool:
        return bool(self.labels)

    @classmethod
    def of(cls, labels: Iterable[LabelT]) -> Taint[LabelT]:
        return cls(frozenset(labels))

    def join(self, other: Taint[LabelT]) -> Taint[LabelT]:
        return Taint(self.labels | other.labels)

    def leq(self, other: Taint[LabelT]) -> bool:
        return self.labels <= other.labels

    def project(
        self, projector: Callable[[LabelT], Any] = deterministic_projection
    ) -> dict[str, Any]:
        projected = [projector(label) for label in self.labels]
        return {
            "tainted": self.tainted,
            "labels": sorted(projected, key=_stable_token),
        }

    def to_projection(
        self, projector: Callable[[LabelT], Any] = deterministic_projection
    ) -> dict[str, Any]:
        return self.project(projector)


@dataclass(frozen=True)
class InterproceduralFact(Generic[ValueT, CleanupT, ResultT, LabelT]):
    """The product lattice used by interprocedural summary fixed points."""

    may_values: MayValue[ValueT]
    preserved_registers: MustPreservedRegisters
    stack_cleanup: ExactOrConflict[CleanupT]
    results: ExactOrConflict[ResultT]
    return_behavior: ReturnBehavior
    taint: Taint[LabelT]

    @classmethod
    def bottom(
        cls, register_universe: Iterable[str]
    ) -> InterproceduralFact[Any, Any, Any, Any]:
        return cls(
            may_values=Bottom(),
            preserved_registers=MustPreservedRegisters(
                frozenset(register_universe)
            ),
            stack_cleanup=NoExactValue(),
            results=NoExactValue(),
            return_behavior=ReturnBehavior(),
            taint=Taint(),
        )

    @property
    def complete(self) -> bool:
        return (
            self.may_values.complete
            and self.stack_cleanup.complete
            and self.results.complete
            and not self.return_behavior.incomplete
        )

    def join(
        self,
        other: InterproceduralFact[ValueT, CleanupT, ResultT, LabelT],
        *,
        maximum: int,
    ) -> InterproceduralFact[ValueT, CleanupT, ResultT, LabelT]:
        return InterproceduralFact(
            may_values=self.may_values.join(
                other.may_values, maximum=maximum
            ),
            preserved_registers=self.preserved_registers.meet(
                other.preserved_registers
            ),
            stack_cleanup=self.stack_cleanup.join(other.stack_cleanup),
            results=self.results.join(other.results),
            return_behavior=self.return_behavior.join(other.return_behavior),
            taint=self.taint.join(other.taint),
        )

    def leq(
        self, other: InterproceduralFact[ValueT, CleanupT, ResultT, LabelT]
    ) -> bool:
        return (
            self.may_values.leq(other.may_values)
            and self.preserved_registers.leq(other.preserved_registers)
            and self.stack_cleanup.leq(other.stack_cleanup)
            and self.results.leq(other.results)
            and self.return_behavior.leq(other.return_behavior)
            and self.taint.leq(other.taint)
        )

    def project(
        self,
        *,
        project_value: Callable[[ValueT], Any] = deterministic_projection,
        project_cleanup: Callable[[CleanupT], Any] = deterministic_projection,
        project_result: Callable[[ResultT], Any] = deterministic_projection,
        project_taint: Callable[[LabelT], Any] = deterministic_projection,
    ) -> dict[str, Any]:
        return {
            "complete": self.complete,
            "may_values": self.may_values.project(project_value),
            "preserved_registers": self.preserved_registers.project(),
            "stack_cleanup": self.stack_cleanup.project(project_cleanup),
            "results": self.results.project(project_result),
            "return_behavior": self.return_behavior.project(),
            "taint": self.taint.project(project_taint),
        }

    to_projection = project


MayBottom = Bottom
MayFinite = Finite
MayTop = Top
ExactBottom = NoExactValue
Conflicting = Conflict
ProductFact = InterproceduralFact


__all__ = [
    "Bottom",
    "Conflict",
    "Conflicting",
    "Exact",
    "ExactBottom",
    "ExactOrConflict",
    "Finite",
    "InterproceduralFact",
    "MayBottom",
    "MayFinite",
    "MayTop",
    "MayValue",
    "MustPreservedRegisters",
    "NoExactValue",
    "ProductFact",
    "ReturnBehavior",
    "Taint",
    "Top",
    "bounded_may_join",
    "deterministic_projection",
    "exact_join",
    "finite",
    "may_leq",
    "project_exact",
    "project_may_value",
]
