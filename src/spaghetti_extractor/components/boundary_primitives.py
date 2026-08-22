"""Closed, proof-bound primitive registry for component boundary plans.

The registry is deliberately framework-owned.  Relation documents may name a
primitive, but cannot provide code or weaken its phase, effect, footprint, or
proof requirements.
"""

from __future__ import annotations

import copy
from dataclasses import dataclass
from typing import Mapping, Sequence

from ..artifacts.artifact_set import canonical_sha256_v3
from .formats import BOUNDARY_PRIMITIVE_MANIFEST_V1_FORMAT
from .relation_ir import RelationSortV1


PRIMITIVE_MANIFEST_V1 = BOUNDARY_PRIMITIVE_MANIFEST_V1_FORMAT
EFFECT_CLASSES = frozenset({"pure", "machine_write", "world_effect"})
PROOF_KINDS = frozenset({"smt", "lean", "domain_receipt"})


class BoundaryPrimitiveError(ValueError):
    """A primitive registry or invocation is malformed or unsupported."""


@dataclass(frozen=True)
class BoundaryPrimitiveV1:
    identity: str
    family: str
    operation: str
    effect_class: str
    phases: tuple[str, ...]
    minimum_arguments: int
    maximum_arguments: int
    result_kinds: tuple[str, ...]
    proof_kinds: tuple[str, ...]
    evaluator: str
    c_lowerer: str

    def validate_call(
        self,
        *,
        arguments: Sequence[RelationSortV1],
        result: RelationSortV1,
        phase: str,
    ) -> None:
        if phase not in self.phases:
            raise BoundaryPrimitiveError(
                f"primitive {self.identity!r} is unavailable during {phase!r}"
            )
        if not self.minimum_arguments <= len(arguments) <= self.maximum_arguments:
            raise BoundaryPrimitiveError(
                f"primitive {self.identity!r} has the wrong arity"
            )
        if result.kind not in self.result_kinds:
            raise BoundaryPrimitiveError(
                f"primitive {self.identity!r} cannot produce {result.kind!r}"
            )
        _validate_builtin_operands(self.identity, arguments, result)

    def to_payload(self) -> dict[str, object]:
        return {
            "id": self.identity,
            "family": self.family,
            "operation": self.operation,
            "effect_class": self.effect_class,
            "phases": list(self.phases),
            "arity": {
                "minimum": self.minimum_arguments,
                "maximum": self.maximum_arguments,
            },
            "result_kinds": list(self.result_kinds),
            "proof_kinds": list(self.proof_kinds),
            "implementations": {
                "evaluator": self.evaluator,
                "c_lowerer": self.c_lowerer,
            },
        }


def _primitive(
    identity: str,
    *,
    effect_class: str,
    phases: Sequence[str],
    arity: int | tuple[int, int],
    result_kinds: Sequence[str],
    proof_kinds: Sequence[str],
) -> BoundaryPrimitiveV1:
    family, operation = identity.split(".", 1)
    minimum, maximum = (arity, arity) if isinstance(arity, int) else arity
    return BoundaryPrimitiveV1(
        identity=identity,
        family=family,
        operation=operation,
        effect_class=effect_class,
        phases=tuple(phases),
        minimum_arguments=minimum,
        maximum_arguments=maximum,
        result_kinds=tuple(result_kinds),
        proof_kinds=tuple(proof_kinds),
        evaluator=f"spx.reference.{identity}.v1",
        c_lowerer=f"spx.c.{identity}.v1",
    )


_ALL_PHASES = ("entry", "exit", "cutpoint", "event_before", "event_after")
_BUILTINS = (
    _primitive(
        "origin.resolve",
        effect_class="pure",
        phases=_ALL_PHASES,
        arity=2,
        result_kinds=("reference",),
        proof_kinds=("lean", "domain_receipt"),
    ),
    _primitive(
        "origin.address",
        effect_class="pure",
        phases=("exit", "cutpoint", "event_before", "event_after"),
        arity=1,
        result_kinds=("bitvector",),
        proof_kinds=("lean", "domain_receipt"),
    ),
    _primitive(
        "capability.import",
        effect_class="pure",
        phases=_ALL_PHASES,
        arity=(1, 2),
        result_kinds=("resource", "callback"),
        proof_kinds=("lean", "domain_receipt"),
    ),
    _primitive(
        "capability.export",
        effect_class="pure",
        phases=("exit", "event_before", "event_after"),
        arity=1,
        result_kinds=("bitvector",),
        proof_kinds=("lean", "domain_receipt"),
    ),
    _primitive(
        "atomic.invoke",
        effect_class="world_effect",
        phases=("event_before", "event_after"),
        arity=(1, 8),
        result_kinds=("bool", "bitvector", "record"),
        proof_kinds=("domain_receipt",),
    ),
    _primitive(
        "callback.invoke",
        effect_class="world_effect",
        phases=("event_before", "event_after"),
        arity=(1, 16),
        result_kinds=("bool", "bitvector", "scalar", "enum", "record", "resource", "callback"),
        proof_kinds=("domain_receipt",),
    ),
    _primitive(
        "callback.exchange",
        effect_class="world_effect",
        phases=("event_after",),
        arity=(1, 2),
        result_kinds=("callback",),
        proof_kinds=("lean", "domain_receipt"),
    ),
    _primitive(
        "service.invoke",
        effect_class="world_effect",
        phases=("event_before", "event_after"),
        arity=(0, 16),
        result_kinds=("bool", "bitvector", "scalar", "enum", "record", "reference", "view", "resource", "callback"),
        proof_kinds=("domain_receipt",),
    ),
)


class BoundaryPrimitiveRegistryV1:
    def __init__(self, primitives: Sequence[BoundaryPrimitiveV1] = _BUILTINS):
        ordered = tuple(sorted(primitives, key=lambda item: item.identity))
        identities = tuple(item.identity for item in ordered)
        if not ordered or identities != tuple(sorted(set(identities))):
            raise BoundaryPrimitiveError(
                "boundary primitives must be nonempty, unique, and ordered"
            )
        for primitive in ordered:
            if primitive.effect_class not in EFFECT_CLASSES:
                raise BoundaryPrimitiveError("primitive effect class is unsupported")
            if set(primitive.proof_kinds) - PROOF_KINDS:
                raise BoundaryPrimitiveError("primitive proof kind is unsupported")
            if not primitive.evaluator or not primitive.c_lowerer:
                raise BoundaryPrimitiveError(
                    "every boundary primitive requires evaluator and C implementations"
                )
        self.primitives = ordered
        self._index = {item.identity: item for item in ordered}

    @property
    def sha256(self) -> str:
        return canonical_sha256_v3(self.to_payload())

    def primitive(self, identity: str) -> BoundaryPrimitiveV1:
        try:
            return self._index[identity]
        except KeyError as exc:
            raise BoundaryPrimitiveError(
                f"unknown boundary primitive {identity!r}"
            ) from exc

    def to_payload(self) -> dict[str, object]:
        return {
            "format": PRIMITIVE_MANIFEST_V1,
            "primitives": [item.to_payload() for item in self.primitives],
        }

    @classmethod
    def parse(cls, value: object) -> "BoundaryPrimitiveRegistryV1":
        if not isinstance(value, Mapping) or set(value) != {"format", "primitives"}:
            raise BoundaryPrimitiveError("primitive manifest has invalid fields")
        if value["format"] != PRIMITIVE_MANIFEST_V1:
            raise BoundaryPrimitiveError("unsupported primitive manifest format")
        if not isinstance(value["primitives"], list):
            raise BoundaryPrimitiveError("primitive manifest inventory is invalid")
        canonical = cls().to_payload()
        if copy.deepcopy(dict(value)) != canonical:
            raise BoundaryPrimitiveError(
                "primitive manifest differs from the framework registry"
            )
        return cls()


def _validate_builtin_operands(
    identity: str,
    arguments: Sequence[RelationSortV1],
    result: RelationSortV1,
) -> None:
    if identity == "origin.resolve":
        if any(item.kind != "bitvector" for item in arguments):
            raise BoundaryPrimitiveError("origin.resolve requires address and extent words")
    elif identity == "origin.address":
        if arguments[0].kind != "reference" or result.kind != "bitvector":
            raise BoundaryPrimitiveError("origin.address requires one reference")
    elif identity == "capability.import":
        if any(item.kind != "bitvector" for item in arguments):
            raise BoundaryPrimitiveError("capability.import requires machine words")
    elif identity == "capability.export":
        if arguments[0].kind not in {"resource", "callback"}:
            raise BoundaryPrimitiveError("capability.export requires a capability")


DEFAULT_BOUNDARY_PRIMITIVES = BoundaryPrimitiveRegistryV1()


__all__ = [
    "BoundaryPrimitiveError",
    "BoundaryPrimitiveRegistryV1",
    "BoundaryPrimitiveV1",
    "DEFAULT_BOUNDARY_PRIMITIVES",
    "EFFECT_CLASSES",
    "PRIMITIVE_MANIFEST_V1",
]
