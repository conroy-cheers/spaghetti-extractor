"""Runtime-neutral callback protocol state and admission semantics."""

from __future__ import annotations

from dataclasses import dataclass, replace
from enum import IntEnum
from typing import Hashable

from ..components.capabilities import CapabilityStatus
from ..external.callback_protocols import CallbackProtocolV1


class CallbackDispositionKind(IntEnum):
    ABSENT = 0
    DEFAULT = 1
    IGNORE = 2
    CALLABLE = 3


@dataclass(frozen=True)
class CallbackDisposition:
    kind: CallbackDispositionKind
    target_id: str | None = None

    def __post_init__(self) -> None:
        if (self.kind is CallbackDispositionKind.CALLABLE) != (
            self.target_id is not None
        ):
            raise ValueError("only callable callback dispositions have a target")


@dataclass(frozen=True)
class CallbackInvocation:
    instance_key: Hashable
    generation: int
    ordinal: int


@dataclass(frozen=True)
class CallbackInstanceState:
    generation: int = 0
    installed: CallbackDisposition = CallbackDisposition(
        CallbackDispositionKind.ABSENT
    )
    admitted_count: int = 0
    completed_count: int = 0
    in_flight: tuple[CallbackInvocation, ...] = ()
    expired: bool = False
    last_status: CapabilityStatus = CapabilityStatus.OK

    def replace(
        self, disposition: CallbackDisposition
    ) -> tuple["CallbackInstanceState", CallbackDisposition]:
        if self.expired:
            return replace(self, last_status=CapabilityStatus.EXPIRED), self.installed
        previous = self.installed
        return (
            replace(
                self,
                generation=self.generation + 1,
                installed=disposition,
                admitted_count=0,
                completed_count=0,
                last_status=CapabilityStatus.OK,
            ),
            previous,
        )

    def admit(
        self, protocol: CallbackProtocolV1, instance_key: Hashable
    ) -> tuple["CallbackInstanceState", CallbackInvocation | None]:
        maximum = protocol.cardinality.maximum
        if self.expired:
            return replace(self, last_status=CapabilityStatus.EXPIRED), None
        if self.installed.kind is not CallbackDispositionKind.CALLABLE:
            return replace(self, last_status=CapabilityStatus.UNSUPPORTED), None
        if maximum is not None and self.admitted_count >= maximum:
            return replace(self, last_status=CapabilityStatus.EXPIRED), None
        invocation = CallbackInvocation(
            instance_key, self.generation, self.admitted_count
        )
        return (
            replace(
                self,
                admitted_count=self.admitted_count + 1,
                in_flight=(*self.in_flight, invocation),
                last_status=CapabilityStatus.OK,
            ),
            invocation,
        )

    def complete(self, invocation: CallbackInvocation) -> "CallbackInstanceState":
        if invocation not in self.in_flight:
            return replace(self, last_status=CapabilityStatus.EXPIRED)
        return replace(
            self,
            completed_count=self.completed_count + 1,
            in_flight=tuple(row for row in self.in_flight if row != invocation),
            last_status=CapabilityStatus.OK,
        )

    def expire(self) -> "CallbackInstanceState":
        return replace(
            self,
            expired=True,
            installed=CallbackDisposition(CallbackDispositionKind.ABSENT),
            last_status=CapabilityStatus.EXPIRED,
        )


__all__ = [
    "CallbackDisposition",
    "CallbackDispositionKind",
    "CallbackInstanceState",
    "CallbackInvocation",
]
