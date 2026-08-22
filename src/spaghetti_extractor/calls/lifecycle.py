"""Ownership and value-lifecycle transitions for checked calls."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping, Sequence

from ..artifacts.formats import (
    CALL_LIFECYCLE_RECEIPT_V1_FORMAT,
    CALL_LIFECYCLE_V1_FORMAT,
)
from ..components.relation_ir import BOOL_SORT, RelationExpressionV1
from ._canonical import (
    CallProtocolError,
    array,
    content_id,
    digest,
    exact,
    identifier,
    object_,
    text,
    verify_content_id,
)


TRANSITIONS = frozenset(
    {
        "borrow_shared",
        "borrow_mutable",
        "consume",
        "transfer",
        "produce",
        "initialize_if",
        "update",
        "retain",
        "release",
        "escape_callback",
    }
)


@dataclass(frozen=True)
class ValuePathV1:
    slot_id: str
    fields: tuple[str, ...]

    @classmethod
    def parse(cls, value: object, context: str = "lifecycle value path") -> "ValuePathV1":
        row = object_(value, context)
        exact(row, {"slot_id", "fields"}, context)
        return cls(
            identifier(row["slot_id"], f"{context} slot id"),
            tuple(identifier(item, f"{context} field") for item in array(row["fields"], f"{context} fields")),
        )

    @property
    def key(self) -> tuple[str, tuple[str, ...]]:
        return self.slot_id, self.fields

    def to_payload(self) -> dict[str, object]:
        return {"slot_id": self.slot_id, "fields": list(self.fields)}


@dataclass(frozen=True)
class LifecycleBindingV1:
    identity: str
    path: ValuePathV1
    transition: str
    resource_kind: str
    provider_domain: str
    service_id: str | None
    condition: Mapping[str, object] | None

    @classmethod
    def parse(cls, value: object, context: str) -> "LifecycleBindingV1":
        row = object_(value, context)
        exact(row, {"id", "path", "transition", "resource_kind", "provider_domain", "service_id", "condition"}, context)
        transition = text(row["transition"], f"{context} transition")
        if transition not in TRANSITIONS:
            raise CallProtocolError(f"{context} transition is unsupported")
        service = None if row["service_id"] is None else identifier(row["service_id"], f"{context} service id")
        if transition in {"retain", "release", "consume", "produce", "transfer"} and service is None:
            raise CallProtocolError(f"{context} ownership transition requires a service")
        condition = None if row["condition"] is None else dict(object_(row["condition"], f"{context} condition"))
        if condition is not None:
            predicate = RelationExpressionV1.parse(condition, f"{context} condition")
            if predicate.sort != BOOL_SORT or any(
                path.root != "result" for path in predicate.logical_paths()
            ):
                raise CallProtocolError(
                    f"{context} condition must be a Boolean predicate over call results"
                )
        if transition == "initialize_if" and condition is None:
            raise CallProtocolError(f"{context} conditional initialization lacks a condition")
        if transition != "initialize_if" and condition is not None:
            raise CallProtocolError(f"{context} condition is valid only for conditional initialization")
        return cls(
            identifier(row["id"], f"{context} id"),
            ValuePathV1.parse(row["path"], f"{context} path"),
            transition,
            identifier(row["resource_kind"], f"{context} resource kind"),
            identifier(row["provider_domain"], f"{context} provider domain"),
            service,
            condition,
        )

    def to_payload(self) -> dict[str, object]:
        return {
            "id": self.identity,
            "path": self.path.to_payload(),
            "transition": self.transition,
            "resource_kind": self.resource_kind,
            "provider_domain": self.provider_domain,
            "service_id": self.service_id,
            "condition": None if self.condition is None else dict(self.condition),
        }


@dataclass(frozen=True)
class CallLifecycleV1:
    lifecycle_id: str
    bindings: tuple[LifecycleBindingV1, ...]
    interaction_contract_ids: tuple[str, ...]

    @classmethod
    def create(
        cls,
        bindings: Sequence[LifecycleBindingV1 | Mapping[str, object]],
        *,
        interaction_contract_ids: Sequence[str] = (),
    ) -> "CallLifecycleV1":
        parsed = tuple(item if isinstance(item, LifecycleBindingV1) else LifecycleBindingV1.parse(item, f"lifecycle binding {index}") for index, item in enumerate(bindings))
        ordered = tuple(sorted(parsed, key=lambda item: item.identity))
        if [item.identity for item in ordered] != sorted(set(item.identity for item in ordered)):
            raise CallProtocolError("lifecycle bindings must be unique and ordered")
        path_transitions = [(item.path.key, item.transition) for item in ordered]
        if len(path_transitions) != len(set(path_transitions)):
            raise CallProtocolError("one lifecycle transition is declared twice for a value path")
        contracts = tuple(sorted(set(identifier(item, "interaction contract id") for item in interaction_contract_ids)))
        core = {"format": CALL_LIFECYCLE_V1_FORMAT, "bindings": [item.to_payload() for item in ordered], "interaction_contract_ids": list(contracts)}
        return cls(content_id("call-lifecycle-v1", core), ordered, contracts)

    @classmethod
    def parse(cls, value: object) -> "CallLifecycleV1":
        row = object_(value, "call lifecycle")
        exact(row, {"format", "id", "bindings", "interaction_contract_ids"}, "call lifecycle")
        if row["format"] != CALL_LIFECYCLE_V1_FORMAT:
            raise CallProtocolError("unsupported call lifecycle format")
        result = cls.create(
            [LifecycleBindingV1.parse(item, f"lifecycle binding {index}") for index, item in enumerate(array(row["bindings"], "lifecycle bindings"))],
            interaction_contract_ids=[str(item) for item in array(row["interaction_contract_ids"], "interaction contract ids")],
        )
        if row["id"] != result.lifecycle_id:
            raise CallProtocolError("call lifecycle id does not bind its contents")
        return result

    def to_payload(self) -> dict[str, object]:
        return {"format": CALL_LIFECYCLE_V1_FORMAT, "id": self.lifecycle_id, "bindings": [item.to_payload() for item in self.bindings], "interaction_contract_ids": list(self.interaction_contract_ids)}


@dataclass(frozen=True)
class CallLifecycleReceiptV1:
    receipt_id: str
    status: str
    lifecycle_sha256: str
    obligations: tuple[Mapping[str, str], ...]

    @classmethod
    def check(cls, lifecycle: CallLifecycleV1) -> "CallLifecycleReceiptV1":
        obligations: list[Mapping[str, str]] = []
        for binding in lifecycle.bindings:
            provider_bound = (
                binding.service_id is None or bool(lifecycle.interaction_contract_ids)
            )
            obligations.append(
                {
                    "id": binding.identity,
                    "status": "checked" if provider_bound else "incomplete",
                    "code": (
                        "local_lifecycle_transition_checked"
                        if binding.service_id is None
                        else "provider_lifecycle_contract_bound"
                        if provider_bound
                        else "provider_lifecycle_contract_missing"
                    ),
                }
            )
        if not obligations:
            obligations.append(
                {
                    "id": "call.empty-lifecycle",
                    "status": "checked",
                    "code": "empty_lifecycle_checked",
                }
            )
        status = (
            "complete"
            if all(item["status"] == "checked" for item in obligations)
            else "incomplete"
        )
        lifecycle_sha256 = lifecycle.lifecycle_id.split(":", 1)[1]
        core = {
            "format": CALL_LIFECYCLE_RECEIPT_V1_FORMAT,
            "status": status,
            "lifecycle_sha256": lifecycle_sha256,
            "obligations": [dict(item) for item in obligations],
        }
        return cls(
            content_id("call-lifecycle-receipt-v1", core),
            status,
            lifecycle_sha256,
            tuple(obligations),
        )

    @classmethod
    def parse(cls, value: object) -> "CallLifecycleReceiptV1":
        row = object_(value, "call lifecycle receipt")
        exact(
            row,
            {"format", "id", "status", "lifecycle_sha256", "obligations"},
            "call lifecycle receipt",
        )
        if row["format"] != CALL_LIFECYCLE_RECEIPT_V1_FORMAT:
            raise CallProtocolError("unsupported call lifecycle receipt format")
        status = text(row["status"], "call lifecycle receipt status")
        if status not in {"complete", "incomplete"}:
            raise CallProtocolError("call lifecycle receipt status is unsupported")
        obligations = tuple(
            _parse_lifecycle_obligation(item, f"lifecycle obligation {index}")
            for index, item in enumerate(
                array(row["obligations"], "call lifecycle receipt obligations")
            )
        )
        identities = [item["id"] for item in obligations]
        if not obligations or identities != sorted(set(identities)):
            raise CallProtocolError(
                "call lifecycle receipt obligations must be nonempty, unique, and ordered"
            )
        complete = all(item["status"] == "checked" for item in obligations)
        if (status == "complete") != complete:
            raise CallProtocolError(
                "call lifecycle receipt status disagrees with its obligations"
            )
        lifecycle_sha256 = digest(
            row["lifecycle_sha256"], "call lifecycle receipt lifecycle digest"
        )
        core = {
            "format": CALL_LIFECYCLE_RECEIPT_V1_FORMAT,
            "status": status,
            "lifecycle_sha256": lifecycle_sha256,
            "obligations": [dict(item) for item in obligations],
        }
        receipt_id = verify_content_id(
            row["id"],
            "call-lifecycle-receipt-v1",
            core,
            "call lifecycle receipt",
        )
        return cls(receipt_id, status, lifecycle_sha256, obligations)

    def to_payload(self) -> dict[str, object]:
        return {
            "format": CALL_LIFECYCLE_RECEIPT_V1_FORMAT,
            "id": self.receipt_id,
            "status": self.status,
            "lifecycle_sha256": self.lifecycle_sha256,
            "obligations": [dict(item) for item in self.obligations],
        }


def _parse_lifecycle_obligation(
    value: object, context: str
) -> Mapping[str, str]:
    row = object_(value, context)
    exact(row, {"id", "status", "code"}, context)
    status = text(row["status"], f"{context} status")
    if status not in {"checked", "incomplete"}:
        raise CallProtocolError(f"{context} status is unsupported")
    return {
        "id": identifier(row["id"], f"{context} id"),
        "status": status,
        "code": identifier(row["code"], f"{context} code"),
    }


__all__ = [
    "CallLifecycleReceiptV1",
    "CallLifecycleV1",
    "LifecycleBindingV1",
    "ValuePathV1",
]
