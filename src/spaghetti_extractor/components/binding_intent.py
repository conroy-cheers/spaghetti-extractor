"""Canonical operator intent for binding V5 component operations to transfer V2.

This is the retained, non-authorizing input shared by component work packages,
direct portable-provider qualification, and reusable-library adoption.  It is
deliberately independent of the retired component-contract and machine-binding
receipt formats.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping, Sequence

from ..artifacts.artifact_set import canonical_sha256_v3
from ..boundary._canonical import (
    BoundaryModelError,
    array,
    canonical,
    digest,
    exact,
    identifier,
    object_,
    uint,
)
from .formats import COMPONENT_MACHINE_BINDING_INTENT_V1_FORMAT


_SEMANTIC_KINDS = frozenset({"operation", "callback"})


def _identifiers(value: object, context: str) -> tuple[str, ...]:
    rows = (
        value
        if isinstance(value, Sequence) and not isinstance(value, (str, bytes))
        else array(value, context)
    )
    result = tuple(sorted(set(identifier(item, context) for item in rows)))
    if len(result) != len(rows):
        raise BoundaryModelError(f"{context} values are duplicated")
    return result


def _digests(value: object, context: str) -> tuple[str, ...]:
    rows = array(value, context)
    result = tuple(sorted(set(digest(item, context) for item in rows)))
    if len(result) != len(rows):
        raise BoundaryModelError(f"{context} values are duplicated")
    return result


def _object_authority_selectors(value: object) -> list[dict[str, str]]:
    result: list[dict[str, str]] = []
    for index, item in enumerate(array(value, "object authority selectors")):
        row = object_(item, f"object authority selector {index}")
        exact(
            row,
            {"authority_id", "rule_id"},
            f"object authority selector {index}",
        )
        authority_id = identifier(
            row["authority_id"],
            f"object authority selector {index} authority",
        )
        rule_id = row["rule_id"]
        if not isinstance(rule_id, str) or not rule_id:
            raise BoundaryModelError(
                f"object authority selector {index} rule id is invalid"
            )
        result.append({"authority_id": authority_id, "rule_id": rule_id})
    result.sort(key=lambda row: row["authority_id"])
    if len({row["authority_id"] for row in result}) != len(result):
        raise BoundaryModelError("object authority selectors are duplicated")
    return result


@dataclass(frozen=True, order=True)
class MachineOperationSemanticsV1:
    operation_id: str
    kind: str
    unit_ids: tuple[str, ...]
    entry_rvas: tuple[int, ...]
    transfer_ids: tuple[str, ...]
    effect_ids: tuple[str, ...]
    service_ids: tuple[str, ...]
    callback_ids: tuple[str, ...]
    outcome_protocol_ids: tuple[str, ...]
    machine_projection: Mapping[str, object]
    semantic_sha256: str

    @classmethod
    def create(
        cls,
        *,
        operation_id: str,
        kind: str,
        unit_ids: Sequence[str],
        entry_rvas: Sequence[int],
        transfer_ids: Sequence[str],
        effect_ids: Sequence[str],
        service_ids: Sequence[str],
        callback_ids: Sequence[str],
        outcome_protocol_ids: Sequence[str],
        machine_projection: Mapping[str, object] | None = None,
    ) -> "MachineOperationSemanticsV1":
        semantic_kind = identifier(kind, "machine operation semantics kind")
        if semantic_kind not in _SEMANTIC_KINDS:
            raise BoundaryModelError(
                "machine operation semantics kind is unsupported"
            )
        units = _identifiers(unit_ids, "machine operation unit")
        entries = tuple(
            sorted(
                set(
                    uint(item, "machine operation entry RVA")
                    for item in entry_rvas
                )
            )
        )
        transfers = _identifiers(transfer_ids, "machine operation transfer")
        if not units or not entries or not transfers:
            raise BoundaryModelError(
                "machine operation semantics require units, entries, and transfers"
            )
        fields = {
            "id": identifier(operation_id, "machine operation semantics id"),
            "kind": semantic_kind,
            "unit_ids": list(units),
            "entry_rvas": list(entries),
            "transfer_ids": list(transfers),
            "effect_ids": list(
                _identifiers(effect_ids, "machine operation effect")
            ),
            "service_ids": list(
                _identifiers(service_ids, "machine operation service")
            ),
            "callback_ids": list(
                _identifiers(callback_ids, "machine operation callback")
            ),
            "outcome_protocol_ids": list(
                _identifiers(
                    outcome_protocol_ids,
                    "machine operation outcome protocol",
                )
            ),
            "machine_projection": canonical(
                dict(
                    object_(
                        machine_projection or {},
                        "machine operation projection",
                    )
                )
            ),
        }
        return cls(
            str(fields["id"]),
            semantic_kind,
            units,
            entries,
            transfers,
            tuple(fields["effect_ids"]),
            tuple(fields["service_ids"]),
            tuple(fields["callback_ids"]),
            tuple(fields["outcome_protocol_ids"]),
            fields["machine_projection"],
            canonical_sha256_v3(fields),
        )

    @classmethod
    def parse(cls, value: object) -> "MachineOperationSemanticsV1":
        row = object_(value, "machine operation semantics")
        exact(
            row,
            {
                "id",
                "kind",
                "unit_ids",
                "entry_rvas",
                "transfer_ids",
                "effect_ids",
                "service_ids",
                "callback_ids",
                "outcome_protocol_ids",
                "semantic_sha256",
                "machine_projection",
            },
            "machine operation semantics",
        )
        result = cls.create(
            operation_id=str(row["id"]),
            kind=str(row["kind"]),
            unit_ids=[str(item) for item in array(row["unit_ids"], "machine units")],
            entry_rvas=[int(item) for item in array(row["entry_rvas"], "machine entries")],
            transfer_ids=[str(item) for item in array(row["transfer_ids"], "machine transfers")],
            effect_ids=[str(item) for item in array(row["effect_ids"], "machine effects")],
            service_ids=[str(item) for item in array(row["service_ids"], "machine services")],
            callback_ids=[str(item) for item in array(row["callback_ids"], "machine callbacks")],
            outcome_protocol_ids=[
                str(item)
                for item in array(row["outcome_protocol_ids"], "machine outcomes")
            ],
            machine_projection=dict(
                object_(row["machine_projection"], "machine projection")
            ),
        )
        if row["semantic_sha256"] != result.semantic_sha256:
            raise BoundaryModelError(
                "machine operation semantics digest is stale"
            )
        return result

    def to_payload(self) -> dict[str, object]:
        return {
            "id": self.operation_id,
            "kind": self.kind,
            "unit_ids": list(self.unit_ids),
            "entry_rvas": list(self.entry_rvas),
            "transfer_ids": list(self.transfer_ids),
            "effect_ids": list(self.effect_ids),
            "service_ids": list(self.service_ids),
            "callback_ids": list(self.callback_ids),
            "outcome_protocol_ids": list(self.outcome_protocol_ids),
            "machine_projection": canonical(dict(self.machine_projection)),
            "semantic_sha256": self.semantic_sha256,
        }


@dataclass(frozen=True, order=True)
class ComponentMachineBindingOperationIntentV1:
    semantics: MachineOperationSemanticsV1
    authority: Mapping[str, object]

    def to_payload(self) -> dict[str, object]:
        semantic = self.semantics.to_payload()
        semantic.pop("semantic_sha256")
        return {**semantic, **canonical(dict(self.authority))}


@dataclass(frozen=True)
class ComponentMachineBindingIntentV1:
    component_id: str
    status: str
    operations: tuple[ComponentMachineBindingOperationIntentV1, ...]
    blockers: tuple[Mapping[str, object], ...]
    intent_sha256: str

    @classmethod
    def create(
        cls,
        *,
        component_id: str,
        operations: Sequence[Mapping[str, object]],
        blockers: Sequence[Mapping[str, object]] = (),
    ) -> "ComponentMachineBindingIntentV1":
        parsed: list[ComponentMachineBindingOperationIntentV1] = []
        for index, value in enumerate(operations):
            row = object_(
                value,
                f"component machine binding intent operation {index}",
            )
            exact(
                row,
                {
                    "id",
                    "kind",
                    "unit_ids",
                    "entry_rvas",
                    "transfer_ids",
                    "effect_ids",
                    "service_ids",
                    "callback_ids",
                    "outcome_protocol_ids",
                    "machine_projection",
                    "object_authority_selectors",
                    "pointer_views",
                    "relation_receipt_sha256s",
                    "induction_evidence_sha256",
                },
                f"component machine binding intent operation {index}",
            )
            semantics = MachineOperationSemanticsV1.create(
                operation_id=str(row["id"]),
                kind=str(row["kind"]),
                unit_ids=[str(item) for item in array(row["unit_ids"], "binding intent units")],
                entry_rvas=[int(item) for item in array(row["entry_rvas"], "binding intent entries")],
                transfer_ids=[str(item) for item in array(row["transfer_ids"], "binding intent transfers")],
                effect_ids=[str(item) for item in array(row["effect_ids"], "binding intent effects")],
                service_ids=[str(item) for item in array(row["service_ids"], "binding intent services")],
                callback_ids=[str(item) for item in array(row["callback_ids"], "binding intent callbacks")],
                outcome_protocol_ids=[str(item) for item in array(row["outcome_protocol_ids"], "binding intent outcomes")],
                machine_projection=dict(
                    object_(row["machine_projection"], "binding intent projection")
                ),
            )
            induction = row["induction_evidence_sha256"]
            authority = {
                "object_authority_selectors": _object_authority_selectors(
                    row["object_authority_selectors"]
                ),
                "pointer_views": canonical(
                    list(array(row["pointer_views"], "binding intent pointer views"))
                ),
                "relation_receipt_sha256s": list(
                    _digests(
                        row["relation_receipt_sha256s"],
                        "binding intent relation receipt",
                    )
                ),
                "induction_evidence_sha256": (
                    None
                    if induction is None
                    else digest(induction, "binding intent induction evidence")
                ),
            }
            parsed.append(
                ComponentMachineBindingOperationIntentV1(semantics, authority)
            )
        parsed.sort(key=lambda item: item.semantics.operation_id)
        ids = tuple(item.semantics.operation_id for item in parsed)
        if ids != tuple(sorted(set(ids))):
            raise BoundaryModelError(
                "component machine binding intent operations are duplicated"
            )
        normalized_blockers = tuple(
            sorted(
                (
                    canonical(
                        dict(
                            object_(
                                item,
                                f"binding intent blocker {index}",
                            )
                        )
                    )
                    for index, item in enumerate(blockers)
                ),
                key=canonical_sha256_v3,
            )
        )
        status = "complete" if parsed and not normalized_blockers else "incomplete"
        core = {
            "format": COMPONENT_MACHINE_BINDING_INTENT_V1_FORMAT,
            "status": status,
            "component_id": identifier(
                component_id,
                "component machine binding intent id",
            ),
            "operations": [item.to_payload() for item in parsed],
            "blockers": [canonical(dict(item)) for item in normalized_blockers],
        }
        return cls(
            str(core["component_id"]),
            status,
            tuple(parsed),
            normalized_blockers,
            canonical_sha256_v3(core),
        )

    @classmethod
    def parse(cls, value: object) -> "ComponentMachineBindingIntentV1":
        row = object_(value, "component machine binding intent V1")
        exact(
            row,
            {
                "format",
                "status",
                "component_id",
                "operations",
                "blockers",
                "intent_sha256",
            },
            "component machine binding intent V1",
        )
        if row["format"] != COMPONENT_MACHINE_BINDING_INTENT_V1_FORMAT:
            raise BoundaryModelError(
                "unsupported component machine binding intent format"
            )
        result = cls.create(
            component_id=str(row["component_id"]),
            operations=[
                dict(object_(item, f"binding intent operation {index}"))
                for index, item in enumerate(
                    array(row["operations"], "binding intent operations")
                )
            ],
            blockers=[
                dict(object_(item, f"binding intent blocker {index}"))
                for index, item in enumerate(
                    array(row["blockers"], "binding intent blockers")
                )
            ],
        )
        if result.to_payload() != dict(row):
            raise BoundaryModelError(
                "component machine binding intent V1 is stale"
            )
        return result

    def to_payload(self) -> dict[str, object]:
        core = {
            "format": COMPONENT_MACHINE_BINDING_INTENT_V1_FORMAT,
            "status": self.status,
            "component_id": self.component_id,
            "operations": [item.to_payload() for item in self.operations],
            "blockers": [canonical(dict(item)) for item in self.blockers],
        }
        return {**core, "intent_sha256": self.intent_sha256}


__all__ = [
    "ComponentMachineBindingIntentV1",
    "ComponentMachineBindingOperationIntentV1",
    "MachineOperationSemanticsV1",
]
