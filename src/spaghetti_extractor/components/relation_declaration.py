"""Durable operator selection of reusable contracts for interaction sites."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping, Sequence

from .formats import COMPONENT_RELATION_DECLARATION_V2_FORMAT
from .interaction_inventory import ComponentInteractionInventoryV1


class ComponentRelationDeclarationError(ValueError):
    """A relation declaration is malformed or stale against its inventory."""


def _object(value: object, context: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise ComponentRelationDeclarationError(f"{context} must be an object")
    return value


def _array(value: object, context: str) -> Sequence[object]:
    if not isinstance(value, list):
        raise ComponentRelationDeclarationError(f"{context} must be an array")
    return value


def _text(value: object, context: str) -> str:
    if not isinstance(value, str) or not value:
        raise ComponentRelationDeclarationError(f"{context} must be a nonempty string")
    return value


@dataclass(frozen=True)
class DeclaredInteractionV2:
    site_id: str
    contract_id: str

    @classmethod
    def parse(cls, value: object, context: str) -> "DeclaredInteractionV2":
        row = _object(value, context)
        if set(row) != {"site_id", "contract_id"}:
            raise ComponentRelationDeclarationError(f"{context} fields differ")
        return cls(_text(row["site_id"], f"{context} site"), _text(row["contract_id"], f"{context} contract"))

    def to_payload(self) -> dict[str, object]:
        return {"site_id": self.site_id, "contract_id": self.contract_id}


@dataclass(frozen=True)
class DeclaredOperationRelationV2:
    operation_id: str
    interactions: tuple[DeclaredInteractionV2, ...]

    @classmethod
    def parse(cls, value: object, context: str) -> "DeclaredOperationRelationV2":
        row = _object(value, context)
        if set(row) != {"operation_id", "interactions"}:
            raise ComponentRelationDeclarationError(f"{context} fields differ")
        interactions = tuple(
            DeclaredInteractionV2.parse(item, f"{context} interaction {index}")
            for index, item in enumerate(_array(row["interactions"], f"{context} interactions"))
        )
        ids = [item.site_id for item in interactions]
        if ids != sorted(set(ids)):
            raise ComponentRelationDeclarationError(f"{context} interactions must be unique and ordered")
        return cls(_text(row["operation_id"], f"{context} operation"), interactions)

    def to_payload(self) -> dict[str, object]:
        return {"operation_id": self.operation_id, "interactions": [item.to_payload() for item in self.interactions]}


@dataclass(frozen=True)
class ComponentRelationDeclarationV2:
    component_id: str
    machine_backend: str
    operations: tuple[DeclaredOperationRelationV2, ...]

    @classmethod
    def parse(cls, value: object) -> "ComponentRelationDeclarationV2":
        row = _object(value, "component relation declaration")
        if set(row) != {"format", "component_id", "machine_backend", "operations"}:
            raise ComponentRelationDeclarationError("component relation declaration fields differ")
        if row["format"] != COMPONENT_RELATION_DECLARATION_V2_FORMAT:
            raise ComponentRelationDeclarationError("unsupported component relation declaration format")
        operations = tuple(
            DeclaredOperationRelationV2.parse(item, f"declared operation {index}")
            for index, item in enumerate(_array(row["operations"], "declared operations"))
        )
        ids = [item.operation_id for item in operations]
        if ids != sorted(set(ids)):
            raise ComponentRelationDeclarationError("declared operations must be unique and ordered")
        return cls(_text(row["component_id"], "declared component"), _text(row["machine_backend"], "declared backend"), operations)

    def selections_for(self, inventory: ComponentInteractionInventoryV1) -> dict[str, str]:
        if self.component_id != inventory.component_id:
            raise ComponentRelationDeclarationError("relation declaration component changed")
        inventory_operations = {item.operation_id: item for item in inventory.operations}
        selections: dict[str, str] = {}
        for operation in self.operations:
            available = inventory_operations.get(operation.operation_id)
            if available is None:
                raise ComponentRelationDeclarationError(f"declared operation {operation.operation_id!r} disappeared")
            sites = {item.identity: item for item in available.sites}
            for declared in operation.interactions:
                site = sites.get(declared.site_id)
                if site is None:
                    raise ComponentRelationDeclarationError(f"interaction site {declared.site_id!r} disappeared")
                if declared.contract_id not in site.contract_candidates:
                    raise ComponentRelationDeclarationError(f"interaction contract {declared.contract_id!r} is no longer a candidate")
                if declared.site_id in selections:
                    raise ComponentRelationDeclarationError(f"interaction site {declared.site_id!r} was selected twice")
                selections[declared.site_id] = declared.contract_id
        required = {
            site.identity
            for operation in inventory.operations
            for site in operation.sites
            if site.contract_candidates
        }
        if set(selections) != required:
            raise ComponentRelationDeclarationError(
                f"relation declaration must select every ambiguous interaction: missing={sorted(required-set(selections))!r}, extra={sorted(set(selections)-required)!r}"
            )
        return selections

    def to_payload(self) -> dict[str, object]:
        return {
            "format": COMPONENT_RELATION_DECLARATION_V2_FORMAT,
            "component_id": self.component_id,
            "machine_backend": self.machine_backend,
            "operations": [item.to_payload() for item in self.operations],
        }


__all__ = [
    "ComponentRelationDeclarationError", "ComponentRelationDeclarationV2",
    "DeclaredInteractionV2", "DeclaredOperationRelationV2",
]
