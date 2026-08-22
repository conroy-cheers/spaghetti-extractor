"""Ownership and resource transitions over canonical boundary value paths."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping, Sequence

from ..artifacts.formats import (
    BOUNDARY_LIFECYCLE_RECEIPT_V1_FORMAT,
    BOUNDARY_LIFECYCLE_V1_FORMAT,
)
from ._canonical import BoundaryModelError, array, canonical, content_sha256, exact, identifier, object_, text
from .model import BoundarySchemaV1, BoundaryValueV1, resolve_field_path_type


BOUNDARY_LIFECYCLE_V1 = BOUNDARY_LIFECYCLE_V1_FORMAT
BOUNDARY_LIFECYCLE_RECEIPT_V1 = BOUNDARY_LIFECYCLE_RECEIPT_V1_FORMAT
TRANSITIONS = frozenset({
    "borrow_shared", "borrow_mutable", "consume", "transfer", "produce",
    "initialize_if", "update", "retain", "release", "escape_callback",
})
PROVIDER_TRANSITIONS = frozenset({"consume", "transfer", "produce", "retain", "release", "escape_callback"})


@dataclass(frozen=True)
class BoundaryValuePathV1:
    root: str
    value_id: str
    fields: tuple[str, ...]

    @classmethod
    def parse(cls, value: object, context: str = "boundary value path") -> "BoundaryValuePathV1":
        row = object_(value, context)
        exact(row, {"root", "value_id", "fields"}, context)
        root = text(row["root"], f"{context} root")
        if root not in {"parameter", "result", "state", "service_parameter", "service_result"}:
            raise BoundaryModelError(f"{context} root is unsupported")
        return cls(root, identifier(row["value_id"], f"{context} value"), tuple(identifier(item, f"{context} field") for item in array(row["fields"], f"{context} fields")))

    def to_payload(self) -> dict[str, object]:
        return {"root": self.root, "value_id": self.value_id, "fields": list(self.fields)}


@dataclass(frozen=True)
class BoundaryLifecycleBindingV1:
    identity: str
    path: BoundaryValuePathV1
    transition: str
    resource_kind: str
    provider_domain: str
    service_id: str | None
    interaction_contract_id: str | None
    condition: Mapping[str, object] | None

    @classmethod
    def parse(cls, value: object, context: str) -> "BoundaryLifecycleBindingV1":
        row = object_(value, context)
        exact(row, {"id", "path", "transition", "resource_kind", "provider_domain", "service_id", "interaction_contract_id", "condition"}, context)
        transition = text(row["transition"], f"{context} transition")
        if transition not in TRANSITIONS:
            raise BoundaryModelError(f"{context} transition is unsupported")
        condition = None if row["condition"] is None else dict(object_(row["condition"], f"{context} condition"))
        if (transition == "initialize_if") != (condition is not None):
            raise BoundaryModelError(f"{context} conditional initialization and condition disagree")
        service = None if row["service_id"] is None else identifier(row["service_id"], f"{context} service")
        contract = None if row["interaction_contract_id"] is None else identifier(row["interaction_contract_id"], f"{context} interaction contract")
        if transition in PROVIDER_TRANSITIONS and (service is None or contract is None):
            raise BoundaryModelError(f"{context} provider transition lacks service or interaction contract")
        return cls(identifier(row["id"], f"{context} id"), BoundaryValuePathV1.parse(row["path"], f"{context} path"), transition, identifier(row["resource_kind"], f"{context} resource kind"), identifier(row["provider_domain"], f"{context} provider domain"), service, contract, condition)

    def to_payload(self) -> dict[str, object]:
        return {"id": self.identity, "path": self.path.to_payload(), "transition": self.transition, "resource_kind": self.resource_kind, "provider_domain": self.provider_domain, "service_id": self.service_id, "interaction_contract_id": self.interaction_contract_id, "condition": None if self.condition is None else canonical(dict(self.condition))}


@dataclass(frozen=True)
class BoundaryLifecycleRootV1:
    root: str
    values: tuple[BoundaryValueV1, ...]

    @classmethod
    def create(
        cls,
        *,
        root: str,
        values: Sequence[BoundaryValueV1 | Mapping[str, object]],
    ) -> "BoundaryLifecycleRootV1":
        if root not in {
            "parameter", "result", "state", "service_parameter", "service_result"
        }:
            raise BoundaryModelError("boundary lifecycle root is unsupported")
        parsed = tuple(
            sorted(
                (
                    item
                    if isinstance(item, BoundaryValueV1)
                    else BoundaryValueV1.parse(item, f"{root} lifecycle value {index}")
                    for index, item in enumerate(values)
                ),
                key=lambda item: item.identity,
            )
        )
        if [item.identity for item in parsed] != sorted(
            set(item.identity for item in parsed)
        ):
            raise BoundaryModelError("boundary lifecycle root values are duplicated")
        return cls(root, parsed)

    @classmethod
    def parse(cls, value: object, context: str) -> "BoundaryLifecycleRootV1":
        row = object_(value, context)
        exact(row, {"root", "values"}, context)
        return cls.create(
            root=str(row["root"]),
            values=[
                BoundaryValueV1.parse(item, f"{context} value {index}")
                for index, item in enumerate(array(row["values"], f"{context} values"))
            ],
        )

    def to_payload(self) -> dict[str, object]:
        return {"root": self.root, "values": [item.to_payload() for item in self.values]}


@dataclass(frozen=True)
class BoundaryLifecycleV1:
    schema_sha256: str
    signature_id: str
    roots: tuple[BoundaryLifecycleRootV1, ...]
    bindings: tuple[BoundaryLifecycleBindingV1, ...]
    lifecycle_sha256: str

    @classmethod
    def create(
        cls,
        *,
        schema: BoundarySchemaV1,
        signature_id: str,
        bindings: Sequence[BoundaryLifecycleBindingV1 | Mapping[str, object]],
        additional_roots: Mapping[
            str, Sequence[BoundaryValueV1 | Mapping[str, object]]
        ] | None = None,
    ) -> "BoundaryLifecycleV1":
        signature = schema.signature_index.get(signature_id)
        if signature is None:
            raise BoundaryModelError("boundary lifecycle names an unknown signature")
        parsed = tuple(sorted((item if isinstance(item, BoundaryLifecycleBindingV1) else BoundaryLifecycleBindingV1.parse(item, f"lifecycle binding {index}") for index, item in enumerate(bindings)), key=lambda item: item.identity))
        ids = [item.identity for item in parsed]
        if ids != sorted(set(ids)):
            raise BoundaryModelError("boundary lifecycle bindings must be unique and ordered")
        root_rows = {
            "parameter": signature.parameters,
            "result": signature.results,
            **(dict(additional_roots) if additional_roots is not None else {}),
        }
        roots = tuple(
            BoundaryLifecycleRootV1.create(root=root, values=values)
            for root, values in sorted(root_rows.items())
        )
        if len({item.root for item in roots}) != len(roots):
            raise BoundaryModelError("boundary lifecycle roots are duplicated")
        root_index = {item.root: item.values for item in roots}
        for binding in parsed:
            _validate_path(schema, root_index, binding.path)
        core = {"format": BOUNDARY_LIFECYCLE_V1, "schema_sha256": schema.schema_sha256, "signature_id": signature.identity, "roots": [item.to_payload() for item in roots], "bindings": [item.to_payload() for item in parsed]}
        return cls(schema.schema_sha256, signature.identity, roots, parsed, content_sha256(core))

    @classmethod
    def parse(
        cls, value: object, *, schema: BoundarySchemaV1
    ) -> "BoundaryLifecycleV1":
        row = object_(value, "boundary lifecycle")
        exact(
            row,
            {
                "format", "schema_sha256", "signature_id", "roots", "bindings",
                "lifecycle_sha256",
            },
            "boundary lifecycle",
        )
        if row["format"] != BOUNDARY_LIFECYCLE_V1:
            raise BoundaryModelError("unsupported boundary lifecycle format")
        if row["schema_sha256"] != schema.schema_sha256:
            raise BoundaryModelError("boundary lifecycle binds another schema")
        roots = tuple(
            BoundaryLifecycleRootV1.parse(item, f"lifecycle root {index}")
            for index, item in enumerate(array(row["roots"], "lifecycle roots"))
        )
        root_index = {item.root: item.values for item in roots}
        additional = {
            root: values
            for root, values in root_index.items()
            if root not in {"parameter", "result"}
        }
        result = cls.create(
            schema=schema,
            signature_id=str(row["signature_id"]),
            bindings=[
                BoundaryLifecycleBindingV1.parse(item, f"lifecycle binding {index}")
                for index, item in enumerate(
                    array(row["bindings"], "lifecycle bindings")
                )
            ],
            additional_roots=additional,
        )
        if [item.to_payload() for item in roots] != [
            item.to_payload() for item in result.roots
        ]:
            raise BoundaryModelError("boundary lifecycle roots are stale")
        if row["lifecycle_sha256"] != result.lifecycle_sha256:
            raise BoundaryModelError("boundary lifecycle digest is stale")
        return result

    def to_payload(self) -> dict[str, object]:
        return {"format": BOUNDARY_LIFECYCLE_V1, "schema_sha256": self.schema_sha256, "signature_id": self.signature_id, "roots": [item.to_payload() for item in self.roots], "bindings": [item.to_payload() for item in self.bindings], "lifecycle_sha256": self.lifecycle_sha256}


@dataclass(frozen=True)
class BoundaryLifecycleReceiptV1:
    lifecycle_sha256: str
    status: str
    obligations: tuple[Mapping[str, str], ...]
    receipt_sha256: str

    @classmethod
    def check(cls, lifecycle: BoundaryLifecycleV1, *, checked_interaction_contract_ids: Sequence[str]) -> "BoundaryLifecycleReceiptV1":
        checked = set(checked_interaction_contract_ids)
        obligations = tuple({"id": item.identity, "status": "checked" if item.interaction_contract_id is None or item.interaction_contract_id in checked else "incomplete", "code": "local_transition_checked" if item.interaction_contract_id is None else "interaction_contract_bound" if item.interaction_contract_id in checked else "interaction_contract_missing"} for item in lifecycle.bindings) or ({"id": "boundary.empty-lifecycle", "status": "checked", "code": "empty_lifecycle_checked"},)
        status = "complete" if all(item["status"] == "checked" for item in obligations) else "incomplete"
        core = {"format": BOUNDARY_LIFECYCLE_RECEIPT_V1, "lifecycle_sha256": lifecycle.lifecycle_sha256, "status": status, "obligations": [dict(item) for item in obligations]}
        return cls(lifecycle.lifecycle_sha256, status, obligations, content_sha256(core))

    def to_payload(self) -> dict[str, object]:
        return {"format": BOUNDARY_LIFECYCLE_RECEIPT_V1, "lifecycle_sha256": self.lifecycle_sha256, "status": self.status, "obligations": [dict(item) for item in self.obligations], "receipt_sha256": self.receipt_sha256}

    @classmethod
    def parse(
        cls, value: object, *, lifecycle: BoundaryLifecycleV1
    ) -> "BoundaryLifecycleReceiptV1":
        row = object_(value, "boundary lifecycle receipt")
        exact(
            row,
            {"format", "lifecycle_sha256", "status", "obligations", "receipt_sha256"},
            "boundary lifecycle receipt",
        )
        if (
            row["format"] != BOUNDARY_LIFECYCLE_RECEIPT_V1
            or row["lifecycle_sha256"] != lifecycle.lifecycle_sha256
        ):
            raise BoundaryModelError(
                "boundary lifecycle receipt binds another lifecycle or format"
            )
        obligations = tuple(
            dict(object_(item, f"lifecycle obligation {index}"))
            for index, item in enumerate(
                array(row["obligations"], "lifecycle obligations")
            )
        )
        core = {
            "format": BOUNDARY_LIFECYCLE_RECEIPT_V1,
            "lifecycle_sha256": lifecycle.lifecycle_sha256,
            "status": str(row["status"]),
            "obligations": [dict(item) for item in obligations],
        }
        result = cls(
            lifecycle.lifecycle_sha256,
            str(row["status"]),
            obligations,
            content_sha256(core),
        )
        if row["receipt_sha256"] != result.receipt_sha256:
            raise BoundaryModelError("boundary lifecycle receipt digest is stale")
        return result


def _validate_path(
    schema: BoundarySchemaV1,
    roots: Mapping[str, Sequence[BoundaryValueV1]],
    path: BoundaryValuePathV1,
) -> None:
    values = roots.get(path.root, ())
    value = next((item for item in values if item.identity == path.value_id), None)
    if value is None:
        raise BoundaryModelError(f"boundary lifecycle path names unknown {path.root} {path.value_id!r}")
    resolve_field_path_type(
        schema, value.type_id, path.fields, context="boundary lifecycle path"
    )


__all__ = ["BoundaryLifecycleBindingV1", "BoundaryLifecycleReceiptV1", "BoundaryLifecycleRootV1", "BoundaryLifecycleV1", "BoundaryValuePathV1"]
