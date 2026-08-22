"""Fail-closed activation readiness over exact component receipt hashes."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Mapping, Sequence

from ..artifacts.artifact_set import canonical_sha256_v3
from .interface_ir import PortableComponentInterfaceV2


COMPONENT_ACTIVATION_RECEIPT_V2 = (
    "spaghetti-extractor-component-activation-receipt-v2"
)
COMPONENT_ACTIVATION_RECEIPT_V3 = (
    "spaghetti-extractor-component-activation-receipt-v3"
)
COMPONENT_ACTIVATION_RECEIPT_V1 = COMPONENT_ACTIVATION_RECEIPT_V2
ACTIVATION_RECEIPT_V1_FORMAT = COMPONENT_ACTIVATION_RECEIPT_V2
ACTIVATION_FACET_IDS_V2 = (
    "interface",
    "source_profile",
    "source_compile",
    "machine_binding",
    "semantic_refinement",
    "service_graph",
    "ownership",
)
ACTIVATION_FACET_IDS = (
    "interface",
    "source_profile",
    "source_compile",
    "machine_binding",
    "relation",
    "boundary_plan",
    "semantic_refinement",
    "service_graph",
    "ownership",
)
_ALL_FACET_IDS = frozenset(ACTIVATION_FACET_IDS)

_DIGEST = re.compile(r"[0-9a-f]{64}")
_IDENTIFIER = re.compile(r"[a-z][a-z0-9_]{0,127}")
_COMPONENT_ID = re.compile(r"[a-z0-9](?:[a-z0-9._-]*[a-z0-9])?\Z")
_FACET_STATUSES = frozenset(
    {"checked", "satisfied", "incomplete", "violated", "stale"}
)
_SATISFIED_STATUSES = frozenset({"checked", "satisfied"})
_ACTION_TEXT = {
    "interface": "check the exact portable interface and regenerate its receipt",
    "source_profile": "satisfy the restricted C profile and regenerate its receipt",
    "source_compile": "compile the exact content-bound source and regenerate its receipt",
    "machine_binding": "check the exact machine binding and regenerate its receipt",
    "relation": "check the constructive machine-to-portable relation and regenerate its proof receipt",
    "boundary_plan": "compile the checked relation into an executable boundary plan",
    "semantic_refinement": "check the source against the machine-derived semantic contract",
    "service_graph": "close the exact service graph and regenerate its receipt",
    "ownership": "complete exact and exclusive implementation ownership and regenerate its receipt",
}
_DIGEST_FIELDS = {
    "source_compile": (
        "receipt_sha256",
        "compile_receipt_sha256",
        "source_compile_sha256",
    ),
    "source_profile": ("receipt_sha256",),
    "machine_binding": ("receipt_sha256", "binding_sha256"),
    "relation": ("receipt_sha256",),
    "boundary_plan": ("receipt_sha256",),
    "semantic_refinement": ("receipt_sha256",),
    "service_graph": ("graph_sha256", "receipt_sha256"),
    "ownership": ("receipt_sha256", "activation_plan_sha256"),
}


class ActivationReceiptError(ValueError):
    """An activation facet or receipt is malformed or contradictory."""


@dataclass(frozen=True)
class ActivationFacetV1:
    identity: str
    required: bool
    status: str
    expected_receipt_sha256: str | None
    receipt_sha256: str | None

    @classmethod
    def create(
        cls,
        *,
        identity: str,
        status: str,
        receipt_sha256: str | None,
        expected_receipt_sha256: str | None = None,
        required: bool = True,
    ) -> "ActivationFacetV1":
        if expected_receipt_sha256 is None and receipt_sha256 is not None:
            expected_receipt_sha256 = receipt_sha256
        if (
            receipt_sha256 is not None
            and expected_receipt_sha256 is not None
            and receipt_sha256 != expected_receipt_sha256
        ):
            status = "stale"
        elif status in _SATISFIED_STATUSES and receipt_sha256 is None:
            status = "incomplete"
        return cls.parse(
            {
                "id": identity,
                "required": required,
                "status": status,
                "expected_receipt_sha256": expected_receipt_sha256,
                "receipt_sha256": receipt_sha256,
            }
        )

    @classmethod
    def parse(cls, value: object) -> "ActivationFacetV1":
        row = _object(value, "activation facet")
        _exact(
            row,
            {
                "id",
                "required",
                "status",
                "expected_receipt_sha256",
                "receipt_sha256",
            },
            "activation facet",
        )
        identity = _identifier(row["id"], "activation facet id")
        if identity not in _ALL_FACET_IDS:
            raise ActivationReceiptError(
                f"unsupported activation facet {identity!r}"
            )
        required = row["required"]
        if not isinstance(required, bool):
            raise ActivationReceiptError("activation facet required flag is not Boolean")
        status = _text(row["status"], "activation facet status")
        if status not in _FACET_STATUSES:
            raise ActivationReceiptError(
                f"unsupported activation facet status {status!r}"
            )
        expected = _optional_digest(
            row["expected_receipt_sha256"], "expected activation receipt digest"
        )
        observed = _optional_digest(
            row["receipt_sha256"], "observed activation receipt digest"
        )
        mismatched = expected is not None and observed is not None and expected != observed
        if status == "stale" and not mismatched:
            raise ActivationReceiptError(
                "stale activation facet requires mismatched expected and observed hashes"
            )
        if status != "stale" and mismatched:
            raise ActivationReceiptError(
                "activation facet with mismatched hashes must be stale"
            )
        if status in _SATISFIED_STATUSES and (
            expected is None or observed is None or expected != observed
        ):
            raise ActivationReceiptError(
                "checked or satisfied activation facet requires one exact receipt hash"
            )
        return cls(identity, required, status, expected, observed)

    @property
    def authorizing(self) -> bool:
        return (
            self.status in _SATISFIED_STATUSES
            and self.expected_receipt_sha256 is not None
            and self.receipt_sha256 == self.expected_receipt_sha256
        )

    def to_payload(self) -> dict[str, object]:
        return {
            "id": self.identity,
            "required": self.required,
            "status": self.status,
            "expected_receipt_sha256": self.expected_receipt_sha256,
            "receipt_sha256": self.receipt_sha256,
        }


FacetStatusV1 = ActivationFacetV1


@dataclass(frozen=True)
class ActivationNextActionV1:
    rank: int
    facet_id: str
    code: str
    action: str

    @classmethod
    def parse(cls, value: object) -> "ActivationNextActionV1":
        row = _object(value, "activation next action")
        _exact(
            row,
            {"rank", "facet_id", "code", "action"},
            "activation next action",
        )
        rank = row["rank"]
        if not isinstance(rank, int) or isinstance(rank, bool) or rank < 1:
            raise ActivationReceiptError("activation next-action rank is invalid")
        facet_id = _identifier(row["facet_id"], "activation next-action facet")
        if facet_id not in _ALL_FACET_IDS:
            raise ActivationReceiptError("activation next-action facet is unsupported")
        return cls(
            rank=rank,
            facet_id=facet_id,
            code=_identifier(row["code"], "activation next-action code"),
            action=_text(row["action"], "activation next action"),
        )

    def to_payload(self) -> dict[str, object]:
        return {
            "rank": self.rank,
            "facet_id": self.facet_id,
            "code": self.code,
            "action": self.action,
        }


@dataclass(frozen=True)
class ActivationReceiptV1:
    component_id: str
    status: str
    activation_authorized: bool
    bindings: Mapping[str, str]
    facets: tuple[ActivationFacetV1, ...]
    next_actions: tuple[ActivationNextActionV1, ...]
    receipt_sha256: str
    format_version: str = COMPONENT_ACTIVATION_RECEIPT_V2

    @classmethod
    def create(
        cls,
        *,
        component_id: str = "component",
        bindings: Mapping[str, str] | None = None,
        facets: Mapping[str, ActivationFacetV1 | Mapping[str, object]]
        | Sequence[ActivationFacetV1 | Mapping[str, object]],
    ) -> "ActivationReceiptV1":
        indexed = _coerce_facets(facets)
        facet_ids = (
            ACTIVATION_FACET_IDS
            if any(item in indexed for item in ("relation", "boundary_plan"))
            else ACTIVATION_FACET_IDS_V2
        )
        complete_facets = tuple(
            indexed.get(
                facet_id,
                ActivationFacetV1.create(
                    identity=facet_id,
                    status="incomplete",
                    receipt_sha256=None,
                ),
            )
            for facet_id in facet_ids
        )
        status, authorized, actions = _reduce(complete_facets)
        core: dict[str, object] = {
            "format": (
                COMPONENT_ACTIVATION_RECEIPT_V3
                if facet_ids == ACTIVATION_FACET_IDS
                else COMPONENT_ACTIVATION_RECEIPT_V2
            ),
            "component_id": _component_id(component_id, "activation component id"),
            "status": status,
            "activation_authorized": authorized,
            "bindings": _normalize_bindings(bindings or {}),
            "facets": [item.to_payload() for item in complete_facets],
            "next_actions": [item.to_payload() for item in actions],
        }
        return cls.parse(
            {**core, "receipt_sha256": canonical_sha256_v3(core)}
        )

    @classmethod
    def from_receipts(
        cls,
        *,
        interface: object | None,
        source_profile: object | None,
        source_compile: object | None,
        machine_binding: object | None,
        semantic_refinement: object | None,
        service_graph: object | None,
        ownership: object | None,
        relation: object | None = None,
        boundary_plan: object | None = None,
        component_id: str | None = None,
        expected_hashes: Mapping[str, str] | None = None,
    ) -> "ActivationReceiptV1":
        """Reduce exact upstream records, checking their embedded self-hashes."""

        expected = dict(expected_hashes or {})
        unknown = sorted(set(expected) - set(ACTIVATION_FACET_IDS))
        if unknown:
            raise ActivationReceiptError(
                f"unknown expected activation facet hashes: {unknown!r}"
            )
        inputs = {
            "interface": interface,
            "source_profile": source_profile,
            "source_compile": source_compile,
            "machine_binding": machine_binding,
            "semantic_refinement": semantic_refinement,
            "service_graph": service_graph,
            "ownership": ownership,
        }
        if relation is not None or boundary_plan is not None:
            inputs.update({"relation": relation, "boundary_plan": boundary_plan})
        facets = {
            facet_id: _facet_from_receipt(
                facet_id, value, expected_sha256=expected.get(facet_id)
            )
            for facet_id, value in inputs.items()
        }
        component_id, bindings, invalid_facets = _cross_bind_receipts(
            inputs, component_id=component_id
        )
        for facet_id in invalid_facets:
            facet = facets[facet_id]
            facets[facet_id] = ActivationFacetV1.create(
                identity=facet.identity,
                status="violated",
                receipt_sha256=facet.receipt_sha256,
                expected_receipt_sha256=facet.receipt_sha256,
            )
        return cls.create(
            component_id=component_id,
            bindings=bindings,
            facets=facets,
        )

    @classmethod
    def parse(cls, value: object) -> "ActivationReceiptV1":
        row = _object(value, "component activation receipt")
        _exact(
            row,
            {
                "format",
                "component_id",
                "status",
                "activation_authorized",
                "bindings",
                "facets",
                "next_actions",
                "receipt_sha256",
            },
            "component activation receipt",
        )
        format_version = row["format"]
        if format_version not in {
            COMPONENT_ACTIVATION_RECEIPT_V2,
            COMPONENT_ACTIVATION_RECEIPT_V3,
        }:
            raise ActivationReceiptError("unsupported component activation receipt format")
        component_id = _component_id(row["component_id"], "activation component id")
        bindings = _normalize_bindings(
            _object(row["bindings"], "activation receipt bindings")
        )
        facets = tuple(
            ActivationFacetV1.parse(item)
            for item in _array(row["facets"], "activation facets")
        )
        facet_ids = (
            ACTIVATION_FACET_IDS
            if format_version == COMPONENT_ACTIVATION_RECEIPT_V3
            else ACTIVATION_FACET_IDS_V2
        )
        if tuple(item.identity for item in facets) != facet_ids:
            raise ActivationReceiptError(
                "activation receipt must contain every facet in canonical order"
            )
        expected_status, expected_authorized, expected_actions = _reduce(facets)
        status = _text(row["status"], "activation receipt status")
        authorized = row["activation_authorized"]
        if (
            status != expected_status
            or not isinstance(authorized, bool)
            or authorized is not expected_authorized
        ):
            raise ActivationReceiptError(
                "activation receipt status or authority contradicts its facets"
            )
        actions = tuple(
            ActivationNextActionV1.parse(item)
            for item in _array(row["next_actions"], "activation next actions")
        )
        if actions != expected_actions:
            raise ActivationReceiptError(
                "activation receipt next actions are stale or incorrectly ranked"
            )
        core = dict(row)
        observed = _digest(core.pop("receipt_sha256"), "activation receipt digest")
        if canonical_sha256_v3(core) != observed:
            raise ActivationReceiptError("component activation receipt digest is stale")
        return cls(
            component_id, status, authorized, bindings, facets, actions, observed,
            str(format_version),
        )

    def to_payload(self) -> dict[str, object]:
        return {
            "format": self.format_version,
            "component_id": self.component_id,
            "status": self.status,
            "activation_authorized": self.activation_authorized,
            "bindings": dict(self.bindings),
            "facets": [item.to_payload() for item in self.facets],
            "next_actions": [item.to_payload() for item in self.next_actions],
            "receipt_sha256": self.receipt_sha256,
        }


def build_activation_receipt(
    *,
    component_id: str = "component",
    bindings: Mapping[str, str] | None = None,
    interface: ActivationFacetV1 | Mapping[str, object],
    source_profile: ActivationFacetV1 | Mapping[str, object],
    source_compile: ActivationFacetV1 | Mapping[str, object],
    machine_binding: ActivationFacetV1 | Mapping[str, object],
    semantic_refinement: ActivationFacetV1 | Mapping[str, object],
    service_graph: ActivationFacetV1 | Mapping[str, object],
    ownership: ActivationFacetV1 | Mapping[str, object],
) -> ActivationReceiptV1:
    """Build a receipt from seven explicitly typed facet statuses."""

    return ActivationReceiptV1.create(
        component_id=component_id,
        bindings=bindings,
        facets={
            "interface": interface,
            "source_profile": source_profile,
            "source_compile": source_compile,
            "machine_binding": machine_binding,
            "semantic_refinement": semantic_refinement,
            "service_graph": service_graph,
            "ownership": ownership,
        }
    )


def _cross_bind_receipts(
    inputs: Mapping[str, object | None],
    *,
    component_id: str | None,
) -> tuple[str, dict[str, str], set[str]]:
    """Bind all activation facets to one portable component revision."""

    interface_value = inputs["interface"]
    try:
        interface = (
            interface_value
            if isinstance(interface_value, PortableComponentInterfaceV2)
            else PortableComponentInterfaceV2.parse(interface_value)
        )
    except (TypeError, ValueError):
        return "component", {}, {"interface"}

    inferred_ids = [
        value
        for payload, field in (
            (_optional_payload(inputs["source_compile"]), "component_id"),
            (_optional_payload(inputs["source_profile"]), "component_id"),
            (_optional_payload(inputs["semantic_refinement"]), "component_id"),
            (_optional_payload(inputs["ownership"]), "lift_unit_id"),
        )
        if payload is not None
        for value in [payload.get(field)]
        if isinstance(value, str)
    ]
    component_id = _component_id(
        component_id or (inferred_ids[0] if inferred_ids else interface.identity),
        "activation component id",
    )
    interface_sha256 = interface.sha256
    bindings: dict[str, str] = {"interface_sha256": interface_sha256}
    invalid: set[str] = set()

    compile_payload = _optional_payload(inputs["source_compile"])
    if compile_payload is not None:
        compile_bindings = _mapping_or_empty(compile_payload.get("bindings"))
        if (
            compile_payload.get("component_id") != component_id
            or compile_payload.get("interface_id") != interface.identity
            or compile_bindings.get("interface_sha256") != interface_sha256
        ):
            invalid.add("source_compile")
        implementation = compile_bindings.get("implementation_sha256")
        if isinstance(implementation, str) and _DIGEST.fullmatch(implementation):
            bindings["implementation_sha256"] = implementation

    profile_payload = _optional_payload(inputs["source_profile"])
    source_profile_receipt_sha256: str | None = None
    if profile_payload is not None:
        profile_bindings = _mapping_or_empty(profile_payload.get("bindings"))
        observed_profile_digest = profile_payload.get("receipt_sha256")
        if isinstance(observed_profile_digest, str) and _DIGEST.fullmatch(
            observed_profile_digest
        ):
            source_profile_receipt_sha256 = observed_profile_digest
        if (
            profile_payload.get("component_id") != component_id
            or ("implementation_sha256" in bindings and
                profile_bindings.get("implementation_sha256") != bindings["implementation_sha256"])
        ):
            invalid.add("source_profile")

    machine_payload = _optional_payload(inputs["machine_binding"])
    if machine_payload is not None:
        machine_format = machine_payload.get("format")
        if machine_format in {
            "spaghetti-extractor-component-machine-binding-v3",
            "spaghetti-extractor-component-machine-binding-v4",
        }:
            machine_bindings = _mapping_or_empty(
                machine_payload.get("source_artifacts")
            )
            exact_machine = _mapping_or_empty(machine_payload.get("exact_machine"))
            if (
                machine_payload.get("component_id") != component_id
                or machine_payload.get("interface_sha256") != interface_sha256
            ):
                invalid.add("machine_binding")
            if (
                interface.format_version
                == "spaghetti-extractor-component-interface-ir-v4"
                and (
                    machine_format
                    != "spaghetti-extractor-component-machine-binding-v4"
                    or "relation_ir_sha256" not in machine_bindings
                    or "relation_receipt_sha256" not in machine_bindings
                )
            ):
                invalid.add("machine_binding")
            fields = {
                "component_machine_binding_sha256": machine_bindings.get(
                    "machine_binding_sha256"
                ),
                "machine_ir_sha256": exact_machine.get("machine_ir_sha256"),
                "machine_ir_manifest_sha256": exact_machine.get(
                    "machine_ir_manifest_sha256"
                ),
                "pe_sha256": exact_machine.get("pe_sha256"),
                "relation_ir_sha256": machine_bindings.get("relation_ir_sha256"),
                "relation_receipt_sha256": machine_bindings.get(
                    "relation_receipt_sha256"
                ),
            }
        else:
            machine_bindings = _mapping_or_empty(machine_payload.get("bindings"))
            if machine_bindings.get("interface_sha256") != interface_sha256:
                invalid.add("machine_binding")
            fields = {
                field: machine_bindings.get(field)
                for field in (
                    "component_machine_binding_sha256",
                    "machine_ir_sha256",
                    "machine_ir_manifest_sha256",
                    "pe_sha256",
                )
            }
        for field, value in fields.items():
            if isinstance(value, str) and _DIGEST.fullmatch(value):
                bindings[field] = value

    relation_payload = _optional_payload(inputs.get("relation"))
    if relation_payload is not None:
        relation_sha256 = relation_payload.get("relation_sha256")
        relation_receipt_sha256 = relation_payload.get("receipt_sha256")
        if (
            relation_payload.get("component_id") != component_id
            or relation_payload.get("status") != "checked"
            or (
                "relation_ir_sha256" in bindings
                and relation_sha256 != bindings["relation_ir_sha256"]
            )
            or (
                "relation_receipt_sha256" in bindings
                and relation_receipt_sha256 != bindings["relation_receipt_sha256"]
            )
        ):
            invalid.add("relation")
        if isinstance(relation_sha256, str) and _DIGEST.fullmatch(relation_sha256):
            bindings["relation_ir_sha256"] = relation_sha256
        if isinstance(relation_receipt_sha256, str) and _DIGEST.fullmatch(
            relation_receipt_sha256
        ):
            bindings["relation_receipt_sha256"] = relation_receipt_sha256

    boundary_payload = _optional_payload(inputs.get("boundary_plan"))
    if boundary_payload is not None:
        plan_sha256 = boundary_payload.get("plan_sha256")
        plan_receipt_sha256 = boundary_payload.get("receipt_sha256")
        if (
            boundary_payload.get("component_id") != component_id
            or boundary_payload.get("status") != "checked"
        ):
            invalid.add("boundary_plan")
        if isinstance(plan_sha256, str) and _DIGEST.fullmatch(plan_sha256):
            bindings["boundary_plan_sha256"] = plan_sha256
        if isinstance(plan_receipt_sha256, str) and _DIGEST.fullmatch(
            plan_receipt_sha256
        ):
            bindings["boundary_plan_receipt_sha256"] = plan_receipt_sha256

    refinement_payload = _optional_payload(inputs["semantic_refinement"])
    if refinement_payload is not None:
        refinement_bindings = _mapping_or_empty(refinement_payload.get("bindings"))
        refinement_source_profile = refinement_bindings.get("source_profile_sha256")
        refinement_source_plan = refinement_bindings.get("source_plan_sha256")
        compile_plan_hashes = (
            _mapping_or_empty(compile_payload.get("bindings")).get(
                "inductive_source_plan_sha256s"
            )
            if compile_payload is not None
            else None
        )
        if (
            refinement_payload.get("component_id") != component_id
            or refinement_bindings.get("interface_sha256") != interface_sha256
            or ("implementation_sha256" in bindings and
                refinement_bindings.get("implementation_sha256") != bindings["implementation_sha256"])
            or (
                source_profile_receipt_sha256 is not None
                and refinement_source_profile != source_profile_receipt_sha256
            )
            or (
                refinement_source_plan is not None
                and (
                    not isinstance(compile_plan_hashes, list)
                    or refinement_source_plan not in compile_plan_hashes
                )
            )
        ):
            invalid.add("semantic_refinement")
        for field in (
            "semantic_contract_sha256",
            "source_profile_sha256",
            "source_plan_sha256",
            "relation_sha256",
            "machine_receipt_sha256",
        ):
            value = refinement_bindings.get(field)
            if isinstance(value, str) and _DIGEST.fullmatch(value):
                bindings[field] = value

    service_payload = _optional_payload(inputs["service_graph"])
    if service_payload is not None:
        interfaces = service_payload.get("interfaces")
        matching = [
            item
            for item in interfaces
            if isinstance(interfaces, list) and isinstance(item, Mapping)
            and item.get("id") == interface.identity
        ] if isinstance(interfaces, list) else []
        if len(matching) != 1 or matching[0].get("sha256") != interface_sha256:
            invalid.add("service_graph")

    ownership_payload = _optional_payload(inputs["ownership"])
    if ownership_payload is not None:
        ownership_bindings = _mapping_or_empty(ownership_payload.get("bindings"))
        if ownership_payload.get("lift_unit_id") != component_id:
            invalid.add("ownership")
        contract_sha256 = ownership_bindings.get("contract_sha256")
        if isinstance(contract_sha256, str) and _DIGEST.fullmatch(contract_sha256):
            bindings["contract_sha256"] = contract_sha256

    return component_id, bindings, invalid


def _optional_payload(value: object | None) -> dict[str, object] | None:
    return None if value is None else _receipt_payload(value)


def _mapping_or_empty(value: object) -> Mapping[str, object]:
    return value if isinstance(value, Mapping) else {}


def _normalize_bindings(value: Mapping[str, object]) -> dict[str, str]:
    result: dict[str, str] = {}
    for key, digest in value.items():
        identity = _identifier(key, "activation binding id")
        result[identity] = _digest(digest, f"activation binding {identity}")
    return dict(sorted(result.items()))


def _coerce_facets(
    values: Mapping[str, ActivationFacetV1 | Mapping[str, object]]
    | Sequence[ActivationFacetV1 | Mapping[str, object]],
) -> dict[str, ActivationFacetV1]:
    if isinstance(values, Mapping):
        unknown = sorted(set(values) - _ALL_FACET_IDS)
        if unknown:
            raise ActivationReceiptError(f"unsupported activation facets: {unknown!r}")
        result = {
            identity: _coerce_facet(identity, value)
            for identity, value in values.items()
        }
    else:
        rows = tuple(
            value
            if isinstance(value, ActivationFacetV1)
            else ActivationFacetV1.parse(value)
            for value in values
        )
        result = {item.identity: item for item in rows}
        if len(result) != len(rows):
            raise ActivationReceiptError("activation facets are duplicated")
    return result


def _coerce_facet(
    identity: str, value: ActivationFacetV1 | Mapping[str, object]
) -> ActivationFacetV1:
    if isinstance(value, ActivationFacetV1):
        if value.identity != identity:
            raise ActivationReceiptError(
                "activation facet map key does not match its record id"
            )
        return value
    row = dict(_object(value, f"activation facet {identity}"))
    if "id" not in row:
        row["id"] = identity
    return ActivationFacetV1.parse(row)


def _facet_from_receipt(
    facet_id: str, value: object | None, *, expected_sha256: str | None
) -> ActivationFacetV1:
    if value is None:
        return ActivationFacetV1.create(
            identity=facet_id,
            status="incomplete",
            receipt_sha256=None,
            expected_receipt_sha256=expected_sha256,
        )
    if facet_id == "interface":
        try:
            interface = (
                value
                if isinstance(value, PortableComponentInterfaceV2)
                else PortableComponentInterfaceV2.parse(value)
            )
        except (TypeError, ValueError):
            return ActivationFacetV1.create(
                identity=facet_id,
                status="violated",
                receipt_sha256=canonical_sha256_v3(_receipt_payload(value)),
                expected_receipt_sha256=expected_sha256,
            )
        observed = interface.sha256
        return ActivationFacetV1.create(
            identity=facet_id,
            status="checked",
            receipt_sha256=observed,
            expected_receipt_sha256=expected_sha256 or observed,
        )

    payload = _receipt_payload(value)
    observed, bound_expected = _bound_receipt_digest(facet_id, payload)
    stale = observed != bound_expected
    raw_status = payload.get("status")
    status = (
        "stale"
        if stale
        else str(raw_status)
        if raw_status in _FACET_STATUSES
        else "incomplete"
    )
    return ActivationFacetV1.create(
        identity=facet_id,
        status=status,
        receipt_sha256=observed,
        expected_receipt_sha256=expected_sha256 or bound_expected,
    )


def _bound_receipt_digest(
    facet_id: str, payload: Mapping[str, object]
) -> tuple[str, str]:
    for field in _DIGEST_FIELDS[facet_id]:
        if field not in payload:
            continue
        observed = _digest(payload[field], f"{facet_id} receipt digest")
        core = dict(payload)
        core.pop(field)
        return observed, canonical_sha256_v3(core)
    observed = canonical_sha256_v3(payload)
    return observed, observed


def _receipt_payload(value: object) -> dict[str, object]:
    if hasattr(value, "to_payload"):
        value = value.to_payload()  # type: ignore[union-attr]
    return dict(_object(value, "activation facet receipt"))


def _reduce(
    facets: Sequence[ActivationFacetV1],
) -> tuple[str, bool, tuple[ActivationNextActionV1, ...]]:
    blockers = [item for item in facets if item.required and not item.authorizing]
    authorized = not blockers
    status = (
        "checked"
        if authorized
        else "violated"
        if any(item.status in {"violated", "stale"} for item in blockers)
        else "incomplete"
    )
    actions = tuple(
        ActivationNextActionV1(
            rank=index,
            facet_id=facet.identity,
            code=(
                "refresh_stale_receipt"
                if facet.status == "stale"
                else "resolve_facet_violation"
                if facet.status == "violated"
                else "complete_required_facet"
            ),
            action=_ACTION_TEXT[facet.identity],
        )
        for index, facet in enumerate(blockers, start=1)
    )
    return status, authorized, actions


def _object(value: object, context: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise ActivationReceiptError(f"{context} must be an object")
    return value


def _array(value: object, context: str) -> list[object]:
    if not isinstance(value, list):
        raise ActivationReceiptError(f"{context} must be an array")
    return value


def _text(value: object, context: str) -> str:
    if not isinstance(value, str) or not value:
        raise ActivationReceiptError(f"{context} must be a nonempty string")
    return value


def _identifier(value: object, context: str) -> str:
    result = _text(value, context)
    if _IDENTIFIER.fullmatch(result) is None:
        raise ActivationReceiptError(f"{context} is not a portable identifier")
    return result


def _component_id(value: object, context: str) -> str:
    result = _text(value, context)
    if _COMPONENT_ID.fullmatch(result) is None:
        raise ActivationReceiptError(f"{context} is not a stable artifact identifier")
    return result


def _digest(value: object, context: str) -> str:
    result = _text(value, context)
    if _DIGEST.fullmatch(result) is None:
        raise ActivationReceiptError(f"{context} must be a SHA-256 digest")
    return result


def _optional_digest(value: object, context: str) -> str | None:
    return None if value is None else _digest(value, context)


def _exact(value: Mapping[str, object], fields: set[str], context: str) -> None:
    if set(value) != fields:
        raise ActivationReceiptError(
            f"{context} fields differ: missing={sorted(fields-set(value))!r}, "
            f"extra={sorted(set(value)-fields)!r}"
        )


__all__ = [
    "ACTIVATION_FACET_IDS",
    "ACTIVATION_RECEIPT_V1_FORMAT",
    "COMPONENT_ACTIVATION_RECEIPT_V1",
    "ActivationFacetV1",
    "ActivationNextActionV1",
    "ActivationReceiptError",
    "ActivationReceiptV1",
    "COMPONENT_ACTIVATION_RECEIPT_V2",
    "FacetStatusV1",
    "build_activation_receipt",
]
