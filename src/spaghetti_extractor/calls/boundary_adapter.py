"""Read-only adapters from legacy call artifacts to canonical boundaries.

New producers should author :mod:`spaghetti_extractor.boundary` artifacts.  The
adapters live on the legacy side of the dependency edge so the neutral kernel
never imports call, component, compiler, or machine-IR models.
"""

from __future__ import annotations

from typing import Sequence

from ..boundary import (
    BoundaryEvidenceReceiptV1,
    BoundaryFactSetV1,
    BoundaryFactV1,
    BoundaryRequirementV1,
    BoundaryLifecycleV1,
    BoundarySchemaV1,
    BoundarySubjectV1,
    BoundaryValueV1,
    TargetDataLayoutV1,
)
from .evidence import MachineCallEvidenceV1, TRANSPORT_FIELDS
from .frame import PhysicalCallFrameV2
from .frame import PhysicalCallFrameV3
from .lifecycle import CallLifecycleV1
from .types import PortableTypeGraphV1, TargetLayoutSetV1


def schema_from_call_v1(
    graph: PortableTypeGraphV1, *, function_type_id: str, schema_id: str
) -> BoundarySchemaV1:
    """Losslessly wrap a V1 type graph and one function as a boundary schema."""

    function = graph.index[function_type_id]
    parameters = [
        _value(f"arg{index}", str(type_id))
        for index, type_id in enumerate(function.body["parameter_type_ids"])
    ]
    result_type_id = str(function.body["result_type_id"])
    results = (
        []
        if graph.index[result_type_id].kind == "void"
        else [_value("result0", result_type_id)]
    )
    return BoundarySchemaV1.create(
        schema_id=schema_id,
        types=[item.to_payload() for item in graph.nodes],
        signatures=[{
            "id": function_type_id,
            "function_type_id": function_type_id,
            "parameters": parameters,
            "results": results,
        }],
    )


def layout_from_call_v1(
    layout_set: TargetLayoutSetV1, *, schema: BoundarySchemaV1
) -> TargetDataLayoutV1:
    """Convert a legacy call layout, enforcing the stronger canonical checks."""

    return TargetDataLayoutV1.create(
        target=layout_set.target,
        abi_dialect=layout_set.abi_dialect,
        byte_order=layout_set.byte_order,
        pointer_width_bits=layout_set.pointer_width_bits,
        packing=layout_set.packing,
        schema=schema,
        layouts=[{
            "type_id": item.type_id,
            "size_bits": item.size_bits,
            "alignment_bits": item.alignment_bits,
            "value_bits": item.value_bits,
            "abi_class": _abi_class(schema.type_index[item.type_id].kind),
            "fields": [field.to_payload() for field in item.fields],
            "padding": [padding.to_payload() for padding in item.padding],
        } for item in layout_set.layouts],
    )


def reconcile_machine_call_evidence_v1(
    *,
    expected: PhysicalCallFrameV2,
    evidence: Sequence[MachineCallEvidenceV1],
) -> BoundaryEvidenceReceiptV1:
    """Join partial V1 observations fieldwise against an expected frame."""

    payload = expected.to_payload()
    subject = BoundarySubjectV1.parse(expected.subject.to_payload())
    binary_sha256 = evidence[0].binary_sha256 if evidence else "0" * 64
    requirements = tuple(
        BoundaryRequirementV1.create(
            key=f"call-frame.{key}",
            legal_values=[payload[key]],
            rule_ids=[f"{expected.abi_dialect}.{key}"],
            requires_observation=key in {"arguments", "results", "stack"},
        )
        for key in sorted(TRANSPORT_FIELDS)
    )
    sources = [
        BoundaryFactSetV1.create(
            producer_class="dialect_rule",
            producer_id=f"{expected.abi_dialect}.lowering",
            subject=subject,
            binary_sha256=binary_sha256,
            facts=tuple(
                BoundaryFactV1.create(
                    key=f"call-frame.{key}", state="exact", values=[payload[key]]
                )
                for key in sorted(TRANSPORT_FIELDS)
            ),
        )
    ]
    sources.extend(
        BoundaryFactSetV1.create(
            producer_class="machine_observation",
            producer_id=item.producer,
            subject=subject,
            binary_sha256=item.binary_sha256,
            facts=tuple(
                BoundaryFactV1.create(
                    key=f"call-frame.{key}", state="exact", values=[value]
                )
                for key, value in sorted(item.observed_fields.items())
            ),
            dependency_ids=item.dependency_ids,
        )
        for item in evidence
    )
    return BoundaryEvidenceReceiptV1.reconcile(
        subject=subject,
        binary_sha256=binary_sha256,
        requirements=requirements,
        fact_sets=sources,
    )


def lifecycle_from_call_v1(
    *,
    schema: BoundarySchemaV1,
    signature_id: str,
    frame: PhysicalCallFrameV3,
    lifecycle: CallLifecycleV1,
) -> BoundaryLifecycleV1:
    """Translate legacy slot paths through the checked V3 value bindings."""

    paths = {item.slot_id: item.path for item in frame.bindings}
    rows = []
    for binding in lifecycle.bindings:
        path = paths.get(binding.path.slot_id)
        if path is None:
            raise ValueError(
                f"legacy lifecycle names unbound slot {binding.path.slot_id!r}"
            )
        contracts = lifecycle.interaction_contract_ids
        if binding.service_id is not None and len(contracts) != 1:
            raise ValueError(
                "legacy provider lifecycle requires exactly one interaction contract "
                "for lossless canonical migration"
            )
        rows.append({
            "id": binding.identity,
            "path": {
                "root": path.root,
                "value_id": path.value_id,
                "fields": [*path.fields, *binding.path.fields],
            },
            "transition": binding.transition,
            "resource_kind": binding.resource_kind,
            "provider_domain": binding.provider_domain,
            "service_id": binding.service_id,
            "interaction_contract_id": (
                contracts[0] if binding.service_id is not None else None
            ),
            "condition": binding.condition,
        })
    return BoundaryLifecycleV1.create(
        schema=schema, signature_id=signature_id, bindings=rows
    )


def _value(identity: str, type_id: str) -> dict[str, object]:
    return BoundaryValueV1.parse({
        "id": identity,
        "type_id": type_id,
        "interpretation": "value",
        "nullable": False,
        "access": "none",
        "extent": {"kind": "none", "bytes": None, "value_id": None},
        "resource_kind": None,
        "provider_domain": None,
    }, f"legacy call value {identity}").to_payload()


def _abi_class(kind: str) -> str:
    if kind in {"record", "union", "array"}:
        return "aggregate"
    if kind == "pointer":
        return "pointer"
    if kind in {"float", "complex"}:
        return "floating"
    if kind == "vector":
        return "vector"
    return "integer"


__all__ = [
    "layout_from_call_v1",
    "lifecycle_from_call_v1",
    "reconcile_machine_call_evidence_v1",
    "schema_from_call_v1",
]
