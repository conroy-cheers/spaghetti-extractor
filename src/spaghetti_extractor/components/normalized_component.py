"""Neutral in-memory component semantics used by proof and native lowering.

These models are not serialized public contracts.  They normalize one retained
V5 human interface plus machine-binding intent for the contextual proof,
machine overlay, and native-object compiler.  Keeping them format-free prevents
the direct V6 path from reopening retired V4/V5 authority receipts merely to
share implementation code.
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
)
from .binding_intent import MachineOperationSemanticsV1
from .interface_package_v5 import CompiledComponentInterfaceV5
from .interface_v5 import PortableComponentInterfaceV5


@dataclass(frozen=True, order=True)
class NormalizedOperationContract:
    operation_id: str
    signature_id: str
    projection_sha256: str
    projection_receipt_sha256: str
    lifecycle_sha256: str
    lifecycle_receipt_sha256: str
    semantic_sha256: str
    unit_ids: tuple[str, ...]
    entry_rvas: tuple[int, ...]

    def to_payload(self) -> dict[str, object]:
        return {
            "id": self.operation_id,
            "signature_id": self.signature_id,
            "projection_sha256": self.projection_sha256,
            "projection_receipt_sha256": self.projection_receipt_sha256,
            "lifecycle_sha256": self.lifecycle_sha256,
            "lifecycle_receipt_sha256": self.lifecycle_receipt_sha256,
            "semantic_sha256": self.semantic_sha256,
            "unit_ids": list(self.unit_ids),
            "entry_rvas": list(self.entry_rvas),
        }


@dataclass(frozen=True)
class NormalizedComponentContract:
    component_id: str
    status: str
    interface_sha256: str
    schema_sha256: str
    machine_semantics: tuple[MachineOperationSemanticsV1, ...]
    operations: tuple[NormalizedOperationContract, ...]
    issues: tuple[Mapping[str, object], ...]
    contract_sha256: str

    @classmethod
    def create(
        cls,
        *,
        interface: PortableComponentInterfaceV5,
        machine_semantics: Sequence[MachineOperationSemanticsV1],
        issues: Sequence[Mapping[str, object]] = (),
    ) -> "NormalizedComponentContract":
        semantics = tuple(
            sorted(machine_semantics, key=lambda item: item.operation_id)
        )
        semantic_ids = tuple(item.operation_id for item in semantics)
        if semantic_ids != tuple(sorted(set(semantic_ids))):
            raise BoundaryModelError(
                "normalized component machine semantics are duplicated"
            )
        interface_index = {item.identity: item for item in interface.operations}
        semantic_index = {item.operation_id: item for item in semantics}
        normalized_issues = [
            canonical(
                dict(object_(item, f"normalized component issue {index}"))
            )
            for index, item in enumerate(issues)
        ]
        for operation_id in sorted(set(interface_index) - set(semantic_index)):
            normalized_issues.append(
                {
                    "code": "machine_operation_semantics_missing",
                    "operation_id": operation_id,
                }
            )
        for operation_id in sorted(set(semantic_index) - set(interface_index)):
            normalized_issues.append(
                {
                    "code": "machine_operation_semantics_unreachable",
                    "operation_id": operation_id,
                }
            )
        operations: list[NormalizedOperationContract] = []
        for operation_id in sorted(set(interface_index) & set(semantic_index)):
            operation = interface_index[operation_id]
            semantics_row = semantic_index[operation_id]
            if set(semantics_row.effect_ids) != set(operation.effect_ids):
                normalized_issues.append(
                    {
                        "code": "machine_operation_effects_disagree",
                        "operation_id": operation_id,
                    }
                )
            if set(semantics_row.service_ids) != set(
                operation.allowed_service_ids
            ):
                normalized_issues.append(
                    {
                        "code": "machine_operation_services_disagree",
                        "operation_id": operation_id,
                    }
                )
            operations.append(
                NormalizedOperationContract(
                    operation_id,
                    operation.signature_id,
                    operation.projection_sha256,
                    operation.projection_receipt_sha256,
                    operation.lifecycle_sha256,
                    operation.lifecycle_receipt_sha256,
                    semantics_row.semantic_sha256,
                    semantics_row.unit_ids,
                    semantics_row.entry_rvas,
                )
            )
        ordered_issues = tuple(
            sorted(normalized_issues, key=canonical_sha256_v3)
        )
        status = "checked" if not ordered_issues else "incomplete"
        core = {
            "model": "normalized-component-semantics-v1",
            "status": status,
            "component_id": interface.identity,
            "interface_sha256": interface.interface_sha256,
            "schema_sha256": interface.schema_sha256,
            "machine_semantics": [item.to_payload() for item in semantics],
            "operations": [item.to_payload() for item in operations],
            "issues": [canonical(dict(item)) for item in ordered_issues],
        }
        return cls(
            interface.identity,
            status,
            interface.interface_sha256,
            interface.schema_sha256,
            semantics,
            tuple(operations),
            ordered_issues,
            canonical_sha256_v3(core),
        )


@dataclass(frozen=True)
class NormalizedMachineBinding:
    component_id: str
    status: str
    contract_sha256: str
    artifacts: Mapping[str, str]
    operations: tuple[Mapping[str, object], ...]
    blockers: tuple[Mapping[str, object], ...]
    binding_sha256: str

    @classmethod
    def create(
        cls,
        *,
        bundle: CompiledComponentInterfaceV5,
        contract: NormalizedComponentContract,
        artifacts: Mapping[str, str],
        operation_authority: Mapping[str, Mapping[str, object]],
        blockers: Sequence[Mapping[str, object]] = (),
    ) -> "NormalizedMachineBinding":
        if (
            contract.component_id != bundle.interface.identity
            or contract.interface_sha256 != bundle.interface.interface_sha256
        ):
            raise BoundaryModelError(
                "normalized component contract disagrees with its interface"
            )
        required_artifacts = {
            "pe_sha256",
            "machine_ir_sha256",
            "machine_ir_manifest_sha256",
            "structural_units_sha256",
            "unit_inventory_sha256",
            "component_unit_inventory_sha256",
        }
        if set(artifacts) != required_artifacts:
            raise BoundaryModelError(
                "normalized component binding artifact set is incomplete"
            )
        normalized_artifacts = {
            key: digest(artifacts[key], f"normalized component binding {key}")
            for key in sorted(required_artifacts)
        }
        contract_index = {
            item.operation_id: item for item in contract.operations
        }
        rows: list[Mapping[str, object]] = []
        normalized_blockers = [
            canonical(
                dict(object_(item, f"normalized binding blocker {index}"))
            )
            for index, item in enumerate(blockers)
        ]
        for operation in bundle.interface.operations:
            authority = operation_authority.get(operation.identity)
            operation_contract = contract_index.get(operation.identity)
            if authority is None or operation_contract is None:
                normalized_blockers.append(
                    {
                        "code": "component_operation_authority_missing",
                        "operation_id": operation.identity,
                    }
                )
                continue
            authority_row = object_(
                authority,
                f"normalized component operation {operation.identity} authority",
            )
            exact(
                authority_row,
                {
                    "object_authority_selectors",
                    "pointer_views",
                    "service_ids",
                    "callback_ids",
                    "outcome_protocol_ids",
                    "relation_receipt_sha256s",
                    "induction_evidence_sha256",
                },
                f"normalized component operation {operation.identity} authority",
            )
            service_ids = _identifiers(
                authority_row["service_ids"], "normalized binding service"
            )
            if service_ids != operation.allowed_service_ids:
                normalized_blockers.append(
                    {
                        "code": "component_binding_services_disagree",
                        "operation_id": operation.identity,
                    }
                )
            induction = authority_row["induction_evidence_sha256"]
            rows.append(
                {
                    "id": operation.identity,
                    "semantic_sha256": operation_contract.semantic_sha256,
                    "projection_sha256": operation.projection_sha256,
                    "projection_receipt_sha256": operation.projection_receipt_sha256,
                    "lifecycle_sha256": operation.lifecycle_sha256,
                    "lifecycle_receipt_sha256": operation.lifecycle_receipt_sha256,
                    "unit_ids": list(operation_contract.unit_ids),
                    "entry_rvas": list(operation_contract.entry_rvas),
                    "object_authority_selectors": _object_authority_selectors(
                        authority_row["object_authority_selectors"]
                    ),
                    "pointer_views": canonical(
                        list(array(authority_row["pointer_views"], "pointer views"))
                    ),
                    "service_ids": list(service_ids),
                    "callback_ids": list(
                        _identifiers(
                            authority_row["callback_ids"],
                            "normalized binding callback",
                        )
                    ),
                    "outcome_protocol_ids": list(
                        _identifiers(
                            authority_row["outcome_protocol_ids"],
                            "normalized binding outcome",
                        )
                    ),
                    "relation_receipt_sha256s": list(
                        _digests(
                            authority_row["relation_receipt_sha256s"],
                            "normalized relation receipt",
                        )
                    ),
                    "induction_evidence_sha256": (
                        None
                        if induction is None
                        else digest(induction, "normalized induction evidence")
                    ),
                }
            )
        rows.sort(key=lambda item: str(item["id"]))
        ordered_blockers = tuple(
            sorted(normalized_blockers, key=canonical_sha256_v3)
        )
        status = (
            "checked"
            if contract.status == "checked"
            and not ordered_blockers
            and len(rows) == len(bundle.interface.operations)
            else "incomplete"
        )
        core = {
            "model": "normalized-component-binding-v1",
            "status": status,
            "component_id": bundle.interface.identity,
            "contract_sha256": contract.contract_sha256,
            "artifacts": normalized_artifacts,
            "operations": rows,
            "blockers": [canonical(dict(item)) for item in ordered_blockers],
        }
        return cls(
            bundle.interface.identity,
            status,
            contract.contract_sha256,
            normalized_artifacts,
            tuple(rows),
            ordered_blockers,
            canonical_sha256_v3(core),
        )


def _identifiers(value: object, context: str) -> tuple[str, ...]:
    rows = array(value, context)
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


__all__ = [
    "NormalizedComponentContract",
    "NormalizedMachineBinding",
    "NormalizedOperationContract",
]
