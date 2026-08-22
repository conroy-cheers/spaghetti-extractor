"""Generate a trust-zero Lean audit for one canonical component relation."""

from __future__ import annotations

from .interface_ir import PortableComponentInterfaceV2
from .interaction_contract import InteractionContractCatalogV1
from .interaction_inventory import ComponentInteractionInventoryV1
from .relation_checker import check_component_relation
from .relation_ir import ComponentRelationIRV1


class RelationLeanError(ValueError):
    """A relation cannot be submitted to the Lean kernel."""


def render_relation_certificate(
    *,
    relation: ComponentRelationIRV1,
    interface: PortableComponentInterfaceV2,
    interaction_inventory: ComponentInteractionInventoryV1,
    contract_catalog: InteractionContractCatalogV1,
) -> str:
    """Render an artifact-specific certificate over the proved relation kernel.

    Python establishes only that the artifact can be encoded.  Lean checks the
    submitted static certificate and the reusable lens/reference theorems at
    trust level zero.  The resulting olean digest is required by the receipt.
    """

    preview = check_component_relation(
        relation=relation,
        interface=interface,
        interaction_inventory=interaction_inventory,
        contract_catalog=contract_catalog,
        lean_artifact_sha256=None,
    )
    blockers = [
        item
        for item in preview.obligations
        if item.identity != "proof.lean" and item.status != "checked"
    ]
    if blockers:
        detail = ", ".join(f"{item.identity}:{item.code}" for item in blockers)
        raise RelationLeanError(f"relation has unresolved pre-Lean obligations: {detail}")
    relation_name = _lean_identifier(relation.component_id)
    operation_count = len(relation.operations)
    schedules = {
        operation.operation_id: (
            [clause.identity for clause in operation.clauses]
            + [
                f"{interaction.identity}.{port.identity}"
                for interaction in operation.interactions
                for port in interaction.ports
            ]
        )
        for operation in relation.operations
    }
    clause_count = sum(len(items) for items in schedules.values())
    operation_schedules = ",\n  ".join(
        "{ id := \"%s\", actions := [%s] }"
        % (
            operation.operation_id,
            ", ".join(
                "{ id := \"%s\", sequence := %d }" % (identity, index)
                for index, identity in enumerate(schedules[operation.operation_id])
            ),
        )
        for operation in relation.operations
    )
    return f"""import SpaghettiExtractor.Components.Relations

namespace SpaghettiExtractor.Generated.{relation_name}

open SpaghettiExtractor.Components.Relations

def relationSha256 : String := \"{relation.relation_sha256}\"
def operationCount : Nat := {operation_count}
def clauseCount : Nat := {clause_count}

def certificate : BoundaryPlanCertificate := {{
  operations := [
  {operation_schedules}
  ]
  operationCount := operationCount
  clauseCount := clauseCount
}}

theorem certificate_checked : checkBoundaryPlanCertificate certificate = true := by
  rfl

theorem certificate_sound :
    ((certificate.operationCount > 0 ∧
    certificate.operations.length = certificate.operationCount) ∧
    (certificate.operations.map (·.actions.length)).sum = certificate.clauseCount) ∧
    certificate.operations.all OperationSchedule.valid = true :=
  checkBoundaryPlanCertificate_sound certificate certificate_checked

#print axioms certificate_sound

end SpaghettiExtractor.Generated.{relation_name}
"""


def _lean_identifier(value: str) -> str:
    pieces = [piece for piece in value.replace("-", "_").replace(".", "_").split("_") if piece]
    rendered = "".join(piece[:1].upper() + piece[1:] for piece in pieces)
    if not rendered or not rendered[0].isalpha() or not all(item.isalnum() for item in rendered):
        raise RelationLeanError("component id cannot be rendered as a Lean namespace")
    return rendered


__all__ = ["RelationLeanError", "render_relation_certificate"]
