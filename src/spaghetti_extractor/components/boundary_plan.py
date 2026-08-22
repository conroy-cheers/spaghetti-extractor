"""Compilation of checked relations into occurrence-local boundary templates."""

from __future__ import annotations

import copy
import re
from dataclasses import dataclass
from typing import Mapping, Sequence

from ..artifacts.artifact_set import canonical_sha256_v3
from .boundary_primitives import (
    BoundaryPrimitiveError,
    BoundaryPrimitiveRegistryV1,
    DEFAULT_BOUNDARY_PRIMITIVES,
)
from .formats import (
    COMPONENT_BOUNDARY_PLAN_RECEIPT_V3_FORMAT,
    COMPONENT_BOUNDARY_PLAN_V3_FORMAT,
)
from .relation_ir import ComponentRelationIRV1, RelationClauseV1, RelationInteractionV1
from .relation_receipt import ComponentRelationReceiptV1


BOUNDARY_PLAN_V3 = COMPONENT_BOUNDARY_PLAN_V3_FORMAT
BOUNDARY_PLAN_RECEIPT_V3 = COMPONENT_BOUNDARY_PLAN_RECEIPT_V3_FORMAT
_DIGEST = re.compile(r"[0-9a-f]{64}\Z")


class ComponentBoundaryPlanError(ValueError):
    """A compiled boundary plan is malformed, stale, or unauthorized."""


def _digest(value: object, context: str) -> str:
    if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
        raise ComponentBoundaryPlanError(f"{context} must be a SHA-256 digest")
    return value


@dataclass(frozen=True)
class BoundaryActionV1:
    identity: str
    sequence: int
    phase: str
    kind: str
    effect_class: str
    clause: Mapping[str, object]
    primitive_ids: tuple[str, ...]

    @classmethod
    def parse(cls, value: object, context: str) -> "BoundaryActionV1":
        if not isinstance(value, Mapping) or set(value) != {
            "id", "sequence", "phase", "kind", "effect_class", "clause", "primitive_ids"
        }:
            raise ComponentBoundaryPlanError(f"{context} has invalid fields")
        text = (value["id"], value["phase"], value["kind"], value["effect_class"])
        if not all(isinstance(item, str) and item for item in text):
            raise ComponentBoundaryPlanError(f"{context} identity is invalid")
        sequence = value["sequence"]
        if not isinstance(sequence, int) or isinstance(sequence, bool) or sequence < 0:
            raise ComponentBoundaryPlanError(f"{context} sequence is invalid")
        if not isinstance(value["clause"], Mapping) or not isinstance(value["primitive_ids"], list):
            raise ComponentBoundaryPlanError(f"{context} payload is invalid")
        primitives = tuple(value["primitive_ids"])
        if any(not isinstance(item, str) or not item for item in primitives) or primitives != tuple(sorted(set(primitives))):
            raise ComponentBoundaryPlanError(f"{context} primitives are invalid")
        return cls(
            str(value["id"]), sequence, str(value["phase"]), str(value["kind"]),
            str(value["effect_class"]), copy.deepcopy(dict(value["clause"])), primitives,
        )

    def to_payload(self) -> dict[str, object]:
        return {
            "id": self.identity,
            "sequence": self.sequence,
            "phase": self.phase,
            "kind": self.kind,
            "effect_class": self.effect_class,
            "clause": copy.deepcopy(dict(self.clause)),
            "primitive_ids": list(self.primitive_ids),
        }


def _parse_actions(value: object, context: str, phases: set[str]) -> tuple[BoundaryActionV1, ...]:
    if not isinstance(value, list):
        raise ComponentBoundaryPlanError(f"{context} actions are invalid")
    actions = tuple(BoundaryActionV1.parse(item, f"{context} action {index}") for index, item in enumerate(value))
    if tuple(item.sequence for item in actions) != tuple(range(len(actions))):
        raise ComponentBoundaryPlanError(f"{context} schedule is invalid")
    if any(item.phase not in phases for item in actions):
        raise ComponentBoundaryPlanError(f"{context} contains an action in the wrong phase")
    return actions


@dataclass(frozen=True)
class BoundaryInteractionPlanV1:
    identity: str
    machine_event: Mapping[str, object]
    contract_id: str | None
    contract_sha256: str | None
    contract_receipt_sha256: str | None
    before_actions: tuple[BoundaryActionV1, ...]
    invoke_action: BoundaryActionV1
    after_actions: tuple[BoundaryActionV1, ...]

    @classmethod
    def parse(cls, value: object, context: str) -> "BoundaryInteractionPlanV1":
        if not isinstance(value, Mapping) or set(value) != {
            "id", "machine_event", "contract_id", "contract_sha256",
            "contract_receipt_sha256", "before_actions", "invoke_action", "after_actions"
        }:
            raise ComponentBoundaryPlanError(f"{context} has invalid fields")
        if not isinstance(value["id"], str) or not value["id"] or not isinstance(value["machine_event"], Mapping):
            raise ComponentBoundaryPlanError(f"{context} identity is invalid")
        before = _parse_actions(value["before_actions"], f"{context} before", {"event_before"})
        after = _parse_actions(value["after_actions"], f"{context} after", {"event_after"})
        invoke = BoundaryActionV1.parse(value["invoke_action"], f"{context} invocation")
        if invoke.kind != "invoke" or invoke.effect_class != "world_effect" or invoke.sequence != len(before):
            raise ComponentBoundaryPlanError(f"{context} invocation is invalid")
        if tuple(item.sequence for item in after) != tuple(range(len(after))):
            raise ComponentBoundaryPlanError(f"{context} after schedule is invalid")
        contract_id = value["contract_id"]
        hashes = (value["contract_sha256"], value["contract_receipt_sha256"])
        if contract_id is None:
            if hashes != (None, None):
                raise ComponentBoundaryPlanError(f"{context} contract binding is partial")
        elif not isinstance(contract_id, str) or not contract_id:
            raise ComponentBoundaryPlanError(f"{context} contract id is invalid")
        else:
            _digest(hashes[0], f"{context} contract")
            _digest(hashes[1], f"{context} contract receipt")
        return cls(
            str(value["id"]), copy.deepcopy(dict(value["machine_event"])),
            None if contract_id is None else str(contract_id),
            None if hashes[0] is None else str(hashes[0]),
            None if hashes[1] is None else str(hashes[1]),
            before, invoke, after,
        )

    def to_payload(self) -> dict[str, object]:
        return {
            "id": self.identity,
            "machine_event": copy.deepcopy(dict(self.machine_event)),
            "contract_id": self.contract_id,
            "contract_sha256": self.contract_sha256,
            "contract_receipt_sha256": self.contract_receipt_sha256,
            "before_actions": [item.to_payload() for item in self.before_actions],
            "invoke_action": self.invoke_action.to_payload(),
            "after_actions": [item.to_payload() for item in self.after_actions],
        }


@dataclass(frozen=True)
class BoundaryOperationPlanV2:
    operation_id: str
    entry_actions: tuple[BoundaryActionV1, ...]
    interactions: tuple[BoundaryInteractionPlanV1, ...]
    exit_actions: tuple[BoundaryActionV1, ...]
    cutpoint_actions: tuple[BoundaryActionV1, ...]

    @property
    def actions(self) -> tuple[BoundaryActionV1, ...]:
        """Flattened boundary schedule used by finite-path lowering."""
        return self.entry_actions + self.exit_actions + self.cutpoint_actions

    @classmethod
    def parse(cls, value: object, context: str) -> "BoundaryOperationPlanV2":
        if not isinstance(value, Mapping) or set(value) != {
            "operation_id", "entry_actions", "interactions", "exit_actions", "cutpoint_actions"
        }:
            raise ComponentBoundaryPlanError(f"{context} has invalid fields")
        if not isinstance(value["operation_id"], str) or not value["operation_id"]:
            raise ComponentBoundaryPlanError(f"{context} operation id is invalid")
        if not isinstance(value["interactions"], list):
            raise ComponentBoundaryPlanError(f"{context} interactions are invalid")
        interactions = tuple(
            BoundaryInteractionPlanV1.parse(item, f"{context} interaction {index}")
            for index, item in enumerate(value["interactions"])
        )
        ids = [item.identity for item in interactions]
        if ids != sorted(set(ids)):
            raise ComponentBoundaryPlanError(f"{context} interactions are not canonical")
        return cls(
            str(value["operation_id"]),
            _parse_actions(value["entry_actions"], f"{context} entry", {"entry"}),
            interactions,
            _parse_actions(value["exit_actions"], f"{context} exit", {"exit"}),
            _parse_actions(value["cutpoint_actions"], f"{context} cutpoint", {"cutpoint"}),
        )

    def to_payload(self) -> dict[str, object]:
        return {
            "operation_id": self.operation_id,
            "entry_actions": [item.to_payload() for item in self.entry_actions],
            "interactions": [item.to_payload() for item in self.interactions],
            "exit_actions": [item.to_payload() for item in self.exit_actions],
            "cutpoint_actions": [item.to_payload() for item in self.cutpoint_actions],
        }


@dataclass(frozen=True)
class ComponentBoundaryPlanV2:
    component_id: str
    machine_backend: str
    bindings: Mapping[str, str]
    operations: tuple[BoundaryOperationPlanV2, ...]
    plan_sha256: str

    @property
    def relation_sha256(self) -> str:
        return self.bindings["relation_sha256"]

    @classmethod
    def parse(cls, value: object) -> "ComponentBoundaryPlanV2":
        if not isinstance(value, Mapping) or set(value) != {
            "format", "component_id", "machine_backend", "bindings", "operations", "plan_sha256"
        } or value.get("format") != BOUNDARY_PLAN_V3:
            raise ComponentBoundaryPlanError("unsupported or malformed component boundary plan")
        bindings, operations = value["bindings"], value["operations"]
        if not isinstance(bindings, Mapping) or not isinstance(operations, list):
            raise ComponentBoundaryPlanError("component boundary plan inventory is invalid")
        required = {
            "relation_sha256", "relation_receipt_sha256", "interface_sha256",
            "semantic_contract_sha256", "machine_ir_sha256", "primitive_registry_sha256",
            "object_authority_sha256", "interaction_inventory_sha256",
            "interaction_contract_catalog_sha256",
        }
        if set(bindings) < required or any(_DIGEST.fullmatch(str(item)) is None for item in bindings.values()):
            raise ComponentBoundaryPlanError("component boundary plan bindings are invalid")
        parsed = tuple(BoundaryOperationPlanV2.parse(item, f"boundary operation {index}") for index, item in enumerate(operations))
        ids = [item.operation_id for item in parsed]
        if not parsed or ids != sorted(set(ids)):
            raise ComponentBoundaryPlanError("boundary operations must be unique and ordered")
        core = {key: copy.deepcopy(item) for key, item in value.items() if key != "plan_sha256"}
        observed = _digest(value["plan_sha256"], "component boundary plan digest")
        if canonical_sha256_v3(core) != observed:
            raise ComponentBoundaryPlanError("component boundary plan digest is stale")
        return cls(str(value["component_id"]), str(value["machine_backend"]), dict(sorted(bindings.items())), parsed, observed)

    def to_payload(self) -> dict[str, object]:
        core = {
            "format": BOUNDARY_PLAN_V3,
            "component_id": self.component_id,
            "machine_backend": self.machine_backend,
            "bindings": dict(self.bindings),
            "operations": [item.to_payload() for item in self.operations],
        }
        return {**core, "plan_sha256": self.plan_sha256}


@dataclass(frozen=True)
class ComponentBoundaryPlanReceiptV2:
    component_id: str
    plan_sha256: str
    status: str
    obligations: tuple[Mapping[str, object], ...]
    receipt_sha256: str

    @property
    def authorizing(self) -> bool:
        return self.status == "checked"

    @classmethod
    def parse(cls, value: object) -> "ComponentBoundaryPlanReceiptV2":
        if not isinstance(value, Mapping) or set(value) != {
            "format", "component_id", "plan_sha256", "status", "obligations", "receipt_sha256"
        } or value.get("format") != BOUNDARY_PLAN_RECEIPT_V3:
            raise ComponentBoundaryPlanError("unsupported or malformed boundary plan receipt")
        if value["status"] not in {"checked", "incomplete", "violated"} or not isinstance(value["obligations"], list):
            raise ComponentBoundaryPlanError("boundary plan receipt status is invalid")
        obligations = tuple(copy.deepcopy(dict(item)) for item in value["obligations"] if isinstance(item, Mapping))
        if len(obligations) != len(value["obligations"]):
            raise ComponentBoundaryPlanError("boundary plan obligation is invalid")
        ids = [str(item.get("id")) for item in obligations]
        if not obligations or ids != sorted(set(ids)):
            raise ComponentBoundaryPlanError("boundary plan obligations are not canonical")
        if (value["status"] == "checked") != all(item.get("status") == "checked" for item in obligations):
            raise ComponentBoundaryPlanError("boundary plan receipt status is inconsistent")
        core = {key: copy.deepcopy(item) for key, item in value.items() if key != "receipt_sha256"}
        observed = _digest(value["receipt_sha256"], "boundary plan receipt digest")
        if canonical_sha256_v3(core) != observed:
            raise ComponentBoundaryPlanError("boundary plan receipt digest is stale")
        return cls(str(value["component_id"]), _digest(value["plan_sha256"], "boundary plan digest"), str(value["status"]), obligations, observed)

    def to_payload(self) -> dict[str, object]:
        return {
            "format": BOUNDARY_PLAN_RECEIPT_V3,
            "component_id": self.component_id,
            "plan_sha256": self.plan_sha256,
            "status": self.status,
            "obligations": [copy.deepcopy(dict(item)) for item in self.obligations],
            "receipt_sha256": self.receipt_sha256,
        }


def compile_component_boundary_plan(
    *,
    relation: ComponentRelationIRV1,
    relation_receipt: ComponentRelationReceiptV1,
    object_authority_sha256: str,
    primitive_registry: BoundaryPrimitiveRegistryV1 = DEFAULT_BOUNDARY_PRIMITIVES,
) -> tuple[ComponentBoundaryPlanV2, ComponentBoundaryPlanReceiptV2]:
    relation_receipt.validate_for(relation)
    if not relation_receipt.authorizing:
        raise ComponentBoundaryPlanError("unchecked relation cannot compile an executable plan")
    _digest(object_authority_sha256, "boundary plan object authority digest")
    primitive_errors: list[tuple[str, str]] = []
    operation_payloads: list[dict[str, object]] = []
    for operation in relation.operations:
        by_phase: dict[str, list[dict[str, object]]] = {"entry": [], "exit": [], "cutpoint": []}
        for clause in operation.clauses:
            if clause.phase not in by_phase:
                primitive_errors.append((f"{operation.operation_id}.{clause.identity}", "event clause is not owned by an interaction"))
                continue
            by_phase[clause.phase].append(_action_payload(clause, len(by_phase[clause.phase]), primitive_registry, primitive_errors, operation.operation_id))
        interactions = [
            _interaction_plan_payload(item, primitive_registry, primitive_errors, operation.operation_id)
            for item in operation.interactions
        ]
        operation_payloads.append({
            "operation_id": operation.operation_id,
            "entry_actions": by_phase["entry"],
            "interactions": interactions,
            "exit_actions": by_phase["exit"],
            "cutpoint_actions": by_phase["cutpoint"],
        })
    bindings = {
        **dict(relation.bindings),
        "relation_sha256": relation.relation_sha256,
        "relation_receipt_sha256": relation_receipt.receipt_sha256,
        "primitive_registry_sha256": primitive_registry.sha256,
        "object_authority_sha256": object_authority_sha256,
    }
    core = {
        "format": BOUNDARY_PLAN_V3,
        "component_id": relation.component_id,
        "machine_backend": relation.machine_backend,
        "bindings": dict(sorted(bindings.items())),
        "operations": operation_payloads,
    }
    plan = ComponentBoundaryPlanV2.parse({**core, "plan_sha256": canonical_sha256_v3(core)})
    evidence = sorted({plan.plan_sha256, *plan.bindings.values()})
    obligations = [
        {"id": "authority.object", "status": "checked", "code": "object_authority_exact", "evidence": evidence},
        {"id": "binding.relation", "status": "checked", "code": "relation_receipt_authorizing", "evidence": evidence},
        {"id": "coverage.templates", "status": "checked", "code": "interaction_templates_exact", "evidence": evidence},
        {
            "id": "registry.primitives",
            "status": "violated" if primitive_errors else "checked",
            "code": "primitive_invocation_invalid:" + ";".join(f"{key}:{detail}" for key, detail in primitive_errors) if primitive_errors else "primitive_implementations_complete",
            "evidence": [] if primitive_errors else evidence,
        },
    ]
    status = "violated" if primitive_errors else "checked"
    receipt_core = {
        "format": BOUNDARY_PLAN_RECEIPT_V3,
        "component_id": plan.component_id,
        "plan_sha256": plan.plan_sha256,
        "status": status,
        "obligations": sorted(obligations, key=lambda item: str(item["id"])),
    }
    receipt = ComponentBoundaryPlanReceiptV2.parse({**receipt_core, "receipt_sha256": canonical_sha256_v3(receipt_core)})
    return plan, receipt


def _interaction_plan_payload(
    interaction: RelationInteractionV1,
    registry: BoundaryPrimitiveRegistryV1,
    failures: list[tuple[str, str]],
    operation_id: str,
) -> dict[str, object]:
    before = [
        _action_payload(item, index, registry, failures, operation_id)
        for index, item in enumerate(port for port in interaction.ports if port.phase == "event_before")
    ]
    invocation = {
        "id": f"{interaction.identity}.invoke",
        "sequence": len(before),
        "phase": "event_before",
        "kind": "invoke",
        "effect_class": "world_effect",
        "clause": interaction.to_payload(),
        "primitive_ids": [interaction.primitive_id],
    }
    try:
        primitive = registry.primitive(interaction.primitive_id)
        if primitive.effect_class != "world_effect" or "event_before" not in primitive.phases:
            raise BoundaryPrimitiveError("interaction primitive is not an event-before world effect")
    except BoundaryPrimitiveError as exc:
        failures.append((f"{operation_id}.{interaction.identity}", str(exc)))
    after = [
        _action_payload(item, index, registry, failures, operation_id)
        for index, item in enumerate(port for port in interaction.ports if port.phase == "event_after")
    ]
    return {
        "id": interaction.identity,
        "machine_event": copy.deepcopy(dict(interaction.machine_event)),
        "contract_id": interaction.contract_id,
        "contract_sha256": interaction.contract_sha256,
        "contract_receipt_sha256": interaction.contract_receipt_sha256,
        "before_actions": before,
        "invoke_action": invocation,
        "after_actions": after,
    }


def _action_payload(
    clause: RelationClauseV1,
    sequence: int,
    registry: BoundaryPrimitiveRegistryV1,
    failures: list[tuple[str, str]],
    operation_id: str,
) -> dict[str, object]:
    primitive_ids = _clause_primitives(clause)
    effect_class = "world_effect" if clause.kind == "effect_link" else ("machine_write" if clause.realize else "pure")
    for expression, primitive_id in _clause_primitive_calls(clause):
        try:
            primitive = registry.primitive(primitive_id)
            primitive.validate_call(arguments=[item.sort for item in expression.arguments], result=expression.sort, phase=clause.phase)
            if primitive.effect_class != "pure":
                effect_class = primitive.effect_class
        except BoundaryPrimitiveError as exc:
            failures.append((f"{operation_id}.{clause.identity}", str(exc)))
    return {
        "id": clause.identity,
        "sequence": sequence,
        "phase": clause.phase,
        "kind": clause.kind,
        "effect_class": effect_class,
        "clause": clause.to_payload(),
        "primitive_ids": list(primitive_ids),
    }


def _clause_primitive_calls(clause: RelationClauseV1):
    expressions = [item for item in (clause.observe, clause.predicate) if item is not None]
    for write in clause.realize:
        expressions.extend((write.value, write.guard))
    for root in expressions:
        for expression in root.walk():
            if expression.op == "authority_call":
                yield expression, str(expression.attributes["primitive"])


def _clause_primitives(clause: RelationClauseV1) -> tuple[str, ...]:
    return tuple(sorted({primitive for _expression, primitive in _clause_primitive_calls(clause)}))


__all__ = [
    "BOUNDARY_PLAN_RECEIPT_V3", "BOUNDARY_PLAN_V3", "BoundaryActionV1",
    "BoundaryInteractionPlanV1", "BoundaryOperationPlanV2",
    "ComponentBoundaryPlanError", "ComponentBoundaryPlanReceiptV2",
    "ComponentBoundaryPlanV2",
    "compile_component_boundary_plan",
]
