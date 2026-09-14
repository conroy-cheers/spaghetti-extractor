"""Non-authorizing relation intent and fail-closed V4 relation facet."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping, Sequence

from ..artifacts.artifact_set import canonical_sha256_v3
from ..boundary._canonical import (
    BoundaryModelError,
    array,
    canonical,
    exact,
    identifier,
    object_,
)
from .formats import COMPONENT_RELATION_INTENT_V1_FORMAT
from .relation_ir import BOOL_SORT, RelationExpressionV1


_POLICY = {
    "intent_authorizes": False,
    "checked_evidence_required": True,
    "tests_authorize": False,
}
_RELATIONS = {"borrowed_interior_or_null"}


@dataclass(frozen=True)
class ComponentRelationIntentV1:
    component_id: str
    status: str
    operations: tuple[Mapping[str, object], ...]
    blockers: tuple[Mapping[str, object], ...]
    intent_sha256: str

    def checked_normal_exit_views(self, **proof_inputs) -> list[dict[str, object]]:
        """Check supported normal-return facts in an existing local proof world.

        This inspection does not qualify a provider or compose a callee summary.
        Unsupported predicates and stale proof inputs fail closed.
        """
        from .normal_exit_postconditions import checked_normal_exit_view_postconditions

        return checked_normal_exit_view_postconditions(intent=self, **proof_inputs)

    @classmethod
    def create(
        cls,
        *,
        component_id: str,
        operations: Sequence[Mapping[str, object]],
        blockers: Sequence[Mapping[str, object]],
    ) -> "ComponentRelationIntentV1":
        normalized_operations = tuple(sorted(
            (_operation(item) for item in operations),
            key=lambda item: str(item["operation_id"]),
        ))
        operation_ids = tuple(str(item["operation_id"]) for item in normalized_operations)
        if not operation_ids or len(operation_ids) != len(set(operation_ids)):
            raise BoundaryModelError(
                "component relation intent operations must be nonempty and unique"
            )
        normalized_blockers = tuple(sorted(
            (_blocker(item) for item in blockers),
            key=lambda item: str(item["code"]),
        ))
        blocker_codes = tuple(str(item["code"]) for item in normalized_blockers)
        if len(blocker_codes) != len(set(blocker_codes)):
            raise BoundaryModelError("component relation intent blockers are duplicated")
        status = "incomplete" if normalized_blockers else "ready_for_check"
        core = {
            "format": COMPONENT_RELATION_INTENT_V1_FORMAT,
            "component_id": identifier(component_id, "relation intent component"),
            "status": status,
            "operations": list(normalized_operations),
            "blockers": list(normalized_blockers),
            "policy": _POLICY,
        }
        return cls(
            str(core["component_id"]),
            status,
            normalized_operations,
            normalized_blockers,
            canonical_sha256_v3(core),
        )

    @classmethod
    def parse(cls, value: object) -> "ComponentRelationIntentV1":
        row = object_(value, "component relation intent V1")
        exact(
            row,
            {
                "format", "component_id", "status", "operations", "blockers",
                "policy", "intent_sha256",
            },
            "component relation intent V1",
        )
        if row["format"] != COMPONENT_RELATION_INTENT_V1_FORMAT:
            raise BoundaryModelError("component relation intent format is unsupported")
        if row["policy"] != _POLICY:
            raise BoundaryModelError("component relation intent policy is unsupported")
        result = cls.create(
            component_id=str(row["component_id"]),
            operations=[
                dict(object_(item, f"relation operation {index}"))
                for index, item in enumerate(array(row["operations"], "relation operations"))
            ],
            blockers=[
                dict(object_(item, f"relation blocker {index}"))
                for index, item in enumerate(array(row["blockers"], "relation blockers"))
            ],
        )
        if row["status"] != result.status:
            raise BoundaryModelError("component relation intent status is stale")
        if row["intent_sha256"] != result.intent_sha256:
            raise BoundaryModelError("component relation intent digest is stale")
        return result

    def to_payload(self) -> dict[str, object]:
        core = {
            "format": COMPONENT_RELATION_INTENT_V1_FORMAT,
            "component_id": self.component_id,
            "status": self.status,
            "operations": [canonical(dict(item)) for item in self.operations],
            "blockers": [canonical(dict(item)) for item in self.blockers],
            "policy": _POLICY,
        }
        return {**core, "intent_sha256": self.intent_sha256}


def _operation(value: Mapping[str, object]) -> Mapping[str, object]:
    row = object_(value, "component relation operation")
    exact(row, {"operation_id", "requirements"}, "component relation operation")
    requirements = tuple(sorted(
        (_requirement(item) for item in array(row["requirements"], "relation requirements")),
        key=lambda item: str(item["id"]),
    ))
    ids = tuple(str(item["id"]) for item in requirements)
    if not ids or len(ids) != len(set(ids)):
        raise BoundaryModelError("relation requirements must be nonempty and unique")
    return canonical({
        "operation_id": identifier(row["operation_id"], "relation operation"),
        "requirements": list(requirements),
    })


def _requirement(value: object) -> Mapping[str, object]:
    row = object_(value, "component relation requirement")
    if row.get("relation") == "normal_exit_postcondition":
        exact(row, {"id", "relation", "expression"}, "normal exit postcondition")
        expression = RelationExpressionV1.parse(row["expression"])
        if (expression.sort != BOOL_SORT or expression.machine_places() or
                any(node.op == "authority_call" for node in expression.walk())):
            raise BoundaryModelError("normal exit postcondition must be a logical Boolean predicate")
        return canonical({"id": identifier(row["id"], "relation requirement"),
                          "relation": row["relation"], "expression": expression.to_payload()})
    exact(
        row,
        {"id", "relation", "service_id", "origin_parameter_id", "result_value_id"},
        "component relation requirement",
    )
    relation = row["relation"]
    if relation not in _RELATIONS:
        raise BoundaryModelError("component relation requirement is unsupported")
    return canonical({
        "id": identifier(row["id"], "relation requirement"),
        "relation": relation,
        "service_id": identifier(row["service_id"], "relation service"),
        "origin_parameter_id": identifier(row["origin_parameter_id"], "relation origin"),
        "result_value_id": identifier(row["result_value_id"], "relation result"),
    })


def _blocker(value: Mapping[str, object]) -> Mapping[str, object]:
    row = object_(value, "component relation blocker")
    exact(row, {"code", "detail"}, "component relation blocker")
    detail = row["detail"]
    if not isinstance(detail, str) or not detail.strip():
        raise BoundaryModelError("component relation blocker detail must be nonempty")
    return canonical({
        "code": identifier(row["code"], "relation blocker"),
        "detail": detail,
    })


__all__ = [
    "ComponentRelationIntentV1",
]
