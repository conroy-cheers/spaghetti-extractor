"""Content-bound checking receipts for component Relation IR."""

from __future__ import annotations

import copy
import re
from dataclasses import dataclass
from typing import Mapping, Sequence

from ..artifacts.artifact_set import canonical_sha256_v3
from .formats import COMPONENT_RELATION_RECEIPT_V2_FORMAT
from .relation_ir import ComponentRelationIRV1


RELATION_RECEIPT_V2 = COMPONENT_RELATION_RECEIPT_V2_FORMAT
_DIGEST = re.compile(r"[0-9a-f]{64}\Z")
_STATUSES = frozenset({"checked", "incomplete", "violated"})


class ComponentRelationReceiptError(ValueError):
    """A relation receipt is malformed, stale, or claims unsound authority."""


def _digest(value: object, context: str) -> str:
    if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
        raise ComponentRelationReceiptError(f"{context} must be a SHA-256 digest")
    return value


@dataclass(frozen=True)
class RelationObligationV1:
    identity: str
    status: str
    code: str
    evidence: tuple[str, ...]

    @classmethod
    def parse(cls, value: object, context: str) -> "RelationObligationV1":
        if not isinstance(value, Mapping) or set(value) != {"id", "status", "code", "evidence"}:
            raise ComponentRelationReceiptError(f"{context} has invalid fields")
        identity, status, code = value["id"], value["status"], value["code"]
        if not all(isinstance(item, str) and item for item in (identity, status, code)):
            raise ComponentRelationReceiptError(f"{context} text fields are invalid")
        if status not in _STATUSES:
            raise ComponentRelationReceiptError(f"{context} status is unsupported")
        raw_evidence = value["evidence"]
        if not isinstance(raw_evidence, list):
            raise ComponentRelationReceiptError(f"{context} evidence must be an array")
        evidence = tuple(_digest(item, f"{context} evidence") for item in raw_evidence)
        if evidence != tuple(sorted(set(evidence))):
            raise ComponentRelationReceiptError(f"{context} evidence must be unique and ordered")
        return cls(identity, status, code, evidence)

    def to_payload(self) -> dict[str, object]:
        return {"id": self.identity, "status": self.status, "code": self.code, "evidence": list(self.evidence)}


@dataclass(frozen=True)
class ComponentRelationReceiptV1:
    component_id: str
    relation_sha256: str
    status: str
    obligations: tuple[RelationObligationV1, ...]
    checker: Mapping[str, object]
    receipt_sha256: str

    @property
    def authorizing(self) -> bool:
        return self.status == "checked"

    @classmethod
    def parse(cls, value: object) -> "ComponentRelationReceiptV1":
        if not isinstance(value, Mapping) or set(value) != {"format", "component_id", "relation_sha256", "status", "obligations", "checker", "receipt_sha256"}:
            raise ComponentRelationReceiptError("component relation receipt has invalid fields")
        if value["format"] != RELATION_RECEIPT_V2:
            raise ComponentRelationReceiptError("unsupported component relation receipt format")
        component_id = value["component_id"]
        if not isinstance(component_id, str) or not component_id:
            raise ComponentRelationReceiptError("component relation receipt id is invalid")
        status = value["status"]
        if status not in _STATUSES:
            raise ComponentRelationReceiptError("component relation receipt status is unsupported")
        raw_obligations = value["obligations"]
        if not isinstance(raw_obligations, list):
            raise ComponentRelationReceiptError("component relation obligations must be an array")
        obligations = tuple(RelationObligationV1.parse(item, f"relation obligation {index}") for index, item in enumerate(raw_obligations))
        ids = [item.identity for item in obligations]
        if not obligations or ids != sorted(set(ids)):
            raise ComponentRelationReceiptError("relation obligations must be nonempty, unique, and ordered")
        if status == "checked" and any(item.status != "checked" for item in obligations):
            raise ComponentRelationReceiptError("checked relation has an unchecked obligation")
        if status != "checked" and all(item.status == "checked" for item in obligations):
            raise ComponentRelationReceiptError("non-checked relation has no failing obligation")
        checker = value["checker"]
        if not isinstance(checker, Mapping) or set(checker) != {"id", "version", "lean_artifact_sha256"}:
            raise ComponentRelationReceiptError("relation checker binding is invalid")
        if not isinstance(checker["id"], str) or not checker["id"] or not isinstance(checker["version"], str) or not checker["version"]:
            raise ComponentRelationReceiptError("relation checker identity is invalid")
        if checker["lean_artifact_sha256"] is not None:
            _digest(checker["lean_artifact_sha256"], "Lean relation artifact")
        core = {key: copy.deepcopy(item) for key, item in value.items() if key != "receipt_sha256"}
        receipt_sha256 = _digest(value["receipt_sha256"], "component relation receipt digest")
        if canonical_sha256_v3(core) != receipt_sha256:
            raise ComponentRelationReceiptError("component relation receipt digest is stale")
        return cls(component_id, _digest(value["relation_sha256"], "component relation digest"), status, obligations, copy.deepcopy(dict(checker)), receipt_sha256)

    @classmethod
    def create(
        cls,
        *,
        relation: ComponentRelationIRV1,
        obligations: Sequence[Mapping[str, object] | RelationObligationV1],
        checker_id: str = "spaghetti-extractor-relation-kernel-v2",
        checker_version: str = "2",
        lean_artifact_sha256: str | None = None,
    ) -> "ComponentRelationReceiptV1":
        obligation_payload = [item.to_payload() if isinstance(item, RelationObligationV1) else copy.deepcopy(dict(item)) for item in obligations]
        parsed = [RelationObligationV1.parse(item, f"relation obligation {index}") for index, item in enumerate(obligation_payload)]
        status = "violated" if any(item.status == "violated" for item in parsed) else "incomplete" if any(item.status == "incomplete" for item in parsed) else "checked"
        core = {
            "format": RELATION_RECEIPT_V2,
            "component_id": relation.component_id,
            "relation_sha256": relation.relation_sha256,
            "status": status,
            "obligations": obligation_payload,
            "checker": {"id": checker_id, "version": checker_version, "lean_artifact_sha256": lean_artifact_sha256},
        }
        return cls.parse({**core, "receipt_sha256": canonical_sha256_v3(core)})

    def validate_for(self, relation: ComponentRelationIRV1) -> None:
        if self.component_id != relation.component_id or self.relation_sha256 != relation.relation_sha256:
            raise ComponentRelationReceiptError("relation receipt is bound to a different relation")

    def to_payload(self) -> dict[str, object]:
        return {
            "format": RELATION_RECEIPT_V2,
            "component_id": self.component_id,
            "relation_sha256": self.relation_sha256,
            "status": self.status,
            "obligations": [item.to_payload() for item in self.obligations],
            "checker": copy.deepcopy(dict(self.checker)),
            "receipt_sha256": self.receipt_sha256,
        }


__all__ = [
    "ComponentRelationReceiptError",
    "ComponentRelationReceiptV1",
    "RELATION_RECEIPT_V2",
    "RelationObligationV1",
]
