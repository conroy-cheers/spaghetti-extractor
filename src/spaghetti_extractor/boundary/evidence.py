"""Field-wise evidence reconciliation for checked boundary layouts and frames."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping, Sequence

from ..artifacts.artifact_set import canonical_sha256_v3
from ..artifacts.formats import (
    BOUNDARY_EVIDENCE_RECEIPT_V1_FORMAT,
    BOUNDARY_FACT_SET_V1_FORMAT,
)
from ._canonical import (
    BoundaryModelError,
    array,
    canonical,
    content_id,
    digest,
    exact,
    identifier,
    object_,
)


BOUNDARY_FACT_SET_V1 = BOUNDARY_FACT_SET_V1_FORMAT
BOUNDARY_EVIDENCE_RECEIPT_V1 = BOUNDARY_EVIDENCE_RECEIPT_V1_FORMAT
FACT_STATES = frozenset({"unknown", "exact", "alternatives", "contradiction"})
PRODUCER_CLASSES = frozenset({
    "machine_observation",
    "checked_authority",
    "reviewed_declaration",
    "dialect_rule",
    "compiler_proposal",
    "debug_proposal",
    "decompiler_proposal",
})
AUTHORITATIVE_CLASSES = frozenset({
    "machine_observation", "checked_authority", "reviewed_declaration", "dialect_rule"
})
OBSERVATION_CLASSES = frozenset({"machine_observation", "checked_authority"})


def _value_key(value: object) -> str:
    return canonical_sha256_v3(value)


@dataclass(frozen=True)
class BoundarySubjectV1:
    kind: str
    identity: str
    image_selector: str | None

    @classmethod
    def parse(cls, value: object, context: str = "boundary subject") -> "BoundarySubjectV1":
        row = object_(value, context)
        exact(row, {"kind", "id", "image_selector"}, context)
        return cls(
            identifier(row["kind"], f"{context} kind"),
            identifier(row["id"], f"{context} id"),
            None if row["image_selector"] is None else identifier(row["image_selector"], f"{context} image selector"),
        )

    def to_payload(self) -> dict[str, object]:
        return {"kind": self.kind, "id": self.identity, "image_selector": self.image_selector}


@dataclass(frozen=True)
class BoundaryFactV1:
    key: str
    state: str
    values: tuple[object, ...]

    @classmethod
    def create(cls, *, key: str, state: str, values: Sequence[object] = ()) -> "BoundaryFactV1":
        key_value = identifier(key, "boundary fact key")
        if state not in FACT_STATES:
            raise BoundaryModelError("boundary fact state is unsupported")
        unique = {_value_key(item): canonical(item) for item in values}
        ordered = tuple(unique[item] for item in sorted(unique))
        if state in {"unknown", "contradiction"} and ordered:
            raise BoundaryModelError(f"{state} boundary fact cannot retain candidates")
        if state == "exact" and len(ordered) != 1:
            raise BoundaryModelError("exact boundary fact requires one candidate")
        if state == "alternatives" and len(ordered) < 2:
            raise BoundaryModelError("alternative boundary fact requires multiple candidates")
        return cls(key_value, state, ordered)

    @classmethod
    def parse(cls, value: object, context: str) -> "BoundaryFactV1":
        row = object_(value, context)
        exact(row, {"key", "state", "values"}, context)
        return cls.create(key=str(row["key"]), state=str(row["state"]), values=array(row["values"], f"{context} values"))

    def to_payload(self) -> dict[str, object]:
        return {"key": self.key, "state": self.state, "values": [canonical(item) for item in self.values]}


@dataclass(frozen=True)
class BoundaryFactSetV1:
    fact_set_id: str
    producer_class: str
    producer_id: str
    subject: BoundarySubjectV1
    binary_sha256: str
    facts: tuple[BoundaryFactV1, ...]
    dependency_ids: tuple[str, ...]

    @classmethod
    def create(
        cls,
        *,
        producer_class: str,
        producer_id: str,
        subject: BoundarySubjectV1 | Mapping[str, object],
        binary_sha256: str,
        facts: Sequence[BoundaryFactV1 | Mapping[str, object]],
        dependency_ids: Sequence[str] = (),
    ) -> "BoundaryFactSetV1":
        if producer_class not in PRODUCER_CLASSES:
            raise BoundaryModelError("boundary evidence producer class is unsupported")
        parsed_subject = subject if isinstance(subject, BoundarySubjectV1) else BoundarySubjectV1.parse(subject)
        parsed = tuple(sorted((item if isinstance(item, BoundaryFactV1) else BoundaryFactV1.parse(item, f"boundary fact {index}") for index, item in enumerate(facts)), key=lambda item: item.key))
        keys = [item.key for item in parsed]
        if not parsed or keys != sorted(set(keys)):
            raise BoundaryModelError("boundary facts must be nonempty, unique, and ordered")
        dependencies = tuple(sorted(set(identifier(item, "boundary fact dependency") for item in dependency_ids)))
        core = {
            "format": BOUNDARY_FACT_SET_V1,
            "producer_class": producer_class,
            "producer_id": identifier(producer_id, "boundary evidence producer id"),
            "subject": parsed_subject.to_payload(),
            "binary_sha256": digest(binary_sha256, "boundary evidence binary digest"),
            "facts": [item.to_payload() for item in parsed],
            "dependency_ids": list(dependencies),
        }
        return cls(content_id("boundary-fact-set-v1", core), producer_class, str(core["producer_id"]), parsed_subject, str(core["binary_sha256"]), parsed, dependencies)

    @classmethod
    def parse(cls, value: object) -> "BoundaryFactSetV1":
        row = object_(value, "boundary fact set")
        exact(row, {"format", "id", "producer_class", "producer_id", "subject", "binary_sha256", "facts", "dependency_ids"}, "boundary fact set")
        if row["format"] != BOUNDARY_FACT_SET_V1:
            raise BoundaryModelError("unsupported boundary fact-set format")
        result = cls.create(producer_class=str(row["producer_class"]), producer_id=str(row["producer_id"]), subject=BoundarySubjectV1.parse(row["subject"]), binary_sha256=str(row["binary_sha256"]), facts=[BoundaryFactV1.parse(item, f"boundary fact {index}") for index, item in enumerate(array(row["facts"], "boundary facts"))], dependency_ids=[str(item) for item in array(row["dependency_ids"], "boundary fact dependencies")])
        if row["id"] != result.fact_set_id:
            raise BoundaryModelError("boundary fact-set id does not bind its contents")
        return result

    @property
    def authoritative(self) -> bool:
        return self.producer_class in AUTHORITATIVE_CLASSES

    def to_payload(self) -> dict[str, object]:
        return {
            "format": BOUNDARY_FACT_SET_V1,
            "id": self.fact_set_id,
            "producer_class": self.producer_class,
            "producer_id": self.producer_id,
            "subject": self.subject.to_payload(),
            "binary_sha256": self.binary_sha256,
            "facts": [item.to_payload() for item in self.facts],
            "dependency_ids": list(self.dependency_ids),
        }


@dataclass(frozen=True)
class BoundaryRequirementV1:
    key: str
    legal_values: tuple[object, ...]
    rule_ids: tuple[str, ...]
    requires_observation: bool

    @classmethod
    def create(cls, *, key: str, legal_values: Sequence[object], rule_ids: Sequence[str], requires_observation: bool) -> "BoundaryRequirementV1":
        values = {_value_key(item): canonical(item) for item in legal_values}
        if not values:
            raise BoundaryModelError("boundary requirement has no legal values")
        return cls(identifier(key, "boundary requirement key"), tuple(values[item] for item in sorted(values)), tuple(sorted(set(identifier(item, "dialect rule id") for item in rule_ids))), requires_observation)

    @classmethod
    def parse(cls, value: object, context: str) -> "BoundaryRequirementV1":
        row = object_(value, context)
        exact(row, {"key", "legal_values", "rule_ids", "requires_observation"}, context)
        flag = row["requires_observation"]
        if not isinstance(flag, bool):
            raise BoundaryModelError(f"{context} observation flag must be Boolean")
        return cls.create(key=str(row["key"]), legal_values=array(row["legal_values"], f"{context} legal values"), rule_ids=[str(item) for item in array(row["rule_ids"], f"{context} rule ids")], requires_observation=flag)

    def to_payload(self) -> dict[str, object]:
        return {"key": self.key, "legal_values": [canonical(item) for item in self.legal_values], "rule_ids": list(self.rule_ids), "requires_observation": self.requires_observation}


@dataclass(frozen=True)
class BoundaryEvidenceObligationV1:
    key: str
    status: str
    value: object | None
    code: str
    evidence_ids: tuple[str, ...]
    rule_ids: tuple[str, ...]

    def to_payload(self) -> dict[str, object]:
        return {"key": self.key, "status": self.status, "value": canonical(self.value), "code": self.code, "evidence_ids": list(self.evidence_ids), "rule_ids": list(self.rule_ids)}


@dataclass(frozen=True)
class BoundaryEvidenceReceiptV1:
    receipt_id: str
    subject: BoundarySubjectV1
    binary_sha256: str
    status: str
    obligations: tuple[BoundaryEvidenceObligationV1, ...]
    fact_set_ids: tuple[str, ...]

    @classmethod
    def reconcile(
        cls,
        *,
        subject: BoundarySubjectV1 | Mapping[str, object],
        binary_sha256: str,
        requirements: Sequence[BoundaryRequirementV1],
        fact_sets: Sequence[BoundaryFactSetV1],
    ) -> "BoundaryEvidenceReceiptV1":
        parsed_subject = subject if isinstance(subject, BoundarySubjectV1) else BoundarySubjectV1.parse(subject)
        binary = digest(binary_sha256, "boundary reconciliation binary digest")
        requirement_rows = tuple(sorted(requirements, key=lambda item: item.key))
        if not requirement_rows or [item.key for item in requirement_rows] != sorted(set(item.key for item in requirement_rows)):
            raise BoundaryModelError("boundary requirements must be nonempty, unique, and ordered")
        for source in fact_sets:
            if source.subject != parsed_subject or source.binary_sha256 != binary:
                raise BoundaryModelError("boundary fact set describes another subject or binary")
        facts_by_key: dict[str, list[tuple[BoundaryFactSetV1, BoundaryFactV1]]] = {}
        for source in fact_sets:
            for fact in source.facts:
                facts_by_key.setdefault(fact.key, []).append((source, fact))
        unknown_keys = set(facts_by_key) - {item.key for item in requirement_rows}
        if unknown_keys:
            raise BoundaryModelError(f"boundary fact sets contain unrequested facts {sorted(unknown_keys)!r}")
        obligations: list[BoundaryEvidenceObligationV1] = []
        for requirement in requirement_rows:
            legal = {_value_key(item): item for item in requirement.legal_values}
            candidates = dict(legal)
            evidence_ids: set[str] = set()
            observation_ids: set[str] = set()
            contradiction = False
            for source, fact in facts_by_key.get(requirement.key, []):
                evidence_ids.add(source.fact_set_id)
                if fact.state == "contradiction":
                    contradiction = True
                    continue
                if fact.state == "unknown":
                    continue
                if source.producer_class in OBSERVATION_CLASSES:
                    observation_ids.add(source.fact_set_id)
                observed = {_value_key(item) for item in fact.values}
                candidates = {key: value for key, value in candidates.items() if key in observed}
            if contradiction or not candidates:
                status, value, code = "violated", None, "boundary_evidence_contradiction"
            elif len(candidates) != 1:
                status, value, code = "incomplete", None, "boundary_evidence_ambiguous"
            elif requirement.requires_observation and not observation_ids:
                status, value, code = "incomplete", None, "authoritative_boundary_evidence_missing"
            else:
                status, value, code = "checked", next(iter(candidates.values())), "boundary_fact_resolved"
            obligations.append(BoundaryEvidenceObligationV1(requirement.key, status, value, code, tuple(sorted(evidence_ids)), requirement.rule_ids))
        status = "violated" if any(item.status == "violated" for item in obligations) else "incomplete" if any(item.status != "checked" for item in obligations) else "complete"
        fact_set_ids = tuple(sorted(source.fact_set_id for source in fact_sets))
        core = {
            "format": BOUNDARY_EVIDENCE_RECEIPT_V1,
            "subject": parsed_subject.to_payload(),
            "binary_sha256": binary,
            "status": status,
            "obligations": [item.to_payload() for item in obligations],
            "fact_set_ids": list(fact_set_ids),
        }
        return cls(content_id("boundary-evidence-receipt-v1", core), parsed_subject, binary, status, tuple(obligations), fact_set_ids)

    def to_payload(self) -> dict[str, object]:
        return {
            "format": BOUNDARY_EVIDENCE_RECEIPT_V1,
            "id": self.receipt_id,
            "subject": self.subject.to_payload(),
            "binary_sha256": self.binary_sha256,
            "status": self.status,
            "obligations": [item.to_payload() for item in self.obligations],
            "fact_set_ids": list(self.fact_set_ids),
        }


__all__ = [
    "AUTHORITATIVE_CLASSES",
    "BoundaryEvidenceObligationV1",
    "BoundaryEvidenceReceiptV1",
    "BoundaryFactSetV1",
    "BoundaryFactV1",
    "BoundaryRequirementV1",
    "BoundarySubjectV1",
]
