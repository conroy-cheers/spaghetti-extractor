"""Deterministic finite-domain ABI constraint solving.

The solver intersects checked alternatives over equality components.  It never
widens an overflow to an unconstrained ABI: excess alternatives and missing
facts remain explicit incomplete frontiers.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

from ..artifacts.formats import (
    ABI_CONSTRAINT_RESULT_FORMAT,
    ABI_FACT_SET_FORMAT,
)
from .model import (
    AbiFactV1,
    AbiModelError,
    AbiTargetV1,
    AbiValueV1,
    PhysicalAbiCertificateV1,
    PhysicalAbiProfileV1,
    ReviewedAbiAssumptionV1,
    StackCleanupV1,
    VariadicPolicyV1,
    canonical_json_bytes,
    canonical_sha256,
)


PHYSICAL_PROFILE_FIELDS = (
    "arguments",
    "calling_convention",
    "preserved_state",
    "results",
    "stack_alignment_bytes",
    "stack_cleanup",
    "stack_coordinate",
    "target",
    "variadic",
)


@dataclass(frozen=True, order=True)
class AbiEqualityConstraintV1:
    left_subject_id: str
    left_field: str
    right_subject_id: str
    right_field: str
    evidence_ids: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        for value, label in (
            (self.left_subject_id, "left ABI equality subject"),
            (self.left_field, "left ABI equality field"),
            (self.right_subject_id, "right ABI equality subject"),
            (self.right_field, "right ABI equality field"),
        ):
            if not value:
                raise AbiModelError(f"{label} must be nonempty")
        if self.evidence_ids != tuple(sorted(set(self.evidence_ids))):
            raise AbiModelError("ABI equality evidence IDs must be sorted and unique")

    def to_payload(self) -> dict[str, object]:
        return {
            "left": {"subject_id": self.left_subject_id, "field": self.left_field},
            "right": {
                "subject_id": self.right_subject_id,
                "field": self.right_field,
            },
            "evidence_ids": list(self.evidence_ids),
        }

    @classmethod
    def parse(cls, value: object) -> "AbiEqualityConstraintV1":
        if not isinstance(value, Mapping) or set(value) != {
            "left",
            "right",
            "evidence_ids",
        }:
            raise AbiModelError("ABI equality fields are malformed")
        left = value["left"]
        right = value["right"]
        if (
            not isinstance(left, Mapping)
            or not isinstance(right, Mapping)
            or set(left) != {"subject_id", "field"}
            or set(right) != {"subject_id", "field"}
            or not isinstance(value["evidence_ids"], list)
        ):
            raise AbiModelError("ABI equality endpoints are malformed")
        return cls(
            str(left["subject_id"]),
            str(left["field"]),
            str(right["subject_id"]),
            str(right["field"]),
            tuple(sorted(set(str(item) for item in value["evidence_ids"]))),
        )


@dataclass(frozen=True)
class AbiConstraintResultV1:
    status: str
    certificates: tuple[PhysicalAbiCertificateV1, ...]
    facts_sha256: str
    constraint_sha256: str
    issues: tuple[Mapping[str, Any], ...]

    def to_payload(self) -> dict[str, object]:
        return {
            "format": ABI_CONSTRAINT_RESULT_FORMAT,
            "status": self.status,
            "facts_sha256": self.facts_sha256,
            "constraint_sha256": self.constraint_sha256,
            "certificates": [item.to_payload() for item in self.certificates],
            "issues": list(self.issues),
        }

    def write(self, path: Path | str) -> None:
        destination = Path(path)
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(canonical_json_bytes(self.to_payload()) + b"\n")


class _UnionFind:
    def __init__(self) -> None:
        self.parent: dict[tuple[str, str], tuple[str, str]] = {}

    def add(self, value: tuple[str, str]) -> None:
        self.parent.setdefault(value, value)

    def find(self, value: tuple[str, str]) -> tuple[str, str]:
        self.add(value)
        parent = self.parent[value]
        if parent != value:
            self.parent[value] = self.find(parent)
        return self.parent[value]

    def union(self, left: tuple[str, str], right: tuple[str, str]) -> None:
        left_root = self.find(left)
        right_root = self.find(right)
        if left_root == right_root:
            return
        root, child = sorted((left_root, right_root))
        self.parent[child] = root


def facts_from_profile(
    *,
    subject_id: str,
    profile: PhysicalAbiProfileV1,
    evidence_ids: Iterable[str],
    dependency_ids: Iterable[str] = (),
) -> tuple[AbiFactV1, ...]:
    payload = profile.to_payload()
    values = {
        "target": payload["target"],
        "calling_convention": payload["calling_convention"],
        "stack_coordinate": payload["stack_coordinate"],
        "stack_alignment_bytes": payload["stack_alignment_bytes"],
        "arguments": payload["arguments"],
        "results": payload["results"],
        "stack_cleanup": payload["stack_cleanup"],
        "variadic": payload["variadic"],
        "preserved_state": payload["preserved_state"],
    }
    return tuple(
        AbiFactV1.create(
            subject_id=subject_id,
            field=field,
            status="exact",
            values=(value,),
            evidence_ids=evidence_ids,
            dependency_ids=dependency_ids,
        )
        for field, value in sorted(values.items())
    )


def _value_keys(fact: AbiFactV1) -> set[bytes] | None:
    if fact.status == "unknown":
        return None
    if fact.status == "contradiction":
        return set()
    return {canonical_json_bytes(value) for value in fact.values}


def _merge_component(
    *,
    members: Sequence[tuple[str, str]],
    supplied: Mapping[tuple[str, str], Sequence[AbiFactV1]],
    constraint_evidence: Iterable[str],
    max_alternatives: int,
) -> tuple[str, tuple[Any, ...], tuple[str, ...], tuple[str, ...], str | None]:
    possible: set[bytes] | None = None
    evidence: set[str] = set(constraint_evidence)
    dependencies: set[str] = set()
    contradiction = False
    for member in members:
        for fact in supplied.get(member, ()):
            evidence.update(fact.evidence_ids)
            dependencies.update(fact.dependency_ids)
            values = _value_keys(fact)
            if values is None:
                continue
            if not values:
                contradiction = True
                continue
            possible = values if possible is None else possible.intersection(values)
            if not possible:
                contradiction = True
    if contradiction:
        return (
            "contradiction",
            (),
            tuple(sorted(evidence)),
            tuple(sorted(dependencies)),
            "abi_constraint_contradiction",
        )
    if possible is None:
        return (
            "unknown",
            (),
            tuple(sorted(evidence)),
            tuple(sorted(dependencies)),
            "abi_required_fact_missing",
        )
    if len(possible) > max_alternatives:
        return (
            "unknown",
            (),
            tuple(sorted(evidence)),
            tuple(sorted(dependencies)),
            "abi_alternative_budget_exceeded",
        )
    values = tuple(json.loads(item) for item in sorted(possible))
    return (
        "exact" if len(values) == 1 else "alternatives",
        values,
        tuple(sorted(evidence)),
        tuple(sorted(dependencies)),
        None,
    )


def _native_resolved_facts(
    *,
    subjects: Mapping[str, str],
    facts: Sequence[AbiFactV1],
    equalities: Sequence[AbiEqualityConstraintV1],
    required_fields: Mapping[str, Sequence[str]],
    max_alternatives: int,
) -> tuple[AbiFactV1, ...] | None:
    # Delayed import avoids a module cycle: the adapter uses the canonical
    # equality record from this module, while this solver owns fallback policy.
    from .native_solver import optional_native_abi_solver

    native = optional_native_abi_solver()
    if native is None:
        return None
    return native.resolve_facts(
        subjects=subjects,
        facts=facts,
        equalities=equalities,
        required_fields=required_fields,
        max_alternatives=max_alternatives,
    )


def _profile_from_facts(facts: Mapping[str, AbiFactV1]) -> PhysicalAbiProfileV1:
    def exact(field: str) -> Any:
        fact = facts[field]
        if fact.status != "exact":
            raise AbiModelError(f"physical ABI field {field} is not exact")
        return fact.values[0]

    raw_arguments = exact("arguments")
    raw_results = exact("results")
    if not isinstance(raw_arguments, list) or not isinstance(raw_results, list):
        raise AbiModelError("physical ABI arguments/results facts are malformed")
    preserved = exact("preserved_state")
    if not isinstance(preserved, list):
        raise AbiModelError("physical ABI preserved-state fact is malformed")
    return PhysicalAbiProfileV1.create(
        target=AbiTargetV1.parse(exact("target")),
        calling_convention=str(exact("calling_convention")),
        arguments=tuple(AbiValueV1.parse(item) for item in raw_arguments),
        results=tuple(AbiValueV1.parse(item) for item in raw_results),
        stack_cleanup=StackCleanupV1.parse(exact("stack_cleanup")),
        variadic=VariadicPolicyV1.parse(exact("variadic")),
        preserved_state=tuple(str(item) for item in preserved),
        stack_alignment_bytes=int(exact("stack_alignment_bytes")),
    )


def solve_abi_constraints(
    *,
    subjects: Mapping[str, str],
    facts: Iterable[AbiFactV1],
    equalities: Iterable[AbiEqualityConstraintV1] = (),
    required_fields: Mapping[str, Iterable[str]] | None = None,
    assumptions: Iterable[ReviewedAbiAssumptionV1] = (),
    reviewed_assumptions: Iterable[str] = (),
    max_alternatives: int = 16,
) -> AbiConstraintResultV1:
    """Resolve a finite ABI constraint graph and issue per-subject certificates."""

    if max_alternatives < 2:
        raise AbiModelError("ABI alternative budget must be at least two")
    subject_rows = dict(subjects)
    ordered_assumptions = tuple(sorted(assumptions, key=lambda row: row.assumption_id))
    assumption_by_subject: dict[str, set[str]] = {}
    assumed_facts: list[AbiFactV1] = []
    for assumption in ordered_assumptions:
        if assumption.subject_id not in subject_rows:
            raise AbiModelError(
                f"reviewed ABI assumption references unknown subject "
                f"{assumption.subject_id!r}"
            )
        if subject_rows[assumption.subject_id] != assumption.subject_kind:
            raise AbiModelError("reviewed ABI assumption subject kind disagrees")
        assumption_by_subject.setdefault(assumption.subject_id, set()).add(
            assumption.assumption_id
        )
        for fact in assumption.facts:
            assumed_facts.append(
                AbiFactV1.create(
                    subject_id=fact.subject_id,
                    field=fact.field,
                    status=fact.status,
                    values=fact.values,
                    evidence_ids=(*fact.evidence_ids, assumption.assumption_id),
                    dependency_ids=fact.dependency_ids,
                )
            )
    supplied: dict[tuple[str, str], list[AbiFactV1]] = {}
    ordered_facts = tuple(
        sorted(
            (*facts, *assumed_facts),
            key=lambda row: (
                row.subject_id,
                row.field,
                row.status,
                canonical_json_bytes(row.to_payload()),
            ),
        )
    )
    for fact in ordered_facts:
        if fact.subject_id not in subject_rows:
            raise AbiModelError(f"ABI fact references unknown subject {fact.subject_id!r}")
        if fact.field not in PHYSICAL_PROFILE_FIELDS:
            raise AbiModelError(f"ABI fact references unsupported field {fact.field!r}")
        supplied.setdefault((fact.subject_id, fact.field), []).append(fact)
    required = {
        subject_id: tuple(sorted(set(fields)))
        for subject_id, fields in (required_fields or {}).items()
    }
    for subject_id in subject_rows:
        required.setdefault(subject_id, PHYSICAL_PROFILE_FIELDS)
    for subject_id, fields in required.items():
        unsupported = set(fields) - set(PHYSICAL_PROFILE_FIELDS)
        if unsupported:
            raise AbiModelError(
                f"required ABI fields for {subject_id!r} are unsupported: "
                f"{sorted(unsupported)!r}"
            )

    union = _UnionFind()
    ordered_equalities = tuple(sorted(equalities))
    for equality in ordered_equalities:
        if {
            equality.left_field,
            equality.right_field,
        } - set(PHYSICAL_PROFILE_FIELDS):
            raise AbiModelError("ABI equality references an unsupported field")
        for subject_id in (equality.left_subject_id, equality.right_subject_id):
            if subject_id not in subject_rows:
                raise AbiModelError(
                    f"ABI equality references unknown subject {subject_id!r}"
                )
        left = (equality.left_subject_id, equality.left_field)
        right = (equality.right_subject_id, equality.right_field)
        union.union(left, right)
    for subject_id, fields in required.items():
        if subject_id not in subject_rows:
            raise AbiModelError(f"required ABI fields name unknown subject {subject_id!r}")
        for field in fields:
            union.add((subject_id, field))
    for key in supplied:
        union.add(key)

    components: dict[tuple[str, str], list[tuple[str, str]]] = {}
    for key in union.parent:
        components.setdefault(union.find(key), []).append(key)
    equality_evidence: dict[tuple[str, str], set[str]] = {}
    for equality in ordered_equalities:
        root = union.find((equality.left_subject_id, equality.left_field))
        equality_evidence.setdefault(root, set()).update(equality.evidence_ids)
    native_facts = _native_resolved_facts(
        subjects=subject_rows,
        facts=ordered_facts,
        equalities=ordered_equalities,
        required_fields=required,
        max_alternatives=max_alternatives,
    )
    resolved_by_key: dict[tuple[str, str], AbiFactV1] = (
        {}
        if native_facts is None
        else {(row.subject_id, row.field): row for row in native_facts}
    )
    issue_by_key: dict[tuple[str, str], str] = {}
    for root, members in sorted(components.items()):
        representative = resolved_by_key.get(members[0])
        needs_python_resolution = native_facts is None or (
            representative is not None
            and representative.status in {"unknown", "contradiction"}
        )
        issue = None
        if needs_python_resolution:
            merged = _merge_component(
                members=members,
                supplied=supplied,
                constraint_evidence=equality_evidence.get(root, ()),
                max_alternatives=max_alternatives,
            )
            status, values, evidence_ids, dependency_ids, issue = merged
            for subject_id, field in members:
                resolved_by_key[(subject_id, field)] = AbiFactV1.create(
                    subject_id=subject_id,
                    field=field,
                    status=status,
                    values=values,
                    evidence_ids=evidence_ids,
                    dependency_ids=dependency_ids,
                )
        elif representative is None:
            raise AbiModelError("native ABI solver omitted an equality component")
        for subject_id, field in members:
            if issue is not None:
                issue_by_key[(subject_id, field)] = issue

    certificates = []
    global_issues: list[Mapping[str, Any]] = []
    global_assumption_ids = tuple(sorted(set(reviewed_assumptions)))
    for subject_id, subject_kind in sorted(subject_rows.items()):
        fields = required[subject_id]
        resolved = {
            field: resolved_by_key.get(
                (subject_id, field),
                AbiFactV1.create(
                    subject_id=subject_id,
                    field=field,
                    status="unknown",
                ),
            )
            for field in fields
        }
        issues: list[Mapping[str, Any]] = []
        for field, fact in sorted(resolved.items()):
            if fact.status == "exact":
                continue
            code = issue_by_key.get((subject_id, field))
            if code is None:
                code = (
                    "abi_fact_ambiguous"
                    if fact.status == "alternatives"
                    else "abi_required_fact_missing"
                )
            issues.append(
                {
                    "status": (
                        "violated" if fact.status == "contradiction" else "incomplete"
                    ),
                    "code": code,
                    "subject_id": subject_id,
                    "field": field,
                    "alternatives": list(fact.values),
                }
            )
        status = (
            "violated"
            if any(issue["status"] == "violated" for issue in issues)
            else "incomplete"
            if issues
            else "complete"
        )
        profile = None
        if status == "complete" and set(PHYSICAL_PROFILE_FIELDS).issubset(resolved):
            profile = _profile_from_facts(resolved)
        dependency_ids = {
            dependency
            for fact in resolved.values()
            for dependency in fact.dependency_ids
        }
        certificate = PhysicalAbiCertificateV1.create(
            status=status,
            subject_kind=subject_kind,
            subject_id=subject_id,
            profile=profile,
            facts=resolved.values(),
            reviewed_assumption_ids=(
                *global_assumption_ids,
                *sorted(assumption_by_subject.get(subject_id, ())),
            ),
            issues=issues,
            dependency_ids=dependency_ids,
        )
        certificates.append(certificate)
        global_issues.extend(issues)

    overall = (
        "violated"
        if any(item.status == "violated" for item in certificates)
        else "incomplete"
        if any(item.status == "incomplete" for item in certificates)
        else "complete"
    )
    fact_payload = {
        "format": ABI_FACT_SET_FORMAT,
        "subjects": subject_rows,
        "facts": [item.to_payload() for item in ordered_facts],
    }
    constraint_payload = {
        "equalities": [item.to_payload() for item in ordered_equalities],
        "required_fields": {key: list(value) for key, value in sorted(required.items())},
        "assumptions": [item.to_payload() for item in ordered_assumptions],
        "max_alternatives": max_alternatives,
    }
    return AbiConstraintResultV1(
        overall,
        tuple(certificates),
        canonical_sha256(fact_payload),
        canonical_sha256(constraint_payload),
        tuple(
            sorted(
                global_issues,
                key=lambda item: (
                    str(item["status"]),
                    str(item["subject_id"]),
                    str(item["field"]),
                ),
            )
        ),
    )


__all__ = [
    "PHYSICAL_PROFILE_FIELDS",
    "AbiConstraintResultV1",
    "AbiEqualityConstraintV1",
    "facts_from_profile",
    "solve_abi_constraints",
]
