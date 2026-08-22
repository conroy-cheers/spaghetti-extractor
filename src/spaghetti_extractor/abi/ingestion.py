"""Canonical ingestion of reviewed ABI declarations and extracted ABI facts.

This layer validates and content-binds inputs without making an authority
decision. Logical contradictions use a distinct status so the consuming
authority checker can classify them as ``violated`` at its own boundary.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

from ..artifacts.artifact_set import CanonicalValueV3
from ..artifacts.formats import ABI_DECLARATION_INGESTION_FORMAT
from .declarations import PhysicalAbiDeclarationSetV1, PhysicalAbiDeclarationV1
from .extraction import AbiExtractionResultV1
from .model import (
    AbiEvidenceV1,
    AbiFactV1,
    AbiModelError,
    canonical_json_bytes,
    canonical_sha256,
    stable_id,
)
from .solver import AbiEqualityConstraintV1, facts_from_profile, solve_abi_constraints


_INGESTION_STATUSES = frozenset({"complete", "incomplete", "contradiction"})
_ISSUE_STATUSES = frozenset({"incomplete", "contradiction"})


def _text(value: object, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise AbiModelError(f"{label} must be nonempty")
    return value


def _sha256(value: object, label: str) -> str:
    result = _text(value, label)
    if len(result) != 64 or any(character not in "0123456789abcdef" for character in result):
        raise AbiModelError(f"{label} must be a lowercase SHA-256")
    return result


def _optional_sha256(value: object, label: str) -> str | None:
    return None if value is None else _sha256(value, label)


def _strings(value: object, label: str) -> tuple[str, ...]:
    if not isinstance(value, list):
        raise AbiModelError(f"{label} must be an array")
    result = tuple(_text(item, label) for item in value)
    if result != tuple(sorted(set(result))):
        raise AbiModelError(f"{label} must be sorted and unique")
    return result


def _object(value: object, fields: set[str], label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or set(value) != fields:
        raise AbiModelError(f"{label} fields are malformed")
    return value


@dataclass(frozen=True, order=True)
class CatalogMemberIdentityV1:
    identity_id: str
    catalog_id: str
    snapshot_id: str
    source_index_sha256: str
    function_id: str
    member_id: str
    symbols: tuple[str, ...]
    exact_bytes_sha256: str | None
    normalized_bytes_sha256: str | None

    @property
    def identity_payload(self) -> dict[str, object]:
        return {
            "catalog_id": self.catalog_id,
            "snapshot_id": self.snapshot_id,
            "source_index_sha256": self.source_index_sha256,
            "function_id": self.function_id,
            "member_id": self.member_id,
            "symbols": list(self.symbols),
            "exact_bytes_sha256": self.exact_bytes_sha256,
            "normalized_bytes_sha256": self.normalized_bytes_sha256,
        }

    def __post_init__(self) -> None:
        for value, label in (
            (self.catalog_id, "catalog member catalog ID"),
            (self.snapshot_id, "catalog member snapshot ID"),
            (self.function_id, "catalog member function ID"),
            (self.member_id, "catalog member ID"),
        ):
            _text(value, label)
        _sha256(self.source_index_sha256, "catalog member source-index SHA-256")
        if not self.symbols or self.symbols != tuple(sorted(set(self.symbols))):
            raise AbiModelError("catalog member symbols must be nonempty, sorted, and unique")
        _optional_sha256(self.exact_bytes_sha256, "catalog member exact-bytes SHA-256")
        _optional_sha256(
            self.normalized_bytes_sha256,
            "catalog member normalized-bytes SHA-256",
        )
        expected = stable_id("catalog-member-abi-identity-v1", self.identity_payload)
        if self.identity_id != expected:
            raise AbiModelError("catalog member ABI identity does not bind its contents")

    @classmethod
    def create(
        cls,
        *,
        catalog_id: str,
        snapshot_id: str,
        source_index_sha256: str,
        function_id: str,
        member_id: str,
        symbols: Iterable[str],
        exact_bytes_sha256: str | None = None,
        normalized_bytes_sha256: str | None = None,
    ) -> "CatalogMemberIdentityV1":
        canonical_symbols = tuple(sorted(set(symbols)))
        identity = {
            "catalog_id": catalog_id,
            "snapshot_id": snapshot_id,
            "source_index_sha256": source_index_sha256,
            "function_id": function_id,
            "member_id": member_id,
            "symbols": list(canonical_symbols),
            "exact_bytes_sha256": exact_bytes_sha256,
            "normalized_bytes_sha256": normalized_bytes_sha256,
        }
        return cls(
            stable_id("catalog-member-abi-identity-v1", identity),
            catalog_id,
            snapshot_id,
            source_index_sha256,
            function_id,
            member_id,
            canonical_symbols,
            exact_bytes_sha256,
            normalized_bytes_sha256,
        )

    def to_payload(self) -> dict[str, object]:
        return {"id": self.identity_id, **self.identity_payload}

    @classmethod
    def parse(cls, value: object) -> "CatalogMemberIdentityV1":
        row = _object(
            value,
            {
                "id",
                "catalog_id",
                "snapshot_id",
                "source_index_sha256",
                "function_id",
                "member_id",
                "symbols",
                "exact_bytes_sha256",
                "normalized_bytes_sha256",
            },
            "catalog member ABI identity",
        )
        return cls(
            _text(row["id"], "catalog member ABI identity ID"),
            _text(row["catalog_id"], "catalog member catalog ID"),
            _text(row["snapshot_id"], "catalog member snapshot ID"),
            _sha256(row["source_index_sha256"], "catalog member source-index SHA-256"),
            _text(row["function_id"], "catalog member function ID"),
            _text(row["member_id"], "catalog member ID"),
            _strings(row["symbols"], "catalog member symbols"),
            _optional_sha256(row["exact_bytes_sha256"], "catalog member exact-bytes SHA-256"),
            _optional_sha256(
                row["normalized_bytes_sha256"],
                "catalog member normalized-bytes SHA-256",
            ),
        )


@dataclass(frozen=True)
class CatalogMemberAbiDeclarationV1:
    binding_id: str
    member: CatalogMemberIdentityV1
    declaration_set_sha256: str
    declaration_snapshot_id: str
    declaration: PhysicalAbiDeclarationV1

    @property
    def identity_payload(self) -> dict[str, object]:
        return {
            "member": self.member.to_payload(),
            "declaration_set_sha256": self.declaration_set_sha256,
            "declaration_snapshot_id": self.declaration_snapshot_id,
            "declaration": self.declaration.to_payload(),
        }

    def __post_init__(self) -> None:
        _sha256(
            self.declaration_set_sha256,
            "catalog member declaration-set SHA-256",
        )
        _text(
            self.declaration_snapshot_id,
            "catalog member declaration snapshot ID",
        )
        expected = stable_id("catalog-member-abi-declaration-v1", self.identity_payload)
        if self.binding_id != expected:
            raise AbiModelError("catalog member ABI declaration does not bind its contents")

    @classmethod
    def create(
        cls,
        *,
        member: CatalogMemberIdentityV1,
        declaration_set: PhysicalAbiDeclarationSetV1,
        declaration_id: str,
    ) -> "CatalogMemberAbiDeclarationV1":
        declarations = {
            declaration.declaration_id: declaration
            for declaration in declaration_set.declarations
        }
        try:
            declaration = declarations[declaration_id]
        except KeyError as error:
            raise AbiModelError(
                "catalog member binding references an unknown ABI declaration"
            ) from error
        identity = {
            "member": member.to_payload(),
            "declaration_set_sha256": declaration_set.declaration_set_sha256,
            "declaration_snapshot_id": declaration_set.snapshot_id,
            "declaration": declaration.to_payload(),
        }
        return cls(
            stable_id("catalog-member-abi-declaration-v1", identity),
            member,
            declaration_set.declaration_set_sha256,
            declaration_set.snapshot_id,
            declaration,
        )

    def to_payload(self) -> dict[str, object]:
        return {"id": self.binding_id, **self.identity_payload}

    @classmethod
    def parse(cls, value: object) -> "CatalogMemberAbiDeclarationV1":
        row = _object(
            value,
            {
                "id",
                "member",
                "declaration_set_sha256",
                "declaration_snapshot_id",
                "declaration",
            },
            "catalog member ABI declaration",
        )
        return cls(
            _text(row["id"], "catalog member ABI declaration ID"),
            CatalogMemberIdentityV1.parse(row["member"]),
            _sha256(
                row["declaration_set_sha256"],
                "catalog member declaration-set SHA-256",
            ),
            _text(
                row["declaration_snapshot_id"],
                "catalog member declaration snapshot ID",
            ),
            PhysicalAbiDeclarationV1.parse(row["declaration"]),
        )


@dataclass(frozen=True, order=True)
class IngestedAbiSubjectV1:
    subject_id: str
    subject_kind: str

    def __post_init__(self) -> None:
        _text(self.subject_id, "ingested ABI subject ID")
        _text(self.subject_kind, "ingested ABI subject kind")

    def to_payload(self) -> dict[str, str]:
        return {"id": self.subject_id, "kind": self.subject_kind}

    @classmethod
    def parse(cls, value: object) -> "IngestedAbiSubjectV1":
        row = _object(value, {"id", "kind"}, "ingested ABI subject")
        return cls(
            _text(row["id"], "ingested ABI subject ID"),
            _text(row["kind"], "ingested ABI subject kind"),
        )


@dataclass(frozen=True)
class AbiIngestionIssueV1:
    issue_id: str
    status: str
    code: str
    subject_id: str
    field: str | None
    evidence_ids: tuple[str, ...]
    dependency_ids: tuple[str, ...]
    details: CanonicalValueV3

    @property
    def identity_payload(self) -> dict[str, object]:
        return {
            "status": self.status,
            "code": self.code,
            "subject_id": self.subject_id,
            "field": self.field,
            "evidence_ids": list(self.evidence_ids),
            "dependency_ids": list(self.dependency_ids),
            "details": self.details.to_value(),
        }

    def __post_init__(self) -> None:
        if self.status not in _ISSUE_STATUSES:
            raise AbiModelError(f"unsupported ABI ingestion issue status {self.status!r}")
        _text(self.code, "ABI ingestion issue code")
        _text(self.subject_id, "ABI ingestion issue subject ID")
        if self.field is not None:
            _text(self.field, "ABI ingestion issue field")
        for values, label in (
            (self.evidence_ids, "ABI ingestion issue evidence IDs"),
            (self.dependency_ids, "ABI ingestion issue dependency IDs"),
        ):
            if values != tuple(sorted(set(values))):
                raise AbiModelError(f"{label} must be sorted and unique")
        expected = stable_id("abi-ingestion-issue-v1", self.identity_payload)
        if self.issue_id != expected:
            raise AbiModelError("ABI ingestion issue ID does not bind its contents")

    @classmethod
    def create(
        cls,
        *,
        status: str,
        code: str,
        subject_id: str,
        field: str | None = None,
        evidence_ids: Iterable[str] = (),
        dependency_ids: Iterable[str] = (),
        details: object = None,
    ) -> "AbiIngestionIssueV1":
        evidence = tuple(sorted(set(evidence_ids)))
        dependencies = tuple(sorted(set(dependency_ids)))
        canonical_details = CanonicalValueV3.of(details)
        identity = {
            "status": status,
            "code": code,
            "subject_id": subject_id,
            "field": field,
            "evidence_ids": list(evidence),
            "dependency_ids": list(dependencies),
            "details": canonical_details.to_value(),
        }
        return cls(
            stable_id("abi-ingestion-issue-v1", identity),
            status,
            code,
            subject_id,
            field,
            evidence,
            dependencies,
            canonical_details,
        )

    def to_payload(self) -> dict[str, object]:
        return {"id": self.issue_id, **self.identity_payload}

    @classmethod
    def parse(cls, value: object) -> "AbiIngestionIssueV1":
        row = _object(
            value,
            {
                "id",
                "status",
                "code",
                "subject_id",
                "field",
                "evidence_ids",
                "dependency_ids",
                "details",
            },
            "ABI ingestion issue",
        )
        return cls(
            _text(row["id"], "ABI ingestion issue ID"),
            _text(row["status"], "ABI ingestion issue status"),
            _text(row["code"], "ABI ingestion issue code"),
            _text(row["subject_id"], "ABI ingestion issue subject ID"),
            None if row["field"] is None else _text(row["field"], "ABI ingestion issue field"),
            _strings(row["evidence_ids"], "ABI ingestion issue evidence IDs"),
            _strings(row["dependency_ids"], "ABI ingestion issue dependency IDs"),
            CanonicalValueV3.of(row["details"]),
        )


@dataclass(frozen=True)
class AbiDeclarationIngestionV1:
    status: str
    subjects: tuple[IngestedAbiSubjectV1, ...]
    member_declarations: tuple[CatalogMemberAbiDeclarationV1, ...]
    evidence: tuple[AbiEvidenceV1, ...]
    facts: tuple[AbiFactV1, ...]
    equalities: tuple[AbiEqualityConstraintV1, ...]
    issues: tuple[AbiIngestionIssueV1, ...]
    ingestion_sha256: str

    @property
    def core_payload(self) -> dict[str, object]:
        return {
            "format": ABI_DECLARATION_INGESTION_FORMAT,
            "status": self.status,
            "subjects": [row.to_payload() for row in self.subjects],
            "member_declarations": [
                row.to_payload() for row in self.member_declarations
            ],
            "evidence": [row.to_payload() for row in self.evidence],
            "facts": [row.to_payload() for row in self.facts],
            "equalities": [row.to_payload() for row in self.equalities],
            "issues": [row.to_payload() for row in self.issues],
        }

    @property
    def has_contradictions(self) -> bool:
        return self.status == "contradiction"

    def __post_init__(self) -> None:
        if self.status not in _INGESTION_STATUSES:
            raise AbiModelError(f"unsupported ABI ingestion status {self.status!r}")
        _require_sorted_unique(self.subjects, lambda row: row.subject_id, "ABI ingestion subjects")
        _require_sorted_unique(
            self.member_declarations,
            lambda row: row.binding_id,
            "ABI ingestion member declarations",
        )
        _require_sorted_unique(self.evidence, lambda row: row.evidence_id, "ABI ingestion evidence")
        _require_sorted_unique(
            self.facts,
            lambda row: canonical_json_bytes(row.to_payload()),
            "ABI ingestion facts",
        )
        _require_sorted_unique(
            self.equalities,
            lambda row: canonical_json_bytes(row.to_payload()),
            "ABI ingestion equalities",
        )
        _require_sorted_unique(self.issues, lambda row: row.issue_id, "ABI ingestion issues")
        expected_status = _status_from_issues(self.issues)
        if self.status != expected_status:
            raise AbiModelError("ABI ingestion status does not match its issues")
        _sha256(self.ingestion_sha256, "ABI ingestion SHA-256")
        if self.ingestion_sha256 != canonical_sha256(self.core_payload):
            raise AbiModelError("ABI ingestion hash is stale")

    def to_payload(self) -> dict[str, object]:
        return {**self.core_payload, "ingestion_sha256": self.ingestion_sha256}

    def write(self, path: Path | str) -> None:
        destination = Path(path)
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(canonical_json_bytes(self.to_payload()) + b"\n")

    @classmethod
    def read(cls, path: Path | str) -> "AbiDeclarationIngestionV1":
        payload = json.loads(Path(path).read_text(encoding="utf-8"))
        row = _object(
            payload,
            {
                "format",
                "status",
                "subjects",
                "member_declarations",
                "evidence",
                "facts",
                "equalities",
                "issues",
                "ingestion_sha256",
            },
            "ABI declaration ingestion",
        )
        if row["format"] != ABI_DECLARATION_INGESTION_FORMAT:
            raise AbiModelError("ABI declaration ingestion format is unsupported")
        arrays = {}
        for field in (
            "subjects",
            "member_declarations",
            "evidence",
            "facts",
            "equalities",
            "issues",
        ):
            if not isinstance(row[field], list):
                raise AbiModelError(f"ABI declaration ingestion {field} must be an array")
            arrays[field] = row[field]
        return cls(
            status=_text(row["status"], "ABI declaration ingestion status"),
            subjects=tuple(IngestedAbiSubjectV1.parse(item) for item in arrays["subjects"]),
            member_declarations=tuple(
                CatalogMemberAbiDeclarationV1.parse(item)
                for item in arrays["member_declarations"]
            ),
            evidence=tuple(AbiEvidenceV1.parse(item) for item in arrays["evidence"]),
            facts=tuple(AbiFactV1.parse(item) for item in arrays["facts"]),
            equalities=tuple(
                AbiEqualityConstraintV1.parse(item) for item in arrays["equalities"]
            ),
            issues=tuple(AbiIngestionIssueV1.parse(item) for item in arrays["issues"]),
            ingestion_sha256=_sha256(row["ingestion_sha256"], "ABI ingestion SHA-256"),
        )


def ingest_abi_declarations(
    *,
    member_declarations: Iterable[CatalogMemberAbiDeclarationV1] = (),
    extraction_results: Sequence[AbiExtractionResultV1 | Path | str] = (),
    out: Path | str | None = None,
) -> AbiDeclarationIngestionV1:
    """Merge reviewed declarations and prior extraction bundles canonically."""

    binding_index: dict[str, CatalogMemberAbiDeclarationV1] = {}
    for binding in member_declarations:
        previous = binding_index.get(binding.binding_id)
        if previous is not None and previous != binding:
            raise AbiModelError("ABI declaration binding identity is contradictory")
        binding_index[binding.binding_id] = binding
    bindings = tuple(binding_index[key] for key in sorted(binding_index))
    subjects: dict[str, str] = {}
    evidence: dict[str, AbiEvidenceV1] = {}
    facts: dict[bytes, AbiFactV1] = {}
    equalities: dict[bytes, AbiEqualityConstraintV1] = {}
    issues: dict[str, AbiIngestionIssueV1] = {}

    def issue(**kwargs: Any) -> None:
        row = AbiIngestionIssueV1.create(**kwargs)
        issues[row.issue_id] = row

    def subject(subject_id: str, subject_kind: str, dependency_id: str) -> None:
        previous = subjects.get(subject_id)
        if previous is not None and previous != subject_kind:
            issue(
                status="contradiction",
                code="abi_subject_kind_contradiction",
                subject_id=subject_id,
                dependency_ids=(dependency_id,),
                details={"observed": sorted({previous, subject_kind})},
            )
            return
        subjects[subject_id] = subject_kind

    for binding in bindings:
        member = binding.member
        declaration = binding.declaration
        subject(member.function_id, "library_member", binding.binding_id)
        if binding.declaration_snapshot_id != member.snapshot_id:
            issue(
                status="contradiction",
                code="abi_declaration_snapshot_contradiction",
                subject_id=member.function_id,
                dependency_ids=(binding.binding_id,),
                details={
                    "catalog_snapshot_id": member.snapshot_id,
                    "declaration_snapshot_id": binding.declaration_snapshot_id,
                },
            )
        if not set(member.symbols).intersection(declaration.symbols):
            issue(
                status="contradiction",
                code="abi_declaration_symbol_contradiction",
                subject_id=member.function_id,
                dependency_ids=(binding.binding_id,),
                details={
                    "catalog_symbols": list(member.symbols),
                    "declaration_symbols": list(declaration.symbols),
                },
            )
        declaration_evidence = AbiEvidenceV1.create(
            kind="pinned_catalog_member_abi_declaration",
            producer=declaration.producer,
            subject_kind="library_member",
            subject_id=member.function_id,
            dependencies=(
                member.source_index_sha256,
                member.identity_id,
                binding.binding_id,
                binding.declaration_set_sha256,
                declaration.declaration_id,
                declaration.source_sha256,
                *declaration.dependency_ids,
            ),
            payload={
                "catalog_member": member.to_payload(),
                "declaration_id": declaration.declaration_id,
                "declaration_source_kind": declaration.source_kind,
                "declaration_source_sha256": declaration.source_sha256,
                "profile_id": declaration.profile.profile_id,
                "prototype": (
                    None
                    if declaration.prototype is None
                    else declaration.prototype.to_payload()
                ),
                "effects": (
                    None
                    if declaration.effects is None
                    else declaration.effects.to_payload()
                ),
            },
        )
        evidence[declaration_evidence.evidence_id] = declaration_evidence
        for fact in facts_from_profile(
            subject_id=member.function_id,
            profile=declaration.profile,
            evidence_ids=(declaration_evidence.evidence_id,),
            dependency_ids=(binding.binding_id, declaration.declaration_id),
        ):
            facts[canonical_json_bytes(fact.to_payload())] = fact

    grouped_bindings: dict[str, list[CatalogMemberAbiDeclarationV1]] = {}
    for binding in bindings:
        grouped_bindings.setdefault(binding.member.function_id, []).append(binding)
    for subject_id, rows in grouped_bindings.items():
        prototypes = {
            canonical_json_bytes(row.declaration.prototype.to_payload())
            for row in rows
            if row.declaration.prototype is not None
        }
        effects = {
            canonical_json_bytes(row.declaration.effects.to_payload())
            for row in rows
            if row.declaration.effects is not None
        }
        for values, code in (
            (prototypes, "abi_portable_prototype_contradiction"),
            (effects, "abi_boundary_effects_contradiction"),
        ):
            if len(values) > 1:
                issue(
                    status="contradiction",
                    code=code,
                    subject_id=subject_id,
                    dependency_ids=(row.binding_id for row in rows),
                    details={"declaration_ids": sorted(row.declaration.declaration_id for row in rows)},
                )

    for input_result in extraction_results:
        extraction = (
            input_result
            if isinstance(input_result, AbiExtractionResultV1)
            else AbiExtractionResultV1.read(input_result)
        )
        extraction_id = canonical_sha256(extraction.to_payload())
        for subject_id, subject_kind in sorted(extraction.subjects.items()):
            subject(subject_id, subject_kind, extraction_id)
        for row in extraction.evidence:
            previous = evidence.get(row.evidence_id)
            if previous is not None and previous != row:
                issue(
                    status="contradiction",
                    code="abi_evidence_identity_contradiction",
                    subject_id=row.subject_id,
                    evidence_ids=(row.evidence_id,),
                    dependency_ids=(extraction_id,),
                    details=None,
                )
            evidence[row.evidence_id] = row
        for row in extraction.facts:
            facts[canonical_json_bytes(row.to_payload())] = row
        for row in extraction.equalities:
            equalities[canonical_json_bytes(row.to_payload())] = row
        for raw in extraction.issues:
            raw_status = str(raw.get("status", "incomplete"))
            issue(
                status=(
                    "contradiction" if raw_status == "violated" else "incomplete"
                ),
                code=str(raw.get("code", "abi_extraction_issue")),
                subject_id=str(raw.get("subject_id", f"extraction:{extraction_id}")),
                field=(None if raw.get("field") is None else str(raw["field"])),
                dependency_ids=(extraction_id,),
                details=_ingestion_details(raw),
            )
        if extraction.status == "violated" and not any(
            str(raw.get("status")) == "violated" for raw in extraction.issues
        ):
            issue(
                status="contradiction",
                code="abi_extraction_status_contradiction",
                subject_id=f"extraction:{extraction_id}",
                dependency_ids=(extraction_id,),
                details=None,
            )
        elif extraction.status == "incomplete" and not extraction.issues:
            issue(
                status="incomplete",
                code="abi_extraction_incomplete",
                subject_id=f"extraction:{extraction_id}",
                dependency_ids=(extraction_id,),
                details=None,
            )

    evidence_ids = set(evidence)
    valid_facts: list[AbiFactV1] = []
    for fact in facts.values():
        missing_evidence = set(fact.evidence_ids) - evidence_ids
        if fact.subject_id not in subjects or missing_evidence:
            issue(
                status="contradiction",
                code="abi_fact_binding_contradiction",
                subject_id=fact.subject_id,
                field=fact.field,
                evidence_ids=fact.evidence_ids,
                details={"missing_evidence_ids": sorted(missing_evidence)},
            )
            continue
        valid_facts.append(fact)
        if fact.status == "contradiction":
            issue(
                status="contradiction",
                code="abi_input_fact_contradiction",
                subject_id=fact.subject_id,
                field=fact.field,
                evidence_ids=fact.evidence_ids,
                dependency_ids=fact.dependency_ids,
                details=None,
            )

    valid_equalities: list[AbiEqualityConstraintV1] = []
    for equality in equalities.values():
        missing_subjects = {
            equality.left_subject_id,
            equality.right_subject_id,
        } - set(subjects)
        missing_evidence = set(equality.evidence_ids) - evidence_ids
        if missing_subjects or missing_evidence:
            issue(
                status="contradiction",
                code="abi_equality_binding_contradiction",
                subject_id=equality.left_subject_id,
                evidence_ids=equality.evidence_ids,
                details={
                    "missing_subject_ids": sorted(missing_subjects),
                    "missing_evidence_ids": sorted(missing_evidence),
                },
            )
            continue
        valid_equalities.append(equality)

    if subjects and (valid_facts or valid_equalities):
        solved = solve_abi_constraints(
            subjects=subjects,
            facts=valid_facts,
            equalities=valid_equalities,
        )
        for raw in solved.issues:
            if raw.get("status") != "violated":
                continue
            issue(
                status="contradiction",
                code=str(raw.get("code", "abi_constraint_contradiction")),
                subject_id=str(raw.get("subject_id", "abi-ingestion")),
                field=None if raw.get("field") is None else str(raw["field"]),
                details=_ingestion_details(raw),
            )

    subject_rows = tuple(
        IngestedAbiSubjectV1(subject_id, kind)
        for subject_id, kind in sorted(subjects.items())
    )
    evidence_rows = tuple(sorted(evidence.values(), key=lambda row: row.evidence_id))
    fact_rows = tuple(facts[key] for key in sorted(facts))
    equality_rows = tuple(equalities[key] for key in sorted(equalities))
    issue_rows = tuple(sorted(issues.values(), key=lambda row: row.issue_id))
    status = _status_from_issues(issue_rows)
    core = {
        "format": ABI_DECLARATION_INGESTION_FORMAT,
        "status": status,
        "subjects": [row.to_payload() for row in subject_rows],
        "member_declarations": [row.to_payload() for row in bindings],
        "evidence": [row.to_payload() for row in evidence_rows],
        "facts": [row.to_payload() for row in fact_rows],
        "equalities": [row.to_payload() for row in equality_rows],
        "issues": [row.to_payload() for row in issue_rows],
    }
    result = AbiDeclarationIngestionV1(
        status,
        subject_rows,
        bindings,
        evidence_rows,
        fact_rows,
        equality_rows,
        issue_rows,
        canonical_sha256(core),
    )
    if out is not None:
        result.write(out)
    return result


def _status_from_issues(issues: Iterable[AbiIngestionIssueV1]) -> str:
    statuses = {issue.status for issue in issues}
    if "contradiction" in statuses:
        return "contradiction"
    if "incomplete" in statuses:
        return "incomplete"
    return "complete"


def _ingestion_details(value: Mapping[str, Any]) -> dict[str, Any]:
    return {
        str(key): (
            "contradiction"
            if key == "status" and item == "violated"
            else item
        )
        for key, item in value.items()
    }


def _require_sorted_unique(
    values: Sequence[Any], key: Any, label: str
) -> None:
    keys = tuple(key(value) for value in values)
    if keys != tuple(sorted(set(keys))):
        raise AbiModelError(f"{label} must be sorted and unique")


__all__ = [
    "ABI_DECLARATION_INGESTION_FORMAT",
    "AbiDeclarationIngestionV1",
    "AbiIngestionIssueV1",
    "CatalogMemberAbiDeclarationV1",
    "CatalogMemberIdentityV1",
    "IngestedAbiSubjectV1",
    "ingest_abi_declarations",
]
