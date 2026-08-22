"""Physical ABI catalogs derived from immutable linked-library artifacts."""

from __future__ import annotations

import json
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Sequence

from ..artifacts.formats import PHYSICAL_ABI_CATALOG_FORMAT
from ..libraries.abi_catalog import (
    CATALOG_SEARCH_INDEX_CODEC_V3,
    build_catalog_search_index,
)
from .declarations import PhysicalAbiDeclarationSetV1, PhysicalAbiDeclarationV1
from .model import (
    AbiEvidenceV1,
    AbiFactV1,
    PhysicalAbiCertificateV1,
    canonical_json_bytes,
    canonical_sha256,
)
from .solver import AbiConstraintResultV1, facts_from_profile, solve_abi_constraints
from .symbols import infer_pe32_symbol_abi


@dataclass(frozen=True)
class PhysicalAbiCatalogV1:
    status: str
    catalog_id: str
    source_index_sha256: str
    decoration_model: str
    declaration_set_sha256: str | None
    evidence: tuple[AbiEvidenceV1, ...]
    facts: tuple[AbiFactV1, ...]
    certificates: tuple[PhysicalAbiCertificateV1, ...]
    function_subjects: tuple[Mapping[str, Any], ...]
    issues: tuple[Mapping[str, Any], ...]
    catalog_sha256: str

    @property
    def core_payload(self) -> dict[str, object]:
        return {
            "format": PHYSICAL_ABI_CATALOG_FORMAT,
            "status": self.status,
            "catalog_id": self.catalog_id,
            "source_index_sha256": self.source_index_sha256,
            "decoration_model": self.decoration_model,
            "declaration_set_sha256": self.declaration_set_sha256,
            "evidence": [item.to_payload() for item in self.evidence],
            "facts": [item.to_payload() for item in self.facts],
            "certificates": [item.to_payload() for item in self.certificates],
            "functions": list(self.function_subjects),
            "issues": list(self.issues),
        }

    def to_payload(self) -> dict[str, object]:
        return {**self.core_payload, "catalog_sha256": self.catalog_sha256}

    @classmethod
    def create(
        cls,
        *,
        status: str,
        catalog_id: str,
        source_index_sha256: str,
        decoration_model: str,
        declaration_set_sha256: str | None,
        evidence: tuple[AbiEvidenceV1, ...],
        facts: tuple[AbiFactV1, ...],
        certificates: tuple[PhysicalAbiCertificateV1, ...],
        function_subjects: tuple[Mapping[str, Any], ...],
        issues: tuple[Mapping[str, Any], ...],
    ) -> "PhysicalAbiCatalogV1":
        placeholder = cls(
            status,
            catalog_id,
            source_index_sha256,
            decoration_model,
            declaration_set_sha256,
            evidence,
            facts,
            certificates,
            function_subjects,
            issues,
            "0" * 64,
        )
        return cls(
            status,
            catalog_id,
            source_index_sha256,
            decoration_model,
            declaration_set_sha256,
            evidence,
            facts,
            certificates,
            function_subjects,
            issues,
            canonical_sha256(placeholder.core_payload),
        )

    def write(self, path: Path | str) -> None:
        destination = Path(path)
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(canonical_json_bytes(self.to_payload()) + b"\n")

    @classmethod
    def read(cls, path: Path | str) -> "PhysicalAbiCatalogV1":
        source = Path(path)
        payload = json.loads(source.read_text(encoding="utf-8"))
        if not isinstance(payload, Mapping):
            raise ValueError("physical ABI catalog must be an object")
        expected = {
            "format",
            "status",
            "catalog_id",
            "source_index_sha256",
            "decoration_model",
            "declaration_set_sha256",
            "evidence",
            "facts",
            "certificates",
            "functions",
            "issues",
            "catalog_sha256",
        }
        if set(payload) != expected or payload.get("format") != PHYSICAL_ABI_CATALOG_FORMAT:
            raise ValueError("physical ABI catalog fields or format are unsupported")
        for field in ("evidence", "facts", "certificates", "functions", "issues"):
            if not isinstance(payload[field], list):
                raise ValueError(f"physical ABI catalog {field} must be an array")
        result = cls(
            status=str(payload["status"]),
            catalog_id=str(payload["catalog_id"]),
            source_index_sha256=str(payload["source_index_sha256"]),
            decoration_model=str(payload["decoration_model"]),
            declaration_set_sha256=(
                None
                if payload["declaration_set_sha256"] is None
                else str(payload["declaration_set_sha256"])
            ),
            evidence=tuple(AbiEvidenceV1.parse(item) for item in payload["evidence"]),
            facts=tuple(AbiFactV1.parse(item) for item in payload["facts"]),
            certificates=tuple(
                PhysicalAbiCertificateV1.parse(item)
                for item in payload["certificates"]
            ),
            function_subjects=tuple(
                dict(item) if isinstance(item, Mapping) else _raise_function()
                for item in payload["functions"]
            ),
            issues=tuple(
                dict(item) if isinstance(item, Mapping) else _raise_issue()
                for item in payload["issues"]
            ),
            catalog_sha256=str(payload["catalog_sha256"]),
        )
        if result.catalog_sha256 != canonical_sha256(result.core_payload):
            raise ValueError("physical ABI catalog hash is stale")
        return result


def _raise_function() -> Mapping[str, Any]:
    raise ValueError("physical ABI catalog function must be an object")


def _raise_issue() -> Mapping[str, Any]:
    raise ValueError("physical ABI catalog issue must be an object")


def build_physical_abi_catalog(
    *,
    artifact_index: Path | str,
    out: Path | str,
    decoration_model: str,
    declarations: Path | str | None = None,
) -> PhysicalAbiCatalogV1:
    source = Path(artifact_index)
    payload = json.loads(source.read_text(encoding="utf-8"))
    if not isinstance(payload, Mapping):
        raise ValueError("library artifact index must be an object")
    catalog_id = str(payload.get("catalog_id", ""))
    index_sha256 = str(payload.get("index_sha256", ""))
    if not catalog_id or len(index_sha256) != 64:
        raise ValueError("library artifact index identity is malformed")
    declaration_set = (
        None
        if declarations is None
        else PhysicalAbiDeclarationSetV1.read(declarations)
    )
    snapshot = payload.get("snapshot")
    snapshot_id = snapshot.get("id") if isinstance(snapshot, Mapping) else None
    if declaration_set is not None and declaration_set.snapshot_id != snapshot_id:
        raise ValueError(
            "physical ABI declarations target another library snapshot"
        )
    with tempfile.TemporaryDirectory(prefix="spaghetti-abi-catalog-") as temporary:
        search_path = Path(temporary) / "search-index.json"
        build_catalog_search_index([source], search_path)
        search = CATALOG_SEARCH_INDEX_CODEC_V3.read(search_path)

    evidence: list[AbiEvidenceV1] = []
    facts: list[AbiFactV1] = []
    functions: list[Mapping[str, Any]] = []
    issues: list[Mapping[str, Any]] = []
    subjects: dict[str, str] = {}
    declarations_by_symbol: dict[str, list[PhysicalAbiDeclarationV1]] = {}
    if declaration_set is not None:
        for declaration in declaration_set.declarations:
            for symbol in declaration.symbols:
                declarations_by_symbol.setdefault(symbol, []).append(declaration)
    for function in search.functions:
        subject_id = function.function_id
        subjects[subject_id] = "library_member"
        inferred = infer_pe32_symbol_abi(
            subject_id=subject_id,
            subject_kind="library_member",
            symbols=function.symbols,
            decoration_model=decoration_model,
            dependency_ids=(index_sha256,),
        )
        if inferred is not None:
            evidence.append(inferred.evidence)
            facts.extend(inferred.facts)
        matches = {
            declaration.declaration_id: declaration
            for symbol in function.symbols
            for declaration in declarations_by_symbol.get(symbol, ())
        }
        declaration = None
        if len(matches) == 1:
            declaration = next(iter(matches.values()))
            declaration_evidence = AbiEvidenceV1.create(
                kind="pinned_physical_abi_declaration",
                producer=declaration.producer,
                subject_kind="library_member",
                subject_id=subject_id,
                dependencies=(
                    index_sha256,
                    declaration.declaration_id,
                    declaration.source_sha256,
                    *declaration.dependency_ids,
                ),
                payload={
                    "symbols": list(declaration.symbols),
                    "source_kind": declaration.source_kind,
                    "source_sha256": declaration.source_sha256,
                    "profile_id": declaration.profile.profile_id,
                },
            )
            evidence.append(declaration_evidence)
            facts.extend(
                facts_from_profile(
                    subject_id=subject_id,
                    profile=declaration.profile,
                    evidence_ids=(declaration_evidence.evidence_id,),
                    dependency_ids=(
                        declaration.declaration_id,
                        declaration.source_sha256,
                    ),
                )
            )
        elif len(matches) > 1:
            issues.append(
                {
                    "status": "violated",
                    "code": "abi_declaration_match_ambiguous",
                    "subject_id": subject_id,
                    "declaration_ids": sorted(matches),
                }
            )
        functions.append(
            {
                "function_id": function.function_id,
                "symbols": list(function.symbols),
                "undecorated_symbol": (
                    None if inferred is None else inferred.undecorated_symbol
                ),
                "declaration_id": (
                    None if declaration is None else declaration.declaration_id
                ),
                "portable_prototype": (
                    None
                    if declaration is None or declaration.prototype is None
                    else declaration.prototype.to_payload()
                ),
                "boundary_effects": (
                    None
                    if declaration is None or declaration.effects is None
                    else declaration.effects.to_payload()
                ),
                "certificate_id": None,
            }
        )
    solved: AbiConstraintResultV1 = solve_abi_constraints(
        subjects=subjects,
        facts=facts,
    )
    certificates = solved.certificates
    certificate_by_subject = {item.subject_id: item for item in certificates}
    functions = [
        {
            **row,
            "certificate_id": certificate_by_subject[row["function_id"]].certificate_id,
        }
        for row in functions
    ]
    issues.extend(solved.issues)
    for certificate in certificates:
        if certificate.status == "incomplete":
            issues.append(
                {
                    "status": "incomplete",
                    "code": "abi_declaration_or_machine_evidence_required",
                    "subject_id": certificate.subject_id,
                    "next_action": (
                        "provide pinned header/debug declarations or additional "
                        "checked call-boundary evidence"
                    ),
                }
            )
    status = (
        "violated"
        if solved.status == "violated"
        or any(issue.get("status") == "violated" for issue in issues)
        else "incomplete"
        if issues or solved.status == "incomplete"
        else "complete"
    )
    result = PhysicalAbiCatalogV1.create(
        status=status,
        catalog_id=catalog_id,
        source_index_sha256=index_sha256,
        decoration_model=decoration_model,
        declaration_set_sha256=(
            None
            if declaration_set is None
            else declaration_set.declaration_set_sha256
        ),
        evidence=tuple(sorted(evidence)),
        facts=tuple(sorted(facts, key=lambda row: (row.subject_id, row.field))),
        certificates=certificates,
        function_subjects=tuple(
            sorted(functions, key=lambda row: str(row["function_id"]))
        ),
        issues=tuple(
            sorted(
                issues,
                key=lambda row: (
                    str(row.get("status")),
                    str(row.get("subject_id")),
                    str(row.get("code")),
                ),
            )
        ),
    )
    result.write(out)
    return result


__all__ = ["PhysicalAbiCatalogV1", "build_physical_abi_catalog"]
