from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from enum import Enum
from typing import Any

from .analyses.callsite import (
    CALLSITE_PRESERVATION_ANALYSIS_FORMAT,
    CALLSITE_PRESERVATION_CERTIFICATE_FORMAT,
)
from .schema import REGISTERS, SchemaError


CALLSITE_PRESERVATION_ARTIFACT_FORMAT = (
    "stage-a-relational-callsite-preservation-v1"
)
CALLSITE_PRESERVATION_REQUIRED_REPLAY = (
    "Lean must replay every normalized behavior, control edge, return "
    "inventory, nested dependency, and preserved relation"
)
CALLSITE_PRESERVATION_TRUST_ROLE = (
    "analysis_and_certificate_proposal_only"
)
PROPOSAL_EDGE_KIND = "internal_callsite_preservation_summary"

_SHA256_RE = re.compile(r"[0-9a-f]{64}")


class ArtifactStatus(str, Enum):
    PROPOSAL_REQUIRES_REPLAY = "proposal_requires_generated_lean_replay"
    FIXED_POINT_BUDGET_EXHAUSTED = "incomplete_fixed_point_budget_exhausted"


class SummaryStatus(str, Enum):
    SATISFIED = "satisfied"
    INCOMPLETE = "incomplete"
    NOT_APPLICABLE = "not_applicable"


class AnalysisStatus(str, Enum):
    SATISFIED = "satisfied"
    INCOMPLETE = "incomplete"


@dataclass(frozen=True)
class ImportRelation:
    original: str
    candidate: str
    import_json: str


@dataclass(frozen=True)
class ReturnInventoryEntry:
    return_node_id: int
    continuation_id: int


@dataclass(frozen=True)
class ReachableEdge:
    source: int
    target: int


@dataclass(frozen=True)
class BehaviorHash:
    node_id: int
    original: str
    candidate: str


@dataclass(frozen=True)
class NestedDependency:
    node_id: int
    summary_id: str
    certificate_hash: str


@dataclass(frozen=True)
class CertificateClosure:
    finite: bool
    all_reachable_exits_matched: bool
    all_nodes_can_reach_return: bool
    all_requested_registers_identity_preserved: bool


@dataclass(frozen=True)
class CallsiteCertificate:
    callsite_id: int
    callee_entry: int
    requested_relations: tuple[ImportRelation, ...]
    reachable_node_ids: tuple[int, ...]
    reachable_edges: tuple[ReachableEdge, ...]
    return_inventory: tuple[ReturnInventoryEntry, ...]
    behavior_hashes: tuple[BehaviorHash, ...]
    nested_dependencies: tuple[NestedDependency, ...]
    cyclic_node_ids: tuple[int, ...]
    closure: CertificateClosure
    id: str
    certificate_hash: str


@dataclass(frozen=True)
class AnalysisIssue:
    code: str
    node_id: int | None
    field: str | None
    reference_json: str | None
    nested_reason_codes: tuple[str, ...]


@dataclass(frozen=True)
class CallsiteAnalysis:
    status: AnalysisStatus
    callsite_id: int
    reason_codes: tuple[str, ...]
    issues: tuple[AnalysisIssue, ...]
    certificate: CallsiteCertificate | None


@dataclass(frozen=True)
class CallsiteSummary:
    callsite_region_index: int
    callee_region_index: int | None
    continuation_region_index: int | None
    return_region_indices: tuple[int, ...]
    requested_relations: tuple[ImportRelation, ...]
    status: SummaryStatus
    reason_codes: tuple[str, ...]
    analysis: CallsiteAnalysis | None


@dataclass(frozen=True)
class ProposalEdge:
    source_region_index: int
    target_region_index: int
    certificate_id: str
    certificate_hash: str
    preserved_import_relations: tuple[ImportRelation, ...]
    return_region_indices: tuple[int, ...]
    kind: str = PROPOSAL_EDGE_KIND
    environment_barrier: bool = False
    proposal_only: bool = True


@dataclass(frozen=True)
class ArtifactCounts:
    call_summaries: int
    satisfied: int
    incomplete: int
    not_applicable: int
    proposal_edges: int
    certificates: int


@dataclass(frozen=True)
class TrustMetadata:
    role: str
    acceptance_authority: bool
    required_replay: str


@dataclass(frozen=True)
class CallsitePreservationArtifact:
    status: ArtifactStatus
    summaries: tuple[CallsiteSummary, ...]
    certificates: tuple[CallsiteCertificate, ...]
    proposal_edges: tuple[ProposalEdge, ...]
    counts: ArtifactCounts
    trust: TrustMetadata
    format: str = CALLSITE_PRESERVATION_ARTIFACT_FORMAT


def _canonical_json(value: Any) -> str:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    )


def _sha256(value: Any) -> str:
    return hashlib.sha256(_canonical_json(value).encode("utf-8")).hexdigest()


def _object(value: Any, context: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise SchemaError(f"{context} must be an object")
    return value


def _objects(value: Any, context: str) -> list[Mapping[str, Any]]:
    if not isinstance(value, list) or any(
        not isinstance(item, Mapping) for item in value
    ):
        raise SchemaError(f"{context} must be a list of objects")
    return list(value)


def _exact_fields(
    payload: Mapping[str, Any], fields: set[str], context: str,
) -> None:
    missing = sorted(fields - set(payload))
    unknown = sorted(set(payload) - fields)
    if missing or unknown:
        details: list[str] = []
        if missing:
            details.append(f"missing fields {missing}")
        if unknown:
            details.append(f"unknown fields {unknown}")
        raise SchemaError(f"{context} has " + " and ".join(details))


def _allowed_fields(
    payload: Mapping[str, Any], required: set[str], allowed: set[str], context: str,
) -> None:
    missing = sorted(required - set(payload))
    unknown = sorted(set(payload) - allowed)
    if missing or unknown:
        details: list[str] = []
        if missing:
            details.append(f"missing fields {missing}")
        if unknown:
            details.append(f"unknown fields {unknown}")
        raise SchemaError(f"{context} has " + " and ".join(details))


def _string(value: Any, context: str) -> str:
    if not isinstance(value, str) or not value:
        raise SchemaError(f"{context} must be a non-empty string")
    return value


def _integer(
    value: Any,
    context: str,
    *,
    region_count: int | None = None,
) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise SchemaError(f"{context} must be a non-negative integer")
    if region_count is not None and value >= region_count:
        raise SchemaError(f"{context} is outside the region inventory")
    return value


def _sha256_string(value: Any, context: str) -> str:
    digest = _string(value, context)
    if _SHA256_RE.fullmatch(digest) is None:
        raise SchemaError(f"{context} must be a lowercase SHA-256 digest")
    return digest


def _string_inventory(
    value: Any,
    context: str,
    *,
    allow_empty: bool,
) -> tuple[str, ...]:
    if not isinstance(value, list) or any(
        not isinstance(item, str) or not item for item in value
    ):
        raise SchemaError(f"{context} must be a list of non-empty strings")
    result = tuple(value)
    if not allow_empty and not result:
        raise SchemaError(f"{context} must not be empty")
    if list(result) != sorted(set(result)):
        raise SchemaError(f"{context} must be unique and canonically ordered")
    return result


def _region_inventory(
    value: Any,
    context: str,
    *,
    region_count: int | None,
    allow_empty: bool,
) -> tuple[int, ...]:
    if not isinstance(value, list):
        raise SchemaError(f"{context} must be a list")
    result = tuple(
        _integer(item, f"{context}[]", region_count=region_count)
        for item in value
    )
    if not allow_empty and not result:
        raise SchemaError(f"{context} must not be empty")
    if list(result) != sorted(set(result)):
        raise SchemaError(f"{context} must be unique and canonically ordered")
    return result


def _json_text(value: Any, context: str) -> str:
    def validate_json(item: Any, path: str) -> None:
        if item is None or isinstance(item, (str, bool, int)):
            return
        if isinstance(item, float):
            try:
                _canonical_json(item)
            except ValueError as exc:
                raise SchemaError(f"{path} must contain finite JSON values") from exc
            return
        if isinstance(item, list):
            for index, child in enumerate(item):
                validate_json(child, f"{path}[{index}]")
            return
        if isinstance(item, Mapping):
            if any(not isinstance(key, str) for key in item):
                raise SchemaError(f"{path} object keys must be strings")
            for key, child in item.items():
                validate_json(child, f"{path}.{key}")
            return
        raise SchemaError(f"{path} must contain only JSON values")

    validate_json(value, context)
    return _canonical_json(value)


def _relation_payload(relation: ImportRelation) -> dict[str, Any]:
    return {
        "original": relation.original,
        "candidate": relation.candidate,
        "import": json.loads(relation.import_json),
    }


def _parse_relations(
    value: Any,
    context: str,
    *,
    allow_empty: bool,
) -> tuple[ImportRelation, ...]:
    rows = _objects(value, context)
    result: list[ImportRelation] = []
    keys: list[str] = []
    original_owners: set[str] = set()
    candidate_owners: set[str] = set()
    for index, row in enumerate(rows):
        row_context = f"{context}[{index}]"
        _exact_fields(row, {"original", "candidate", "import"}, row_context)
        original = _string(row.get("original"), f"{row_context}.original")
        candidate = _string(row.get("candidate"), f"{row_context}.candidate")
        if original not in REGISTERS or candidate not in REGISTERS:
            raise SchemaError(f"{row_context} must name x86 registers")
        imported = _object(row.get("import"), f"{row_context}.import")
        if not imported:
            raise SchemaError(f"{row_context}.import must not be empty")
        relation = ImportRelation(
            original=original,
            candidate=candidate,
            import_json=_json_text(imported, f"{row_context}.import"),
        )
        key = _canonical_json(_relation_payload(relation))
        if key in keys:
            raise SchemaError(f"{context} contains a duplicate relation")
        if original in original_owners or candidate in candidate_owners:
            raise SchemaError(f"{context} contains an ambiguous register relation")
        keys.append(key)
        original_owners.add(original)
        candidate_owners.add(candidate)
        result.append(relation)
    if not allow_empty and not result:
        raise SchemaError(f"{context} must not be empty")
    if keys != sorted(keys):
        raise SchemaError(f"{context} is not in canonical relation order")
    return tuple(result)


def _parse_return_inventory(
    value: Any,
    context: str,
    *,
    region_count: int | None,
) -> tuple[ReturnInventoryEntry, ...]:
    rows = _objects(value, context)
    result: list[ReturnInventoryEntry] = []
    for index, row in enumerate(rows):
        row_context = f"{context}[{index}]"
        _exact_fields(
            row, {"return_node_id", "continuation_id"}, row_context
        )
        result.append(ReturnInventoryEntry(
            return_node_id=_integer(
                row.get("return_node_id"),
                f"{row_context}.return_node_id",
                region_count=region_count,
            ),
            continuation_id=_integer(
                row.get("continuation_id"),
                f"{row_context}.continuation_id",
                region_count=region_count,
            ),
        ))
    if not result:
        raise SchemaError(f"{context} must not be empty")
    node_ids = [row.return_node_id for row in result]
    if node_ids != sorted(set(node_ids)):
        raise SchemaError(
            f"{context} return node ids must be unique and canonically ordered"
        )
    if len({row.continuation_id for row in result}) != 1:
        raise SchemaError(f"{context} must name one continuation")
    return tuple(result)


def _parse_reachable_edges(
    value: Any,
    context: str,
    *,
    region_count: int | None,
) -> tuple[ReachableEdge, ...]:
    rows = _objects(value, context)
    result: list[ReachableEdge] = []
    seen: set[tuple[int, int]] = set()
    for index, row in enumerate(rows):
        row_context = f"{context}[{index}]"
        _exact_fields(row, {"source", "target"}, row_context)
        edge = ReachableEdge(
            source=_integer(
                row.get("source"),
                f"{row_context}.source",
                region_count=region_count,
            ),
            target=_integer(
                row.get("target"),
                f"{row_context}.target",
                region_count=region_count,
            ),
        )
        key = (edge.source, edge.target)
        if key in seen:
            raise SchemaError(f"{context} contains a duplicate edge")
        seen.add(key)
        result.append(edge)
    return tuple(result)


def _parse_behavior_hashes(
    value: Any,
    context: str,
    *,
    region_count: int | None,
) -> tuple[BehaviorHash, ...]:
    rows = _objects(value, context)
    result: list[BehaviorHash] = []
    for index, row in enumerate(rows):
        row_context = f"{context}[{index}]"
        _exact_fields(row, {"node_id", "original", "candidate"}, row_context)
        result.append(BehaviorHash(
            node_id=_integer(
                row.get("node_id"),
                f"{row_context}.node_id",
                region_count=region_count,
            ),
            original=_sha256_string(
                row.get("original"), f"{row_context}.original"
            ),
            candidate=_sha256_string(
                row.get("candidate"), f"{row_context}.candidate"
            ),
        ))
    node_ids = [row.node_id for row in result]
    if node_ids != sorted(set(node_ids)):
        raise SchemaError(
            f"{context} node ids must be unique and canonically ordered"
        )
    return tuple(result)


def _parse_nested_dependencies(
    value: Any,
    context: str,
    *,
    region_count: int | None,
) -> tuple[NestedDependency, ...]:
    rows = _objects(value, context)
    result: list[NestedDependency] = []
    for index, row in enumerate(rows):
        row_context = f"{context}[{index}]"
        _exact_fields(
            row, {"node_id", "summary_id", "certificate_hash"}, row_context
        )
        result.append(NestedDependency(
            node_id=_integer(
                row.get("node_id"),
                f"{row_context}.node_id",
                region_count=region_count,
            ),
            summary_id=_string(
                row.get("summary_id"), f"{row_context}.summary_id"
            ),
            certificate_hash=_sha256_string(
                row.get("certificate_hash"),
                f"{row_context}.certificate_hash",
            ),
        ))
    keys = [(row.node_id, row.summary_id) for row in result]
    if keys != sorted(set(keys)):
        raise SchemaError(f"{context} must be unique and canonically ordered")
    if len({row.node_id for row in result}) != len(result):
        raise SchemaError(f"{context} contains a duplicate dependency node")
    return tuple(result)


def _parse_closure(value: Any, context: str) -> CertificateClosure:
    payload = _object(value, context)
    fields = {
        "finite",
        "all_reachable_exits_matched",
        "all_nodes_can_reach_return",
        "all_requested_registers_identity_preserved",
    }
    _exact_fields(payload, fields, context)
    if any(payload.get(field) is not True for field in fields):
        raise SchemaError(f"{context} must explicitly satisfy every closure claim")
    return CertificateClosure(
        finite=True,
        all_reachable_exits_matched=True,
        all_nodes_can_reach_return=True,
        all_requested_registers_identity_preserved=True,
    )


def _parse_certificate(
    value: Any,
    context: str,
    *,
    region_count: int | None,
) -> CallsiteCertificate:
    payload = _object(value, context)
    fields = {
        "format",
        "callsite_id",
        "callee_entry",
        "requested_relations",
        "reachable_node_ids",
        "reachable_edges",
        "return_inventory",
        "behavior_hashes",
        "nested_dependencies",
        "cyclic_node_ids",
        "closure",
        "id",
        "certificate_hash",
    }
    _exact_fields(payload, fields, context)
    if payload.get("format") != CALLSITE_PRESERVATION_CERTIFICATE_FORMAT:
        raise SchemaError(f"{context}.format is unsupported")
    callsite_id = _integer(
        payload.get("callsite_id"),
        f"{context}.callsite_id",
        region_count=region_count,
    )
    callee_entry = _integer(
        payload.get("callee_entry"),
        f"{context}.callee_entry",
        region_count=region_count,
    )
    relations = _parse_relations(
        payload.get("requested_relations"),
        f"{context}.requested_relations",
        allow_empty=False,
    )
    reachable_nodes = _region_inventory(
        payload.get("reachable_node_ids"),
        f"{context}.reachable_node_ids",
        region_count=region_count,
        allow_empty=False,
    )
    edges = _parse_reachable_edges(
        payload.get("reachable_edges"),
        f"{context}.reachable_edges",
        region_count=region_count,
    )
    returns = _parse_return_inventory(
        payload.get("return_inventory"),
        f"{context}.return_inventory",
        region_count=region_count,
    )
    behavior_hashes = _parse_behavior_hashes(
        payload.get("behavior_hashes"),
        f"{context}.behavior_hashes",
        region_count=region_count,
    )
    nested = _parse_nested_dependencies(
        payload.get("nested_dependencies"),
        f"{context}.nested_dependencies",
        region_count=region_count,
    )
    cyclic_nodes = _region_inventory(
        payload.get("cyclic_node_ids"),
        f"{context}.cyclic_node_ids",
        region_count=region_count,
        allow_empty=True,
    )
    closure = _parse_closure(payload.get("closure"), f"{context}.closure")
    certificate_id = _string(payload.get("id"), f"{context}.id")
    certificate_hash = _sha256_string(
        payload.get("certificate_hash"), f"{context}.certificate_hash"
    )

    reachable_set = set(reachable_nodes)
    if callee_entry not in reachable_set:
        raise SchemaError(f"{context}.callee_entry must be reachable")
    if any(
        edge.source not in reachable_set or edge.target not in reachable_set
        for edge in edges
    ):
        raise SchemaError(f"{context}.reachable_edges must refer to reachable nodes")
    if any(row.return_node_id not in reachable_set for row in returns):
        raise SchemaError(f"{context}.return_inventory must refer to reachable nodes")
    if tuple(row.node_id for row in behavior_hashes) != reachable_nodes:
        raise SchemaError(
            f"{context}.behavior_hashes must cover reachable nodes exactly"
        )
    if any(row.node_id not in reachable_set for row in nested):
        raise SchemaError(
            f"{context}.nested_dependencies must refer to reachable nodes"
        )
    if not set(cyclic_nodes).issubset(reachable_set):
        raise SchemaError(f"{context}.cyclic_node_ids must be reachable")

    supplied_unsigned = dict(payload)
    supplied_unsigned.pop("certificate_hash")
    if certificate_hash != _sha256(supplied_unsigned):
        raise SchemaError(f"{context}.certificate_hash does not match payload")
    identity_payload = dict(supplied_unsigned)
    identity_payload.pop("id")
    expected_id = (
        f"callsite-preservation:{callsite_id}:{callee_entry}:"
        f"{_sha256(identity_payload)[:16]}"
    )
    if certificate_id != expected_id:
        raise SchemaError(f"{context}.id does not match certificate identity")

    return CallsiteCertificate(
        callsite_id=callsite_id,
        callee_entry=callee_entry,
        requested_relations=relations,
        reachable_node_ids=reachable_nodes,
        reachable_edges=edges,
        return_inventory=returns,
        behavior_hashes=behavior_hashes,
        nested_dependencies=nested,
        cyclic_node_ids=cyclic_nodes,
        closure=closure,
        id=certificate_id,
        certificate_hash=certificate_hash,
    )


def _issue_payload(issue: AnalysisIssue) -> dict[str, Any]:
    payload: dict[str, Any] = {"code": issue.code}
    if issue.node_id is not None:
        payload["node_id"] = issue.node_id
    if issue.field is not None:
        payload["field"] = issue.field
    if issue.reference_json is not None:
        payload["reference"] = json.loads(issue.reference_json)
    if issue.nested_reason_codes:
        payload["nested_reason_codes"] = list(issue.nested_reason_codes)
    return payload


def _parse_issues(
    value: Any,
    context: str,
    *,
    region_count: int | None,
) -> tuple[AnalysisIssue, ...]:
    rows = _objects(value, context)
    result: list[AnalysisIssue] = []
    for index, row in enumerate(rows):
        row_context = f"{context}[{index}]"
        _allowed_fields(
            row,
            {"code"},
            {"code", "node_id", "field", "reference", "nested_reason_codes"},
            row_context,
        )
        node_id = None
        if "node_id" in row:
            node_id = _integer(
                row.get("node_id"),
                f"{row_context}.node_id",
                region_count=region_count,
            )
        field = None
        if "field" in row:
            field = _string(row.get("field"), f"{row_context}.field")
        reference_json = None
        if "reference" in row:
            reference_json = _json_text(
                row.get("reference"), f"{row_context}.reference"
            )
        nested_reason_codes: tuple[str, ...] = ()
        if "nested_reason_codes" in row:
            nested_reason_codes = _string_inventory(
                row.get("nested_reason_codes"),
                f"{row_context}.nested_reason_codes",
                allow_empty=False,
            )
        result.append(AnalysisIssue(
            code=_string(row.get("code"), f"{row_context}.code"),
            node_id=node_id,
            field=field,
            reference_json=reference_json,
            nested_reason_codes=nested_reason_codes,
        ))
    keys = [_canonical_json(_issue_payload(issue)) for issue in result]
    if keys != sorted(set(keys)):
        raise SchemaError(f"{context} must be unique and canonically ordered")
    return tuple(result)


def _parse_analysis(
    value: Any,
    context: str,
    *,
    region_count: int | None,
) -> CallsiteAnalysis:
    payload = _object(value, context)
    _exact_fields(
        payload,
        {"format", "status", "callsite_id", "reason_codes", "issues", "certificate"},
        context,
    )
    if payload.get("format") != CALLSITE_PRESERVATION_ANALYSIS_FORMAT:
        raise SchemaError(f"{context}.format is unsupported")
    try:
        status = AnalysisStatus(payload.get("status"))
    except (TypeError, ValueError) as exc:
        raise SchemaError(f"{context}.status is unsupported") from exc
    callsite_id = _integer(
        payload.get("callsite_id"),
        f"{context}.callsite_id",
        region_count=region_count,
    )
    reasons = _string_inventory(
        payload.get("reason_codes"),
        f"{context}.reason_codes",
        allow_empty=status is AnalysisStatus.SATISFIED,
    )
    issues = _parse_issues(
        payload.get("issues"), f"{context}.issues", region_count=region_count
    )
    certificate = None
    if payload.get("certificate") is not None:
        certificate = _parse_certificate(
            payload.get("certificate"),
            f"{context}.certificate",
            region_count=region_count,
        )
    if status is AnalysisStatus.SATISFIED:
        if reasons or issues or certificate is None:
            raise SchemaError(
                f"{context} satisfied analysis must contain only a certificate"
            )
    else:
        issue_codes = tuple(sorted({issue.code for issue in issues}))
        if not issues or reasons != issue_codes or certificate is not None:
            raise SchemaError(
                f"{context} incomplete analysis has inconsistent diagnostics"
            )
    if certificate is not None and certificate.callsite_id != callsite_id:
        raise SchemaError(f"{context}.certificate callsite does not match analysis")
    return CallsiteAnalysis(
        status=status,
        callsite_id=callsite_id,
        reason_codes=reasons,
        issues=issues,
        certificate=certificate,
    )


def _parse_summary(
    value: Any,
    context: str,
    *,
    region_count: int | None,
) -> CallsiteSummary:
    payload = _object(value, context)
    _exact_fields(
        payload,
        {
            "callsite_region_index",
            "callee_region_index",
            "continuation_region_index",
            "return_region_indices",
            "requested_relations",
            "status",
            "reason_codes",
            "analysis",
        },
        context,
    )
    callsite = _integer(
        payload.get("callsite_region_index"),
        f"{context}.callsite_region_index",
        region_count=region_count,
    )
    callee = None
    if payload.get("callee_region_index") is not None:
        callee = _integer(
            payload.get("callee_region_index"),
            f"{context}.callee_region_index",
            region_count=region_count,
        )
    continuation = None
    if payload.get("continuation_region_index") is not None:
        continuation = _integer(
            payload.get("continuation_region_index"),
            f"{context}.continuation_region_index",
            region_count=region_count,
        )
    returns = _region_inventory(
        payload.get("return_region_indices"),
        f"{context}.return_region_indices",
        region_count=region_count,
        allow_empty=True,
    )
    complete_shape = callee is not None and continuation is not None and bool(returns)
    empty_shape = callee is None and continuation is None and not returns
    if not complete_shape and not empty_shape:
        raise SchemaError(f"{context} has a malformed return inventory shape")
    relations = _parse_relations(
        payload.get("requested_relations"),
        f"{context}.requested_relations",
        allow_empty=True,
    )
    try:
        status = SummaryStatus(payload.get("status"))
    except (TypeError, ValueError) as exc:
        raise SchemaError(f"{context}.status is unsupported") from exc
    reasons = _string_inventory(
        payload.get("reason_codes"),
        f"{context}.reason_codes",
        allow_empty=status is SummaryStatus.SATISFIED,
    )
    analysis = None
    if payload.get("analysis") is not None:
        analysis = _parse_analysis(
            payload.get("analysis"),
            f"{context}.analysis",
            region_count=region_count,
        )
    if status is SummaryStatus.NOT_APPLICABLE:
        if (
            relations
            or analysis is not None
            or reasons != ("no_import_register_relations_at_callsite",)
        ):
            raise SchemaError(f"{context} has inconsistent not-applicable state")
    elif analysis is None or analysis.status.value != status.value:
        raise SchemaError(f"{context}.analysis status does not match summary")
    elif not relations or reasons != analysis.reason_codes:
        raise SchemaError(f"{context} has inconsistent analysis diagnostics")
    if status is SummaryStatus.SATISFIED:
        if not complete_shape or analysis is None or analysis.certificate is None:
            raise SchemaError(f"{context} satisfied summary has no complete certificate")
        certificate = analysis.certificate
        if (
            certificate.callsite_id != callsite
            or certificate.callee_entry != callee
            or certificate.requested_relations != relations
            or tuple(row.return_node_id for row in certificate.return_inventory) != returns
            or any(
                row.continuation_id != continuation
                for row in certificate.return_inventory
            )
        ):
            raise SchemaError(f"{context} certificate does not match summary metadata")
    return CallsiteSummary(
        callsite_region_index=callsite,
        callee_region_index=callee,
        continuation_region_index=continuation,
        return_region_indices=returns,
        requested_relations=relations,
        status=status,
        reason_codes=reasons,
        analysis=analysis,
    )


def _parse_proposal_edge(
    value: Any,
    context: str,
    *,
    region_count: int | None,
) -> ProposalEdge:
    payload = _object(value, context)
    _exact_fields(
        payload,
        {
            "source_region_index",
            "target_region_index",
            "kind",
            "environment_barrier",
            "proposal_only",
            "certificate_id",
            "certificate_hash",
            "preserved_import_relations",
            "return_region_indices",
        },
        context,
    )
    if payload.get("kind") != PROPOSAL_EDGE_KIND:
        raise SchemaError(f"{context}.kind is unsupported")
    if payload.get("environment_barrier") is not False:
        raise SchemaError(f"{context}.environment_barrier must be false")
    if payload.get("proposal_only") is not True:
        raise SchemaError(f"{context}.proposal_only must be true")
    return ProposalEdge(
        source_region_index=_integer(
            payload.get("source_region_index"),
            f"{context}.source_region_index",
            region_count=region_count,
        ),
        target_region_index=_integer(
            payload.get("target_region_index"),
            f"{context}.target_region_index",
            region_count=region_count,
        ),
        certificate_id=_string(
            payload.get("certificate_id"), f"{context}.certificate_id"
        ),
        certificate_hash=_sha256_string(
            payload.get("certificate_hash"), f"{context}.certificate_hash"
        ),
        preserved_import_relations=_parse_relations(
            payload.get("preserved_import_relations"),
            f"{context}.preserved_import_relations",
            allow_empty=False,
        ),
        return_region_indices=_region_inventory(
            payload.get("return_region_indices"),
            f"{context}.return_region_indices",
            region_count=region_count,
            allow_empty=False,
        ),
    )


def _parse_counts(value: Any, context: str) -> ArtifactCounts:
    payload = _object(value, context)
    fields = {
        "call_summaries",
        "satisfied",
        "incomplete",
        "not_applicable",
        "proposal_edges",
        "certificates",
    }
    _exact_fields(payload, fields, context)
    values = {
        field: _integer(payload.get(field), f"{context}.{field}")
        for field in fields
    }
    return ArtifactCounts(**values)


def _parse_trust(value: Any, context: str) -> TrustMetadata:
    payload = _object(value, context)
    _exact_fields(
        payload, {"role", "acceptance_authority", "required_replay"}, context
    )
    if payload.get("role") != CALLSITE_PRESERVATION_TRUST_ROLE:
        raise SchemaError(f"{context}.role is unsupported")
    if payload.get("acceptance_authority") is not False:
        raise SchemaError(f"{context}.acceptance_authority must be false")
    if payload.get("required_replay") != CALLSITE_PRESERVATION_REQUIRED_REPLAY:
        raise SchemaError(f"{context}.required_replay is unsupported")
    return TrustMetadata(
        role=CALLSITE_PRESERVATION_TRUST_ROLE,
        acceptance_authority=False,
        required_replay=CALLSITE_PRESERVATION_REQUIRED_REPLAY,
    )


def parse_callsite_preservation_artifact(
    value: Any,
    *,
    region_count: int | None = None,
) -> CallsitePreservationArtifact:
    """Parse and fully validate the versioned callsite-preservation interface."""
    if region_count is not None and (
        isinstance(region_count, bool)
        or not isinstance(region_count, int)
        or region_count < 0
    ):
        raise SchemaError("region_count must be a non-negative integer")
    payload = _object(value, "callsite preservation artifact")
    _exact_fields(
        payload,
        {"format", "status", "summaries", "certificates", "proposal_edges", "counts", "trust"},
        "callsite preservation artifact",
    )
    if payload.get("format") != CALLSITE_PRESERVATION_ARTIFACT_FORMAT:
        raise SchemaError("unsupported callsite preservation artifact format")
    try:
        status = ArtifactStatus(payload.get("status"))
    except (TypeError, ValueError) as exc:
        raise SchemaError("unsupported callsite preservation artifact status") from exc

    summaries = tuple(
        _parse_summary(
            row, f"summaries[{index}]", region_count=region_count
        )
        for index, row in enumerate(_objects(payload.get("summaries"), "summaries"))
    )
    summary_ids = [row.callsite_region_index for row in summaries]
    if summary_ids != sorted(set(summary_ids)):
        raise SchemaError("summaries must have unique, canonically ordered callsites")

    certificates = tuple(
        _parse_certificate(
            row, f"certificates[{index}]", region_count=region_count
        )
        for index, row in enumerate(
            _objects(payload.get("certificates"), "certificates")
        )
    )
    certificate_ids = [row.id for row in certificates]
    certificate_hashes = [row.certificate_hash for row in certificates]
    if certificate_ids != sorted(set(certificate_ids)):
        raise SchemaError("certificates must have unique, canonically ordered ids")
    if len(certificate_hashes) != len(set(certificate_hashes)):
        raise SchemaError("certificates must have unique hashes")
    certificates_by_id = {row.id: row for row in certificates}

    proposal_edges = tuple(
        _parse_proposal_edge(
            row, f"proposal_edges[{index}]", region_count=region_count
        )
        for index, row in enumerate(
            _objects(payload.get("proposal_edges"), "proposal_edges")
        )
    )
    edge_keys = [
        (row.source_region_index, row.target_region_index, row.certificate_id)
        for row in proposal_edges
    ]
    if edge_keys != sorted(set(edge_keys)):
        raise SchemaError("proposal_edges must be unique and canonically ordered")
    pair_keys = [
        (row.source_region_index, row.target_region_index)
        for row in proposal_edges
    ]
    if len(pair_keys) != len(set(pair_keys)):
        raise SchemaError("proposal_edges contains a duplicate edge")

    counts = _parse_counts(payload.get("counts"), "counts")
    trust = _parse_trust(payload.get("trust"), "trust")
    summaries_by_callsite = {
        row.callsite_region_index: row for row in summaries
    }
    edges_by_callsite = {
        row.source_region_index: row for row in proposal_edges
    }
    if len(edges_by_callsite) != len(proposal_edges):
        raise SchemaError("proposal_edges contains duplicate source callsites")

    for certificate in certificates:
        for dependency in certificate.nested_dependencies:
            nested = certificates_by_id.get(dependency.summary_id)
            if (
                nested is None
                or nested.certificate_hash != dependency.certificate_hash
                or nested.callsite_id != dependency.node_id
            ):
                raise SchemaError(
                    f"certificate {certificate.id} has an invalid nested dependency"
                )

    satisfied_summaries = 0
    incomplete_summaries = 0
    not_applicable_summaries = 0
    for summary in summaries:
        if summary.status is SummaryStatus.SATISFIED:
            satisfied_summaries += 1
            assert summary.analysis is not None
            assert summary.analysis.certificate is not None
            certificate = certificates_by_id.get(summary.analysis.certificate.id)
            if certificate != summary.analysis.certificate:
                raise SchemaError(
                    "satisfied summary certificate is absent from certificate inventory"
                )
            edge = edges_by_callsite.get(summary.callsite_region_index)
            if (
                edge is None
                or edge.target_region_index != summary.continuation_region_index
                or edge.certificate_id != certificate.id
                or edge.certificate_hash != certificate.certificate_hash
                or edge.preserved_import_relations != summary.requested_relations
                or edge.return_region_indices != summary.return_region_indices
            ):
                raise SchemaError(
                    "satisfied summary has no matching proposal-only edge"
                )
        elif summary.status is SummaryStatus.INCOMPLETE:
            incomplete_summaries += 1
            if summary.callsite_region_index in edges_by_callsite:
                raise SchemaError("incomplete summary must not emit a proposal edge")
        else:
            not_applicable_summaries += 1
            if summary.callsite_region_index in edges_by_callsite:
                raise SchemaError("not-applicable summary must not emit a proposal edge")

    if any(edge.source_region_index not in summaries_by_callsite for edge in proposal_edges):
        raise SchemaError("proposal edge source has no callsite summary")
    expected_counts = ArtifactCounts(
        call_summaries=len(summaries),
        satisfied=satisfied_summaries,
        incomplete=incomplete_summaries,
        not_applicable=not_applicable_summaries,
        proposal_edges=len(proposal_edges),
        certificates=len(certificates),
    )
    if counts != expected_counts:
        raise SchemaError("callsite preservation counts are inconsistent")

    return CallsitePreservationArtifact(
        status=status,
        summaries=summaries,
        certificates=certificates,
        proposal_edges=proposal_edges,
        counts=counts,
        trust=trust,
    )


def validate_callsite_preservation_artifact(
    value: Any,
    *,
    region_count: int | None = None,
) -> CallsitePreservationArtifact:
    if isinstance(value, CallsitePreservationArtifact):
        value = _artifact_payload(value)
    return parse_callsite_preservation_artifact(value, region_count=region_count)


def _certificate_payload(certificate: CallsiteCertificate) -> dict[str, Any]:
    return {
        "format": CALLSITE_PRESERVATION_CERTIFICATE_FORMAT,
        "callsite_id": certificate.callsite_id,
        "callee_entry": certificate.callee_entry,
        "requested_relations": [
            _relation_payload(relation)
            for relation in certificate.requested_relations
        ],
        "reachable_node_ids": list(certificate.reachable_node_ids),
        "reachable_edges": [
            {"source": edge.source, "target": edge.target}
            for edge in certificate.reachable_edges
        ],
        "return_inventory": [{
            "return_node_id": row.return_node_id,
            "continuation_id": row.continuation_id,
        } for row in certificate.return_inventory],
        "behavior_hashes": [{
            "node_id": row.node_id,
            "original": row.original,
            "candidate": row.candidate,
        } for row in certificate.behavior_hashes],
        "nested_dependencies": [{
            "node_id": row.node_id,
            "summary_id": row.summary_id,
            "certificate_hash": row.certificate_hash,
        } for row in certificate.nested_dependencies],
        "cyclic_node_ids": list(certificate.cyclic_node_ids),
        "closure": {
            "finite": certificate.closure.finite,
            "all_reachable_exits_matched": (
                certificate.closure.all_reachable_exits_matched
            ),
            "all_nodes_can_reach_return": (
                certificate.closure.all_nodes_can_reach_return
            ),
            "all_requested_registers_identity_preserved": (
                certificate.closure.all_requested_registers_identity_preserved
            ),
        },
        "id": certificate.id,
        "certificate_hash": certificate.certificate_hash,
    }


def _analysis_payload(analysis: CallsiteAnalysis) -> dict[str, Any]:
    return {
        "format": CALLSITE_PRESERVATION_ANALYSIS_FORMAT,
        "status": analysis.status.value,
        "callsite_id": analysis.callsite_id,
        "reason_codes": list(analysis.reason_codes),
        "issues": [_issue_payload(issue) for issue in analysis.issues],
        "certificate": (
            _certificate_payload(analysis.certificate)
            if analysis.certificate is not None
            else None
        ),
    }


def _artifact_payload(
    artifact: CallsitePreservationArtifact,
) -> dict[str, Any]:
    return {
        "format": artifact.format,
        "status": artifact.status.value,
        "summaries": [{
            "callsite_region_index": summary.callsite_region_index,
            "callee_region_index": summary.callee_region_index,
            "continuation_region_index": summary.continuation_region_index,
            "return_region_indices": list(summary.return_region_indices),
            "requested_relations": [
                _relation_payload(relation)
                for relation in summary.requested_relations
            ],
            "status": summary.status.value,
            "reason_codes": list(summary.reason_codes),
            "analysis": (
                _analysis_payload(summary.analysis)
                if summary.analysis is not None
                else None
            ),
        } for summary in artifact.summaries],
        "certificates": [
            _certificate_payload(certificate)
            for certificate in artifact.certificates
        ],
        "proposal_edges": [{
            "source_region_index": edge.source_region_index,
            "target_region_index": edge.target_region_index,
            "kind": edge.kind,
            "environment_barrier": edge.environment_barrier,
            "proposal_only": edge.proposal_only,
            "certificate_id": edge.certificate_id,
            "certificate_hash": edge.certificate_hash,
            "preserved_import_relations": [
                _relation_payload(relation)
                for relation in edge.preserved_import_relations
            ],
            "return_region_indices": list(edge.return_region_indices),
        } for edge in artifact.proposal_edges],
        "counts": {
            "call_summaries": artifact.counts.call_summaries,
            "satisfied": artifact.counts.satisfied,
            "incomplete": artifact.counts.incomplete,
            "not_applicable": artifact.counts.not_applicable,
            "proposal_edges": artifact.counts.proposal_edges,
            "certificates": artifact.counts.certificates,
        },
        "trust": {
            "role": artifact.trust.role,
            "acceptance_authority": artifact.trust.acceptance_authority,
            "required_replay": artifact.trust.required_replay,
        },
    }


def serialize_callsite_preservation_artifact(
    artifact: CallsitePreservationArtifact,
) -> dict[str, Any]:
    """Validate and serialize an artifact without changing its v1 wire shape."""
    payload = _artifact_payload(artifact)
    parse_callsite_preservation_artifact(payload)
    return payload


def callsite_preservation_artifact_hash(
    value: CallsitePreservationArtifact | Mapping[str, Any],
    *,
    region_count: int | None = None,
) -> str:
    artifact = (
        value
        if isinstance(value, CallsitePreservationArtifact)
        else parse_callsite_preservation_artifact(value, region_count=region_count)
    )
    return _sha256(serialize_callsite_preservation_artifact(artifact))
