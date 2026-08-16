"""Release-scoped identity and boundary hypotheses for library islands."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable

from ..artifacts.formats import LIBRARY_RELEASE_HYPOTHESES_V4_FORMAT
from .v4_record_support import (
    ISSUE_FAMILIES,
    ISSUE_STATUSES,
    STATUSES,
    StrictCodec,
    array,
    canonical_sha256,
    choice,
    fail,
    integer,
    sha256_text,
    stable_id,
    status_from,
    strict_object,
    text,
    text_tuple,
    validate_text_tuple,
)

@dataclass(frozen=True, order=True)
class LibraryIslandIssueV4:
    issue_id: str
    family: str
    status: str
    code: str
    message: str
    location: str

    @property
    def identity_payload(self) -> dict[str, Any]:
        return {
            "family": self.family,
            "status": self.status,
            "code": self.code,
            "message": self.message,
            "location": self.location,
        }

    def __post_init__(self) -> None:
        choice(self.family, ISSUE_FAMILIES, "island issue.family")
        choice(self.status, ISSUE_STATUSES, "island issue.status")
        text(self.code, "island issue.code")
        text(self.message, "island issue.message")
        text(self.location, "island issue.location")
        if self.issue_id != stable_id("library-island-issue-v4", self.identity_payload):
            fail(
                "stale_issue_id",
                "issue ID does not bind its contents",
                "island issue.id",
            )

    @classmethod
    def create(
        cls,
        *,
        family: str,
        status: str,
        code: str,
        message: str,
        location: str,
    ) -> "LibraryIslandIssueV4":
        identity = {
            "family": family,
            "status": status,
            "code": code,
            "message": message,
            "location": location,
        }
        return cls(stable_id("library-island-issue-v4", identity), **identity)

    def to_payload(self) -> dict[str, Any]:
        return {"id": self.issue_id, **self.identity_payload}

    @classmethod
    def from_payload(cls, value: object, location: str) -> "LibraryIslandIssueV4":
        row = strict_object(
            value,
            {"id", "family", "status", "code", "message", "location"},
            location,
        )
        return cls(
            issue_id=text(row["id"], f"{location}.id"),
            family=choice(row["family"], ISSUE_FAMILIES, f"{location}.family"),
            status=choice(row["status"], ISSUE_STATUSES, f"{location}.status"),
            code=text(row["code"], f"{location}.code"),
            message=text(row["message"], f"{location}.message"),
            location=text(row["location"], f"{location}.location"),
        )


@dataclass(frozen=True, order=True)
class LibraryFunctionMatchV4:
    match_id: str
    target_function_id: str
    target_span_start: int
    target_span_end: int
    target_unit_ids: tuple[str, ...]
    catalog_function_id: str
    evidence: tuple[str, ...]
    score: int

    @property
    def identity_payload(self) -> dict[str, Any]:
        return {
            "target_function_id": self.target_function_id,
            "target_span_start": self.target_span_start,
            "target_span_end": self.target_span_end,
            "target_unit_ids": list(self.target_unit_ids),
            "catalog_function_id": self.catalog_function_id,
            "evidence": list(self.evidence),
            "score": self.score,
        }

    def __post_init__(self) -> None:
        text(self.target_function_id, "function match.target_function_id")
        integer(self.target_span_start, "function match.target_span_start", minimum=0)
        integer(self.target_span_end, "function match.target_span_end", minimum=1)
        if self.target_span_end <= self.target_span_start:
            fail(
                "record_value_invalid",
                "target span end must be greater than its start",
                "function match.target_span_end",
            )
        validate_text_tuple(
            self.target_unit_ids, "function match.target_unit_ids", nonempty=True
        )
        text(self.catalog_function_id, "function match.catalog_function_id")
        validate_text_tuple(self.evidence, "function match.evidence", nonempty=True)
        integer(self.score, "function match.score")
        if self.match_id != stable_id("library-function-match-v4", self.identity_payload):
            fail(
                "stale_function_match_id",
                "function match ID does not bind its contents",
                "function match.id",
            )

    @classmethod
    def create(
        cls,
        *,
        target_function_id: str,
        target_span_start: int,
        target_span_end: int,
        target_unit_ids: Iterable[str],
        catalog_function_id: str,
        evidence: Iterable[str],
        score: int,
    ) -> "LibraryFunctionMatchV4":
        identity = {
            "target_function_id": target_function_id,
            "target_span_start": target_span_start,
            "target_span_end": target_span_end,
            "target_unit_ids": list(sorted(set(target_unit_ids))),
            "catalog_function_id": catalog_function_id,
            "evidence": list(sorted(set(evidence))),
            "score": score,
        }
        return cls(
            match_id=stable_id("library-function-match-v4", identity),
            target_function_id=target_function_id,
            target_span_start=target_span_start,
            target_span_end=target_span_end,
            target_unit_ids=tuple(identity["target_unit_ids"]),
            catalog_function_id=catalog_function_id,
            evidence=tuple(identity["evidence"]),
            score=score,
        )

    def to_payload(self) -> dict[str, Any]:
        return {"id": self.match_id, **self.identity_payload}

    @classmethod
    def from_payload(cls, value: object, location: str) -> "LibraryFunctionMatchV4":
        row = strict_object(
            value,
            {
                "id",
                "target_function_id",
                "target_span_start",
                "target_span_end",
                "target_unit_ids",
                "catalog_function_id",
                "evidence",
                "score",
            },
            location,
        )
        return cls(
            match_id=text(row["id"], f"{location}.id"),
            target_function_id=text(
                row["target_function_id"], f"{location}.target_function_id"
            ),
            target_span_start=integer(
                row["target_span_start"], f"{location}.target_span_start", minimum=0
            ),
            target_span_end=integer(
                row["target_span_end"], f"{location}.target_span_end", minimum=1
            ),
            target_unit_ids=text_tuple(
                row["target_unit_ids"], f"{location}.target_unit_ids", nonempty=True
            ),
            catalog_function_id=text(
                row["catalog_function_id"], f"{location}.catalog_function_id"
            ),
            evidence=text_tuple(
                row["evidence"], f"{location}.evidence", nonempty=True
            ),
            score=integer(row["score"], f"{location}.score"),
        )


@dataclass(frozen=True, order=True)
class LibraryReleaseIssueV4:
    issue_id: str
    status: str
    code: str
    message: str
    location: str
    competing_release_ids: tuple[str, ...]

    @property
    def identity_payload(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "code": self.code,
            "message": self.message,
            "location": self.location,
            "competing_release_ids": list(self.competing_release_ids),
        }

    def __post_init__(self) -> None:
        choice(self.status, ISSUE_STATUSES, "release issue.status")
        text(self.code, "release issue.code")
        text(self.message, "release issue.message")
        text(self.location, "release issue.location")
        validate_text_tuple(
            self.competing_release_ids,
            "release issue.competing_release_ids",
            nonempty=True,
        )
        if len(self.competing_release_ids) < 2:
            fail(
                "record_value_invalid",
                "release ambiguity must name at least two releases",
                "release issue.competing_release_ids",
            )
        if self.issue_id != stable_id("library-release-issue-v4", self.identity_payload):
            fail(
                "stale_issue_id",
                "release issue ID does not bind its contents",
                "release issue.id",
            )

    @classmethod
    def create(
        cls,
        *,
        status: str,
        code: str,
        message: str,
        location: str,
        competing_release_ids: Iterable[str],
    ) -> "LibraryReleaseIssueV4":
        identity = {
            "status": status,
            "code": code,
            "message": message,
            "location": location,
            "competing_release_ids": list(sorted(set(competing_release_ids))),
        }
        return cls(
            issue_id=stable_id("library-release-issue-v4", identity),
            status=status,
            code=code,
            message=message,
            location=location,
            competing_release_ids=tuple(identity["competing_release_ids"]),
        )

    def to_payload(self) -> dict[str, Any]:
        return {"id": self.issue_id, **self.identity_payload}

    @classmethod
    def from_payload(cls, value: object, location: str) -> "LibraryReleaseIssueV4":
        row = strict_object(
            value,
            {
                "id",
                "status",
                "code",
                "message",
                "location",
                "competing_release_ids",
            },
            location,
        )
        return cls(
            issue_id=text(row["id"], f"{location}.id"),
            status=choice(row["status"], ISSUE_STATUSES, f"{location}.status"),
            code=text(row["code"], f"{location}.code"),
            message=text(row["message"], f"{location}.message"),
            location=text(row["location"], f"{location}.location"),
            competing_release_ids=text_tuple(
                row["competing_release_ids"],
                f"{location}.competing_release_ids",
                nonempty=True,
            ),
        )


def _canonical_island_issues(
    issues: Iterable[LibraryIslandIssueV4],
) -> tuple[LibraryIslandIssueV4, ...]:
    return tuple(sorted(set(issues), key=lambda issue: issue.issue_id))


def _validate_island_issues(
    issues: tuple[LibraryIslandIssueV4, ...], location: str
) -> None:
    ids = tuple(issue.issue_id for issue in issues)
    if tuple(sorted(set(ids))) != ids:
        fail(
            "record_order_invalid",
            "issues must have unique, canonically sorted IDs",
            location,
        )


def _family_status(
    issues: Iterable[LibraryIslandIssueV4], family: str
) -> str:
    return status_from(issue.status for issue in issues if issue.family == family)


@dataclass(frozen=True)
class LibraryIslandHypothesisV4:
    island_id: str
    target_id: str
    family_id: str
    release_id: str
    target_unit_ids: tuple[str, ...]
    member_ids: tuple[str, ...]
    catalog_function_ids: tuple[str, ...]
    operation_ids: tuple[str, ...]
    matches: tuple[LibraryFunctionMatchV4, ...]
    boundary_edge_ids: tuple[str, ...]
    implementation_ids: tuple[str, ...]
    identity_status: str
    boundary_status: str
    implementation_status: str
    issues: tuple[LibraryIslandIssueV4, ...]
    island_sha256: str

    @property
    def identity_payload(self) -> dict[str, Any]:
        return {
            "target_id": self.target_id,
            "family_id": self.family_id,
            "release_id": self.release_id,
            "target_unit_ids": list(self.target_unit_ids),
            "member_ids": list(self.member_ids),
            "catalog_function_ids": list(self.catalog_function_ids),
            "operation_ids": list(self.operation_ids),
            "match_ids": [match.match_id for match in self.matches],
            "boundary_edge_ids": list(self.boundary_edge_ids),
            "implementation_ids": list(self.implementation_ids),
        }

    @property
    def core_payload(self) -> dict[str, Any]:
        identity = self.identity_payload
        identity.pop("match_ids")
        return {
            "id": self.island_id,
            **identity,
            "matches": [match.to_payload() for match in self.matches],
            "identity_status": self.identity_status,
            "boundary_status": self.boundary_status,
            "implementation_status": self.implementation_status,
            "issues": [issue.to_payload() for issue in self.issues],
        }

    def __post_init__(self) -> None:
        for name, value in (
            ("target_id", self.target_id),
            ("family_id", self.family_id),
            ("release_id", self.release_id),
        ):
            text(value, f"library island.{name}")
        for name, values, nonempty in (
            ("target_unit_ids", self.target_unit_ids, True),
            ("member_ids", self.member_ids, True),
            ("catalog_function_ids", self.catalog_function_ids, True),
            ("operation_ids", self.operation_ids, True),
            ("boundary_edge_ids", self.boundary_edge_ids, False),
            ("implementation_ids", self.implementation_ids, False),
        ):
            validate_text_tuple(values, f"library island.{name}", nonempty=nonempty)
        match_ids = tuple(match.match_id for match in self.matches)
        if not match_ids or tuple(sorted(set(match_ids))) != match_ids:
            fail(
                "record_order_invalid",
                "matches must be nonempty with unique, canonically sorted IDs",
                "library island.matches",
            )
        island_units = set(self.target_unit_ids)
        catalog_functions = set(self.catalog_function_ids)
        for index, match in enumerate(self.matches):
            if not set(match.target_unit_ids) <= island_units:
                fail(
                    "function_match_scope_mismatch",
                    "function match contains units outside the island",
                    f"library island.matches[{index}].target_unit_ids",
                )
            if match.catalog_function_id not in catalog_functions:
                fail(
                    "function_match_scope_mismatch",
                    "matched function is absent from catalog_function_ids",
                    f"library island.matches[{index}].catalog_function_id",
                )
        _validate_island_issues(self.issues, "library island.issues")
        if self.island_id != stable_id("library-island-v4", self.identity_payload):
            fail(
                "stale_island_id",
                "island ID does not bind its identity",
                "library island.id",
            )
        for family, actual in (
            ("identity", self.identity_status),
            ("boundary", self.boundary_status),
            ("implementation", self.implementation_status),
        ):
            choice(actual, STATUSES, f"library island.{family}_status")
            expected = _family_status(self.issues, family)
            if actual != expected:
                fail(
                    "status_evidence_mismatch",
                    f"{family} status must equal {expected!r} from local issues",
                    f"library island.{family}_status",
                )
        sha256_text(self.island_sha256, "library island.island_sha256")
        if self.island_sha256 != canonical_sha256(self.core_payload):
            fail(
                "stale_island_hash",
                "island SHA-256 does not bind its contents",
                "library island.island_sha256",
            )

    @property
    def status(self) -> str:
        return status_from(
            (self.identity_status, self.boundary_status, self.implementation_status)
        )

    @classmethod
    def create(
        cls,
        *,
        target_id: str,
        family_id: str,
        release_id: str,
        target_unit_ids: Iterable[str],
        member_ids: Iterable[str],
        catalog_function_ids: Iterable[str],
        operation_ids: Iterable[str],
        matches: Iterable[LibraryFunctionMatchV4],
        boundary_edge_ids: Iterable[str] = (),
        implementation_ids: Iterable[str] = (),
        issues: Iterable[LibraryIslandIssueV4] = (),
    ) -> "LibraryIslandHypothesisV4":
        units = tuple(sorted(set(target_unit_ids)))
        members = tuple(sorted(set(member_ids)))
        functions = tuple(sorted(set(catalog_function_ids)))
        operations = tuple(sorted(set(operation_ids)))
        canonical_matches = tuple(sorted(set(matches), key=lambda item: item.match_id))
        boundaries = tuple(sorted(set(boundary_edge_ids)))
        implementations = tuple(sorted(set(implementation_ids)))
        canonical_issues = _canonical_island_issues(issues)
        identity = {
            "target_id": target_id,
            "family_id": family_id,
            "release_id": release_id,
            "target_unit_ids": list(units),
            "member_ids": list(members),
            "catalog_function_ids": list(functions),
            "operation_ids": list(operations),
            "match_ids": [match.match_id for match in canonical_matches],
            "boundary_edge_ids": list(boundaries),
            "implementation_ids": list(implementations),
        }
        island_id = stable_id("library-island-v4", identity)
        statuses = {
            family: _family_status(canonical_issues, family)
            for family in ISSUE_FAMILIES
        }
        serialized_identity = dict(identity)
        serialized_identity.pop("match_ids")
        core = {
            "id": island_id,
            **serialized_identity,
            "matches": [match.to_payload() for match in canonical_matches],
            "identity_status": statuses["identity"],
            "boundary_status": statuses["boundary"],
            "implementation_status": statuses["implementation"],
            "issues": [issue.to_payload() for issue in canonical_issues],
        }
        return cls(
            island_id=island_id,
            target_id=target_id,
            family_id=family_id,
            release_id=release_id,
            target_unit_ids=units,
            member_ids=members,
            catalog_function_ids=functions,
            operation_ids=operations,
            matches=canonical_matches,
            boundary_edge_ids=boundaries,
            implementation_ids=implementations,
            identity_status=statuses["identity"],
            boundary_status=statuses["boundary"],
            implementation_status=statuses["implementation"],
            issues=canonical_issues,
            island_sha256=canonical_sha256(core),
        )

    def to_payload(self) -> dict[str, Any]:
        return {**self.core_payload, "island_sha256": self.island_sha256}

    @classmethod
    def from_payload(cls, value: object, location: str) -> "LibraryIslandHypothesisV4":
        fields = {
            "id",
            "target_id",
            "family_id",
            "release_id",
            "target_unit_ids",
            "member_ids",
            "catalog_function_ids",
            "operation_ids",
            "matches",
            "boundary_edge_ids",
            "implementation_ids",
            "identity_status",
            "boundary_status",
            "implementation_status",
            "issues",
            "island_sha256",
        }
        row = strict_object(value, fields, location)
        return cls(
            island_id=text(row["id"], f"{location}.id"),
            target_id=text(row["target_id"], f"{location}.target_id"),
            family_id=text(row["family_id"], f"{location}.family_id"),
            release_id=text(row["release_id"], f"{location}.release_id"),
            target_unit_ids=text_tuple(
                row["target_unit_ids"], f"{location}.target_unit_ids", nonempty=True
            ),
            member_ids=text_tuple(
                row["member_ids"], f"{location}.member_ids", nonempty=True
            ),
            catalog_function_ids=text_tuple(
                row["catalog_function_ids"],
                f"{location}.catalog_function_ids",
                nonempty=True,
            ),
            operation_ids=text_tuple(
                row["operation_ids"], f"{location}.operation_ids", nonempty=True
            ),
            matches=tuple(
                LibraryFunctionMatchV4.from_payload(
                    item, f"{location}.matches[{index}]"
                )
                for index, item in enumerate(array(row["matches"], f"{location}.matches"))
            ),
            boundary_edge_ids=text_tuple(
                row["boundary_edge_ids"], f"{location}.boundary_edge_ids"
            ),
            implementation_ids=text_tuple(
                row["implementation_ids"], f"{location}.implementation_ids"
            ),
            identity_status=choice(
                row["identity_status"], STATUSES, f"{location}.identity_status"
            ),
            boundary_status=choice(
                row["boundary_status"], STATUSES, f"{location}.boundary_status"
            ),
            implementation_status=choice(
                row["implementation_status"],
                STATUSES,
                f"{location}.implementation_status",
            ),
            issues=tuple(
                LibraryIslandIssueV4.from_payload(
                    item, f"{location}.issues[{index}]"
                )
                for index, item in enumerate(array(row["issues"], f"{location}.issues"))
            ),
            island_sha256=sha256_text(
                row["island_sha256"], f"{location}.island_sha256"
            ),
        )


@dataclass(frozen=True)
class LibraryReleaseHypothesesV4:
    hypotheses_id: str
    target_id: str
    family_id: str
    release_id: str
    target_binary_sha256: str
    target_signature_graph_sha256: str
    catalog_search_index_sha256: str
    catalog_release_sha256: str
    islands: tuple[LibraryIslandHypothesisV4, ...]
    issues: tuple[LibraryReleaseIssueV4, ...]
    status: str
    hypotheses_sha256: str

    @property
    def identity_payload(self) -> dict[str, Any]:
        return {
            "target_id": self.target_id,
            "family_id": self.family_id,
            "release_id": self.release_id,
            "target_binary_sha256": self.target_binary_sha256,
            "target_signature_graph_sha256": self.target_signature_graph_sha256,
            "catalog_search_index_sha256": self.catalog_search_index_sha256,
            "catalog_release_sha256": self.catalog_release_sha256,
            "island_ids": [island.island_id for island in self.islands],
        }

    @property
    def core_payload(self) -> dict[str, Any]:
        return {
            "format": LIBRARY_RELEASE_HYPOTHESES_V4_FORMAT,
            "id": self.hypotheses_id,
            "target_id": self.target_id,
            "family_id": self.family_id,
            "release_id": self.release_id,
            "target_binary_sha256": self.target_binary_sha256,
            "target_signature_graph_sha256": self.target_signature_graph_sha256,
            "catalog_search_index_sha256": self.catalog_search_index_sha256,
            "catalog_release_sha256": self.catalog_release_sha256,
            "islands": [island.to_payload() for island in self.islands],
            "issues": [issue.to_payload() for issue in self.issues],
            "status": self.status,
        }

    def __post_init__(self) -> None:
        for name, value in (
            ("target_id", self.target_id),
            ("family_id", self.family_id),
            ("release_id", self.release_id),
        ):
            text(value, f"release hypotheses.{name}")
        for name, value in (
            ("target_binary_sha256", self.target_binary_sha256),
            ("target_signature_graph_sha256", self.target_signature_graph_sha256),
            ("catalog_search_index_sha256", self.catalog_search_index_sha256),
            ("catalog_release_sha256", self.catalog_release_sha256),
        ):
            sha256_text(value, f"release hypotheses.{name}")
        island_ids = tuple(island.island_id for island in self.islands)
        if not island_ids or tuple(sorted(set(island_ids))) != island_ids:
            fail(
                "record_order_invalid",
                "islands must be nonempty with unique, canonically sorted IDs",
                "release hypotheses.islands",
            )
        for index, island in enumerate(self.islands):
            if (
                island.target_id != self.target_id
                or island.family_id != self.family_id
                or island.release_id != self.release_id
            ):
                fail(
                    "island_scope_mismatch",
                    "island belongs to a different target, family, or release",
                    f"release hypotheses.islands[{index}]",
                )
        issue_ids = tuple(issue.issue_id for issue in self.issues)
        if tuple(sorted(set(issue_ids))) != issue_ids:
            fail(
                "record_order_invalid",
                "release issues must have unique, canonically sorted IDs",
                "release hypotheses.issues",
            )
        for index, issue in enumerate(self.issues):
            if self.release_id not in issue.competing_release_ids:
                fail(
                    "release_issue_scope_mismatch",
                    "release ambiguity does not include this release",
                    f"release hypotheses.issues[{index}]",
                )
        expected_status = status_from(
            [island.status for island in self.islands]
            + [issue.status for issue in self.issues]
        )
        choice(self.status, STATUSES, "release hypotheses.status")
        if self.status != expected_status:
            fail(
                "status_evidence_mismatch",
                f"release status must equal {expected_status!r} from its evidence",
                "release hypotheses.status",
            )
        if self.hypotheses_id != stable_id(
            "library-release-hypotheses-v4", self.identity_payload
        ):
            fail(
                "stale_hypotheses_id",
                "hypotheses ID does not bind its release and islands",
                "release hypotheses.id",
            )
        sha256_text(self.hypotheses_sha256, "release hypotheses.hypotheses_sha256")
        if self.hypotheses_sha256 != canonical_sha256(self.core_payload):
            fail(
                "stale_hypotheses_hash",
                "hypotheses SHA-256 does not bind its contents",
                "release hypotheses.hypotheses_sha256",
            )

    @classmethod
    def create(
        cls,
        *,
        target_id: str,
        family_id: str,
        release_id: str,
        target_binary_sha256: str,
        target_signature_graph_sha256: str,
        catalog_search_index_sha256: str,
        catalog_release_sha256: str,
        islands: Iterable[LibraryIslandHypothesisV4],
        issues: Iterable[LibraryReleaseIssueV4] = (),
    ) -> "LibraryReleaseHypothesesV4":
        canonical_islands = tuple(sorted(set(islands), key=lambda item: item.island_id))
        canonical_issues = tuple(sorted(set(issues), key=lambda item: item.issue_id))
        identity = {
            "target_id": target_id,
            "family_id": family_id,
            "release_id": release_id,
            "target_binary_sha256": target_binary_sha256,
            "target_signature_graph_sha256": target_signature_graph_sha256,
            "catalog_search_index_sha256": catalog_search_index_sha256,
            "catalog_release_sha256": catalog_release_sha256,
            "island_ids": [island.island_id for island in canonical_islands],
        }
        hypotheses_id = stable_id("library-release-hypotheses-v4", identity)
        status = status_from(
            [island.status for island in canonical_islands]
            + [issue.status for issue in canonical_issues]
        )
        core = {
            "format": LIBRARY_RELEASE_HYPOTHESES_V4_FORMAT,
            "id": hypotheses_id,
            "target_id": target_id,
            "family_id": family_id,
            "release_id": release_id,
            "target_binary_sha256": target_binary_sha256,
            "target_signature_graph_sha256": target_signature_graph_sha256,
            "catalog_search_index_sha256": catalog_search_index_sha256,
            "catalog_release_sha256": catalog_release_sha256,
            "islands": [island.to_payload() for island in canonical_islands],
            "issues": [issue.to_payload() for issue in canonical_issues],
            "status": status,
        }
        return cls(
            hypotheses_id=hypotheses_id,
            target_id=target_id,
            family_id=family_id,
            release_id=release_id,
            target_binary_sha256=target_binary_sha256,
            target_signature_graph_sha256=target_signature_graph_sha256,
            catalog_search_index_sha256=catalog_search_index_sha256,
            catalog_release_sha256=catalog_release_sha256,
            islands=canonical_islands,
            issues=canonical_issues,
            status=status,
            hypotheses_sha256=canonical_sha256(core),
        )

    def to_payload(self) -> dict[str, Any]:
        return {**self.core_payload, "hypotheses_sha256": self.hypotheses_sha256}

    @classmethod
    def from_payload(cls, value: object, location: str) -> "LibraryReleaseHypothesesV4":
        fields = {
            "format",
            "id",
            "target_id",
            "family_id",
            "release_id",
            "target_binary_sha256",
            "target_signature_graph_sha256",
            "catalog_search_index_sha256",
            "catalog_release_sha256",
            "islands",
            "issues",
            "status",
            "hypotheses_sha256",
        }
        row = strict_object(value, fields, location)
        if row["format"] != LIBRARY_RELEASE_HYPOTHESES_V4_FORMAT:
            fail("wrong_artifact_format", "not V4 release hypotheses", f"{location}.format")
        return cls(
            hypotheses_id=text(row["id"], f"{location}.id"),
            target_id=text(row["target_id"], f"{location}.target_id"),
            family_id=text(row["family_id"], f"{location}.family_id"),
            release_id=text(row["release_id"], f"{location}.release_id"),
            target_binary_sha256=sha256_text(
                row["target_binary_sha256"], f"{location}.target_binary_sha256"
            ),
            target_signature_graph_sha256=sha256_text(
                row["target_signature_graph_sha256"],
                f"{location}.target_signature_graph_sha256",
            ),
            catalog_search_index_sha256=sha256_text(
                row["catalog_search_index_sha256"],
                f"{location}.catalog_search_index_sha256",
            ),
            catalog_release_sha256=sha256_text(
                row["catalog_release_sha256"], f"{location}.catalog_release_sha256"
            ),
            islands=tuple(
                LibraryIslandHypothesisV4.from_payload(
                    item, f"{location}.islands[{index}]"
                )
                for index, item in enumerate(array(row["islands"], f"{location}.islands"))
            ),
            issues=tuple(
                LibraryReleaseIssueV4.from_payload(
                    item, f"{location}.issues[{index}]"
                )
                for index, item in enumerate(array(row["issues"], f"{location}.issues"))
            ),
            status=choice(row["status"], STATUSES, f"{location}.status"),
            hypotheses_sha256=sha256_text(
                row["hypotheses_sha256"], f"{location}.hypotheses_sha256"
            ),
        )


LIBRARY_RELEASE_HYPOTHESES_CODEC_V4 = StrictCodec(
    lambda value: value.to_payload(), LibraryReleaseHypothesesV4.from_payload
)


__all__ = [
    "LIBRARY_RELEASE_HYPOTHESES_CODEC_V4",
    "LIBRARY_RELEASE_HYPOTHESES_V4_FORMAT",
    "LibraryFunctionMatchV4",
    "LibraryIslandHypothesisV4",
    "LibraryIslandIssueV4",
    "LibraryReleaseHypothesesV4",
    "LibraryReleaseIssueV4",
]
