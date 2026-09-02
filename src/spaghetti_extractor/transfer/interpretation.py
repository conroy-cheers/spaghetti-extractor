"""Shared domain coverage contract for canonical transfer operations."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable

from ..artifacts.artifact_set import canonical_sha256_v3
from .model import TransferPlanError
from .operations import (
    EFFECT_OPERATIONS_V2,
    EXPRESSION_OPERATIONS_V2,
    TERMINATOR_OPERATIONS_V2,
)


@dataclass(frozen=True)
class DomainOperationCoverageV2:
    domain: str
    handled_expressions: frozenset[str]
    rejected_expressions: frozenset[str]
    handled_effects: frozenset[str]
    rejected_effects: frozenset[str]
    handled_terminators: frozenset[str]
    rejected_terminators: frozenset[str]

    def __post_init__(self) -> None:
        self._validate_category(
            "expression",
            set(EXPRESSION_OPERATIONS_V2),
            self.handled_expressions,
            self.rejected_expressions,
        )
        self._validate_category(
            "effect",
            set(EFFECT_OPERATIONS_V2),
            self.handled_effects,
            self.rejected_effects,
        )
        self._validate_category(
            "terminator",
            set(TERMINATOR_OPERATIONS_V2),
            self.handled_terminators,
            self.rejected_terminators,
        )

    def _validate_category(
        self,
        category: str,
        registry: set[str],
        handled: frozenset[str],
        rejected: frozenset[str],
    ) -> None:
        overlap = handled & rejected
        missing = registry - handled - rejected
        unknown = (handled | rejected) - registry
        if overlap or missing or unknown:
            raise TransferPlanError(
                f"{self.domain} {category} coverage is not total: "
                f"overlap={sorted(overlap)!r}, missing={sorted(missing)!r}, "
                f"unknown={sorted(unknown)!r}",
                code="transfer_domain_coverage_incomplete",
            )

    def status(self, category: str, operation: str) -> str:
        handled = getattr(self, f"handled_{category}s")
        rejected = getattr(self, f"rejected_{category}s")
        if operation in handled:
            return "handled"
        if operation in rejected:
            return "rejected"
        raise TransferPlanError(
            f"{self.domain} has no {category} coverage for {operation!r}",
            code="transfer_domain_coverage_incomplete",
        )


def total_domain_coverage_v2(
    domain: str,
    *,
    rejected_expressions: Iterable[str] = (),
    rejected_effects: Iterable[str] = (),
    rejected_terminators: Iterable[str] = (),
) -> DomainOperationCoverageV2:
    expression_rejections = frozenset(rejected_expressions)
    effect_rejections = frozenset(rejected_effects)
    terminator_rejections = frozenset(rejected_terminators)
    return DomainOperationCoverageV2(
        domain=domain,
        handled_expressions=frozenset(EXPRESSION_OPERATIONS_V2) - expression_rejections,
        rejected_expressions=expression_rejections,
        handled_effects=frozenset(EFFECT_OPERATIONS_V2) - effect_rejections,
        rejected_effects=effect_rejections,
        handled_terminators=frozenset(TERMINATOR_OPERATIONS_V2)
        - terminator_rejections,
        rejected_terminators=terminator_rejections,
    )


def operation_coverage_matrix_v2(
    domains: Iterable[DomainOperationCoverageV2],
) -> dict[str, Any]:
    rows = tuple(sorted(domains, key=lambda row: row.domain))
    if len({row.domain for row in rows}) != len(rows):
        raise TransferPlanError(
            "transfer operation coverage contains duplicate domains",
            code="transfer_domain_coverage_incomplete",
        )
    operations = []
    registries = (
        ("expression", EXPRESSION_OPERATIONS_V2),
        ("effect", EFFECT_OPERATIONS_V2),
        ("terminator", TERMINATOR_OPERATIONS_V2),
    )
    for category, registry in registries:
        for operation in sorted(registry):
            operations.append({
                "category": category,
                "operation": operation,
                "domains": {
                    row.domain: row.status(category, operation) for row in rows
                },
            })
    core: dict[str, Any] = {
        "format": "spaghetti-extractor-transfer-operation-coverage-v2",
        "status": "complete",
        "authority": "none; missing coverage is a build veto",
        "domain_ids": [row.domain for row in rows],
        "operations": operations,
        "counts": {
            "domains": len(rows),
            "operations": len(operations),
            "rejections": sum(
                status == "rejected"
                for operation in operations
                for status in operation["domains"].values()
            ),
        },
    }
    core["coverage_sha256"] = canonical_sha256_v3(core)
    return core


__all__ = [
    "DomainOperationCoverageV2",
    "operation_coverage_matrix_v2",
    "total_domain_coverage_v2",
]
