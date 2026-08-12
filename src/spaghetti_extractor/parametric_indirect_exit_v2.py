"""Typed root-independent target templates for indirect control exits."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Any, Mapping, Sequence

from .authority_bindings_v2 import (
    AuthorityDataError,
    CanonicalJson,
    IndirectExitBinding,
    UnitBinding,
    canonical_json_bytes,
)


PARAMETRIC_INDIRECT_EXIT_SUMMARY_V2 = (
    "spaghetti-extractor-parametric-indirect-exit-summary-v2"
)
PARAMETRIC_INDIRECT_EXIT_INVENTORY_V2 = (
    "spaghetti-extractor-parametric-indirect-exit-inventory-v2"
)
_REGISTERS = frozenset({"eax", "ebp", "ebx", "ecx", "edi", "edx", "esi", "esp"})
_BINARY_OPS = frozenset({"add32", "sub32", "mul32", "and32"})


@dataclass(frozen=True)
class ParametricIndirectExitSummaryV2:
    """One exact exit expressed relative to a structural callee entry."""

    summary_unit: UnitBinding
    exit_binding: IndirectExitBinding
    status: str
    target_expression: CanonicalJson | None
    dependencies: tuple[str, ...]
    failure_reasons: tuple[str, ...]
    summary_id: str

    def __post_init__(self) -> None:
        if self.summary_unit.binary != self.exit_binding.unit.binary:
            raise AuthorityDataError(
                "parametric indirect-exit bindings name different binaries"
            )
        if self.status not in {"complete", "incomplete"}:
            raise AuthorityDataError(
                "parametric indirect-exit status is unsupported"
            )
        if tuple(sorted(set(self.dependencies))) != self.dependencies or any(
            not _identifier(value, maximum=256) for value in self.dependencies
        ):
            raise AuthorityDataError(
                "parametric indirect-exit dependencies are noncanonical"
            )
        if tuple(sorted(set(self.failure_reasons))) != self.failure_reasons or any(
            not _identifier(value, maximum=128) for value in self.failure_reasons
        ):
            raise AuthorityDataError(
                "parametric indirect-exit failure reasons are noncanonical"
            )
        if self.status == "complete":
            if self.target_expression is None or self.failure_reasons:
                raise AuthorityDataError(
                    "complete parametric indirect-exit summary lacks evidence"
                )
            validate_parametric_target_expression_v2(
                self.target_expression.to_value()
            )
        elif self.target_expression is not None or not self.failure_reasons:
            raise AuthorityDataError(
                "incomplete parametric indirect-exit summary is not fail-closed"
            )
        expected = _summary_id(self.identity_payload())
        if self.summary_id != expected:
            raise AuthorityDataError(
                "parametric indirect-exit summary ID is stale"
            )

    @classmethod
    def complete(
        cls,
        *,
        summary_unit: UnitBinding,
        exit_binding: IndirectExitBinding,
        target_expression: Any,
        dependencies: Sequence[str] = (),
    ) -> "ParametricIndirectExitSummaryV2":
        expression = validate_parametric_target_expression_v2(
            target_expression
        )
        fields = {
            "summary_unit": summary_unit,
            "exit_binding": exit_binding,
            "status": "complete",
            "target_expression": expression,
            "dependencies": tuple(sorted(set(dependencies))),
            "failure_reasons": (),
        }
        return cls(
            **fields,
            summary_id=_summary_id(_identity_payload(**fields)),
        )

    @classmethod
    def incomplete(
        cls,
        *,
        summary_unit: UnitBinding,
        exit_binding: IndirectExitBinding,
        failure_reasons: Sequence[str],
        dependencies: Sequence[str] = (),
    ) -> "ParametricIndirectExitSummaryV2":
        fields = {
            "summary_unit": summary_unit,
            "exit_binding": exit_binding,
            "status": "incomplete",
            "target_expression": None,
            "dependencies": tuple(sorted(set(dependencies))),
            "failure_reasons": tuple(sorted(set(failure_reasons))),
        }
        return cls(
            **fields,
            summary_id=_summary_id(_identity_payload(**fields)),
        )

    def identity_payload(self) -> dict[str, Any]:
        return _identity_payload(
            summary_unit=self.summary_unit,
            exit_binding=self.exit_binding,
            status=self.status,
            target_expression=self.target_expression,
            dependencies=self.dependencies,
            failure_reasons=self.failure_reasons,
        )

    def to_payload(self) -> dict[str, Any]:
        return {
            "format": PARAMETRIC_INDIRECT_EXIT_SUMMARY_V2,
            "id": self.summary_id,
            **self.identity_payload(),
        }

    @classmethod
    def parse(cls, value: Any) -> "ParametricIndirectExitSummaryV2":
        if not isinstance(value, Mapping) or set(value) != {
            "format",
            "id",
            "summary_unit",
            "exit_binding",
            "status",
            "target_expression",
            "dependencies",
            "failure_reasons",
        }:
            raise AuthorityDataError(
                "parametric indirect-exit summary has invalid fields"
            )
        if value.get("format") != PARAMETRIC_INDIRECT_EXIT_SUMMARY_V2:
            raise AuthorityDataError(
                "parametric indirect-exit summary has invalid format"
            )
        dependencies = _string_tuple(value.get("dependencies"), "dependencies")
        failures = _string_tuple(value.get("failure_reasons"), "failure reasons")
        raw_expression = value.get("target_expression")
        expression = (
            None
            if raw_expression is None
            else validate_parametric_target_expression_v2(raw_expression)
        )
        return cls(
            summary_unit=UnitBinding.parse(value.get("summary_unit")),
            exit_binding=IndirectExitBinding.parse(value.get("exit_binding")),
            status=str(value.get("status")),
            target_expression=expression,
            dependencies=dependencies,
            failure_reasons=failures,
            summary_id=str(value.get("id")),
        )


def validate_parametric_target_expression_v2(
    value: Any,
    *,
    finite_alternative_budget: int = 32,
    maximum_nodes: int = 1024,
) -> CanonicalJson:
    """Return canonical JSON after checking the bounded expression language."""

    if finite_alternative_budget <= 0 or maximum_nodes <= 0:
        raise AuthorityDataError(
            "parametric target-expression budgets must be positive"
        )
    nodes = 0

    def visit(raw: Any, depth: int = 0) -> None:
        nonlocal nodes
        nodes += 1
        if nodes > maximum_nodes or depth > 64 or not isinstance(raw, Mapping):
            raise AuthorityDataError(
                "parametric target expression exceeds its structural budget"
            )
        op = raw.get("op")
        if op == "summary_input_register":
            if set(raw) != {"op", "register"} or raw.get("register") not in _REGISTERS:
                raise AuthorityDataError(
                    "parametric register input is malformed"
                )
            return
        if op == "summary_input_stack_word":
            offset = raw.get("offset")
            if (
                set(raw) != {"op", "offset"}
                or not isinstance(offset, int)
                or isinstance(offset, bool)
                or not 4 <= offset <= 0xFFFFFFFF
            ):
                raise AuthorityDataError(
                    "parametric stack input is malformed"
                )
            return
        if op == "constant":
            exact = raw.get("value")
            if (
                set(raw) != {"op", "value", "width"}
                or raw.get("width") != 32
                or not isinstance(exact, int)
                or isinstance(exact, bool)
                or not 0 <= exact <= 0xFFFFFFFF
            ):
                raise AuthorityDataError(
                    "parametric constant is malformed"
                )
            return
        if op == "summary_value":
            if set(raw) != {"op", "value"} or not isinstance(raw.get("value"), Mapping):
                raise AuthorityDataError(
                    "parametric summary value is malformed"
                )
            CanonicalJson.of(raw["value"])
            return
        if op == "load":
            if set(raw) != {"op", "width", "address"} or raw.get("width") != 4:
                raise AuthorityDataError("parametric load is malformed")
            visit(raw.get("address"), depth + 1)
            return
        if op == "finite_alternatives":
            alternatives = raw.get("values")
            if (
                set(raw) != {"op", "values"}
                or not isinstance(alternatives, list)
                or not 1 <= len(alternatives) <= finite_alternative_budget
            ):
                raise AuthorityDataError(
                    "parametric finite alternatives are malformed"
                )
            for alternative in alternatives:
                visit(alternative, depth + 1)
            return
        if op == "neg32":
            if set(raw) != {"op", "arg"}:
                raise AuthorityDataError("parametric negation is malformed")
            visit(raw.get("arg"), depth + 1)
            return
        if op in _BINARY_OPS:
            arguments = raw.get("args")
            if (
                set(raw) != {"op", "args"}
                or not isinstance(arguments, list)
                or len(arguments) != 2
            ):
                raise AuthorityDataError(
                    "parametric binary expression is malformed"
                )
            visit(arguments[0], depth + 1)
            visit(arguments[1], depth + 1)
            return
        raise AuthorityDataError(
            "parametric target expression uses an unsupported operation"
        )

    visit(value)
    return CanonicalJson.of(value)


def build_parametric_indirect_exit_inventory_v2(
    interprocedural: Mapping[str, Any],
) -> dict[str, Any]:
    """Project the exact structural templates from a proposal analysis."""

    call_summaries = interprocedural.get("call_summaries")
    raw_summaries = (
        call_summaries.get("summaries")
        if isinstance(call_summaries, Mapping)
        else None
    )
    if not isinstance(raw_summaries, list):
        raise AuthorityDataError(
            "interprocedural artifact has no call-summary inventory"
        )
    issues: list[dict[str, Any]] = []
    summaries: list[ParametricIndirectExitSummaryV2] = []
    seen: set[tuple[str, str]] = set()
    for raw_summary in raw_summaries:
        if not isinstance(raw_summary, Mapping):
            issues.append({
                "status": "violated",
                "code": "parametric_summary_owner_corrupt",
            })
            continue
        owner = raw_summary.get("target_unit_id")
        inventory = raw_summary.get("parametric_indirect_exits")
        rows = inventory.get("exits") if isinstance(inventory, Mapping) else None
        if not isinstance(owner, str) or not owner or not isinstance(rows, list):
            issues.append({
                "status": "violated",
                "code": "parametric_summary_inventory_corrupt",
                "summary_unit_id": owner,
            })
            continue
        if inventory.get("status") != "complete":
            issues.append({
                "status": "incomplete",
                "code": "parametric_summary_inventory_incomplete",
                "summary_unit_id": owner,
            })
        for raw in rows:
            if not isinstance(raw, Mapping):
                issues.append({
                    "status": "violated",
                    "code": "parametric_summary_row_corrupt",
                    "summary_unit_id": owner,
                })
                continue
            try:
                summary = ParametricIndirectExitSummaryV2.parse(raw)
            except AuthorityDataError:
                issues.append({
                    "status": (
                        "violated"
                        if raw.get("format")
                        == PARAMETRIC_INDIRECT_EXIT_SUMMARY_V2
                        else "incomplete"
                    ),
                    "code": (
                        "parametric_summary_row_corrupt"
                        if raw.get("format")
                        == PARAMETRIC_INDIRECT_EXIT_SUMMARY_V2
                        else "parametric_summary_row_unbound"
                    ),
                    "summary_unit_id": owner,
                })
                continue
            key = (summary.summary_unit.unit_id, summary.exit_binding.exit_id)
            if summary.summary_unit.unit_id != owner or key in seen:
                issues.append({
                    "status": "violated",
                    "code": (
                        "parametric_summary_owner_mismatch"
                        if summary.summary_unit.unit_id != owner
                        else "parametric_summary_subject_duplicated"
                    ),
                    "summary_unit_id": owner,
                    "indirect_exit_id": summary.exit_binding.exit_id,
                })
                continue
            seen.add(key)
            summaries.append(summary)
            if summary.status != "complete":
                issues.append({
                    "status": "incomplete",
                    "code": "parametric_summary_target_incomplete",
                    "summary_unit_id": owner,
                    "indirect_exit_id": summary.exit_binding.exit_id,
                })
    status = (
        "violated"
        if any(issue["status"] == "violated" for issue in issues)
        else "incomplete"
        if issues
        else "complete"
    )
    payloads = [
        summary.to_payload()
        for summary in sorted(summaries, key=lambda row: row.summary_id)
    ]
    return {
        "format": PARAMETRIC_INDIRECT_EXIT_INVENTORY_V2,
        "status": status,
        "source_interprocedural_sha256": hashlib.sha256(
            canonical_json_bytes(interprocedural)
        ).hexdigest(),
        "summaries": payloads,
        "issues": sorted(
            issues,
            key=lambda row: (
                str(row.get("status")),
                str(row.get("code")),
                str(row.get("summary_unit_id")),
                str(row.get("indirect_exit_id")),
            ),
        ),
        "counts": {
            "call_summaries": len(raw_summaries),
            "parametric_summaries": len(payloads),
            "issues": len(issues),
        },
    }


def _identity_payload(
    *,
    summary_unit: UnitBinding,
    exit_binding: IndirectExitBinding,
    status: str,
    target_expression: CanonicalJson | None,
    dependencies: Sequence[str],
    failure_reasons: Sequence[str],
) -> dict[str, Any]:
    return {
        "summary_unit": summary_unit.to_payload(),
        "exit_binding": exit_binding.to_payload(),
        "status": status,
        "target_expression": (
            None if target_expression is None else target_expression.to_value()
        ),
        "dependencies": list(dependencies),
        "failure_reasons": list(failure_reasons),
    }


def _summary_id(payload: Mapping[str, Any]) -> str:
    return "parametric-indirect-exit-v2:" + hashlib.sha256(
        canonical_json_bytes(payload)
    ).hexdigest()


def _identifier(value: Any, *, maximum: int) -> bool:
    return isinstance(value, str) and 0 < len(value) <= maximum


def _string_tuple(value: Any, context: str) -> tuple[str, ...]:
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        raise AuthorityDataError(f"parametric indirect-exit {context} are malformed")
    result = tuple(value)
    if result != tuple(sorted(set(result))):
        raise AuthorityDataError(
            f"parametric indirect-exit {context} are noncanonical"
        )
    return result


__all__ = [
    "PARAMETRIC_INDIRECT_EXIT_INVENTORY_V2",
    "PARAMETRIC_INDIRECT_EXIT_SUMMARY_V2",
    "ParametricIndirectExitSummaryV2",
    "build_parametric_indirect_exit_inventory_v2",
    "validate_parametric_target_expression_v2",
]
