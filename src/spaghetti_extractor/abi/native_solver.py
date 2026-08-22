"""Optional Rust-backed finite-domain ABI equality resolution."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from typing import Any

from .model import AbiFactV1, AbiModelError, canonical_json_bytes
from .solver import PHYSICAL_PROFILE_FIELDS, AbiEqualityConstraintV1


class NativeAbiSolver:
    """Construct canonical Python fact records from bounded native results."""

    def __init__(self, native_module: Any) -> None:
        if getattr(native_module, "ABI_SOLVER_API_VERSION", None) != 1:
            raise RuntimeError("unsupported native ABI-solver API")
        self._native = native_module

    def resolve_facts(
        self,
        *,
        subjects: Mapping[str, str],
        facts: Iterable[AbiFactV1],
        equalities: Iterable[AbiEqualityConstraintV1] = (),
        required_fields: Mapping[str, Iterable[str]] | None = None,
        max_alternatives: int = 16,
        limits: Mapping[str, int] | None = None,
    ) -> tuple[AbiFactV1, ...]:
        """Resolve required subject fields while retaining Python ownership.

        Unknown synthetic inputs materialize required graph nodes without
        widening or otherwise changing the supplied finite domains.
        """

        if max_alternatives < 2:
            raise AbiModelError("ABI alternative budget must be at least two")
        subject_rows = dict(subjects)
        required = {
            subject_id: tuple(sorted(set(fields)))
            for subject_id, fields in (required_fields or {}).items()
        }
        for subject_id in subject_rows:
            required.setdefault(subject_id, PHYSICAL_PROFILE_FIELDS)
        unknown_nodes = tuple(
            AbiFactV1.create(
                subject_id=subject_id,
                field=field,
                status="unknown",
            )
            for subject_id, fields in sorted(required.items())
            for field in fields
        )
        ordered_facts = tuple(
            sorted(
                (*facts, *unknown_nodes),
                key=lambda row: (
                    row.subject_id,
                    row.field,
                    canonical_json_bytes(row.to_payload()),
                ),
            )
        )
        ordered_equalities = tuple(sorted(equalities))
        equality_payloads = []
        for equality in ordered_equalities:
            payload = equality.to_payload()
            payload["evidence_ids"] = sorted(set(equality.evidence_ids))
            equality_payloads.append(payload)
        native_limits = dict(limits or {})
        configured_alternatives = native_limits.setdefault(
            "max_alternatives", max_alternatives
        )
        if configured_alternatives != max_alternatives:
            raise AbiModelError(
                "native max_alternatives conflicts with the solver argument"
            )
        raw = self._native.resolve_abi_equalities(
            subject_rows,
            [fact.to_payload() for fact in ordered_facts],
            equality_payloads,
            native_limits,
        )
        try:
            resolved = tuple(AbiFactV1.parse(row) for row in raw)
        except (TypeError, ValueError) as error:
            raise AbiModelError(
                "native ABI solver returned malformed facts"
            ) from error

        by_key: dict[tuple[str, str], AbiFactV1] = {}
        for fact in resolved:
            key = (fact.subject_id, fact.field)
            if key in by_key:
                raise AbiModelError(
                    "native ABI solver returned a duplicate fact"
                )
            if fact.subject_id not in subject_rows:
                raise AbiModelError(
                    "native ABI solver returned an unknown subject"
                )
            by_key[key] = fact
        expected = tuple(
            (subject_id, field)
            for subject_id, fields in sorted(required.items())
            for field in fields
        )
        if any(key not in by_key for key in expected):
            raise AbiModelError("native ABI solver omitted a required fact")
        return tuple(by_key[key] for key in expected)


def optional_native_abi_solver() -> NativeAbiSolver | None:
    """Return the pinned accelerator when available, otherwise pure Python."""

    try:
        import spaghetti_extractor_native as native
    except ImportError:
        return None
    return NativeAbiSolver(native)


__all__ = ["NativeAbiSolver", "optional_native_abi_solver"]
