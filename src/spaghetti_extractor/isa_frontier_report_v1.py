"""Compact, non-authorizing diagnostics for exact ISA form frontiers."""

from __future__ import annotations

import argparse
import json
import re
from collections import Counter
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from .artifact_set_v3 import canonical_json_bytes_v3
from .machine_ir_isa_requirements_v2 import (
    parse_machine_ir_isa_requirements_v2,
)
from .isa_kernel_selection import ISA_KERNEL_SELECTION_AUTHORITY_FORMAT


ISA_FRONTIER_REPORT_V1_FORMAT = "spaghetti-extractor-isa-frontier-report-v1"


class ISAFrontierReportV1Error(ValueError):
    """The diagnostic inputs are malformed, stale, or contradictory."""


def _sequence(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def _object(value: Any, label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise ISAFrontierReportV1Error(f"{label} must be an object")
    return value


def _digest(value: Any, label: str) -> str:
    if (
        not isinstance(value, str)
        or re.fullmatch(r"[0-9a-f]{64}", value) is None
    ):
        raise ISAFrontierReportV1Error(f"{label} must be a lowercase SHA-256")
    return value


def _selection_summary(
    authority: Mapping[str, Any],
) -> Mapping[str, Any] | None:
    evidence = authority.get("evidence")
    selection_binding = (
        evidence.get("binary_kernel_selection")
        if isinstance(evidence, Mapping)
        else None
    )
    selection = (
        selection_binding.get("artifact")
        if isinstance(selection_binding, Mapping)
        else None
    )
    if selection is None:
        return None
    return _object(selection, "binary ISA selection summary")


def _next_action(status: str, issue_codes: Sequence[str]) -> str:
    if "oracle_dispute_veto" in issue_codes:
        return (
            "reproduce the listed corpus cases and correct the oracle adapter "
            "or architectural definedness rule; if the external "
            "implementations genuinely disagree, add an independent pinned "
            "oracle that resolves the disputed fields"
        )
    if status == "vetoed":
        return (
            "correct the Lean semantics or decoder for the listed form, then "
            "rerun its cached conformance shard"
        )
    return (
        "supply complete, non-disputed Bochs, Unicorn, and Lean evidence for "
        "this exact semantic form"
    )


def build_isa_frontier_report_v1(
    *,
    requirements_payload: Mapping[str, Any],
    selection_authority_payload: Mapping[str, Any],
) -> dict[str, Any]:
    """Build a source-located repair view without changing ISA authority."""

    try:
        requirements = parse_machine_ir_isa_requirements_v2(requirements_payload)
    except ValueError as exc:
        raise ISAFrontierReportV1Error(
            f"cannot replay ISA frontier inputs: {exc}"
        ) from exc
    if selection_authority_payload.get("format") != (
        ISA_KERNEL_SELECTION_AUTHORITY_FORMAT
    ):
        raise ISAFrontierReportV1Error("ISA selection authority format is invalid")
    authority_binary = _object(
        _object(
            selection_authority_payload.get("requirements"),
            "ISA selection requirements",
        ).get("binary"),
        "ISA selection binary",
    )
    if authority_binary.get("sha256") != requirements.binary_sha256:
        raise ISAFrontierReportV1Error(
            "ISA selection authority and requirements bind different PE bytes"
        )
    authority_status = selection_authority_payload.get("status")
    if authority_status not in {"qualified", "incomplete", "violated"}:
        raise ISAFrontierReportV1Error("ISA selection authority status is invalid")
    authority_sha256 = _digest(
        selection_authority_payload.get("authority_sha256"),
        "ISA selection authority digest",
    )
    requirements_sha256 = _digest(
        requirements.payload.get("requirements_sha256"),
        "ISA requirements digest",
    )

    occurrences = _sequence(requirements.payload.get("occurrences"))
    occurrence_counts = Counter(
        str(row["form_id"])
        for row in occurrences
        if isinstance(row, Mapping) and isinstance(row.get("form_id"), str)
    )
    requirements_by_form = {row.form_id: row for row in requirements.forms}
    required_form_ids = sorted(requirements_by_form)
    selection = _selection_summary(selection_authority_payload)
    selected_by_form: dict[str, Mapping[str, Any]] = {}
    if selection is not None:
        selected_binary = _object(selection.get("binary"), "selected ISA binary")
        if selected_binary.get("sha256") != requirements.binary_sha256:
            raise ISAFrontierReportV1Error(
                "binary ISA selection and requirements bind different PE bytes"
            )
        if (
            sorted(_sequence(selection.get("required_form_ids")))
            != required_form_ids
        ):
            raise ISAFrontierReportV1Error(
                "binary ISA selection has a different required-form inventory"
            )
        for raw in _sequence(selection.get("selected_forms")):
            row = _object(raw, "selected ISA form")
            form_id = row.get("form_id")
            if not isinstance(form_id, str) or form_id in selected_by_form:
                raise ISAFrontierReportV1Error(
                    "binary ISA selection form IDs are malformed or duplicated"
                )
            selected_by_form[form_id] = row
        if sorted(selected_by_form) != required_form_ids:
            raise ISAFrontierReportV1Error(
                "binary ISA selection omits or adds a required form"
            )
    issues_by_form: dict[str, list[Mapping[str, Any]]] = {}
    global_issues: list[Mapping[str, Any]] = []
    for raw_issue in _sequence(selection_authority_payload.get("issues")):
        issue = _object(raw_issue, "ISA selection issue")
        form_id = issue.get("form_id")
        if isinstance(form_id, str):
            issues_by_form.setdefault(form_id, []).append(issue)
        else:
            global_issues.append(issue)
    frontiers: list[dict[str, Any]] = []
    for form_id in required_form_ids:
        requirement = requirements_by_form[form_id]
        selected = selected_by_form.get(form_id)
        status = "incomplete" if selected is None else selected.get("status")
        if status not in {"qualified", "incomplete", "disputed", "vetoed"}:
            raise ISAFrontierReportV1Error(
                f"ISA form {form_id!r} has an invalid selection status"
            )
        if selected is not None:
            if selected.get("semantic_form") != requirement.semantic_form:
                raise ISAFrontierReportV1Error(
                    f"ISA form {form_id!r} has contradictory semantics"
                )
            selected_locations = _sequence(selected.get("source_locations"))
            expected_locations = [
                {
                    "image_id": row.image_id,
                    "image_sha256": row.image_sha256,
                    "rva": row.rva,
                    "byte_length": row.byte_length,
                }
                for row in requirement.source_locations
            ]
            if selected_locations != expected_locations:
                raise ISAFrontierReportV1Error(
                    f"ISA form {form_id!r} has contradictory source locations"
                )
        if status == "qualified":
            continue
        issues = issues_by_form.get(form_id, [])
        diagnostics = (
            [] if selected is None else _sequence(selected.get("diagnostics"))
        )
        issue_codes = sorted(
            {
                str(row["code"])
                for row in issues
                if isinstance(row.get("code"), str)
            }
        )
        frontiers.append(
            {
                "form_id": form_id,
                "semantic_form": requirement.semantic_form,
                "status": status,
                "occurrences": occurrence_counts[form_id],
                "source_locations": [
                    {
                        "image_id": row.image_id,
                        "image_sha256": row.image_sha256,
                        "rva": row.rva,
                        "byte_length": row.byte_length,
                    }
                    for row in requirement.source_locations
                ],
                "issue_codes": issue_codes,
                "mismatch_fields": sorted(
                    {
                        str(row["json_path"])
                        for row in diagnostics
                        if isinstance(row.get("json_path"), str)
                    }
                ),
                "diagnostic_examples": [
                    {
                        key: row[key]
                        for key in (
                            "case_id",
                            "code",
                            "json_path",
                            "expected",
                            "observed",
                            "reference_backend_id",
                            "observed_backend_id",
                        )
                        if key in row
                    }
                    for row in sorted(
                        diagnostics,
                        key=lambda item: (
                            str(item.get("json_path", "")),
                            str(item.get("case_id", "")),
                        ),
                    )[:8]
                ],
                "next_action": _next_action(status, issue_codes),
            }
        )

    return {
        "format": ISA_FRONTIER_REPORT_V1_FORMAT,
        "status": authority_status,
        "binary": {
            "id": authority_binary.get("id"),
            "sha256": requirements.binary_sha256,
        },
        "requirements_sha256": requirements_sha256,
        "selection_authority_sha256": authority_sha256,
        "kernel": dict(
            _object(selection_authority_payload.get("kernel"), "ISA kernel")
        ),
        "counts": {
            "forms": len(required_form_ids),
            "qualified_forms": sum(
                row.get("status") == "qualified"
                for row in selected_by_form.values()
            ),
            "frontier_forms": len(frontiers),
            "frontier_occurrences": sum(
                row["occurrences"] for row in frontiers
            ),
            "global_issues": len(global_issues),
        },
        "frontiers": frontiers,
        "global_issues": global_issues,
        "trust": {
            "diagnostic_only": True,
            "selection_authority_checked_by_producer": True,
            "full_oracle_corpus_replayed_here": False,
            "changes_isa_selection": False,
            "authorizes_candidate_generation": False,
            "original_binary_executed": False,
        },
    }


def _load(path: Path, label: str) -> Mapping[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ISAFrontierReportV1Error(f"cannot read {label}: {exc}") from exc
    if not isinstance(value, Mapping):
        raise ISAFrontierReportV1Error(f"{label} must be an object")
    return value


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--requirements", type=Path, required=True)
    parser.add_argument("--selection-authority", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args(argv)
    report = build_isa_frontier_report_v1(
        requirements_payload=_load(args.requirements, "ISA requirements"),
        selection_authority_payload=_load(
            args.selection_authority, "ISA selection authority"
        ),
    )
    args.out.write_bytes(canonical_json_bytes_v3(report))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = [
    "ISA_FRONTIER_REPORT_V1_FORMAT",
    "ISAFrontierReportV1Error",
    "build_isa_frontier_report_v1",
]
