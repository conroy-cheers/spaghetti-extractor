"""Recomputing final audit for strict static-hybrid v2 authority.

The audit is intentionally small. It does not accept copied completion bits:
it replays the static authority report, parses the exact authority bundle, and
binds both to the submitted machine IR and manifest bytes.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Mapping

from .hybrid_authority_v2 import (
    AUTHORITY_BUNDLE_FORMAT,
    AuthorityBundle,
    AuthorityDataError,
    canonical_json_bytes,
)
from .artifact_formats import STATIC_HYBRID_FINAL_AUDIT_V2_FORMAT
from .static_hybrid_authority_v2 import (
    StaticHybridAuthorityV2Error,
    validate_static_hybrid_authority_v2,
)
from .util import write_json


FINAL_AUDIT_POLICY = {
    "v2_authority_is_only_candidate_authority": True,
    "tainted_accepted_facts_forbidden": True,
    "deferred_transfers_forbidden": True,
}


class StaticHybridFinalAuditV2Error(ValueError):
    """The final audit artifact or one of its exact inputs is malformed."""


def build_static_hybrid_final_audit_v2(
    *,
    static_authority: Path | str | Mapping[str, Any],
    authority_bundle: Path | str | Mapping[str, Any] | AuthorityBundle,
    machine_ir: Path | str,
    machine_ir_manifest: Path | str,
) -> dict[str, Any]:
    findings: list[dict[str, str]] = []
    diagnostics_payload: Mapping[str, Any] | None = None
    static_payload, static_sha = _load_json(static_authority, "static authority")
    bundle_payload, bundle_sha = _load_bundle(authority_bundle)
    machine_path = Path(machine_ir)
    manifest_path = Path(machine_ir_manifest)

    report: Mapping[str, Any] | None = None
    bundle: AuthorityBundle | None = None
    try:
        report = validate_static_hybrid_authority_v2(static_payload)
    except (StaticHybridAuthorityV2Error, TypeError, ValueError) as exc:
        findings.append(_finding("violated", "static_authority_replay_failed", str(exc)))
    try:
        bundle = AuthorityBundle.parse(bundle_payload)
    except (AuthorityDataError, TypeError, ValueError) as exc:
        findings.append(_finding("violated", "authority_bundle_replay_failed", str(exc)))

    machine_sha = _sha256_file(machine_path, "machine IR")
    manifest_sha = _sha256_file(manifest_path, "machine-IR manifest")
    if report is not None:
        embedded = report.get("authority_bundle")
        if embedded != bundle_payload:
            findings.append(_finding(
                "violated",
                "authority_bundle_binding_mismatch",
                "the static authority report embeds a different authority bundle",
            ))
        diagnostics = report.get("diagnostics")
        blockers = diagnostics.get("blockers") if isinstance(diagnostics, Mapping) else None
        if isinstance(blockers, list):
            diagnostics_payload = _json_value(
                diagnostics, "static authority diagnostics"
            )
        else:
            findings.append(_finding(
                "violated",
                "static_authority_diagnostics_corrupt",
                "the static authority report has no exact blocker inventory",
            ))
        if report.get("status") == "violated":
            findings.append(_finding(
                "violated", "static_authority_violated", "the static authority gate is violated"
            ))
        elif report.get("status") != "complete" or report.get(
            "authorizes_candidate_generation"
        ) is not True:
            findings.append(_finding(
                "incomplete", "static_authority_incomplete", "the static authority gate has not closed"
            ))
    if bundle is not None and not bundle.authorizes:
        findings.append(_finding(
            "violated" if bundle.status.value == "violated" else "incomplete",
            "authority_bundle_not_authorizing",
            "the v2 authority dependency closure does not authorize candidate generation",
        ))

    findings = sorted(
        {json.dumps(row, sort_keys=True): row for row in findings}.values(),
        key=lambda row: (row["status"], row["code"], row["detail"]),
    )
    status = (
        "violated"
        if any(row["status"] == "violated" for row in findings)
        else "incomplete"
        if findings
        else "pass"
    )
    body = {
        "format": STATIC_HYBRID_FINAL_AUDIT_V2_FORMAT,
        "status": status,
        "policy": dict(FINAL_AUDIT_POLICY),
        "authority_bundle": {
            "format": AUTHORITY_BUNDLE_FORMAT,
            "content_id": None if bundle is None else bundle.content_id,
            "artifact_sha256": bundle_sha,
        },
        "machine_ir": {"sha256": machine_sha},
        "machine_ir_manifest": {"sha256": manifest_sha},
        "static_authority": {"artifact_sha256": static_sha},
        # Preserve the exact dependency-aware inventory. Flattening blockers
        # into findings discards their deterministic IDs, blocked_by edges,
        # primary/dependent classification, and frontier identities.
        "diagnostics": diagnostics_payload,
        "findings": findings,
    }
    return {**body, "audit_sha256": _canonical_sha256(body)}


def validate_static_hybrid_final_audit_v2(
    value: Mapping[str, Any],
    *,
    static_authority: Path | str | Mapping[str, Any],
    authority_bundle: Path | str | Mapping[str, Any] | AuthorityBundle,
    machine_ir: Path | str,
    machine_ir_manifest: Path | str,
) -> dict[str, Any]:
    expected = build_static_hybrid_final_audit_v2(
        static_authority=static_authority,
        authority_bundle=authority_bundle,
        machine_ir=machine_ir,
        machine_ir_manifest=machine_ir_manifest,
    )
    observed = _json_value(value, "final audit")
    if observed != expected:
        raise StaticHybridFinalAuditV2Error(
            "final static-hybrid audit is stale or binds different inputs"
        )
    return expected


def write_static_hybrid_final_audit_v2(
    *,
    out: Path | str,
    **kwargs: Any,
) -> dict[str, Any]:
    result = build_static_hybrid_final_audit_v2(**kwargs)
    write_json(Path(out), result)
    return result


def _load_json(
    value: Path | str | Mapping[str, Any], context: str
) -> tuple[Mapping[str, Any], str]:
    if isinstance(value, Mapping):
        payload = _json_value(value, context)
        encoded = canonical_json_bytes(payload)
    else:
        path = Path(value)
        try:
            encoded = path.read_bytes()
            payload = _json_value(json.loads(encoded), context)
        except (OSError, UnicodeError, json.JSONDecodeError, TypeError, ValueError) as exc:
            raise StaticHybridFinalAuditV2Error(f"cannot read {context}: {exc}") from exc
    return payload, hashlib.sha256(encoded).hexdigest()


def _load_bundle(
    value: Path | str | Mapping[str, Any] | AuthorityBundle,
) -> tuple[Mapping[str, Any], str]:
    if isinstance(value, AuthorityBundle):
        payload = value.to_payload()
        encoded = canonical_json_bytes(payload)
        return payload, hashlib.sha256(encoded).hexdigest()
    return _load_json(value, "authority bundle")


def _sha256_file(path: Path, context: str) -> str:
    try:
        return hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError as exc:
        raise StaticHybridFinalAuditV2Error(f"cannot read {context}: {exc}") from exc


def _finding(status: str, code: str, detail: str) -> dict[str, str]:
    return {
        "status": "violated" if status == "violated" else "incomplete",
        "code": code,
        "detail": detail,
    }


def _canonical_sha256(value: Any) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def _json_value(value: Any, context: str) -> Any:
    try:
        return json.loads(canonical_json_bytes(value).decode("ascii"))
    except (TypeError, ValueError) as exc:
        raise StaticHybridFinalAuditV2Error(f"{context} is not canonical JSON: {exc}") from exc


__all__ = [
    "FINAL_AUDIT_POLICY",
    "StaticHybridFinalAuditV2Error",
    "build_static_hybrid_final_audit_v2",
    "validate_static_hybrid_final_audit_v2",
    "write_static_hybrid_final_audit_v2",
]
