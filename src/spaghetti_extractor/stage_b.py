"""Candidate-only validation and repair feedback.

This module deliberately has no binary-equivalence proof authority.  It binds a
candidate build to its generated sources, compares static evidence with the
original-only reference contract, and incorporates curated candidate-only
behavior tests.  The result is an assurance status and a ranked repair list.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Any

from .contract_tools import (
    REFERENCE_CONTRACT_MODEL_ID,
    stage_b_audit_contract,
    stage_b_check_contract,
)
from .ghidra import DEFAULT_GHIDRA_SCRIPT, _resolve_analyze_headless, _resolve_script_path
from .stage_binary import StageAInputError
from .util import sha256_file, utc_now, write_json


def _load_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise StageAInputError(f"cannot read JSON artifact {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise StageAInputError(f"JSON artifact must be an object: {path}")
    return value


def _artifact(path: Path) -> dict[str, Any]:
    path = Path(path)
    return {"path": str(path), "sha256": sha256_file(path)}


def stage_b_export_decompiler(
    *,
    original: Path,
    target_name: str,
    out: Path,
    analyze_headless: str | None = None,
    script_path: Path | None = None,
    project_dir: Path | None = None,
    project_name: str = "stage-b-decompiler-export",
    timeout_seconds: int | None = None,
) -> dict[str, Any]:
    """Run the optional Ghidra proposal exporter without granting it authority."""

    original = Path(original)
    if not original.is_file():
        raise StageAInputError(f"decompiler input is not available: {original}")
    out = Path(out)
    out.mkdir(parents=True, exist_ok=True)
    project_dir = Path(project_dir) if project_dir is not None else out / "ghidra-projects"
    project_dir.mkdir(parents=True, exist_ok=True)
    executable = _resolve_analyze_headless(analyze_headless)
    scripts = _resolve_script_path(script_path)
    export = out / "ghidra-export.json"
    command = [
        executable,
        str(project_dir),
        f"{project_name}-{target_name}",
        "-import",
        str(original),
        "-scriptPath",
        str(scripts),
        "-postScript",
        DEFAULT_GHIDRA_SCRIPT,
        str(export),
        sha256_file(original),
        "-deleteProject",
    ]
    completed = subprocess.run(
        command,
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=timeout_seconds,
    )
    (out / "stdout.txt").write_text(completed.stdout, encoding="utf-8")
    (out / "stderr.txt").write_text(completed.stderr, encoding="utf-8")
    status = "qualified" if completed.returncode == 0 and export.is_file() else "incomplete"
    result = {
        "format": "stage-b-decompiler-export-v2",
        "status": status,
        "authority": "untrusted-proposal",
        "target_name": target_name,
        "original": _artifact(original),
        "command": command,
        "returncode": completed.returncode,
        "export": _artifact(export) if export.is_file() else None,
    }
    write_json(out / "report.json", result)
    return result


def _provenance_issues(
    *,
    provenance: dict[str, Any],
    skeleton: dict[str, Any],
    target_name: str,
    candidate: Path,
    skeleton_manifest: Path,
) -> list[dict[str, Any]]:
    issues: list[dict[str, Any]] = []
    if skeleton.get("format") != "stage-b-skeleton-v1":
        issues.append({"category": "invalid_skeleton", "message": "unsupported skeleton manifest"})
    if skeleton.get("target_name") != target_name:
        issues.append({"category": "target_mismatch", "message": "skeleton target does not match"})
    if provenance.get("format") != "stage-b-candidate-provenance-v1":
        issues.append({"category": "invalid_provenance", "message": "unsupported candidate provenance"})
    if provenance.get("target_name") != target_name:
        issues.append({"category": "target_mismatch", "message": "candidate provenance target does not match"})
    if provenance.get("skeleton_manifest_sha256") != sha256_file(skeleton_manifest):
        issues.append({"category": "stale_provenance", "message": "skeleton hash does not match provenance"})
    build = provenance.get("build") if isinstance(provenance.get("build"), dict) else {}
    if build.get("output_sha256") != sha256_file(candidate):
        issues.append({"category": "stale_candidate", "message": "candidate hash does not match provenance"})
    return issues


def _functional_issues(payload: dict[str, Any] | None) -> list[dict[str, Any]]:
    if payload is None:
        return []
    if payload.get("format") != "stage-b-functional-report-v1":
        return [{"category": "invalid_functional_report", "message": "unsupported functional report"}]
    serialized = json.dumps(payload, sort_keys=True).lower()
    if '"original"' in serialized:
        return [{"category": "original_runtime_evidence", "message": "functional evidence must be candidate-only"}]
    if payload.get("status") != "pass":
        return [{"category": "functional_failure", "message": "candidate-only functional suite failed"}]
    return []


def stage_b_validate_candidate(
    *,
    candidate: Path,
    linker_map_candidate: Path,
    skeleton_manifest: Path,
    candidate_provenance: Path,
    target_name: str,
    out: Path,
    functional_report: Path | None = None,
    reference_contract: Path,
    model: str = REFERENCE_CONTRACT_MODEL_ID,
    require_functional_evidence: bool = False,
) -> dict[str, Any]:
    """Produce an assurance result without executing the original binary."""

    out = Path(out)
    out.mkdir(parents=True, exist_ok=True)
    candidate = Path(candidate)
    skeleton_manifest = Path(skeleton_manifest)
    provenance_path = Path(candidate_provenance)
    skeleton = _load_json(skeleton_manifest)
    provenance = _load_json(provenance_path)
    functional = _load_json(Path(functional_report)) if functional_report is not None else None
    issues = _provenance_issues(
        provenance=provenance,
        skeleton=skeleton,
        target_name=target_name,
        candidate=candidate,
        skeleton_manifest=skeleton_manifest,
    )
    issues.extend(_functional_issues(functional))
    if require_functional_evidence and functional is None:
        issues.append({"category": "missing_functional_evidence", "message": "candidate-only functional evidence is required"})
    static = stage_b_check_contract(
        reference_contract=Path(reference_contract),
        candidate=candidate,
        linker_map_candidate=Path(linker_map_candidate),
        skeleton_manifest=skeleton_manifest,
        model=model,
        out=out / "static-contract",
    )
    if any(item.get("category") in {"functional_failure", "stale_candidate", "stale_provenance"} for item in issues):
        status = "violated"
    elif issues:
        status = "incomplete"
    else:
        status = str(static.get("status") or "incomplete")
    result = {
        "format": "stage-b-candidate-assurance-v2",
        "status": status,
        "generated_at": utc_now(),
        "target_name": target_name,
        "authority": "static-contract-plus-candidate-only-tests",
        "executes_original_binary": False,
        "reference_contract": _artifact(Path(reference_contract)),
        "candidate": _artifact(candidate),
        "skeleton_manifest": _artifact(skeleton_manifest),
        "candidate_provenance": _artifact(provenance_path),
        "static_contract": static,
        "functional": functional,
        "issues": issues,
        "counts": {"issues": len(issues), "static_issues": int(static.get("counts", {}).get("issues", 0))},
    }
    write_json(out / "candidate-assurance.json", result)
    return result


def stage_b_extract_candidate_crash(
    *, functional_report: Path, out: Path, candidate: Path | None = None
) -> dict[str, Any]:
    report = _load_json(Path(functional_report))
    failures = [
        case for case in report.get("cases", [])
        if isinstance(case, dict) and case.get("status") not in {"pass", "skipped"}
    ]
    result = {
        "format": "stage-b-candidate-failure-report-v2",
        "status": "violated" if failures else "qualified",
        "candidate": _artifact(Path(candidate)) if candidate is not None else None,
        "functional_report": _artifact(Path(functional_report)),
        "failures": failures,
    }
    write_json(Path(out), result)
    return result


def stage_b_explain_delta(
    *,
    reference_contract: Path,
    candidate: Path,
    linker_map_candidate: Path,
    skeleton_manifest: Path,
    out: Path,
    unit_contract_dir: Path | None = None,
    candidate_crash_report: Path | None = None,
    candidate_probe_report: Path | None = None,
    functional_report: Path | None = None,
    candidate_modules: list[dict[str, Any]] | None = None,
    model: str = REFERENCE_CONTRACT_MODEL_ID,
    contract_candidate_validation: dict[str, Any] | Path | None = None,
    focus: str | None = None,
    focused_only: bool = False,
    embed_contract_candidate_validation: bool = True,
) -> dict[str, Any]:
    """Rank contract gaps using static and optional candidate-only evidence."""

    del candidate_probe_report, candidate_modules, embed_contract_candidate_validation
    out = Path(out)
    out.mkdir(parents=True, exist_ok=True)
    if isinstance(contract_candidate_validation, dict):
        validation = contract_candidate_validation
    elif contract_candidate_validation is not None:
        validation = _load_json(Path(contract_candidate_validation))
    else:
        validation = stage_b_check_contract(
            reference_contract=Path(reference_contract),
            candidate=Path(candidate),
            linker_map_candidate=Path(linker_map_candidate),
            skeleton_manifest=Path(skeleton_manifest),
            model=model,
            out=out / "static-contract",
        )
    audit = stage_b_audit_contract(
        reference_contract=Path(reference_contract),
        out=out / "audit",
        contract_candidate_validation=None,
        candidate=Path(candidate),
        linker_map_candidate=Path(linker_map_candidate),
        skeleton_manifest=Path(skeleton_manifest),
        candidate_crash_report=Path(candidate_crash_report) if candidate_crash_report else None,
        unit_contract_dir=Path(unit_contract_dir) if unit_contract_dir else None,
        model=model,
    )
    items = [item for item in audit.get("findings", []) if isinstance(item, dict)]
    if functional_report is not None:
        functional = _load_json(Path(functional_report))
        items.extend(_functional_issues(functional))
    if focus is not None:
        focus_lower = focus.lower()
        focused = [item for item in items if focus_lower in json.dumps(item, sort_keys=True).lower()]
        if focused_only:
            items = focused
    status = "violated" if any(item.get("severity") == "violated" or item.get("category") == "functional_failure" for item in items) else ("incomplete" if items else "qualified")
    result = {
        "format": "stage-b-delta-explanation-v2",
        "status": status,
        "reference_contract": _artifact(Path(reference_contract)),
        "candidate": _artifact(Path(candidate)),
        "candidate_contract_status": validation.get("status"),
        "repair_items": items,
        "counts": {
            "repair_items": len(items),
            "by_family": _count(items, "family"),
            "by_category": _count(items, "category"),
        },
    }
    write_json(out / "stage-b-delta.json", result)
    return result


def _count(items: list[dict[str, Any]], field: str) -> dict[str, int]:
    counts: dict[str, int] = {}
    for item in items:
        key = str(item.get(field) or "unknown")
        counts[key] = counts.get(key, 0) + 1
    return dict(sorted(counts.items()))


def stage_b_diff_delta(*, before: Path, after: Path, out: Path) -> dict[str, Any]:
    old = _load_json(Path(before))
    new = _load_json(Path(after))
    old_items = {json.dumps(item, sort_keys=True): item for item in old.get("repair_items", []) if isinstance(item, dict)}
    new_items = {json.dumps(item, sort_keys=True): item for item in new.get("repair_items", []) if isinstance(item, dict)}
    result = {
        "format": "stage-b-delta-diff-v2",
        "status": "qualified",
        "resolved": [old_items[key] for key in sorted(set(old_items) - set(new_items))],
        "new": [new_items[key] for key in sorted(set(new_items) - set(old_items))],
        "unchanged": [new_items[key] for key in sorted(set(old_items) & set(new_items))],
    }
    write_json(Path(out), result)
    return result


__all__ = [
    "stage_b_diff_delta",
    "stage_b_explain_delta",
    "stage_b_export_decompiler",
    "stage_b_extract_candidate_crash",
    "stage_b_validate_candidate",
]
