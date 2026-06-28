from __future__ import annotations

import json
import re
import shutil
import sqlite3
import subprocess
from pathlib import Path, PurePosixPath
from typing import Any, Iterable

from . import __version__
from .labels import ensure_label, private_artifact_bundle_label, private_artifact_label, slug
from .util import json_dumps, sha256_file, utc_now, write_json
from .workbench import ensure_reimplementation_workbench


PRIVATE_ARTIFACT_FORMAT_VERSION = "wincr-dirty-corpus-v2"
DIRTY_SPEC_SUITE_FORMAT_VERSION = "wincr-dirty-spec-suite-v1"
PRIVATE_ARTIFACT_TAINT_POLICY = {
    "default_taint_level": "dirty_private",
    "publication": "dirty corpus packets are review inputs and must not be published verbatim",
    "taint_levels": {
        "behavioral_dirty": "raw or lightly normalized oracle observations, logs, traces, and fixtures",
        "static_dirty": "static analysis output such as disassembly, xrefs, CFG, strings, imports, and inferred metadata",
        "dirty_private": "mixed private packet content that has not been sanitized for publication",
        "decompiler_high_taint": "optional high-risk decompiler output; never emitted by default and never public",
        "clean_candidate": "human/LLM rewrite target that still needs review before publication",
        "reviewed_public": "reviewed behavioral content eligible for clean public specs/tests",
    },
    "allowed_content": [
        "module hashes and private RVAs",
        "disassembly listings",
        "static CFG/call/data-reference metadata",
        "dynamic trace coverage mapped by module hash and RVA",
        "private oracle and harness evidence",
        "draft routine contracts and unresolved inference notes",
        "per-basic-block disassembly, CFG/coverage context, and clean rewrite templates",
        "private instruction metadata, p-code, decompiler status, and value-trace summaries",
        "offline static HTML and CLI indexes for private review",
        "task-oriented reimplementation plans with private evidence links",
        "dirty spec and test-suite review indexes",
        "per-row dirty review packets for observations, tests, interfaces, and harnesses",
    ],
    "clean_derivation": "public output must be produced from reviewed/sanitized records only",
}

COPYABLE_EVIDENCE_SUFFIXES = {
    ".csv",
    ".err",
    ".json",
    ".jsonl",
    ".log",
    ".md",
    ".out",
    ".stderr",
    ".stdout",
    ".txt",
    ".xml",
    ".yaml",
    ".yml",
}

DIRTY_REVIEW_PACKET_TAINT_LEVELS = {"dirty_private"}
DIRTY_REVIEW_PACKET_STATUSES = {"dirty_unreviewed"}
CLEAN_TEMPLATE_TAINT_LEVELS = {"clean_candidate", "reviewed_public"}
CLEAN_TEMPLATE_REVIEW_STATUSES = {"draft", "reviewed"}
REQUIRED_MODULE_PACKET_FILES = (
    "index.md",
    "static/sections.json",
    "static/imports.json",
    "static/exports.json",
    "static/resources.json",
    "static/functions.json",
    "static/basic-blocks.json",
    "static/cfg-edges.json",
    "static/call-edges.json",
    "static/data-refs.json",
    "static/globals.json",
    "coverage/coverage-blocks.json",
    "coverage/coverage-edges.json",
    "coverage/coverage-call-edges.json",
    "waivers/waivers.json",
    "interfaces/platform-endpoints.json",
)
REQUIRED_ROUTINE_PACKET_FILES = (
    "index.md",
    "static/cfg.json",
    "static/semantics.json",
    "static/decompiler-status.json",
    "static/pcode.json",
    "dynamic/coverage.json",
    "draft/dirty-contract.md",
)
REQUIRED_BLOCK_PACKET_FILES = (
    "index.md",
    "manifest.json",
    "static/context.json",
    "static/disassembly.asm",
    "static/decompiler-status.json",
    "static/instructions.json",
    "static/pcode.json",
    "static/data-flow.json",
    "static/xrefs.json",
    "semantic-summary.md",
    "draft/clean-template.json",
)
OBJDUMP_INSTRUCTION_RE = re.compile(r"^\s*([0-9a-fA-F]+):")


def export_private_artifacts(
    conn: sqlite3.Connection,
    out_dir: Path,
    *,
    artifact_set_id: str | None = None,
    scopes: tuple[str, ...] = ("included", "candidate"),
    include_disassembly: bool = True,
    objdump: str = "llvm-objdump",
    objdump_timeout_seconds: int = 60,
    copy_raw_evidence: bool = True,
    max_raw_evidence_bytes: int = 4 * 1024 * 1024,
    clean: bool = True,
) -> dict[str, Any]:
    metadata = _metadata(conn)
    target_id = metadata.get("target_project_id") or "legacy-halo-ce"
    artifact_id = artifact_set_id or f"{target_id}-dirty-evidence"
    out_dir = out_dir.resolve()
    if clean:
        _clean_artifact_root(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    created_at = utc_now()
    bundle_label = private_artifact_bundle_label(artifact_id, str(out_dir))
    ensure_label(
        conn,
        bundle_label,
        "private_artifact_bundle",
        artifact_id,
        "private dirty clean-room corpus",
        private=True,
        created_at=created_at,
    )
    conn.execute(
        """
        INSERT INTO private_artifact_bundles(
          label, artifact_set_id, root_path, format_version, scopes_json,
          generator_version, created_at, content_manifest_json, summary_json, taint_policy_json
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, '{}', '{}', ?)
        ON CONFLICT(artifact_set_id, root_path) DO UPDATE SET
          format_version = excluded.format_version,
          scopes_json = excluded.scopes_json,
          generator_version = excluded.generator_version,
          created_at = excluded.created_at,
          content_manifest_json = '{}',
          summary_json = '{}',
          taint_policy_json = excluded.taint_policy_json
        """,
        (
            bundle_label,
            artifact_id,
            str(out_dir),
            PRIVATE_ARTIFACT_FORMAT_VERSION,
            json_dumps(list(scopes)),
            __version__,
            created_at,
            json_dumps(PRIVATE_ARTIFACT_TAINT_POLICY),
        ),
    )
    bundle_id = int(
        conn.execute("SELECT id FROM private_artifact_bundles WHERE label = ?", (bundle_label,)).fetchone()["id"]
    )
    conn.execute("DELETE FROM private_artifacts WHERE bundle_id = ?", (bundle_id,))

    artifacts: list[dict[str, Any]] = []

    def add_artifact(
        path: Path,
        *,
        artifact_kind: str,
        entity_label: str | None = None,
        entity_type: str = "artifact",
        binary_id: int | None = None,
        module_sha256: str | None = None,
        rva_start: int | None = None,
        rva_end: int | None = None,
        taint_level: str = "dirty_private",
        source_tool: str = "wincr",
        source_detail: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        artifact = _register_artifact(
            conn,
            bundle_id=bundle_id,
            bundle_label=bundle_label,
            root=out_dir,
            path=path,
            artifact_kind=artifact_kind,
            entity_label=entity_label,
            entity_type=entity_type,
            binary_id=binary_id,
            module_sha256=module_sha256,
            rva_start=rva_start,
            rva_end=rva_end,
            taint_level=taint_level,
            source_tool=source_tool,
            source_detail=source_detail or {},
            created_at=created_at,
        )
        artifacts.append(artifact)
        return artifact

    binaries = _included_binaries(conn, scopes)
    root_summary = _root_summary(conn, scopes)
    root_manifest = {
        "format": PRIVATE_ARTIFACT_FORMAT_VERSION,
        "artifact_role": "private_dirty_corpus",
        "artifact_set_id": artifact_id,
        "generated_at": created_at,
        "generator": {"name": "wincr", "version": __version__},
        "target": {
            "project_id": target_id,
            "project_name": metadata.get("target_project_name", "Windows Target"),
        },
        "scopes": list(scopes),
        "taint_policy": PRIVATE_ARTIFACT_TAINT_POLICY,
        "summary": root_summary,
    }
    manifest_path = out_dir / "manifest.json"
    write_json(manifest_path, root_manifest)
    add_artifact(manifest_path, artifact_kind="bundle_manifest", entity_type="private_artifact_bundle")

    index_path = out_dir / "index.md"
    index_path.write_text(_root_index_markdown(root_manifest), encoding="utf-8")
    add_artifact(index_path, artifact_kind="bundle_index", entity_type="private_artifact_bundle")

    summary_path = out_dir / "catalog-summary.json"
    write_json(summary_path, root_summary)
    add_artifact(summary_path, artifact_kind="catalog_summary", entity_type="catalog")

    _write_root_evidence_packets(conn, out_dir, add_artifact)
    _write_review_packets(
        conn,
        out_dir,
        add_artifact,
        copy_raw_evidence=copy_raw_evidence,
        max_raw_evidence_bytes=max_raw_evidence_bytes,
    )

    for binary in binaries:
        _write_module_packet(
            conn,
            metadata,
            binary,
            out_dir,
            add_artifact,
            include_disassembly=include_disassembly,
            objdump=objdump,
            objdump_timeout_seconds=objdump_timeout_seconds,
        )

    workbench = ensure_reimplementation_workbench(out_dir)
    _register_workbench_artifacts(out_dir, workbench, add_artifact)

    _write_dirty_spec_suite(
        conn,
        out_dir,
        add_artifact,
        root_manifest=root_manifest,
        created_at=created_at,
    )

    content_manifest = {
        "format": PRIVATE_ARTIFACT_FORMAT_VERSION,
        "artifact_role": "private_dirty_corpus_content_manifest",
        "artifact_set_id": artifact_id,
        "bundle_label": bundle_label,
        "root_path": str(out_dir),
        "includes_self": False,
        "artifact_count": len(artifacts),
        "artifacts": sorted(artifacts, key=lambda item: item["path"]),
    }
    content_path = out_dir / "content-manifest.json"
    write_json(content_path, content_manifest)
    add_artifact(content_path, artifact_kind="content_manifest", entity_type="private_artifact_bundle")

    summary = _artifact_summary(artifacts, binaries)
    conn.execute(
        """
        UPDATE private_artifact_bundles
        SET content_manifest_json = ?, summary_json = ?
        WHERE id = ?
        """,
        (json_dumps(content_manifest), json_dumps(summary), bundle_id),
    )
    return {
        "label": bundle_label,
        "artifact_set_id": artifact_id,
        "root_path": str(out_dir),
        "format_version": PRIVATE_ARTIFACT_FORMAT_VERSION,
        "summary": summary,
        "content_manifest": str(content_path),
    }


def _register_workbench_artifacts(out_dir: Path, workbench: dict[str, Any], add_artifact: Any) -> None:
    root_files = [
        (out_dir / "reimplementation-plan.json", "reimplementation_plan_json", "reimplementation_task"),
        (out_dir / "reimplementation-plan.md", "reimplementation_plan_markdown", "reimplementation_task"),
        (out_dir / "cli-index.json", "dirty_corpus_cli_index", "private_artifact_bundle"),
    ]
    for path, kind, entity_type in root_files:
        if path.exists():
            add_artifact(path, artifact_kind=kind, entity_type=entity_type, taint_level="dirty_private")
    html = workbench.get("html") if isinstance(workbench.get("html"), dict) else {}
    for item in html.get("files", []):
        path = Path(str(item))
        if path.exists() and path.is_file() and _is_relative_to(path.resolve(), out_dir):
            add_artifact(
                path,
                artifact_kind="dirty_corpus_review_html",
                entity_type="private_artifact_bundle",
                taint_level="dirty_private",
                source_detail={"workbench": "static_html"},
            )


def _is_relative_to(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
        return True
    except ValueError:
        return False


def validate_dirty_corpus(
    corpus_dir: Path,
    *,
    report_json: Path | None = None,
    report_md: Path | None = None,
) -> dict[str, Any]:
    """Validate a private dirty corpus as the primary review artifact.

    The dirty corpus may contain private oracle identity, raw disassembly,
    absolute evidence paths, and harness details. This validator is not a
    publication sanitizer; it proves that the intermediate artifact is complete
    enough for human/LLM review.
    """

    corpus_dir = corpus_dir.resolve()
    errors: list[str] = []
    warnings: list[str] = []
    manifest = _load_json_object(corpus_dir / "manifest.json", errors, "manifest")
    content_manifest = _load_json_object(corpus_dir / "content-manifest.json", errors, "content manifest")

    if manifest:
        if manifest.get("format") != PRIVATE_ARTIFACT_FORMAT_VERSION:
            errors.append(f"manifest.format must be {PRIVATE_ARTIFACT_FORMAT_VERSION}")
        if manifest.get("artifact_role") != "private_dirty_corpus":
            errors.append("manifest.artifact_role must be private_dirty_corpus")
        if not str(manifest.get("artifact_set_id") or "").strip():
            errors.append("manifest.artifact_set_id is required")
        if not isinstance(manifest.get("taint_policy"), dict):
            errors.append("manifest.taint_policy must be an object")

    artifact_stats = _validate_content_manifest(corpus_dir, content_manifest or {}, errors, warnings)
    root_stats = _validate_dirty_root_files(corpus_dir, errors)
    workbench_stats = _validate_workbench_indexes(corpus_dir, errors, warnings)
    review_stats = _validate_review_packets(corpus_dir, errors, warnings)
    module_stats = _validate_module_packets(corpus_dir, errors, warnings)
    summary = {
        **root_stats,
        **workbench_stats,
        **artifact_stats,
        **review_stats,
        **module_stats,
        "errors": len(errors),
        "warnings": len(warnings),
    }
    result = {
        "status": "pass" if not errors else "fail",
        "format": PRIVATE_ARTIFACT_FORMAT_VERSION,
        "corpus_dir": str(corpus_dir),
        "artifact_set_id": manifest.get("artifact_set_id") if manifest else None,
        "target": manifest.get("target", {}) if manifest else {},
        "summary": summary,
        "errors": errors,
        "warnings": warnings,
    }
    if report_json is not None:
        write_json(report_json, result)
    if report_md is not None:
        report_md.parent.mkdir(parents=True, exist_ok=True)
        report_md.write_text(dirty_corpus_validation_markdown(result), encoding="utf-8")
    return result


def dirty_corpus_validation_markdown(result: dict[str, Any]) -> str:
    summary = result["summary"]
    lines = [
        "# Dirty Corpus Validation",
        "",
        "Private intermediate artifact validation. This report checks reviewability",
        "and evidence integrity; it is not a publication sanitizer.",
        "",
        "## Summary",
        "",
        f"- Status: `{result['status']}`",
        f"- Corpus: `{result['corpus_dir']}`",
        f"- Artifact set: `{result.get('artifact_set_id')}`",
        f"- Content artifacts: {summary.get('content_artifacts', 0)}",
        f"- Review packets: {summary.get('review_packets', 0)}",
        f"- Clean templates: {summary.get('clean_templates', 0)}",
        f"- Module packets: {summary.get('module_packets', 0)}",
        f"- Routine packets: {summary.get('routine_packets', 0)}",
        f"- Basic-block packets: {summary.get('block_packets', 0)} / {summary.get('expected_block_packets', 0)}",
        f"- Errors: {summary.get('errors', 0)}",
        f"- Warnings: {summary.get('warnings', 0)}",
        "",
    ]
    for key, title in (("errors", "Errors"), ("warnings", "Warnings")):
        lines.extend([f"## {title}", ""])
        items = result.get(key, [])
        if not items:
            lines.append("- None.")
        else:
            for item in items[:200]:
                lines.append(f"- {str(item).replace(chr(10), ' ')}")
        lines.append("")
    return "\n".join(lines)


def _load_json_object(path: Path, errors: list[str], description: str) -> dict[str, Any]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        errors.append(f"missing {description}: {path}")
        return {}
    except json.JSONDecodeError as exc:
        errors.append(f"invalid {description} JSON {path}: {exc}")
        return {}
    if not isinstance(data, dict):
        errors.append(f"{description} must be a JSON object: {path}")
        return {}
    return data


def _validate_content_manifest(
    corpus_dir: Path,
    content_manifest: dict[str, Any],
    errors: list[str],
    warnings: list[str],
) -> dict[str, Any]:
    artifacts = content_manifest.get("artifacts", [])
    if not isinstance(artifacts, list):
        errors.append("content-manifest.artifacts must be a list")
        artifacts = []
    if content_manifest.get("format") not in {PRIVATE_ARTIFACT_FORMAT_VERSION, None}:
        errors.append(f"content-manifest.format must be {PRIVATE_ARTIFACT_FORMAT_VERSION}")
    if content_manifest.get("format") is None:
        warnings.append("content-manifest.format is missing")
    if content_manifest.get("artifact_role") not in {"private_dirty_corpus_content_manifest", None}:
        errors.append("content-manifest.artifact_role must be private_dirty_corpus_content_manifest")
    declared_count = content_manifest.get("artifact_count")
    if declared_count is not None and int(declared_count or 0) != len(artifacts):
        errors.append(f"content-manifest.artifact_count={declared_count!r} does not match {len(artifacts)}")

    seen_paths: set[str] = set()
    by_kind: dict[str, int] = {}
    by_taint: dict[str, int] = {}
    for index, artifact in enumerate(artifacts):
        path = f"content-manifest.artifacts[{index}]"
        if not isinstance(artifact, dict):
            errors.append(f"{path} must be an object")
            continue
        for key in ("label", "artifact_kind", "entity_type", "path", "sha256", "size", "taint_level"):
            if key not in artifact:
                errors.append(f"{path}.{key} is required")
        kind = str(artifact.get("artifact_kind") or "")
        taint = str(artifact.get("taint_level") or "")
        by_kind[kind] = by_kind.get(kind, 0) + 1
        by_taint[taint] = by_taint.get(taint, 0) + 1
        if taint not in PRIVATE_ARTIFACT_TAINT_POLICY["taint_levels"]:
            errors.append(f"{path}.taint_level has unknown value {taint!r}")
        rel_path = str(artifact.get("path") or "")
        artifact_path = _safe_corpus_path(corpus_dir, rel_path, errors, path)
        if artifact_path is None:
            continue
        if rel_path in seen_paths:
            errors.append(f"duplicate content artifact path: {rel_path}")
        seen_paths.add(rel_path)
        if not artifact_path.exists():
            errors.append(f"{path}.path is missing on disk: {rel_path}")
            continue
        actual_size = artifact_path.stat().st_size
        recorded_size = artifact.get("size")
        recorded_size_int = int(recorded_size) if recorded_size is not None else -1
        if recorded_size_int != actual_size:
            errors.append(f"{path}.size for {rel_path} does not match disk size {actual_size}")
        expected_sha = str(artifact.get("sha256") or "")
        if expected_sha and sha256_file(artifact_path) != expected_sha:
            errors.append(f"{path}.sha256 for {rel_path} does not match file content")

    return {
        "content_artifacts": len(artifacts),
        "content_artifact_paths": len(seen_paths),
        "content_artifacts_by_kind": by_kind,
        "content_artifacts_by_taint": by_taint,
    }


def _validate_dirty_root_files(corpus_dir: Path, errors: list[str]) -> dict[str, Any]:
    required = (
        "manifest.json",
        "index.md",
        "catalog-summary.json",
        "dirty-specs.json",
        "dirty-specs.md",
        "dirty-tests.json",
        "dirty-tests.md",
        "reimplementation-plan.json",
        "reimplementation-plan.md",
        "cli-index.json",
        "review-html/index.html",
        "review-html/search-index.json",
        "content-manifest.json",
    )
    present = 0
    for rel_path in required:
        if (corpus_dir / rel_path).exists():
            present += 1
        else:
            errors.append(f"missing required dirty corpus root file: {rel_path}")
    return {"root_files": present, "required_root_files": len(required)}


def _validate_workbench_indexes(
    corpus_dir: Path,
    errors: list[str],
    warnings: list[str],
) -> dict[str, Any]:
    plan = _load_json_object(corpus_dir / "reimplementation-plan.json", errors, "reimplementation plan")
    cli_index = _load_json_object(corpus_dir / "cli-index.json", errors, "CLI review index")
    tasks = plan.get("tasks") if isinstance(plan.get("tasks"), list) else []
    labels = cli_index.get("labels") if isinstance(cli_index.get("labels"), dict) else {}
    if plan and plan.get("format") != "wincr-reimplementation-plan-v1":
        errors.append("reimplementation-plan.json.format must be wincr-reimplementation-plan-v1")
    if cli_index and cli_index.get("format") != "wincr-dirty-corpus-cli-index-v1":
        errors.append("cli-index.json.format must be wincr-dirty-corpus-cli-index-v1")
    for index, task in enumerate(tasks):
        if not isinstance(task, dict):
            errors.append(f"reimplementation-plan.json.tasks[{index}] must be an object")
            continue
        if not str(task.get("task_id") or "").strip():
            errors.append(f"reimplementation-plan.json.tasks[{index}].task_id is required")
        links = task.get("private_evidence_links")
        if not isinstance(links, list):
            errors.append(f"reimplementation-plan.json.tasks[{index}].private_evidence_links must be a list")
            continue
        if not links:
            warnings.append(f"reimplementation task {task.get('task_id', index)} has no private evidence links")
        for rel_path in links:
            if not isinstance(rel_path, str):
                errors.append(f"reimplementation task {task.get('task_id', index)} has non-string evidence link")
                continue
            target = _safe_corpus_path(corpus_dir, rel_path, errors, f"reimplementation task {task.get('task_id', index)}")
            if target is not None and not target.exists():
                errors.append(f"reimplementation task {task.get('task_id', index)} points at missing evidence: {rel_path}")
    for label, item in labels.items():
        if not isinstance(item, dict):
            errors.append(f"cli-index label {label} must be an object")
            continue
        rel_path = str(item.get("path") or "")
        if not rel_path:
            warnings.append(f"cli-index label {label} has no path")
            continue
        target = _safe_corpus_path(corpus_dir, rel_path, errors, f"cli-index label {label}")
        if target is not None and not target.exists():
            errors.append(f"cli-index label {label} points at missing path: {rel_path}")
    return {
        "reimplementation_tasks": len(tasks),
        "cli_index_labels": len(labels),
        "html_indexes": 1 if (corpus_dir / "review-html" / "index.html").exists() else 0,
    }


def _validate_review_packets(
    corpus_dir: Path,
    errors: list[str],
    warnings: list[str],
) -> dict[str, Any]:
    review_dir = corpus_dir / "review"
    dirty_paths = sorted(review_dir.glob("*/*/dirty.json")) if review_dir.exists() else []
    clean_templates = sorted(review_dir.glob("*/*/clean-template.json")) if review_dir.exists() else []
    index_files = sorted(review_dir.glob("*/*/index.md")) if review_dir.exists() else []
    evidence_items = 0
    copied_evidence = 0
    for dirty_path in dirty_paths:
        packet = _load_json_object(dirty_path, errors, "dirty review packet")
        rel_dirty = dirty_path.relative_to(corpus_dir).as_posix()
        path_parts = dirty_path.relative_to(review_dir).parts
        category = path_parts[0] if path_parts else ""
        if packet.get("format") != PRIVATE_ARTIFACT_FORMAT_VERSION:
            errors.append(f"{rel_dirty}.format must be {PRIVATE_ARTIFACT_FORMAT_VERSION}")
        if packet.get("packet_kind") != "dirty_review_packet":
            errors.append(f"{rel_dirty}.packet_kind must be dirty_review_packet")
        if packet.get("category") != category:
            errors.append(f"{rel_dirty}.category does not match review directory {category!r}")
        if not str(packet.get("label") or "").strip():
            errors.append(f"{rel_dirty}.label is required")
        if not isinstance(packet.get("row"), dict):
            errors.append(f"{rel_dirty}.row must be an object")
        if packet.get("taint_level") not in DIRTY_REVIEW_PACKET_TAINT_LEVELS:
            errors.append(f"{rel_dirty}.taint_level must be one of {sorted(DIRTY_REVIEW_PACKET_TAINT_LEVELS)}")
        if packet.get("review_status") not in DIRTY_REVIEW_PACKET_STATUSES:
            errors.append(f"{rel_dirty}.review_status must be one of {sorted(DIRTY_REVIEW_PACKET_STATUSES)}")
        template_name = str((packet.get("clean_derivation") or {}).get("template") or "clean-template.json")
        template_path = dirty_path.parent / template_name
        index_path = dirty_path.parent / "index.md"
        if not index_path.exists():
            errors.append(f"{rel_dirty} is missing sibling index.md")
        if not template_path.exists():
            errors.append(f"{rel_dirty} is missing sibling clean template {template_name}")
        else:
            _validate_clean_template_for_dirty_packet(template_path, packet, errors)
        raw_evidence = packet.get("raw_evidence") or []
        if not isinstance(raw_evidence, list):
            errors.append(f"{rel_dirty}.raw_evidence must be a list")
            raw_evidence = []
        for index, item in enumerate(raw_evidence):
            evidence_items += 1
            if not isinstance(item, dict):
                errors.append(f"{rel_dirty}.raw_evidence[{index}] must be an object")
                continue
            if item.get("copied_path"):
                copied_evidence += 1
            _validate_raw_evidence_item(corpus_dir, rel_dirty, index, item, errors, warnings)
    if review_dir.exists() and clean_templates and len(clean_templates) != len(dirty_paths):
        errors.append(
            f"review packet/template count mismatch: dirty={len(dirty_paths)} clean_templates={len(clean_templates)}"
        )
    if review_dir.exists() and index_files and len(index_files) != len(dirty_paths):
        errors.append(f"review packet/index count mismatch: dirty={len(dirty_paths)} indexes={len(index_files)}")
    if not review_dir.exists():
        warnings.append("dirty corpus has no review/ directory")
    elif not dirty_paths:
        warnings.append("dirty corpus has no dirty review packets")
    return {
        "review_packets": len(dirty_paths),
        "clean_templates": len(clean_templates),
        "review_indexes": len(index_files),
        "raw_evidence_items": evidence_items,
        "copied_raw_evidence_items": copied_evidence,
    }


def _validate_clean_template_for_dirty_packet(
    template_path: Path,
    packet: dict[str, Any],
    errors: list[str],
) -> None:
    template = _load_json_object(template_path, errors, "clean template")
    rel_template = template_path.name
    packet_label = str(packet.get("label") or "")
    if template.get("source_dirty_packet_label") != packet_label:
        errors.append(f"{rel_template} source_dirty_packet_label does not match dirty packet label {packet_label!r}")
    if template.get("source_dirty_packet_category") != packet.get("category"):
        errors.append(f"{rel_template} source_dirty_packet_category does not match dirty packet category")
    if template.get("entity_type") != packet.get("entity_type"):
        errors.append(f"{rel_template} entity_type does not match dirty packet")
    if not str(template.get("public_label") or "").strip():
        errors.append(f"{rel_template} public_label is required")
    if template.get("taint_level") not in CLEAN_TEMPLATE_TAINT_LEVELS:
        errors.append(f"{rel_template} taint_level must be one of {sorted(CLEAN_TEMPLATE_TAINT_LEVELS)}")
    if template.get("review_status") not in CLEAN_TEMPLATE_REVIEW_STATUSES:
        errors.append(f"{rel_template} review_status must be one of {sorted(CLEAN_TEMPLATE_REVIEW_STATUSES)}")


def _validate_raw_evidence_item(
    corpus_dir: Path,
    rel_dirty: str,
    index: int,
    item: dict[str, Any],
    errors: list[str],
    warnings: list[str],
) -> None:
    prefix = f"{rel_dirty}.raw_evidence[{index}]"
    for key in ("field", "original_path", "exists", "kind", "copyable"):
        if key not in item:
            errors.append(f"{prefix}.{key} is required")
    copied_path = item.get("copied_path")
    if copied_path:
        copied = _safe_corpus_path(corpus_dir, str(copied_path), errors, prefix)
        if copied is None:
            return
        if not copied.exists():
            errors.append(f"{prefix}.copied_path is missing on disk: {copied_path}")
            return
        expected_sha = item.get("sha256")
        if expected_sha and sha256_file(copied) != expected_sha:
            errors.append(f"{prefix}.copied_path sha256 does not match recorded evidence hash")
        return

    original_path = Path(str(item.get("original_path") or "")).expanduser()
    if not original_path.exists():
        errors.append(f"{prefix} has no copied evidence and original_path is unavailable: {original_path}")
    elif item.get("copyable"):
        warnings.append(f"{prefix} is copyable but was only referenced, so review depends on original_path")


def _validate_module_packets(
    corpus_dir: Path,
    errors: list[str],
    warnings: list[str],
) -> dict[str, Any]:
    modules_dir = corpus_dir / "modules"
    module_manifests = sorted(modules_dir.glob("*/manifest.json")) if modules_dir.exists() else []
    routine_manifests = sorted(modules_dir.glob("*/routines/*/manifest.json")) if modules_dir.exists() else []
    block_manifests = sorted(modules_dir.glob("*/blocks/*/manifest.json")) if modules_dir.exists() else []
    expected_block_packets = 0
    for manifest_path in module_manifests:
        module = _load_json_object(manifest_path, errors, "module packet manifest")
        rel_manifest = manifest_path.relative_to(corpus_dir).as_posix()
        if module.get("format") != PRIVATE_ARTIFACT_FORMAT_VERSION:
            errors.append(f"{rel_manifest}.format must be {PRIVATE_ARTIFACT_FORMAT_VERSION}")
        if module.get("entity_type") != "module":
            errors.append(f"{rel_manifest}.entity_type must be module")
        for key in ("label", "filename", "sha256", "scope", "role", "summary"):
            if key not in module:
                errors.append(f"{rel_manifest}.{key} is required")
        for rel_path in REQUIRED_MODULE_PACKET_FILES:
            if not (manifest_path.parent / rel_path).exists():
                errors.append(f"{rel_manifest} is missing module dossier file {rel_path}")
        if not (manifest_path.parent / "static" / "disassembly.asm").exists():
            warnings.append(f"{rel_manifest} has no static/disassembly.asm")
        summary = module.get("summary")
        if isinstance(summary, dict):
            expected_block_packets += int(summary.get("basic_blocks") or 0)

    for manifest_path in routine_manifests:
        routine = _load_json_object(manifest_path, errors, "routine packet manifest")
        rel_manifest = manifest_path.relative_to(corpus_dir).as_posix()
        if routine.get("format") != PRIVATE_ARTIFACT_FORMAT_VERSION:
            errors.append(f"{rel_manifest}.format must be {PRIVATE_ARTIFACT_FORMAT_VERSION}")
        if routine.get("entity_type") != "routine":
            errors.append(f"{rel_manifest}.entity_type must be routine")
        for key in ("label", "module_label", "module_sha256", "rva_start", "rva_end", "contracts"):
            if key not in routine:
                errors.append(f"{rel_manifest}.{key} is required")
        for rel_path in REQUIRED_ROUTINE_PACKET_FILES:
            if not (manifest_path.parent / rel_path).exists():
                errors.append(f"{rel_manifest} is missing routine dossier file {rel_path}")
        if not (manifest_path.parent / "static" / "disassembly.asm").exists():
            warnings.append(f"{rel_manifest} has no static/disassembly.asm")
        decompiler_path = manifest_path.parent / "static" / "decompiler-status.json"
        if decompiler_path.exists():
            decompiler = _load_json_object(decompiler_path, errors, "routine decompiler status")
            if not str(decompiler.get("status") or "").strip():
                errors.append(f"{decompiler_path.relative_to(corpus_dir).as_posix()} status is required")
        if not str(routine.get("semantic_summary") or "").strip():
            warnings.append(f"{rel_manifest} has an empty routine semantic summary")

    for manifest_path in block_manifests:
        block = _load_json_object(manifest_path, errors, "basic-block packet manifest")
        rel_manifest = manifest_path.relative_to(corpus_dir).as_posix()
        if block.get("format") != PRIVATE_ARTIFACT_FORMAT_VERSION:
            errors.append(f"{rel_manifest}.format must be {PRIVATE_ARTIFACT_FORMAT_VERSION}")
        if block.get("entity_type") != "basic_block":
            errors.append(f"{rel_manifest}.entity_type must be basic_block")
        for key in ("label", "module_label", "module_sha256", "rva_start", "rva_end", "size", "classification"):
            if key not in block:
                errors.append(f"{rel_manifest}.{key} is required")
        if not block.get("function_label"):
            warnings.append(f"{rel_manifest} has no parent routine label")
        for rel_path in REQUIRED_BLOCK_PACKET_FILES:
            if not (manifest_path.parent / rel_path).exists():
                errors.append(f"{rel_manifest} is missing basic-block dossier file {rel_path}")
        if not str(block.get("semantic_summary") or "").strip():
            warnings.append(f"{rel_manifest} has an empty block semantic summary")
        context_path = manifest_path.parent / "static" / "context.json"
        if context_path.exists():
            context = _load_json_object(context_path, errors, "basic-block context")
            if context.get("block", {}).get("label") != block.get("label"):
                errors.append(f"{context_path.relative_to(corpus_dir).as_posix()} block label does not match manifest")
            has_waiver = bool(context.get("static", {}).get("waivers"))
            is_padding = str(block.get("classification") or "") != "code"
            if not context.get("dynamic", {}).get("covered_by_tests") and not has_waiver and not is_padding:
                warnings.append(f"{context_path.relative_to(corpus_dir).as_posix()} has no covered tests")
        disassembly_path = manifest_path.parent / "static" / "disassembly.asm"
        if disassembly_path.exists():
            disassembly = disassembly_path.read_text(encoding="utf-8", errors="replace")
            if "PRIVATE DIRTY BASIC BLOCK DISASSEMBLY" not in disassembly:
                errors.append(f"{disassembly_path.relative_to(corpus_dir).as_posix()} missing dirty block header")
            if "no instruction lines were found" in disassembly:
                warnings.append(f"{disassembly_path.relative_to(corpus_dir).as_posix()} has no sliced instruction lines")
        for rel_path in ("static/instructions.json", "static/pcode.json", "static/data-flow.json", "static/xrefs.json"):
            semantic_path = manifest_path.parent / rel_path
            if semantic_path.exists():
                payload = _load_json_object(semantic_path, errors, rel_path)
                if payload.get("format") != PRIVATE_ARTIFACT_FORMAT_VERSION:
                    errors.append(f"{semantic_path.relative_to(corpus_dir).as_posix()}.format must be {PRIVATE_ARTIFACT_FORMAT_VERSION}")
        template_path = manifest_path.parent / "draft" / "clean-template.json"
        if template_path.exists():
            template = _load_json_object(template_path, errors, "basic-block clean template")
            if template.get("source_dirty_packet_label") != block.get("label"):
                errors.append(f"{template_path.relative_to(corpus_dir).as_posix()} source_dirty_packet_label mismatch")
            if template.get("entity_type") != "basic_block_contract":
                errors.append(f"{template_path.relative_to(corpus_dir).as_posix()} entity_type must be basic_block_contract")
            if template.get("taint_level") not in CLEAN_TEMPLATE_TAINT_LEVELS:
                errors.append(
                    f"{template_path.relative_to(corpus_dir).as_posix()} taint_level must be one of {sorted(CLEAN_TEMPLATE_TAINT_LEVELS)}"
                )
            if template.get("review_status") not in CLEAN_TEMPLATE_REVIEW_STATUSES:
                errors.append(
                    f"{template_path.relative_to(corpus_dir).as_posix()} review_status must be one of {sorted(CLEAN_TEMPLATE_REVIEW_STATUSES)}"
                )
    if expected_block_packets and len(block_manifests) != expected_block_packets:
        errors.append(
            f"basic-block packet count mismatch: expected={expected_block_packets} actual={len(block_manifests)}"
        )
    if not modules_dir.exists():
        warnings.append("dirty corpus has no modules/ directory")
    return {
        "module_packets": len(module_manifests),
        "routine_packets": len(routine_manifests),
        "block_packets": len(block_manifests),
        "expected_block_packets": expected_block_packets,
    }


def _safe_corpus_path(corpus_dir: Path, rel_path: str, errors: list[str], context: str) -> Path | None:
    rel = PurePosixPath(rel_path)
    if not rel_path.strip() or rel.is_absolute() or ".." in rel.parts:
        errors.append(f"{context}.path must be a relative corpus path: {rel_path!r}")
        return None
    return corpus_dir / Path(*rel.parts)


def _clean_artifact_root(out_dir: Path) -> None:
    if not out_dir.exists():
        return
    if out_dir.parent == out_dir:
        raise ValueError(f"refusing to clean filesystem root: {out_dir}")
    if out_dir.is_dir():
        shutil.rmtree(out_dir)
    else:
        out_dir.unlink()


def _write_root_evidence_packets(
    conn: sqlite3.Connection,
    out_dir: Path,
    add_artifact: Any,
) -> None:
    packets = [
        ("oracle-mappings.json", "private_oracle_mappings", _rows(conn, "SELECT * FROM oracle_mappings ORDER BY label")),
        ("waivers.json", "waiver_evidence", _rows(conn, "SELECT * FROM waivers ORDER BY label")),
        (
            "tests/test-runs.json",
            "dynamic_test_runs",
            _rows(conn, "SELECT * FROM test_runs ORDER BY suite, test_id, started_at"),
        ),
        (
            "tests/oracle-tests.json",
            "oracle_test_evidence",
            _rows(conn, "SELECT * FROM oracle_test_cases ORDER BY suite_id, case_kind, test_id"),
        ),
        (
            "tests/internal-harnesses.json",
            "internal_harness_evidence",
            _rows(conn, "SELECT * FROM internal_harnesses ORDER BY target_label, harness_id"),
        ),
        (
            "tests/internal-harness-runs.json",
            "internal_harness_run_evidence",
            _rows(conn, "SELECT * FROM internal_harness_runs ORDER BY test_id"),
        ),
        (
            "tests/value-traces.json",
            "value_trace_evidence",
            _rows(conn, "SELECT * FROM value_traces ORDER BY test_id, module_sha256, routine_label, block_label"),
        ),
        (
            "tests/behavior-contracts.json",
            "behavior_contract_evidence",
            _rows(conn, "SELECT * FROM behavior_contracts ORDER BY contract_id, version"),
        ),
        (
            "tests/behavior-observations.json",
            "behavior_observation_evidence",
            _rows(conn, "SELECT * FROM behavior_observations ORDER BY test_id"),
        ),
        (
            "tests/process-behavior-observations.json",
            "process_behavior_observation_evidence",
            _rows(conn, "SELECT * FROM process_behavior_observations ORDER BY test_id"),
        ),
        (
            "tests/interface-tests.json",
            "interface_test_evidence",
            _rows(conn, "SELECT * FROM interface_test_cases ORDER BY test_id"),
        ),
        (
            "tests/data-state-tests.json",
            "data_state_test_evidence",
            _rows(conn, "SELECT * FROM data_state_test_cases ORDER BY test_id"),
        ),
        (
            "tests/mutation-tests.json",
            "mutation_test_evidence",
            _rows(conn, "SELECT * FROM mutation_test_cases ORDER BY mutation_kind, test_id"),
        ),
        (
            "traces/trace-probes.json",
            "trace_probe_evidence",
            _rows(conn, "SELECT * FROM trace_probe_results ORDER BY probe_id, started_at"),
        ),
        (
            "interfaces/platform-endpoints.json",
            "platform_endpoint_evidence",
            _rows(conn, "SELECT * FROM platform_endpoints ORDER BY lower(dll), COALESCE(symbol, ''), COALESCE(ordinal, -1)"),
        ),
    ]
    for rel_path, kind, payload in packets:
        path = out_dir / rel_path
        write_json(path, payload)
        add_artifact(path, artifact_kind=kind, entity_type="catalog")


def _write_dirty_spec_suite(
    conn: sqlite3.Connection,
    out_dir: Path,
    add_artifact: Any,
    *,
    root_manifest: dict[str, Any],
    created_at: str,
) -> None:
    from .reports import gates_json, tests_json, tests_markdown
    from .spec_generation import specs_json, specs_markdown

    specs = specs_json(conn)
    review_surfaces = _dirty_review_surfaces()
    private_evidence = {
        "catalog_summary": "catalog-summary.json",
        "oracle_mappings": "oracle-mappings.json",
        "waivers": "waivers.json",
        "module_packets": "modules/",
        "review_packets": "review/",
        "root_evidence": "tests/",
        "interfaces": "interfaces/",
        "traces": "traces/",
    }
    common = {
        "format": DIRTY_SPEC_SUITE_FORMAT_VERSION,
        "artifact_role": "private_dirty_intermediate",
        "generated_at": created_at,
        "generator": root_manifest["generator"],
        "target": root_manifest["target"],
        "source_corpus": {
            "format": root_manifest["format"],
            "artifact_role": root_manifest["artifact_role"],
            "artifact_set_id": root_manifest["artifact_set_id"],
        },
        "taint_level": "dirty_private",
        "publication_status": "private_intermediate_not_for_publication",
        "review_model": {
            "unit": "review packet",
            "dirty_packet": "review/<category>/<packet>/dirty.json",
            "rewrite_target": "review/<category>/<packet>/clean-template.json",
            "required_next_step": "human/LLM rewrite into behavioral clean facts, then human review before publication",
        },
        "private_evidence": private_evidence,
        "review_surfaces": review_surfaces,
    }
    dirty_specs = {
        **common,
        "artifact_kind": "dirty_spec_suite",
        "label_first_draft": specs,
    }

    specs_path = out_dir / "dirty-specs.json"
    write_json(specs_path, dirty_specs)
    add_artifact(
        specs_path,
        artifact_kind="dirty_spec_suite",
        entity_type="dirty_spec_suite",
        taint_level="dirty_private",
    )
    specs_md_path = out_dir / "dirty-specs.md"
    specs_md_path.write_text(_dirty_spec_suite_markdown(dirty_specs, specs_markdown(specs)), encoding="utf-8")
    add_artifact(
        specs_md_path,
        artifact_kind="dirty_spec_suite_markdown",
        entity_type="dirty_spec_suite",
        taint_level="dirty_private",
    )

    tests = tests_json(conn)
    gates = gates_json(conn)
    dirty_tests = {
        **common,
        "artifact_kind": "dirty_test_suite",
        "label_first_draft": tests,
        "gate_snapshot": gates,
    }
    tests_path = out_dir / "dirty-tests.json"
    write_json(tests_path, dirty_tests)
    tests_artifact = add_artifact(
        tests_path,
        artifact_kind="dirty_test_suite",
        entity_type="dirty_test_suite",
        taint_level="dirty_private",
    )
    tests_md_path = out_dir / "dirty-tests.md"
    tests_md_path.write_text(_dirty_test_suite_markdown(dirty_tests, tests_markdown(tests, gates)), encoding="utf-8")
    tests_md_artifact = add_artifact(
        tests_md_path,
        artifact_kind="dirty_test_suite_markdown",
        entity_type="dirty_test_suite",
        taint_level="dirty_private",
    )

    tests = tests_json(conn)
    gates = gates_json(conn)
    dirty_tests["label_first_draft"] = tests
    dirty_tests["gate_snapshot"] = gates
    write_json(tests_path, dirty_tests)
    tests_md_path.write_text(_dirty_test_suite_markdown(dirty_tests, tests_markdown(tests, gates)), encoding="utf-8")
    _refresh_registered_artifact(conn, tests_path, tests_artifact)
    _refresh_registered_artifact(conn, tests_md_path, tests_md_artifact)


def _dirty_review_surfaces() -> list[dict[str, str]]:
    return [
        {
            "entity_type": "behavior_contract",
            "category": "behavior-contracts",
            "root_evidence": "tests/behavior-contracts.json",
        },
        {
            "entity_type": "behavior_observation",
            "category": "behavior-observations",
            "root_evidence": "tests/behavior-observations.json",
        },
        {
            "entity_type": "process_behavior_observation",
            "category": "process-behavior-observations",
            "root_evidence": "tests/process-behavior-observations.json",
        },
        {
            "entity_type": "oracle_test_case",
            "category": "oracle-tests",
            "root_evidence": "tests/oracle-tests.json",
        },
        {
            "entity_type": "interface_test_case",
            "category": "interface-tests",
            "root_evidence": "tests/interface-tests.json",
        },
        {
            "entity_type": "data_state_test_case",
            "category": "data-state-tests",
            "root_evidence": "tests/data-state-tests.json",
        },
        {
            "entity_type": "mutation_test_case",
            "category": "mutation-tests",
            "root_evidence": "tests/mutation-tests.json",
        },
        {
            "entity_type": "internal_routine_contract",
            "category": "internal-routine-contracts",
            "root_evidence": "review/internal-routine-contracts/",
        },
        {
            "entity_type": "internal_harness",
            "category": "internal-harnesses",
            "root_evidence": "tests/internal-harnesses.json",
        },
        {
            "entity_type": "internal_harness_run",
            "category": "internal-harness-runs",
            "root_evidence": "tests/internal-harness-runs.json",
        },
    ]


def _dirty_spec_suite_markdown(bundle: dict[str, Any], label_first_markdown: str) -> str:
    lines = [
        "# Private Dirty Spec Suite",
        "",
        "This is private intermediate review input. It may be adjacent to module hashes, RVAs,",
        "raw evidence, disassembly, and harness details in the same corpus. Do not publish it verbatim.",
        "",
        "## Review Flow",
        "",
        f"- Dirty packet: `{bundle['review_model']['dirty_packet']}`",
        f"- Clean rewrite target: `{bundle['review_model']['rewrite_target']}`",
        f"- Required next step: {bundle['review_model']['required_next_step']}",
        "",
        "## Private Evidence",
        "",
    ]
    for key, value in bundle["private_evidence"].items():
        lines.append(f"- {key.replace('_', ' ').title()}: `{value}`")
    lines.extend(["", "## Review Surfaces", ""])
    for surface in bundle["review_surfaces"]:
        lines.append(
            f"- `{surface['entity_type']}` category=`{surface['category']}` "
            f"evidence=`{surface['root_evidence']}`"
        )
    lines.extend(["", "## Label-First Draft", "", label_first_markdown])
    return "\n".join(lines)


def _dirty_test_suite_markdown(bundle: dict[str, Any], label_first_markdown: str) -> str:
    lines = [
        "# Private Dirty Test Suite",
        "",
        "This is private intermediate review input. It indexes observed test evidence",
        "and links that evidence back to review packets and raw sidecars inside the dirty corpus.",
        "",
        "## Review Flow",
        "",
        f"- Dirty packet: `{bundle['review_model']['dirty_packet']}`",
        f"- Clean rewrite target: `{bundle['review_model']['rewrite_target']}`",
        f"- Required next step: {bundle['review_model']['required_next_step']}",
        "",
        "## Gate Snapshot",
        "",
    ]
    for gate, payload in sorted(bundle.get("gate_snapshot", {}).items()):
        status = payload.get("status") if isinstance(payload, dict) else "unknown"
        lines.append(f"- `{gate}`: `{status}`")
    lines.extend(["", "## Label-First Draft", "", label_first_markdown])
    return "\n".join(lines)


def _write_review_packets(
    conn: sqlite3.Connection,
    out_dir: Path,
    add_artifact: Any,
    *,
    copy_raw_evidence: bool,
    max_raw_evidence_bytes: int,
) -> None:
    specs = [
        (
            "behavior-contracts",
            "behavior_contract",
            "SELECT * FROM behavior_contracts ORDER BY contract_id, version",
        ),
        (
            "behavior-observations",
            "behavior_observation",
            """
            SELECT bo.*, bc.label AS behavior_contract_label, bc.contract_id,
                   bc.title AS behavior_contract_title, bc.version AS behavior_contract_version
            FROM behavior_observations bo
            JOIN behavior_contracts bc ON bc.id = bo.behavior_contract_id
            ORDER BY bc.contract_id, bo.test_id
            """,
        ),
        (
            "process-behavior-observations",
            "process_behavior_observation",
            """
            SELECT pbo.*, bc.label AS behavior_contract_label, bc.contract_id,
                   bc.title AS behavior_contract_title, bc.version AS behavior_contract_version
            FROM process_behavior_observations pbo
            JOIN behavior_contracts bc ON bc.id = pbo.behavior_contract_id
            ORDER BY bc.contract_id, pbo.test_id
            """,
        ),
        (
            "internal-routine-contracts",
            "internal_routine_contract",
            """
            SELECT irc.*, f.label AS function_label, f.name AS function_name,
                   f.rva AS function_rva, b.label AS module_label,
                   b.filename AS module_filename, b.sha256 AS module_sha256
            FROM internal_routine_contracts irc
            JOIN functions f ON f.id = irc.function_id
            JOIN binaries b ON b.id = f.binary_id
            ORDER BY irc.public_name, irc.label
            """,
        ),
        (
            "oracle-tests",
            "oracle_test_case",
            "SELECT * FROM oracle_test_cases ORDER BY suite_id, case_kind, test_id",
        ),
        (
            "interface-tests",
            "interface_test_case",
            """
            SELECT itc.*, pe.label AS endpoint_label, pe.dll, pe.symbol, pe.ordinal, pe.subsystem
            FROM interface_test_cases itc
            JOIN platform_endpoints pe ON pe.id = itc.endpoint_id
            ORDER BY lower(pe.dll), COALESCE(pe.symbol, ''), itc.case_kind, itc.test_id
            """,
        ),
        (
            "data-state-tests",
            "data_state_test_case",
            """
            SELECT dst.*, ds.label AS data_structure_label, ds.name AS data_structure_name,
                   ds.structure_kind, ds.description AS data_structure_description
            FROM data_state_test_cases dst
            JOIN data_structures ds ON ds.id = dst.data_structure_id
            ORDER BY ds.structure_kind, ds.name, dst.case_kind, dst.test_id
            """,
        ),
        (
            "mutation-tests",
            "mutation_test_case",
            "SELECT * FROM mutation_test_cases ORDER BY mutation_kind, target_label, test_id",
        ),
        (
            "internal-harnesses",
            "internal_harness",
            "SELECT * FROM internal_harnesses ORDER BY target_label, harness_id",
        ),
        (
            "internal-harness-runs",
            "internal_harness_run",
            """
            SELECT ihr.*, ih.label AS harness_label, ih.target_label, ih.harness_id, ih.harness_kind
            FROM internal_harness_runs ihr
            JOIN internal_harnesses ih ON ih.id = ihr.internal_harness_id
            ORDER BY ih.target_label, ih.harness_id, ihr.test_id
            """,
        ),
    ]
    for category, entity_type, query in specs:
        for row in _rows(conn, query):
            _write_review_packet(
                out_dir,
                add_artifact,
                category=category,
                entity_type=entity_type,
                row=row,
                copy_raw_evidence=copy_raw_evidence,
                max_raw_evidence_bytes=max_raw_evidence_bytes,
            )


def _write_review_packet(
    out_dir: Path,
    add_artifact: Any,
    *,
    category: str,
    entity_type: str,
    row: dict[str, Any],
    copy_raw_evidence: bool,
    max_raw_evidence_bytes: int,
) -> None:
    entity_label = str(row["label"])
    title = _review_packet_title(entity_type, row)
    packet_dir = out_dir / "review" / category / f"{slug(title)}-{entity_label[-12:]}"
    packet_dir.mkdir(parents=True, exist_ok=True)

    raw_evidence = _copy_or_reference_evidence(
        row,
        out_dir,
        packet_dir,
        add_artifact,
        entity_label=entity_label,
        entity_type=entity_type,
        copy_raw_evidence=copy_raw_evidence,
        max_raw_evidence_bytes=max_raw_evidence_bytes,
    )
    dirty_packet = {
        "format": PRIVATE_ARTIFACT_FORMAT_VERSION,
        "packet_kind": "dirty_review_packet",
        "category": category,
        "entity_type": entity_type,
        "label": entity_label,
        "title": title,
        "taint_level": "dirty_private",
        "review_status": "dirty_unreviewed",
        "row": row,
        "raw_evidence": raw_evidence,
        "clean_derivation": {
            "template": "clean-template.json",
            "required_action": "rewrite into behavioral clean-room facts before publication",
            "forbidden_public_content": [
                "raw RVAs or module hashes unless explicitly approved",
                "disassembly or instruction listings",
                "decompiled bodies or copied pseudocode",
                "private harness internals that reveal implementation expression",
            ],
        },
    }
    dirty_path = packet_dir / "dirty.json"
    write_json(dirty_path, dirty_packet)
    add_artifact(
        dirty_path,
        artifact_kind="review_dirty_packet",
        entity_label=entity_label,
        entity_type=entity_type,
        taint_level="dirty_private",
        source_detail={"category": category},
    )

    index_path = packet_dir / "index.md"
    index_path.write_text(_review_packet_index_markdown(dirty_packet), encoding="utf-8")
    add_artifact(
        index_path,
        artifact_kind="review_index",
        entity_label=entity_label,
        entity_type=entity_type,
        taint_level="dirty_private",
        source_detail={"category": category},
    )

    clean_template_path = packet_dir / "clean-template.json"
    write_json(clean_template_path, _clean_derivation_template(dirty_packet))
    add_artifact(
        clean_template_path,
        artifact_kind="review_clean_template",
        entity_label=entity_label,
        entity_type=entity_type,
        taint_level="clean_candidate",
        source_detail={"category": category, "derived_from": dirty_path.name},
    )


def _write_module_packet(
    conn: sqlite3.Connection,
    metadata: dict[str, str],
    binary: dict[str, Any],
    out_dir: Path,
    add_artifact: Any,
    *,
    include_disassembly: bool,
    objdump: str,
    objdump_timeout_seconds: int,
) -> None:
    module_dir = out_dir / "modules" / f"{slug(binary['filename'])}-{str(binary['sha256'])[:12]}"
    module_dir.mkdir(parents=True, exist_ok=True)
    binary_id = int(binary["id"])
    source_path = _binary_source_path(metadata, binary)
    module_summary = _module_summary(conn, binary_id)
    manifest = {
        "format": PRIVATE_ARTIFACT_FORMAT_VERSION,
        "entity_type": "module",
        "label": binary["label"],
        "path": binary["path"],
        "filename": binary["filename"],
        "sha256": binary["sha256"],
        "scope": binary["scope"],
        "role": binary["role"],
        "machine": binary["machine"],
        "image_base": binary["image_base"],
        "entrypoint_rva": binary["entrypoint_rva"],
        "source_path": str(source_path) if source_path else None,
        "summary": module_summary,
        "taint": "dirty_private",
    }
    manifest_path = module_dir / "manifest.json"
    write_json(manifest_path, manifest)
    add_artifact(
        manifest_path,
        artifact_kind="module_manifest",
        entity_label=binary["label"],
        entity_type="module",
        binary_id=binary_id,
        module_sha256=binary["sha256"],
    )

    index_path = module_dir / "index.md"
    index_path.write_text(_module_index_markdown(manifest), encoding="utf-8")
    add_artifact(
        index_path,
        artifact_kind="module_index",
        entity_label=binary["label"],
        entity_type="module",
        binary_id=binary_id,
        module_sha256=binary["sha256"],
    )

    module_packets = [
        (
            "static/sections.json",
            "module_sections",
            _rows(conn, "SELECT * FROM sections WHERE binary_id = ? ORDER BY virtual_address", (binary_id,)),
        ),
        (
            "static/imports.json",
            "module_imports",
            _rows(conn, "SELECT * FROM imports WHERE binary_id = ? ORDER BY lower(dll), COALESCE(symbol, ''), COALESCE(ordinal, -1)", (binary_id,)),
        ),
        (
            "static/exports.json",
            "module_exports",
            _rows(conn, "SELECT * FROM exports WHERE binary_id = ? ORDER BY ordinal", (binary_id,)),
        ),
        (
            "static/resources.json",
            "module_resources",
            _rows(conn, "SELECT * FROM resources WHERE binary_id = ? ORDER BY type_name, name, language", (binary_id,)),
        ),
        (
            "static/functions.json",
            "module_functions",
            _rows(conn, "SELECT * FROM functions WHERE binary_id = ? ORDER BY rva, name", (binary_id,)),
        ),
        (
            "static/basic-blocks.json",
            "module_basic_blocks",
            _rows(conn, "SELECT * FROM basic_blocks WHERE binary_id = ? ORDER BY rva_start, rva_end", (binary_id,)),
        ),
        (
            "static/cfg-edges.json",
            "module_cfg_edges",
            _rows(conn, "SELECT * FROM cfg_edges WHERE binary_id = ? ORDER BY from_rva, to_rva", (binary_id,)),
        ),
        (
            "static/call-edges.json",
            "module_call_edges",
            _rows(conn, "SELECT * FROM call_edges WHERE binary_id = ? ORDER BY caller_rva, callee_symbol", (binary_id,)),
        ),
        (
            "static/data-refs.json",
            "module_data_refs",
            _rows(conn, "SELECT * FROM data_refs WHERE binary_id = ? ORDER BY from_rva, to_rva", (binary_id,)),
        ),
        (
            "static/globals.json",
            "module_globals",
            _rows(conn, "SELECT * FROM globals WHERE binary_id = ? ORDER BY rva, name", (binary_id,)),
        ),
        (
            "coverage/coverage-blocks.json",
            "module_coverage_blocks",
            _rows(conn, "SELECT * FROM coverage_blocks WHERE binary_id = ? ORDER BY rva_start, rva_end", (binary_id,)),
        ),
        (
            "coverage/coverage-edges.json",
            "module_coverage_edges",
            _rows(conn, "SELECT * FROM coverage_edges WHERE binary_id = ? ORDER BY from_rva, to_rva", (binary_id,)),
        ),
        (
            "coverage/coverage-call-edges.json",
            "module_coverage_call_edges",
            _rows(conn, "SELECT * FROM coverage_call_edges WHERE binary_id = ? ORDER BY caller_rva", (binary_id,)),
        ),
        (
            "waivers/waivers.json",
            "module_waivers",
            _rows(conn, "SELECT * FROM waivers WHERE binary_id = ? ORDER BY rva_start, rva_end", (binary_id,)),
        ),
        (
            "interfaces/platform-endpoints.json",
            "module_platform_endpoints",
            _module_endpoint_rows(conn, binary_id),
        ),
    ]
    for rel_path, kind, payload in module_packets:
        path = module_dir / rel_path
        write_json(path, payload)
        add_artifact(
            path,
            artifact_kind=kind,
            entity_label=binary["label"],
            entity_type="module",
            binary_id=binary_id,
            module_sha256=binary["sha256"],
        )

    module_disassembly: str | None = None
    if include_disassembly:
        disassembly_path = module_dir / "static" / "disassembly.asm"
        module_disassembly = _objdump_disassembly(source_path, objdump, objdump_timeout_seconds)
        disassembly_path.parent.mkdir(parents=True, exist_ok=True)
        disassembly_path.write_text(module_disassembly, encoding="utf-8", errors="replace")
        add_artifact(
            disassembly_path,
            artifact_kind="module_disassembly",
            entity_label=binary["label"],
            entity_type="module",
            binary_id=binary_id,
            module_sha256=binary["sha256"],
            source_tool=objdump,
        )

    for block in _basic_blocks_for_binary(conn, binary_id):
        _write_block_packet(
            conn,
            binary,
            block,
            module_dir,
            add_artifact,
            module_disassembly=module_disassembly,
            objdump=objdump,
        )

    for function in _functions_for_binary(conn, binary_id):
        _write_routine_packet(
            conn,
            binary,
            function,
            source_path,
            module_dir,
            add_artifact,
            include_disassembly=include_disassembly,
            objdump=objdump,
            objdump_timeout_seconds=objdump_timeout_seconds,
        )


def _write_block_packet(
    conn: sqlite3.Connection,
    binary: dict[str, Any],
    block: dict[str, Any],
    module_dir: Path,
    add_artifact: Any,
    *,
    module_disassembly: str | None,
    objdump: str,
) -> None:
    binary_id = int(binary["id"])
    rva_start = int(block["rva_start"])
    rva_end = int(block["rva_end"])
    block_dir = module_dir / "blocks" / block["label"]
    block_dir.mkdir(parents=True, exist_ok=True)
    context = _block_context(conn, binary_id, block)
    semantic = _block_semantic_payload(conn, binary_id, block, context)
    manifest = {
        "format": PRIVATE_ARTIFACT_FORMAT_VERSION,
        "entity_type": "basic_block",
        "label": block["label"],
        "module_label": binary["label"],
        "module_sha256": binary["sha256"],
        "function_label": (context.get("function") or {}).get("label"),
        "rva_start": rva_start,
        "rva_end": rva_end,
        "size": int(block["size"]),
        "source": block["source"],
        "classification": block["classification"],
        "confidence": block["confidence"],
        "coverage_summary": context["coverage_summary"],
        "static_context_summary": context["static_context_summary"],
        "decompiler": semantic["decompiler"],
        "semantic_summary": semantic["summary"],
        "taint": "dirty_private",
    }
    manifest_path = block_dir / "manifest.json"
    write_json(manifest_path, manifest)
    add_artifact(
        manifest_path,
        artifact_kind="block_manifest",
        entity_label=block["label"],
        entity_type="basic_block",
        binary_id=binary_id,
        module_sha256=binary["sha256"],
        rva_start=rva_start,
        rva_end=rva_end,
    )

    index_path = block_dir / "index.md"
    index_path.write_text(_block_index_markdown(manifest), encoding="utf-8")
    add_artifact(
        index_path,
        artifact_kind="block_index",
        entity_label=block["label"],
        entity_type="basic_block",
        binary_id=binary_id,
        module_sha256=binary["sha256"],
        rva_start=rva_start,
        rva_end=rva_end,
    )

    context_path = block_dir / "static" / "context.json"
    write_json(context_path, context)
    add_artifact(
        context_path,
        artifact_kind="block_context",
        entity_label=block["label"],
        entity_type="basic_block",
        binary_id=binary_id,
        module_sha256=binary["sha256"],
        rva_start=rva_start,
        rva_end=rva_end,
        taint_level="static_dirty",
    )

    disassembly_path = block_dir / "static" / "disassembly.asm"
    image_base = int(binary["image_base"] or 0)
    disassembly_path.parent.mkdir(parents=True, exist_ok=True)
    disassembly_path.write_text(
        _block_disassembly_from_module(
            module_disassembly,
            block=block,
            module=binary,
            image_base=image_base,
        ),
        encoding="utf-8",
        errors="replace",
    )
    add_artifact(
        disassembly_path,
        artifact_kind="block_disassembly",
        entity_label=block["label"],
        entity_type="basic_block",
        binary_id=binary_id,
        module_sha256=binary["sha256"],
        rva_start=rva_start,
        rva_end=rva_end,
        taint_level="static_dirty",
        source_tool=objdump,
    )

    decompiler_status_path = block_dir / "static" / "decompiler-status.json"
    write_json(decompiler_status_path, manifest["decompiler"])
    add_artifact(
        decompiler_status_path,
        artifact_kind="block_decompiler_status",
        entity_label=block["label"],
        entity_type="basic_block",
        binary_id=binary_id,
        module_sha256=binary["sha256"],
        rva_start=rva_start,
        rva_end=rva_end,
        taint_level="static_dirty",
    )

    semantic_files = [
        ("static/instructions.json", "block_instruction_metadata", semantic["instructions"], "static_dirty"),
        ("static/pcode.json", "block_pcode", semantic["pcode"], "decompiler_high_taint"),
        ("static/data-flow.json", "block_data_flow", semantic["data_flow"], "static_dirty"),
        ("static/xrefs.json", "block_xrefs", semantic["xrefs"], "static_dirty"),
    ]
    for rel_path, kind, payload, taint in semantic_files:
        path = block_dir / rel_path
        write_json(path, payload)
        add_artifact(
            path,
            artifact_kind=kind,
            entity_label=block["label"],
            entity_type="basic_block",
            binary_id=binary_id,
            module_sha256=binary["sha256"],
            rva_start=rva_start,
            rva_end=rva_end,
            taint_level=taint,
        )

    semantic_summary_path = block_dir / "semantic-summary.md"
    semantic_summary_path.write_text(_block_semantic_summary_markdown(manifest, semantic), encoding="utf-8")
    add_artifact(
        semantic_summary_path,
        artifact_kind="block_semantic_summary",
        entity_label=block["label"],
        entity_type="basic_block",
        binary_id=binary_id,
        module_sha256=binary["sha256"],
        rva_start=rva_start,
        rva_end=rva_end,
        taint_level="dirty_private",
    )

    clean_template_path = block_dir / "draft" / "clean-template.json"
    write_json(clean_template_path, _block_clean_template(manifest))
    add_artifact(
        clean_template_path,
        artifact_kind="block_clean_template",
        entity_label=block["label"],
        entity_type="basic_block_contract",
        binary_id=binary_id,
        module_sha256=binary["sha256"],
        rva_start=rva_start,
        rva_end=rva_end,
        taint_level="clean_candidate",
    )


def _write_routine_packet(
    conn: sqlite3.Connection,
    binary: dict[str, Any],
    function: dict[str, Any],
    source_path: Path | None,
    module_dir: Path,
    add_artifact: Any,
    *,
    include_disassembly: bool,
    objdump: str,
    objdump_timeout_seconds: int,
) -> None:
    function_id = int(function["id"])
    rva_start = int(function["rva"])
    rva_end = _function_rva_end(conn, int(binary["id"]), function_id, rva_start)
    routine_dir = module_dir / "routines" / function["label"]
    routine_dir.mkdir(parents=True, exist_ok=True)
    contracts = _rows(
        conn,
        """
        SELECT *
        FROM internal_routine_contracts
        WHERE function_id = ?
        ORDER BY public_name, label
        """,
        (function_id,),
    )
    semantic = _routine_semantic_payload(conn, function_id)
    packet = {
        "format": PRIVATE_ARTIFACT_FORMAT_VERSION,
        "entity_type": "routine",
        "label": function["label"],
        "module_label": binary["label"],
        "module_sha256": binary["sha256"],
        "rva_start": rva_start,
        "rva_end": rva_end,
        "name": function["name"],
        "source": function["source"],
        "calling_convention": function["calling_convention"],
        "signature": function["signature"],
        "subsystem": function["subsystem"],
        "purity": function["purity"],
        "side_effects": function["side_effects"],
        "confidence": function["confidence"],
        "test_status": function["test_status"],
        "clean_room_status": function["clean_room_status"],
        "contracts": contracts,
        "decompiler": semantic["decompiler"],
        "semantic_summary": semantic["summary"],
        "taint": "dirty_private",
    }
    manifest_path = routine_dir / "manifest.json"
    write_json(manifest_path, packet)
    add_artifact(
        manifest_path,
        artifact_kind="routine_manifest",
        entity_label=function["label"],
        entity_type="function",
        binary_id=int(binary["id"]),
        module_sha256=binary["sha256"],
        rva_start=rva_start,
        rva_end=rva_end,
    )

    index_path = routine_dir / "index.md"
    index_path.write_text(_routine_index_markdown(packet), encoding="utf-8")
    add_artifact(
        index_path,
        artifact_kind="routine_index",
        entity_label=function["label"],
        entity_type="function",
        binary_id=int(binary["id"]),
        module_sha256=binary["sha256"],
        rva_start=rva_start,
        rva_end=rva_end,
    )

    routine_packets = [
        (
            "static/cfg.json",
            "routine_cfg",
            {
                "basic_blocks": _rows(
                    conn,
                    "SELECT * FROM basic_blocks WHERE function_id = ? ORDER BY rva_start, rva_end",
                    (function_id,),
                ),
                "cfg_edges": _rows(
                    conn,
                    "SELECT * FROM cfg_edges WHERE function_id = ? ORDER BY from_rva, to_rva",
                    (function_id,),
                ),
                "call_edges": _rows(
                    conn,
                    """
                    SELECT *
                    FROM call_edges
                    WHERE binary_id = ?
                      AND caller_rva >= ?
                      AND caller_rva < ?
                    ORDER BY caller_rva, callee_symbol
                    """,
                    (int(binary["id"]), rva_start, rva_end),
                ),
                "data_refs": _rows(
                    conn,
                    """
                    SELECT *
                    FROM data_refs
                    WHERE binary_id = ?
                      AND from_rva >= ?
                      AND from_rva < ?
                    ORDER BY from_rva, to_rva
                    """,
                    (int(binary["id"]), rva_start, rva_end),
                ),
            },
        ),
        (
            "static/semantics.json",
            "routine_semantics",
            semantic["semantics"],
        ),
        (
            "static/decompiler-status.json",
            "routine_decompiler_status",
            semantic["decompiler"],
        ),
        (
            "static/pcode.json",
            "routine_pcode",
            semantic["pcode"],
        ),
        (
            "dynamic/coverage.json",
            "routine_dynamic_coverage",
            _routine_coverage(conn, int(binary["id"]), rva_start, rva_end),
        ),
        (
            "draft/dirty-contract.md",
            "routine_dirty_contract_draft",
            _dirty_contract_markdown(packet),
        ),
    ]
    for rel_path, kind, payload in routine_packets:
        path = routine_dir / rel_path
        if isinstance(payload, str):
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(payload, encoding="utf-8")
        else:
            write_json(path, payload)
        add_artifact(
            path,
            artifact_kind=kind,
            entity_label=function["label"],
            entity_type="function",
            binary_id=int(binary["id"]),
            module_sha256=binary["sha256"],
            rva_start=rva_start,
            rva_end=rva_end,
            source_tool="wincr",
            taint_level="decompiler_high_taint" if kind == "routine_pcode" else "dirty_private",
        )

    if semantic["decompiled_c"]:
        decompiled_path = routine_dir / "static" / "decompiled.c"
        decompiled_path.parent.mkdir(parents=True, exist_ok=True)
        decompiled_path.write_text(semantic["decompiled_c"], encoding="utf-8", errors="replace")
        add_artifact(
            decompiled_path,
            artifact_kind="routine_decompiled_c",
            entity_label=function["label"],
            entity_type="function",
            binary_id=int(binary["id"]),
            module_sha256=binary["sha256"],
            rva_start=rva_start,
            rva_end=rva_end,
            taint_level="decompiler_high_taint",
            source_tool="ghidra",
        )

    if include_disassembly:
        disassembly_path = routine_dir / "static" / "disassembly.asm"
        image_base = int(binary["image_base"] or 0)
        disassembly = _objdump_disassembly(
            source_path,
            objdump,
            objdump_timeout_seconds,
            start_address=image_base + rva_start if image_base else None,
            stop_address=image_base + rva_end if image_base else None,
        )
        disassembly_path.parent.mkdir(parents=True, exist_ok=True)
        disassembly_path.write_text(disassembly, encoding="utf-8", errors="replace")
        add_artifact(
            disassembly_path,
            artifact_kind="routine_disassembly",
            entity_label=function["label"],
            entity_type="function",
            binary_id=int(binary["id"]),
            module_sha256=binary["sha256"],
            rva_start=rva_start,
            rva_end=rva_end,
            source_tool=objdump,
        )


def _register_artifact(
    conn: sqlite3.Connection,
    *,
    bundle_id: int,
    bundle_label: str,
    root: Path,
    path: Path,
    artifact_kind: str,
    entity_label: str | None,
    entity_type: str,
    binary_id: int | None,
    module_sha256: str | None,
    rva_start: int | None,
    rva_end: int | None,
    taint_level: str,
    source_tool: str,
    source_detail: dict[str, Any],
    created_at: str,
) -> dict[str, Any]:
    rel_path = path.relative_to(root).as_posix()
    label = private_artifact_label(bundle_label, artifact_kind, rel_path)
    ensure_label(conn, label, "private_artifact", rel_path, artifact_kind, private=True, created_at=created_at)
    digest = sha256_file(path)
    size = path.stat().st_size
    conn.execute(
        """
        INSERT INTO private_artifacts(
          label, bundle_id, artifact_kind, entity_label, entity_type, binary_id,
          module_sha256, rva_start, rva_end, path, sha256, size, taint_level,
          source_tool, source_detail_json, created_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            label,
            bundle_id,
            artifact_kind,
            entity_label,
            entity_type,
            binary_id,
            module_sha256,
            rva_start,
            rva_end,
            rel_path,
            digest,
            size,
            taint_level,
            source_tool,
            json_dumps(source_detail),
            created_at,
        ),
    )
    return {
        "label": label,
        "artifact_kind": artifact_kind,
        "entity_label": entity_label,
        "entity_type": entity_type,
        "path": rel_path,
        "sha256": digest,
        "size": size,
        "taint_level": taint_level,
        "source_tool": source_tool,
    }


def _refresh_registered_artifact(conn: sqlite3.Connection, path: Path, artifact: dict[str, Any]) -> None:
    digest = sha256_file(path)
    size = path.stat().st_size
    artifact["sha256"] = digest
    artifact["size"] = size
    conn.execute(
        """
        UPDATE private_artifacts
        SET sha256 = ?, size = ?
        WHERE label = ?
        """,
        (digest, size, artifact["label"]),
    )


def _metadata(conn: sqlite3.Connection) -> dict[str, str]:
    return {str(row["key"]): str(row["value"]) for row in conn.execute("SELECT key, value FROM metadata")}


def _included_binaries(conn: sqlite3.Connection, scopes: Iterable[str]) -> list[dict[str, Any]]:
    scopes = tuple(scopes)
    if not scopes:
        return []
    placeholders = ",".join("?" for _ in scopes)
    return _rows(
        conn,
        f"""
        SELECT *
        FROM binaries
        WHERE scope IN ({placeholders})
        ORDER BY scope, path
        """,
        scopes,
    )


def _root_summary(conn: sqlite3.Connection, scopes: tuple[str, ...]) -> dict[str, Any]:
    binaries = _included_binaries(conn, scopes)
    binary_ids = [int(row["id"]) for row in binaries]
    scoped_counts = _scoped_counts(conn, binary_ids)
    return {
        "modules": len(binaries),
        "scopes": list(scopes),
        **scoped_counts,
    }


def _scoped_counts(conn: sqlite3.Connection, binary_ids: list[int]) -> dict[str, int]:
    if not binary_ids:
        return {
            "functions": 0,
            "basic_blocks": 0,
            "cfg_edges": 0,
            "call_edges": 0,
            "data_refs": 0,
            "function_semantics": 0,
            "block_semantics": 0,
            "value_traces": 0,
            "coverage_blocks": 0,
            "coverage_edges": 0,
            "coverage_call_edges": 0,
            "waivers": 0,
        }
    placeholders = ",".join("?" for _ in binary_ids)
    result: dict[str, int] = {}
    for key, table in {
        "functions": "functions",
        "basic_blocks": "basic_blocks",
        "cfg_edges": "cfg_edges",
        "call_edges": "call_edges",
        "data_refs": "data_refs",
        "function_semantics": "function_semantics",
        "block_semantics": "block_semantics",
        "coverage_blocks": "coverage_blocks",
        "coverage_edges": "coverage_edges",
        "coverage_call_edges": "coverage_call_edges",
        "waivers": "waivers",
    }.items():
        result[key] = int(
            conn.execute(
                f"SELECT COUNT(*) AS count FROM {table} WHERE binary_id IN ({placeholders})",
                binary_ids,
            ).fetchone()["count"]
            or 0
        )
    value_trace_placeholders = ",".join("?" for _ in binary_ids)
    result["value_traces"] = int(
        conn.execute(
            f"""
            SELECT COUNT(*) AS count
            FROM value_traces
            WHERE module_sha256 IN (
              SELECT sha256 FROM binaries WHERE id IN ({value_trace_placeholders})
            )
            """,
            tuple(binary_ids),
        ).fetchone()["count"]
        or 0
    )
    return result


def _module_summary(conn: sqlite3.Connection, binary_id: int) -> dict[str, int]:
    return {
        "sections": _count(conn, "sections", binary_id),
        "imports": _count(conn, "imports", binary_id),
        "exports": _count(conn, "exports", binary_id),
        "resources": _count(conn, "resources", binary_id),
        "executable_ranges": _count(conn, "executable_ranges", binary_id),
        "executable_byte_classes": _count(conn, "executable_byte_classes", binary_id),
        "functions": _count(conn, "functions", binary_id),
        "basic_blocks": _count(conn, "basic_blocks", binary_id),
        "cfg_edges": _count(conn, "cfg_edges", binary_id),
        "call_edges": _count(conn, "call_edges", binary_id),
        "data_refs": _count(conn, "data_refs", binary_id),
        "coverage_blocks": _count(conn, "coverage_blocks", binary_id),
        "coverage_edges": _count(conn, "coverage_edges", binary_id),
        "coverage_call_edges": _count(conn, "coverage_call_edges", binary_id),
        "waivers": _count(conn, "waivers", binary_id),
    }


def _count(conn: sqlite3.Connection, table: str, binary_id: int) -> int:
    return int(
        conn.execute(f"SELECT COUNT(*) AS count FROM {table} WHERE binary_id = ?", (binary_id,)).fetchone()["count"]
        or 0
    )


def _rows(conn: sqlite3.Connection, query: str, params: tuple[Any, ...] = ()) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for row in conn.execute(query, params):
        item = dict(row)
        for key, value in list(item.items()):
            if key.endswith("_json") and isinstance(value, str):
                item[key[:-5]] = _json_value(value)
        rows.append(item)
    return rows


def _json_value(value: str) -> Any:
    try:
        return json.loads(value)
    except json.JSONDecodeError:
        return value


def _module_endpoint_rows(conn: sqlite3.Connection, binary_id: int) -> list[dict[str, Any]]:
    return _rows(
        conn,
        """
        SELECT pe.*, bpe.thunk_rva
        FROM binary_platform_endpoints bpe
        JOIN platform_endpoints pe ON pe.id = bpe.endpoint_id
        WHERE bpe.binary_id = ?
        ORDER BY lower(pe.dll), COALESCE(pe.symbol, ''), COALESCE(pe.ordinal, -1), bpe.thunk_rva
        """,
        (binary_id,),
    )


def _basic_blocks_for_binary(conn: sqlite3.Connection, binary_id: int) -> list[dict[str, Any]]:
    return _rows(conn, "SELECT * FROM basic_blocks WHERE binary_id = ? ORDER BY rva_start, rva_end", (binary_id,))


def _functions_for_binary(conn: sqlite3.Connection, binary_id: int) -> list[dict[str, Any]]:
    return _rows(conn, "SELECT * FROM functions WHERE binary_id = ? ORDER BY rva, name", (binary_id,))


def _block_context(conn: sqlite3.Connection, binary_id: int, block: dict[str, Any]) -> dict[str, Any]:
    rva_start = int(block["rva_start"])
    rva_end = int(block["rva_end"])
    function_id = block.get("function_id")
    function = None
    if function_id is not None:
        function_rows = _rows(conn, "SELECT * FROM functions WHERE id = ?", (int(function_id),))
        function = function_rows[0] if function_rows else None
    outgoing_cfg_edges = _rows(
        conn,
        """
        SELECT *
        FROM cfg_edges
        WHERE binary_id = ?
          AND from_rva >= ?
          AND from_rva < ?
        ORDER BY from_rva, to_rva, edge_type
        """,
        (binary_id, rva_start, rva_end),
    )
    incoming_cfg_edges = _rows(
        conn,
        """
        SELECT *
        FROM cfg_edges
        WHERE binary_id = ?
          AND to_rva >= ?
          AND to_rva < ?
        ORDER BY from_rva, to_rva, edge_type
        """,
        (binary_id, rva_start, rva_end),
    )
    call_edges = _rows(
        conn,
        """
        SELECT *
        FROM call_edges
        WHERE binary_id = ?
          AND caller_rva >= ?
          AND caller_rva < ?
        ORDER BY caller_rva, callee_symbol
        """,
        (binary_id, rva_start, rva_end),
    )
    data_refs = _rows(
        conn,
        """
        SELECT *
        FROM data_refs
        WHERE binary_id = ?
          AND from_rva >= ?
          AND from_rva < ?
        ORDER BY from_rva, to_rva
        """,
        (binary_id, rva_start, rva_end),
    )
    waivers = _rows(
        conn,
        """
        SELECT *
        FROM waivers
        WHERE binary_id = ?
          AND rva_start < ?
          AND rva_end > ?
        ORDER BY rva_start, rva_end
        """,
        (binary_id, rva_end, rva_start),
    )
    coverage_blocks = _rows(
        conn,
        """
        SELECT cb.*, tr.test_id, tr.suite, tr.status AS test_status
        FROM coverage_blocks cb
        JOIN test_runs tr ON tr.id = cb.test_run_id
        WHERE cb.binary_id = ?
          AND cb.rva_start < ?
          AND cb.rva_end > ?
        ORDER BY tr.suite, tr.test_id, cb.rva_start
        """,
        (binary_id, rva_end, rva_start),
    )
    coverage_edges_out = _rows(
        conn,
        """
        SELECT ce.*, tr.test_id, tr.suite, tr.status AS test_status
        FROM coverage_edges ce
        JOIN test_runs tr ON tr.id = ce.test_run_id
        WHERE ce.binary_id = ?
          AND ce.from_rva >= ?
          AND ce.from_rva < ?
        ORDER BY tr.suite, tr.test_id, ce.from_rva, ce.to_rva
        """,
        (binary_id, rva_start, rva_end),
    )
    coverage_edges_in = _rows(
        conn,
        """
        SELECT ce.*, tr.test_id, tr.suite, tr.status AS test_status
        FROM coverage_edges ce
        JOIN test_runs tr ON tr.id = ce.test_run_id
        WHERE ce.binary_id = ?
          AND ce.to_rva >= ?
          AND ce.to_rva < ?
        ORDER BY tr.suite, tr.test_id, ce.from_rva, ce.to_rva
        """,
        (binary_id, rva_start, rva_end),
    )
    coverage_call_edges = _rows(
        conn,
        """
        SELECT cce.*, tr.test_id, tr.suite, tr.status AS test_status
        FROM coverage_call_edges cce
        JOIN test_runs tr ON tr.id = cce.test_run_id
        WHERE cce.binary_id = ?
          AND cce.caller_rva >= ?
          AND cce.caller_rva < ?
        ORDER BY tr.suite, tr.test_id, cce.caller_rva
        """,
        (binary_id, rva_start, rva_end),
    )
    covered_tests = sorted(
        {
            f"{row.get('suite')}:{row.get('test_id')}"
            for rows in (coverage_blocks, coverage_edges_out, coverage_edges_in, coverage_call_edges)
            for row in rows
            if row.get("suite") is not None and row.get("test_id") is not None
        }
    )
    return {
        "format": PRIVATE_ARTIFACT_FORMAT_VERSION,
        "artifact_role": "basic_block_dirty_context",
        "block": dict(block),
        "function": function,
        "static": {
            "incoming_cfg_edges": incoming_cfg_edges,
            "outgoing_cfg_edges": outgoing_cfg_edges,
            "call_edges": call_edges,
            "data_refs": data_refs,
            "waivers": waivers,
        },
        "dynamic": {
            "coverage_blocks": coverage_blocks,
            "incoming_coverage_edges": coverage_edges_in,
            "outgoing_coverage_edges": coverage_edges_out,
            "coverage_call_edges": coverage_call_edges,
            "covered_by_tests": covered_tests,
        },
        "static_context_summary": {
            "incoming_cfg_edges": len(incoming_cfg_edges),
            "outgoing_cfg_edges": len(outgoing_cfg_edges),
            "call_edges": len(call_edges),
            "data_refs": len(data_refs),
            "waivers": len(waivers),
        },
        "coverage_summary": {
            "covered": bool(coverage_blocks or coverage_edges_out or coverage_edges_in or coverage_call_edges),
            "coverage_blocks": len(coverage_blocks),
            "incoming_coverage_edges": len(coverage_edges_in),
            "outgoing_coverage_edges": len(coverage_edges_out),
            "coverage_call_edges": len(coverage_call_edges),
            "covered_by_tests": covered_tests,
        },
    }


def _block_semantic_payload(
    conn: sqlite3.Connection,
    binary_id: int,
    block: dict[str, Any],
    context: dict[str, Any],
) -> dict[str, Any]:
    semantic_rows = _rows(
        conn,
        """
        SELECT *
        FROM block_semantics
        WHERE basic_block_id = ?
        """,
        (int(block["id"]),),
    )
    if semantic_rows:
        row = semantic_rows[0]
        instructions = row.get("instructions") if isinstance(row.get("instructions"), list) else []
        pcode = row.get("pcode") if isinstance(row.get("pcode"), list) else []
        data_flow = row.get("data_flow") if isinstance(row.get("data_flow"), dict) else {}
        xrefs = row.get("xrefs") if isinstance(row.get("xrefs"), dict) else {}
        decompiler = row.get("decompiler_status") if isinstance(row.get("decompiler_status"), dict) else {}
        if not decompiler:
            decompiler = {"status": "not_available", "source": row.get("source") or "ghidra"}
        summary = str(row.get("semantic_summary") or "")
        if not summary:
            summary = _default_block_semantic_summary(block, context, instructions, pcode)
        return {
            "instructions": {
                "format": PRIVATE_ARTIFACT_FORMAT_VERSION,
                "artifact_role": "block_instruction_metadata",
                "items": instructions,
            },
            "pcode": {
                "format": PRIVATE_ARTIFACT_FORMAT_VERSION,
                "artifact_role": "block_pcode",
                "items": pcode,
                "taint_level": "decompiler_high_taint",
            },
            "data_flow": {
                "format": PRIVATE_ARTIFACT_FORMAT_VERSION,
                "artifact_role": "block_data_flow",
                "items": data_flow,
            },
            "xrefs": {
                "format": PRIVATE_ARTIFACT_FORMAT_VERSION,
                "artifact_role": "block_xrefs",
                "items": xrefs,
            },
            "decompiler": decompiler,
            "summary": summary,
        }

    fallback_decompiler = {
        "status": "not_available",
        "reason": "no Ghidra block semantic export was imported for this block",
        "expected_future_location": "static/decompiled.c or static/pcode.json",
    }
    return {
        "instructions": {
            "format": PRIVATE_ARTIFACT_FORMAT_VERSION,
            "artifact_role": "block_instruction_metadata",
            "items": [
                {
                    "rva_start": int(block["rva_start"]),
                    "rva_end": int(block["rva_end"]),
                    "status": "not_imported",
                    "source": "wincr-placeholder",
                }
            ],
        },
        "pcode": {
            "format": PRIVATE_ARTIFACT_FORMAT_VERSION,
            "artifact_role": "block_pcode",
            "items": [],
            "status": "not_available",
            "taint_level": "decompiler_high_taint",
        },
        "data_flow": {
            "format": PRIVATE_ARTIFACT_FORMAT_VERSION,
            "artifact_role": "block_data_flow",
            "items": {
                "data_refs": context["static"]["data_refs"],
                "call_edges": context["static"]["call_edges"],
            },
        },
        "xrefs": {
            "format": PRIVATE_ARTIFACT_FORMAT_VERSION,
            "artifact_role": "block_xrefs",
            "items": {
                "incoming_cfg_edges": context["static"]["incoming_cfg_edges"],
                "outgoing_cfg_edges": context["static"]["outgoing_cfg_edges"],
                "covered_by_tests": context["dynamic"]["covered_by_tests"],
            },
        },
        "decompiler": fallback_decompiler,
        "summary": _default_block_semantic_summary(block, context, [], []),
    }


def _default_block_semantic_summary(
    block: dict[str, Any],
    context: dict[str, Any],
    instructions: list[Any],
    pcode: list[Any],
) -> str:
    return (
        f"Block {block['label']} belongs to "
        f"{(context.get('function') or {}).get('label') or 'an unresolved routine'}; "
        f"instructions={len(instructions)} pcode_ops={len(pcode)} "
        f"covered_tests={len(context['dynamic']['covered_by_tests'])} "
        f"outgoing_cfg_edges={len(context['static']['outgoing_cfg_edges'])}."
    )


def _block_semantic_summary_markdown(manifest: dict[str, Any], semantic: dict[str, Any]) -> str:
    return "\n".join(
        [
            f"# Semantic Summary: {manifest['label']}",
            "",
            "Private dirty semantic summary. Rewrite into behavior before publication.",
            "",
            semantic["summary"],
            "",
            f"- Decompiler status: `{semantic['decompiler'].get('status', 'unknown')}`",
            f"- Instruction metadata: {len(semantic['instructions'].get('items', []))}",
            f"- P-code operations: {len(semantic['pcode'].get('items', []))}",
            f"- Covered tests: {len(manifest['coverage_summary'].get('covered_by_tests', []))}",
            "",
        ]
    )


def _routine_semantic_payload(conn: sqlite3.Connection, function_id: int) -> dict[str, Any]:
    rows = _rows(
        conn,
        """
        SELECT *
        FROM function_semantics
        WHERE function_id = ?
        """,
        (function_id,),
    )
    if rows:
        row = rows[0]
        decompiler = {
            "status": row.get("decompiler_status") or "not_available",
            "error": row.get("decompiler_error") or "",
            "source": row.get("source") or "ghidra",
            "has_decompiled_c": bool(row.get("decompiled_c")),
            "has_pcode": bool(row.get("pcode")),
        }
        summary = (
            f"Routine semantic export: variables={len(row.get('variables') or [])} "
            f"types={len(row.get('inferred_types') or {})} "
            f"strings={len(row.get('strings') or [])} "
            f"callsites={len(row.get('callsites') or [])} "
            f"instructions={len(row.get('instructions') or [])} "
            f"pcode_ops={len(row.get('pcode') or [])}."
        )
        return {
            "decompiler": decompiler,
            "decompiled_c": str(row.get("decompiled_c") or ""),
            "pcode": {
                "format": PRIVATE_ARTIFACT_FORMAT_VERSION,
                "artifact_role": "routine_pcode",
                "items": row.get("pcode") or [],
                "taint_level": "decompiler_high_taint",
            },
            "semantics": {
                "format": PRIVATE_ARTIFACT_FORMAT_VERSION,
                "artifact_role": "routine_semantics",
                "source": row.get("source"),
                "variables": row.get("variables") or [],
                "inferred_types": row.get("inferred_types") or {},
                "stack_refs": row.get("stack_refs") or [],
                "global_refs": row.get("global_refs") or [],
                "strings": row.get("strings") or [],
                "callsites": row.get("callsites") or [],
                "instructions": row.get("instructions") or [],
                "source_metadata": row.get("source") or {},
            },
            "summary": summary,
        }
    decompiler = {
        "status": "not_available",
        "reason": "no Ghidra function semantic export was imported for this routine",
        "expected_future_location": "static/decompiled.c or static/pcode.json",
    }
    return {
        "decompiler": decompiler,
        "decompiled_c": "",
        "pcode": {
            "format": PRIVATE_ARTIFACT_FORMAT_VERSION,
            "artifact_role": "routine_pcode",
            "items": [],
            "status": "not_available",
            "taint_level": "decompiler_high_taint",
        },
        "semantics": {
            "format": PRIVATE_ARTIFACT_FORMAT_VERSION,
            "artifact_role": "routine_semantics",
            "variables": [],
            "inferred_types": {},
            "stack_refs": [],
            "global_refs": [],
            "strings": [],
            "callsites": [],
            "instructions": [],
            "status": "not_available",
        },
        "summary": "No imported function semantic metadata is available; use CFG, disassembly, coverage, and review evidence.",
    }


def _function_rva_end(conn: sqlite3.Connection, binary_id: int, function_id: int, rva_start: int) -> int:
    block_end = conn.execute(
        "SELECT MAX(rva_end) AS rva_end FROM basic_blocks WHERE function_id = ?",
        (function_id,),
    ).fetchone()["rva_end"]
    if block_end is not None and int(block_end) > rva_start:
        return int(block_end)
    next_rva = conn.execute(
        """
        SELECT MIN(rva) AS rva
        FROM functions
        WHERE binary_id = ?
          AND rva > ?
        """,
        (binary_id, rva_start),
    ).fetchone()["rva"]
    if next_rva is not None and int(next_rva) > rva_start:
        return int(next_rva)
    return rva_start + 128


def _routine_coverage(conn: sqlite3.Connection, binary_id: int, rva_start: int, rva_end: int) -> dict[str, Any]:
    return {
        "blocks": _rows(
            conn,
            """
            SELECT cb.*, tr.test_id, tr.suite
            FROM coverage_blocks cb
            JOIN test_runs tr ON tr.id = cb.test_run_id
            WHERE cb.binary_id = ?
              AND cb.rva_start < ?
              AND cb.rva_end > ?
            ORDER BY tr.suite, tr.test_id, cb.rva_start
            """,
            (binary_id, rva_end, rva_start),
        ),
        "cfg_edges": _rows(
            conn,
            """
            SELECT ce.*, tr.test_id, tr.suite
            FROM coverage_edges ce
            JOIN test_runs tr ON tr.id = ce.test_run_id
            WHERE ce.binary_id = ?
              AND ce.from_rva >= ?
              AND ce.from_rva < ?
            ORDER BY tr.suite, tr.test_id, ce.from_rva, ce.to_rva
            """,
            (binary_id, rva_start, rva_end),
        ),
        "call_edges": _rows(
            conn,
            """
            SELECT cce.*, tr.test_id, tr.suite
            FROM coverage_call_edges cce
            JOIN test_runs tr ON tr.id = cce.test_run_id
            WHERE cce.binary_id = ?
              AND cce.caller_rva >= ?
              AND cce.caller_rva < ?
            ORDER BY tr.suite, tr.test_id, cce.caller_rva
            """,
            (binary_id, rva_start, rva_end),
        ),
    }


def _review_packet_title(entity_type: str, row: dict[str, Any]) -> str:
    if entity_type == "behavior_contract":
        return f"{row.get('contract_id', row['label'])}-v{row.get('version', '1')}"
    if entity_type in {"behavior_observation", "process_behavior_observation"}:
        return f"{row.get('contract_id', 'behavior')}-{row.get('test_id', row['label'])}"
    if entity_type == "internal_routine_contract":
        return f"{row.get('public_name', 'routine')}-{row.get('label', 'contract')}"
    if entity_type == "oracle_test_case":
        return f"{row.get('suite_id', 'oracle')}-{row.get('case_kind', 'case')}-{row.get('test_id', row['label'])}"
    if entity_type == "interface_test_case":
        symbol = row.get("symbol") or (f"ord-{row.get('ordinal')}" if row.get("ordinal") is not None else "unknown")
        return f"{row.get('dll', 'interface')}-{symbol}-{row.get('case_kind', 'case')}-{row.get('test_id', row['label'])}"
    if entity_type == "data_state_test_case":
        return f"{row.get('structure_kind', 'data')}-{row.get('data_structure_name', 'structure')}-{row.get('case_kind', 'case')}-{row.get('test_id', row['label'])}"
    if entity_type == "mutation_test_case":
        return f"{row.get('mutation_kind', 'mutation')}-{row.get('test_id', row['label'])}"
    if entity_type == "internal_harness":
        return f"{row.get('harness_id', 'harness')}-{row.get('target_label', row['label'])}"
    if entity_type == "internal_harness_run":
        return f"{row.get('harness_id', 'harness')}-{row.get('test_id', row['label'])}"
    return str(row["label"])


def _copy_or_reference_evidence(
    row: dict[str, Any],
    out_dir: Path,
    packet_dir: Path,
    add_artifact: Any,
    *,
    entity_label: str,
    entity_type: str,
    copy_raw_evidence: bool,
    max_raw_evidence_bytes: int,
) -> list[dict[str, Any]]:
    evidence_items: list[dict[str, Any]] = []
    evidence_dir = packet_dir / "evidence"
    for field, source in _collect_evidence_paths(row):
        info = _evidence_file_info(field, source, max_raw_evidence_bytes=max_raw_evidence_bytes)
        if copy_raw_evidence and info["copyable"]:
            evidence_dir.mkdir(parents=True, exist_ok=True)
            destination = _unique_evidence_destination(evidence_dir, source)
            shutil.copy2(source, destination)
            info["copied_path"] = destination.relative_to(out_dir).as_posix()
            add_artifact(
                destination,
                artifact_kind="review_raw_evidence",
                entity_label=entity_label,
                entity_type=entity_type,
                taint_level="behavioral_dirty",
                source_detail={"source_field": field, "original_path": str(source)},
            )
        evidence_items.append(info)
    return evidence_items


def _collect_evidence_paths(row: dict[str, Any]) -> list[tuple[str, Path]]:
    collected: list[tuple[str, Path]] = []
    seen: set[str] = set()

    def add(field: str, value: Any) -> None:
        if not isinstance(value, str) or not value.strip():
            return
        path = Path(value).expanduser()
        key = str(path)
        if key in seen:
            return
        seen.add(key)
        collected.append((field, path))

    for field in ("fixture_path", "trace_log", "source_log", "result_path", "stdout_path", "stderr_path", "expected_path"):
        add(field, row.get(field))

    for field, path in list(collected):
        if not path.is_file() or path.suffix.lower() not in {".json", ".jsonl"}:
            continue
        for nested_field, nested_path in _nested_evidence_paths(path):
            add(f"{field}.{nested_field}", nested_path)
    return collected


def _nested_evidence_paths(path: Path) -> list[tuple[str, str]]:
    try:
        data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except (OSError, json.JSONDecodeError):
        return []
    results: list[tuple[str, str]] = []

    def walk(value: Any, prefix: str = "") -> None:
        if isinstance(value, dict):
            for key, item in value.items():
                key_text = str(key)
                child_prefix = f"{prefix}.{key_text}" if prefix else key_text
                if key_text.endswith(("_path", "_log", "_file")) and isinstance(item, str):
                    results.append((child_prefix, item))
                else:
                    walk(item, child_prefix)
        elif isinstance(value, list):
            for index, item in enumerate(value):
                walk(item, f"{prefix}[{index}]")

    walk(data)
    return results


def _evidence_file_info(field: str, source: Path, *, max_raw_evidence_bytes: int) -> dict[str, Any]:
    info: dict[str, Any] = {
        "field": field,
        "original_path": str(source),
        "exists": source.exists(),
        "kind": "missing",
        "size": None,
        "sha256": None,
        "copyable": False,
        "copy_skip_reason": "missing",
    }
    if not source.exists():
        return info
    if source.is_dir():
        info.update({"kind": "directory", "copy_skip_reason": "directories are referenced, not copied"})
        return info
    if not source.is_file():
        info.update({"kind": "special", "copy_skip_reason": "not a regular file"})
        return info
    size = source.stat().st_size
    suffix = source.suffix.lower()
    info.update({"kind": "file", "size": size, "suffix": suffix})
    if size <= max_raw_evidence_bytes:
        info["sha256"] = sha256_file(source)
    if suffix not in COPYABLE_EVIDENCE_SUFFIXES:
        info["copy_skip_reason"] = "suffix is not in the conservative raw-evidence allowlist"
    elif size > max_raw_evidence_bytes:
        info["copy_skip_reason"] = f"file exceeds max_raw_evidence_bytes={max_raw_evidence_bytes}"
    else:
        info["copyable"] = True
        info["copy_skip_reason"] = None
    return info


def _unique_evidence_destination(evidence_dir: Path, source: Path) -> Path:
    suffix = source.suffix.lower() if source.suffix else ".raw"
    stem = slug(source.stem or source.name or "evidence")
    candidate = evidence_dir / f"{stem}{suffix}"
    if not candidate.exists():
        return candidate
    index = 2
    while True:
        candidate = evidence_dir / f"{stem}-{index}{suffix}"
        if not candidate.exists():
            return candidate
        index += 1


def _review_packet_index_markdown(packet: dict[str, Any]) -> str:
    lines = [
        f"# Dirty Review Packet: {packet['title']}",
        "",
        "Private dirty corpus packet. Use this as review input and rewrite it into clean behavioral facts before publication.",
        "",
        f"- Entity type: `{packet['entity_type']}`",
        f"- Label: `{packet['label']}`",
        f"- Category: `{packet['category']}`",
        f"- Taint: `{packet['taint_level']}`",
        f"- Review status: `{packet['review_status']}`",
        "",
        "## Files",
        "",
        "- `dirty.json`: full private row data and evidence references.",
        "- `clean-template.json`: blank clean-room derivation target.",
        "- `evidence/`: copied raw log/result sidecars when they are small allowlisted text-like files.",
        "",
        "## Raw Evidence",
        "",
    ]
    if not packet["raw_evidence"]:
        lines.append("- No file sidecars were recorded for this packet.")
    for item in packet["raw_evidence"]:
        copied = item.get("copied_path") or "not copied"
        lines.append(
            f"- `{item['field']}` `{item['original_path']}` exists={item['exists']} "
            f"kind={item['kind']} copied=`{copied}`"
        )
    lines.append("")
    return "\n".join(lines)


def _clean_derivation_template(packet: dict[str, Any]) -> dict[str, Any]:
    template = {
        "schema_version": 1,
        "source_dirty_packet_label": packet["label"],
        "source_dirty_packet_category": packet["category"],
        "entity_type": packet["entity_type"],
        "public_label": packet["label"],
        "taint_level": "clean_candidate",
        "review_status": "draft",
        "evidence_labels": [packet["label"]],
        "sanitized_name": "",
        "purpose_summary": "",
        "inputs": {},
        "outputs": {},
        "preconditions": [],
        "postconditions": [],
        "side_effects": [],
        "state_transitions": [],
        "fixtures": [],
        "test_vectors": [],
        "confidence": "low",
        "review_notes": [],
        "publication_decision": "not_reviewed",
    }
    template.update(_draft_clean_content(packet))
    return template


def _draft_clean_content(packet: dict[str, Any]) -> dict[str, Any]:
    row = packet.get("row", {})
    entity_type = str(packet.get("entity_type", ""))
    title = str(packet.get("title") or row.get("label") or packet.get("label") or "record")
    content: dict[str, Any] = {
        "sanitized_name": slug(title).replace("-", "_"),
        "purpose_summary": _draft_purpose_summary(entity_type, row, title),
        "confidence": _draft_confidence(row),
        "review_notes": [
            "Machine-generated clean-room draft from private dirty corpus metadata; review before publication."
        ],
    }
    if entity_type == "behavior_contract":
        contract = _public_value(row.get("contract") or {})
        content.update(
            {
                "contract_id": _public_value(row.get("contract_id")),
                "version": _public_value(row.get("version")),
                "title": _public_value(row.get("title")),
                "contract": contract,
                "inputs": {
                    "command_line": contract.get("command_line"),
                    "initial_state": contract.get("initial_state"),
                    "scenario_inputs": contract.get("scenario_inputs"),
                    "constants": contract.get("constants"),
                },
                "outputs": {
                    "json_transcript": contract.get("json_transcript"),
                    "projection": contract.get("projection"),
                    "rendering_contract": contract.get("rendering_contract"),
                },
                "state_transitions": _compact_list(contract.get("state_transition")),
                "fixtures": [_fixture_summary(row, packet)],
            }
        )
    elif entity_type == "behavior_observation":
        input_value = _public_value(row.get("input") or {})
        observed = _public_value(row.get("observed") or {})
        content.update(
            {
                "contract_id": _public_value(row.get("contract_id")),
                "test_id": _public_value(row.get("test_id")),
                "status": _public_value(row.get("status")),
                "inputs": input_value,
                "outputs": observed,
                "fixtures": [_fixture_summary(row, packet)],
                "test_vectors": [
                    {
                        "test_id": _public_value(row.get("test_id")),
                        "input": input_value,
                        "expected": observed,
                        "observed_sha256": row.get("observed_sha256"),
                    }
                ],
            }
        )
    elif entity_type == "process_behavior_observation":
        input_value = _public_process_input_value(row.get("input") or {})
        observed = _public_value(row.get("observed") or {})
        content.update(
            {
                "contract_id": _public_value(row.get("contract_id")),
                "test_id": _public_value(row.get("test_id")),
                "status": _public_value(row.get("status")),
                "inputs": input_value,
                "outputs": observed,
                "fixtures": [_fixture_summary(row, packet)],
                "test_vectors": [
                    {
                        "test_id": _public_value(row.get("test_id")),
                        "input": input_value,
                        "expected_process": observed,
                        "observed_sha256": row.get("observed_sha256"),
                    }
                ],
            }
        )
    elif entity_type == "internal_routine_contract":
        content.update(
            {
                "status": _public_value(row.get("review_status")),
                "test_id": _public_value(row.get("label")),
                "public_name": _public_value(row.get("public_name")),
                "purpose_summary": _public_value(row.get("purpose_summary")),
                "calling_convention": _public_value(row.get("calling_convention")),
                "signature": _public_value(row.get("signature")),
                "inputs": _public_value(row.get("input_shape") or {}),
                "outputs": _public_value(row.get("output_shape") or {}),
                "input_shape": _public_value(row.get("input_shape") or {}),
                "output_shape": _public_value(row.get("output_shape") or {}),
                "preconditions": _compact_list(row.get("preconditions")),
                "postconditions": _compact_list(row.get("postconditions")),
                "side_effects": _compact_list(row.get("side_effects")),
                "state_transitions": _compact_list(row.get("state_transitions")),
                "fixtures": _public_fixture_refs(row.get("fixtures")) or [_fixture_summary(row, packet)],
                "evidence_source": _public_value(row.get("evidence_source")),
                "confidence": _public_value(row.get("confidence")) or "low",
                "review_notes": [
                    "Machine-generated routine-contract draft; review evidence, taint, and expression leakage before publication."
                ],
            }
        )
    elif entity_type == "oracle_test_case":
        content.update(
            {
                "status": _public_value(row.get("status")),
                "test_id": _public_value(row.get("test_id")),
                "inputs": {
                    "suite_id": _public_value(row.get("suite_id")),
                    "case_kind": _public_value(row.get("case_kind")),
                    "test_id": _public_value(row.get("test_id")),
                },
                "outputs": {"status": _public_value(row.get("status"))},
                "fixtures": [_fixture_summary(row, packet)],
            }
        )
    elif entity_type == "interface_test_case":
        content.update(
            {
                "status": _public_value(row.get("status")),
                "test_id": _public_value(row.get("test_id")),
                "inputs": {
                    "endpoint": _endpoint_name(row),
                    "case_kind": _public_value(row.get("case_kind")),
                    "test_id": _public_value(row.get("test_id")),
                },
                "outputs": {"status": _public_value(row.get("status"))},
                "side_effects": [_public_value(row.get("evidence"))] if row.get("evidence") else [],
                "fixtures": [_fixture_summary(row, packet)],
            }
        )
    elif entity_type == "data_state_test_case":
        content.update(
            {
                "status": _public_value(row.get("status")),
                "test_id": _public_value(row.get("test_id")),
                "inputs": {
                    "data_structure": _public_value(row.get("data_structure_name")),
                    "structure_kind": _public_value(row.get("structure_kind")),
                    "case_kind": _public_value(row.get("case_kind")),
                    "test_id": _public_value(row.get("test_id")),
                },
                "outputs": {"status": _public_value(row.get("status"))},
                "fixtures": [_fixture_summary(row, packet)],
            }
        )
    elif entity_type == "mutation_test_case":
        content.update(
            {
                "status": _public_value(row.get("status")),
                "test_id": _public_value(row.get("test_id")),
                "inputs": {
                    "mutation_kind": _public_value(row.get("mutation_kind")),
                    "target_label": _public_value(row.get("target_label")),
                    "test_id": _public_value(row.get("test_id")),
                },
                "outputs": {"status": _public_value(row.get("status"))},
                "fixtures": [_fixture_summary(row, packet)],
            }
        )
    elif entity_type in {"internal_harness", "internal_harness_run"}:
        content.update(
            {
                "status": _public_value(row.get("status")),
                "test_id": _public_value(row.get("test_id")),
                "inputs": {
                    "harness_id": _public_value(row.get("harness_id")),
                    "harness_kind": _public_value(row.get("harness_kind")),
                    "target_label": _public_value(row.get("target_label")),
                    "test_id": _public_value(row.get("test_id")),
                },
                "outputs": {"status": _public_value(row.get("status"))},
                "fixtures": [_fixture_summary(row, packet)],
            }
        )
    return _drop_empty(_public_value(content))


def _draft_purpose_summary(entity_type: str, row: dict[str, Any], title: str) -> str:
    if entity_type == "behavior_contract":
        return _public_text(
            row.get("title") or f"Behavioral contract draft for {row.get('contract_id') or title}."
        )
    if entity_type == "behavior_observation":
        return _public_text(f"Observed JSON behavior for {row.get('contract_id') or 'behavior contract'} test {row.get('test_id')}.")
    if entity_type == "process_behavior_observation":
        return _public_text(f"Observed process behavior for {row.get('contract_id') or 'behavior contract'} test {row.get('test_id')}.")
    if entity_type == "internal_routine_contract":
        return _public_text(row.get("purpose_summary") or f"Internal routine contract draft for {row.get('public_name') or title}.")
    if entity_type == "oracle_test_case":
        return _public_text(f"Oracle test case {row.get('suite_id')}:{row.get('case_kind')}:{row.get('test_id')}.")
    if entity_type == "interface_test_case":
        return _public_text(f"Interface case {_endpoint_name(row)} {row.get('case_kind')} for test {row.get('test_id')}.")
    if entity_type == "data_state_test_case":
        return _public_text(f"Data/state case {row.get('structure_kind')} {row.get('case_kind')} for test {row.get('test_id')}.")
    if entity_type == "mutation_test_case":
        return _public_text(f"Mutation effectiveness case {row.get('mutation_kind')} for test {row.get('test_id')}.")
    if entity_type == "internal_harness":
        return _public_text(f"Internal harness draft for {row.get('harness_kind')} target {row.get('target_label')}.")
    if entity_type == "internal_harness_run":
        return _public_text(f"Internal harness run draft for test {row.get('test_id')}.")
    return _public_text(f"Clean-room draft for {title}.")


def _draft_confidence(row: dict[str, Any]) -> str:
    confidence = str(row.get("confidence") or "").lower()
    if confidence in {"low", "medium", "high"}:
        return confidence
    status = str(row.get("status") or "").lower()
    if status in {"pass", "killed"}:
        return "medium"
    if status in {"fail", "survived", "invalid"}:
        return "low"
    return "low"


def _fixture_summary(row: dict[str, Any], packet: dict[str, Any]) -> dict[str, Any]:
    raw_evidence = packet.get("raw_evidence") or []
    copied = [item for item in raw_evidence if item.get("copied_path")]
    return _drop_empty(
        {
            "label": packet.get("label"),
            "test_id": row.get("test_id"),
            "status": row.get("status"),
            "evidence": _public_summary_text(row.get("evidence")),
            "observed_sha256": row.get("observed_sha256"),
            "raw_evidence_files": len(raw_evidence),
            "copied_raw_evidence_files": len(copied),
        }
    )


def _public_fixture_refs(value: Any) -> list[Any]:
    if value is None or value == "":
        return []
    values = value if isinstance(value, list) else [value]
    refs: list[Any] = []
    for item in values:
        if isinstance(item, str):
            path = Path(item)
            if path.name:
                ref: dict[str, Any] = {"name": path.name}
                try:
                    if path.is_file():
                        ref["sha256"] = sha256_file(path)
                        ref["size"] = path.stat().st_size
                except OSError:
                    pass
                refs.append(ref)
            else:
                refs.append(_public_text(item))
        else:
            refs.append(_public_value(item))
    return _drop_empty(refs)


def _endpoint_name(row: dict[str, Any]) -> str:
    dll = row.get("dll") or "endpoint"
    symbol = row.get("symbol") if row.get("symbol") is not None else f"ord_{row.get('ordinal')}"
    return _public_text(f"{dll}!{symbol}")


def _public_value(value: Any) -> Any:
    if isinstance(value, dict):
        return _drop_empty({str(key): _public_value(item) for key, item in value.items()})
    if isinstance(value, list):
        return [_public_value(item) for item in value]
    if isinstance(value, tuple):
        return [_public_value(item) for item in value]
    if isinstance(value, str):
        return _public_text(value)
    return value


def _public_process_input_value(value: Any) -> Any:
    result = _public_value(value)
    if isinstance(value, dict) and "argv" in value and isinstance(result, dict) and "argv" not in result:
        result["argv"] = []
    return result


def _public_text(value: Any) -> str:
    from .util import public_text

    return public_text("" if value is None else value)


def _public_summary_text(value: Any) -> str:
    return _public_text(value).replace("[private path]", "private path redacted")


def _compact_list(value: Any) -> list[Any]:
    if value is None or value == "":
        return []
    if isinstance(value, list):
        return _public_value(value)
    return [_public_value(value)]


def _drop_empty(value: Any) -> Any:
    if isinstance(value, dict):
        result: dict[str, Any] = {}
        for key, item in value.items():
            cleaned = _drop_empty(item)
            if cleaned in ({}, [], None, "") and not (key == "argv" and cleaned == []):
                continue
            result[key] = cleaned
        return result
    if isinstance(value, list):
        return [_drop_empty(item) for item in value if _drop_empty(item) not in ({}, [], None, "")]
    return value


def _binary_source_path(metadata: dict[str, str], binary: dict[str, Any]) -> Path | None:
    install_root = metadata.get("install_root")
    if not install_root:
        return None
    candidate = Path(install_root) / str(binary["path"])
    return candidate if candidate.exists() else None


def _objdump_disassembly(
    source_path: Path | None,
    objdump: str,
    timeout_seconds: int,
    *,
    start_address: int | None = None,
    stop_address: int | None = None,
) -> str:
    if source_path is None:
        return "; source binary path is unavailable; disassembly not generated\n"
    command = [objdump, "-d", "--no-show-raw-insn"]
    if start_address is not None:
        command.append(f"--start-address=0x{start_address:x}")
    if stop_address is not None:
        command.append(f"--stop-address=0x{stop_address:x}")
    command.append(str(source_path))
    try:
        proc = subprocess.run(
            command,
            check=False,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=timeout_seconds,
        )
    except FileNotFoundError:
        return f"; disassembly tool not found: {objdump}\n"
    except subprocess.TimeoutExpired:
        return f"; disassembly timed out after {timeout_seconds} seconds: {' '.join(command)}\n"
    header = [
        "; PRIVATE DIRTY ARTIFACT: do not publish verbatim.",
        f"; command: {' '.join(command)}",
        f"; returncode: {proc.returncode}",
        "",
    ]
    return "\n".join(header) + proc.stdout


def _block_disassembly_from_module(
    module_disassembly: str | None,
    *,
    block: dict[str, Any],
    module: dict[str, Any],
    image_base: int,
) -> str:
    rva_start = int(block["rva_start"])
    rva_end = int(block["rva_end"])
    va_start = image_base + rva_start if image_base else rva_start
    va_end = image_base + rva_end if image_base else rva_end
    header = [
        "; PRIVATE DIRTY BASIC BLOCK DISASSEMBLY: do not publish verbatim.",
        f"; module: {module['path']}",
        f"; module_sha256: {module['sha256']}",
        f"; block_label: {block['label']}",
        f"; rva_range: 0x{rva_start:x}-0x{rva_end:x}",
        f"; va_range: 0x{va_start:x}-0x{va_end:x}",
        f"; source: {block['source']}",
        f"; classification: {block['classification']}",
        "",
    ]
    if not module_disassembly:
        return "\n".join(header + ["; module disassembly was not generated for this corpus.", ""])
    lines: list[str] = []
    for line in module_disassembly.splitlines():
        match = OBJDUMP_INSTRUCTION_RE.match(line)
        if not match:
            continue
        address = int(match.group(1), 16)
        if va_start <= address < va_end:
            lines.append(line)
    if not lines:
        lines.append("; no instruction lines were found for this block in the module disassembly.")
    return "\n".join(header + lines + [""])


def _root_index_markdown(manifest: dict[str, Any]) -> str:
    summary = manifest["summary"]
    return "\n".join(
        [
            "# Private Dirty Corpus",
            "",
            "This corpus is private review input. It may contain module hashes, RVAs, disassembly,",
            "raw trace evidence, and dirty inference notes. Do not publish it verbatim.",
            "",
            f"- Format: `{manifest['format']}`",
            f"- Artifact set: `{manifest['artifact_set_id']}`",
            f"- Generated at: `{manifest['generated_at']}`",
            f"- Target: `{manifest['target']['project_id']}`",
            f"- Modules: {summary['modules']}",
            f"- Functions: {summary['functions']}",
            f"- Basic blocks: {summary['basic_blocks']}",
            f"- CFG edges: {summary['cfg_edges']}",
            f"- Coverage blocks: {summary['coverage_blocks']}",
            "",
            "## Workbench",
            "",
            "- `reimplementation-plan.json` / `.md`: task-oriented rewrite bundles.",
            "- `cli-index.json`: label/search metadata for `wincr review-dirty-corpus`.",
            "- `review-html/index.html`: offline HTML review workbench.",
            "",
        ]
    )


def _module_index_markdown(manifest: dict[str, Any]) -> str:
    summary = manifest["summary"]
    return "\n".join(
        [
            f"# Module Packet: {manifest['filename']}",
            "",
            "Private dirty module dossier. It is intended for clean-spec derivation, not publication.",
            "",
            f"- Label: `{manifest['label']}`",
            f"- SHA256: `{manifest['sha256']}`",
            f"- Path: `{manifest['path']}`",
            f"- Scope: `{manifest['scope']}`",
            f"- Role: `{manifest['role']}`",
            f"- Image base: `{manifest['image_base']}`",
            f"- Entrypoint RVA: `{manifest['entrypoint_rva']}`",
            f"- Functions: {summary['functions']}",
            f"- Basic blocks: {summary['basic_blocks']}",
            f"- CFG edges: {summary['cfg_edges']}",
            f"- Imports: {summary['imports']}",
            "",
        ]
    )


def _block_index_markdown(manifest: dict[str, Any]) -> str:
    coverage = manifest["coverage_summary"]
    static = manifest["static_context_summary"]
    return "\n".join(
        [
            f"# Basic Block Packet: {manifest['label']}",
            "",
            "Private dirty basic-block dossier. Use this with neighboring block packets,",
            "routine context, dynamic coverage, and behavior fixtures to rewrite clean behavior.",
            "",
            f"- Module label: `{manifest['module_label']}`",
            f"- Module SHA256: `{manifest['module_sha256']}`",
            f"- Function label: `{manifest.get('function_label')}`",
            f"- RVA range: `0x{manifest['rva_start']:x}` - `0x{manifest['rva_end']:x}`",
            f"- Size: {manifest['size']}",
            f"- Source: `{manifest['source']}`",
            f"- Classification: `{manifest['classification']}`",
            f"- Confidence: `{manifest['confidence']}`",
            f"- Covered: `{coverage['covered']}` by {len(coverage['covered_by_tests'])} tests",
            f"- Static incoming CFG edges: {static['incoming_cfg_edges']}",
            f"- Static outgoing CFG edges: {static['outgoing_cfg_edges']}",
            f"- Static call edges: {static['call_edges']}",
            f"- Waivers overlapping block: {static['waivers']}",
            "",
            "## Files",
            "",
            "- `manifest.json`: private block identity and summaries.",
            "- `static/context.json`: static and dynamic edge/coverage context.",
            "- `static/disassembly.asm`: block-local assembly sliced from module objdump.",
            "- `static/decompiler-status.json`: records whether decompiler text is available.",
            "- `static/instructions.json`: private per-instruction metadata or explicit missing-tool status.",
            "- `static/pcode.json`: private p-code metadata when imported.",
            "- `static/data-flow.json`: block-local data-flow references.",
            "- `static/xrefs.json`: predecessor/successor, call, and coverage links.",
            "- `semantic-summary.md`: private rewrite-oriented summary and open context.",
            "- `draft/clean-template.json`: clean rewrite target for this block.",
            "",
        ]
    )


def _routine_index_markdown(packet: dict[str, Any]) -> str:
    return "\n".join(
        [
            f"# Routine Packet: {packet['label']}",
            "",
            "Private dirty routine dossier. Public contracts must be rewritten from behavior.",
            "",
            f"- Module label: `{packet['module_label']}`",
            f"- Module SHA256: `{packet['module_sha256']}`",
            f"- RVA range: `0x{packet['rva_start']:x}` - `0x{packet['rva_end']:x}`",
            f"- Name: `{packet['name']}`",
            f"- Source: `{packet['source']}`",
            f"- Calling convention: `{packet['calling_convention']}`",
            f"- Signature: `{packet['signature']}`",
            f"- Subsystem: `{packet['subsystem']}`",
            f"- Purity: `{packet['purity']}`",
            f"- Side effects: {packet['side_effects']}",
            f"- Contracts: {len(packet['contracts'])}",
            f"- Decompiler status: `{packet.get('decompiler', {}).get('status', 'unknown')}`",
            "",
            "## Files",
            "",
            "- `static/cfg.json`: routine CFG, calls, and data references.",
            "- `static/semantics.json`: private variables/types/strings/callsites/instruction metadata.",
            "- `static/decompiler-status.json`: decompiler availability or error status.",
            "- `static/pcode.json`: private routine p-code when available.",
            "- `dynamic/coverage.json`: covered blocks, CFG edges, and call edges.",
            "- `draft/dirty-contract.md`: dirty rewrite prompt for clean contract drafting.",
            "",
        ]
    )


def _dirty_contract_markdown(packet: dict[str, Any]) -> str:
    lines = [
        f"# Dirty Contract Draft: {packet['label']}",
        "",
        "Status: private dirty draft. This may include original labels, RVAs, and static-analysis",
        "inferences. Rewrite into a clean contract before publication.",
        "",
        "## Private Identity",
        "",
        f"- Module SHA256: `{packet['module_sha256']}`",
        f"- RVA start: `0x{packet['rva_start']:x}`",
        f"- RVA end: `0x{packet['rva_end']:x}`",
        f"- Static name: `{packet['name']}`",
        "",
        "## Draft Behavioral Summary",
        "",
        f"- Subsystem: `{packet['subsystem']}`",
        f"- Purity/state: `{packet['purity']}`",
        f"- Side effects: {packet['side_effects']}",
        f"- Calling convention: `{packet['calling_convention']}`",
        f"- Inferred signature: `{packet['signature']}`",
        f"- Confidence: `{packet['confidence']}`",
        f"- Test status: `{packet['test_status']}`",
        "",
        "## Sanitized Contract Candidates",
        "",
    ]
    if not packet["contracts"]:
        lines.append("- None recorded yet.")
    for contract in packet["contracts"]:
        lines.append(f"- `{contract['label']}` `{contract['public_name']}`")
        lines.append(f"  - review: `{contract['review_status']}` taint: `{contract['taint_level']}`")
        lines.append(f"  - purpose: {contract['purpose_summary']}")
    lines.append("")
    return "\n".join(lines)


def _block_clean_template(manifest: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "entity_type": "basic_block_contract",
        "source_dirty_packet_category": "basic-blocks",
        "source_dirty_packet_label": manifest["label"],
        "public_label": manifest["label"],
        "sanitized_name": slug(manifest["label"]),
        "purpose_summary": "Rewrite this private basic-block packet into clean behavioral statements before publication.",
        "inputs": {},
        "outputs": {},
        "preconditions": [],
        "postconditions": [],
        "side_effects": [],
        "state_transitions": [],
        "fixtures": [],
        "test_vectors": [],
        "confidence": manifest.get("confidence", "low"),
        "review_status": "draft",
        "taint_level": "clean_candidate",
        "publication_decision": "not_reviewed",
        "review_notes": [
            "Machine-generated basic-block rewrite target. Use disassembly and dynamic context only as private review input.",
            "Do not publish instruction listings, original control-flow expression, module hashes, or RVAs.",
        ],
    }


def _artifact_summary(artifacts: list[dict[str, Any]], binaries: list[dict[str, Any]]) -> dict[str, Any]:
    by_kind: dict[str, int] = {}
    by_taint: dict[str, int] = {}
    for artifact in artifacts:
        by_kind[str(artifact["artifact_kind"])] = by_kind.get(str(artifact["artifact_kind"]), 0) + 1
        by_taint[str(artifact["taint_level"])] = by_taint.get(str(artifact["taint_level"]), 0) + 1
    return {
        "modules": len(binaries),
        "artifacts": len(artifacts),
        "by_kind": by_kind,
        "by_taint_level": by_taint,
    }
