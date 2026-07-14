from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import stat
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

from .relational.reference_contract import (
    REFERENCE_CONTRACT_MODEL_ID,
    stage_a_smoke_contract,
)
from .stage_b_contract import (
    stage_b_extract_work_items,
    stage_b_contract_coverage,
    stage_b_check_contract,
    stage_b_check_unit,
)
from .stage_b import stage_b_explain_delta, stage_b_validate_candidate
from .stage_b_provenance import stage_b_generate_candidate_provenance
from .util import sha256_file, write_json, utc_now


WORKSPACE_FORMAT = "wincr-slice-workspace-v1"
PREPARE_FORMAT = "wincr-slice-prepare-v1"
NEXT_FORMAT = "wincr-slice-next-v1"
BUILD_FORMAT = "wincr-slice-build-v1"
CHECK_FORMAT = "wincr-slice-check-v1"
FOCUSED_DELTA_FORMAT = "wincr-slice-focused-delta-v1"
CANDIDATE_VALIDATION_FINGERPRINT_FORMAT = "wincr-slice-candidate-validation-fingerprint-v1"
CANDIDATE_VALIDATION_CACHE_FORMAT = "wincr-slice-candidate-validation-cache-v1"
SLICE_PACKET_FORMAT = "wincr-slice-packet-v1"
SLICE_PACKET_INDEX_FORMAT = "wincr-slice-packet-index-v1"

DEFAULT_WORK_DIR = Path("build/wincr-slices")
CONCRETE_SOURCE_KINDS = frozenset(
    {
        "decompiled_function",
        "generated_contract_guided_branch",
        "generated_contract_guided_callback",
        "generated_contract_guided_bytecode",
        "generated_contract_guided_flow",
        "generated_contract_guided_indirect",
        "generated_contract_guided_leaf",
        "generated_checked_semantic_region",
        "generated_helper_from_decompiler_section_gap",
        "generated_runtime_bridge",
    }
)

TARGET_DEFAULTS: dict[str, dict[str, Any]] = {
    "jq": {
        "stage_a_check_attr": "stage-a-jq-fixtures-check",
        "skeleton_attr": "stage-b-jq-skeleton",
        "final_check_attrs": [
            "stage-a-jq-fixtures-check",
            "stage-b-jq-skeleton",
        ],
        "stage_a_check_reference_contract": Path("generated/jq-reference-contract.json"),
        "stage_a_check_unit_contract_dir": Path("generated"),
        "skeleton_root_dir": Path("share/wincr/stage-b/jq/skeleton"),
        "candidate_root_dir": Path("share/wincr/stage-b/jq/generated-closure-candidate"),
        "candidate_exe": "jq-stage-b-generated-closure-candidate.exe",
        "candidate_map": "jq-stage-b-generated-closure-candidate.map",
        "skeleton_manifest": "skeleton-manifest.json",
        "candidate_provenance": "candidate-provenance.json",
        "build_report": "decompiled-c-generated-closure-link-report.json",
        "build_target": "i686-w64-mingw32",
        "build_compiler": "i686-w64-mingw32-cc",
        "build_command_json": [
            "bash",
            "-lc",
            'exec "$WINCR_SLICE_REPO_ROOT/tools/wincr-build-jq-candidate.sh"',
        ],
        "candidate_modules": [
            {
                "name": "libjq-1.dll",
                "candidate": "libjq-1.dll",
                "linker_map": "libjq-1.generated-closure.link.map",
                "skeleton_manifest": "libjq-1-skeleton-manifest.json",
            }
        ],
    }
}


class SliceLoopInputError(Exception):
    pass


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="wincr-slice",
        description="Local Stage B slice iteration loop backed by cached Stage A contracts.",
    )
    parser.add_argument("--work-dir", type=Path, default=DEFAULT_WORK_DIR, help="local hot-loop workspace root")
    subcommands = parser.add_subparsers(dest="command", required=True)

    prepare = subcommands.add_parser("prepare", help="materialize cached Stage A/B artifacts for local slice work")
    prepare.add_argument("target", help="target name, e.g. jq")
    prepare.add_argument("--stage-a-check-root", type=Path, help="realized stage-a check output root")
    prepare.add_argument("--candidate-root", type=Path, help="realized candidate package output root")
    prepare.add_argument("--skeleton-root", type=Path, help="realized source-only skeleton root")
    prepare.add_argument("--reference-contract", type=Path, help="explicit stage-a-reference-contract-v1 path")
    prepare.add_argument("--unit-contract-dir", type=Path, help="explicit Stage A unit-contract sidecar directory")
    prepare.add_argument("--candidate-dir", type=Path, help="explicit candidate artifact directory")
    prepare.add_argument("--target-closure-manifest", type=Path, help="optional target closure manifest for regenerated provenance")
    prepare.add_argument("--build-command", help="shell command used by wincr-slice build")
    prepare.add_argument("--build-command-json", help="JSON argv list used by wincr-slice build")
    prepare.add_argument("--nix-flake", default=".", help="flake reference used with --realize-nix")
    prepare.add_argument("--realize-nix", action="store_true", help="realize canonical roots with nix build --no-link")
    prepare.add_argument("--force", action="store_true", help="replace local copied candidate source")
    prepare.add_argument("--no-copy-candidate-source", action="store_true")
    prepare.set_defaults(func=_cmd_prepare)

    next_work = subcommands.add_parser("next", help="list ranked Stage A work items for the prepared target")
    next_work.add_argument("target")
    next_work.add_argument("--top-k", type=int, default=20)
    next_work.add_argument("--family")
    next_work.add_argument("--focus")
    next_work.add_argument(
        "--source-progress-class",
        action="append",
        choices=["concrete", "placeholder", "boundary", "omitted", "other", "no-anchor"],
        help="filter work items by annotated Stage B source progress class",
    )
    next_work.add_argument(
        "--todo-only",
        action="store_true",
        help="show only source gaps that still need Stage B implementation work",
    )
    next_work.add_argument(
        "--group-by",
        choices=["function", "pattern", "source-kind"],
        help="summarize matched work items by an implementation-relevant grouping",
    )
    next_work.add_argument("--json", action="store_true", help="print machine-readable JSON")
    next_work.add_argument("--out", type=Path, help="optional output JSON path")
    next_work.set_defaults(func=_cmd_next)

    build = subcommands.add_parser("build", help="run a local candidate rebuild command outside the Nix sandbox")
    build.add_argument("target")
    build.add_argument("--region", "--focus", dest="focus", default="all")
    build.add_argument("--command", help="shell command to run")
    build.add_argument("--command-json", help="JSON argv list to run")
    build.add_argument("--timeout-seconds", type=float)
    build.add_argument("--dry-run", action="store_true")
    build.add_argument("--candidate", type=Path, help="candidate executable produced by the build command")
    build.add_argument("--linker-map-candidate", type=Path, help="candidate linker map produced by the build command")
    build.add_argument("--skeleton-manifest", type=Path, help="candidate skeleton manifest produced by the build command")
    build.add_argument("--candidate-provenance", type=Path, help="candidate provenance produced by the build command")
    build.add_argument("--build-report", type=Path, help="build report produced by the build command")
    build.set_defaults(func=_cmd_build)

    check = subcommands.add_parser("check", help="run focused local Stage A-contract validation for a candidate")
    check.add_argument("target")
    check.add_argument("--region", "--focus", dest="focus")
    check.add_argument("--mode", choices=["fast", "full"], default="fast")
    check.add_argument("--candidate", type=Path)
    check.add_argument("--linker-map-candidate", type=Path)
    check.add_argument("--skeleton-manifest", type=Path)
    check.add_argument("--candidate-provenance", type=Path)
    check.add_argument("--build-report", type=Path)
    check.add_argument("--target-closure-manifest", type=Path)
    check.add_argument("--candidate-module", action="append", default=[])
    check.add_argument("--candidate-crash-report", type=Path)
    check.add_argument("--candidate-probe-report", type=Path)
    check.add_argument("--functional-report", type=Path)
    check.add_argument("--build-target")
    check.add_argument("--build-compiler")
    check.add_argument("--skip-delta", action="store_true")
    check.add_argument("--refresh-validation", action="store_true", help="recompute the cached Stage A candidate validation")
    check.add_argument("--no-cache", action="store_true", help="do not read or write the local Stage A candidate-validation cache")
    check.add_argument(
        "--write-full-delta",
        action="store_true",
        help="write the full Stage B delta even when --region/--focus is selected",
    )
    check.add_argument("--canonical-nix", action="store_true", help="also run canonical Nix gate attrs in full mode")
    check.add_argument("--nix-flake", default=".")
    check.add_argument("--json", action="store_true")
    check.set_defaults(func=_cmd_check)

    args = parser.parse_args(argv)
    try:
        return int(args.func(args))
    except SliceLoopInputError as exc:
        print(f"wincr-slice: {exc}", file=sys.stderr)
        return 2


def _cmd_prepare(args: Any) -> int:
    result = prepare_workspace(
        target=args.target,
        work_dir=args.work_dir,
        stage_a_check_root=args.stage_a_check_root,
        candidate_root=args.candidate_root,
        skeleton_root=args.skeleton_root,
        reference_contract=args.reference_contract,
        unit_contract_dir=args.unit_contract_dir,
        candidate_dir=args.candidate_dir,
        target_closure_manifest=args.target_closure_manifest,
        build_command=args.build_command,
        build_command_json=args.build_command_json,
        nix_flake=args.nix_flake,
        realize_nix=args.realize_nix,
        copy_candidate_source=not args.no_copy_candidate_source,
        force=args.force,
    )
    _print_json(result)
    return 0 if result["status"] == "pass" else 1


def _cmd_next(args: Any) -> int:
    result = slice_next(
        target=args.target,
        work_dir=args.work_dir,
        top_k=args.top_k,
        family=args.family,
        focus=args.focus,
        source_progress_classes=args.source_progress_class,
        todo_only=args.todo_only,
        group_by=args.group_by,
        out=args.out,
    )
    if args.json:
        _print_json(result)
    else:
        _print_next_table(result)
    return 0 if result["status"] == "pass" else 1


def _cmd_build(args: Any) -> int:
    result = slice_build(
        target=args.target,
        work_dir=args.work_dir,
        focus=args.focus,
        command=args.command,
        command_json=args.command_json,
        timeout_seconds=args.timeout_seconds,
        dry_run=args.dry_run,
        candidate=args.candidate,
        linker_map_candidate=args.linker_map_candidate,
        skeleton_manifest=args.skeleton_manifest,
        candidate_provenance=args.candidate_provenance,
        build_report=args.build_report,
    )
    _print_json(result)
    return 0 if result["status"] in {"pass", "not_run"} else 1


def _cmd_check(args: Any) -> int:
    result = slice_check(
        target=args.target,
        work_dir=args.work_dir,
        focus=args.focus,
        mode=args.mode,
        candidate=args.candidate,
        linker_map_candidate=args.linker_map_candidate,
        skeleton_manifest=args.skeleton_manifest,
        candidate_provenance=args.candidate_provenance,
        build_report=args.build_report,
        target_closure_manifest=args.target_closure_manifest,
        candidate_module_args=args.candidate_module,
        candidate_crash_report=args.candidate_crash_report,
        candidate_probe_report=args.candidate_probe_report,
        functional_report=args.functional_report,
        build_target=args.build_target,
        build_compiler=args.build_compiler,
        skip_delta=args.skip_delta,
        refresh_validation=args.refresh_validation,
        use_cache=not args.no_cache,
        write_full_delta=args.write_full_delta,
        canonical_nix=args.canonical_nix,
        nix_flake=args.nix_flake,
    )
    if args.json:
        _print_json(result)
    else:
        _print_check_summary(result)
    return 0 if result["status"] == "pass" else 1


def prepare_workspace(
    *,
    target: str,
    work_dir: Path,
    stage_a_check_root: Path | None = None,
    candidate_root: Path | None = None,
    skeleton_root: Path | None = None,
    reference_contract: Path | None = None,
    unit_contract_dir: Path | None = None,
    candidate_dir: Path | None = None,
    target_closure_manifest: Path | None = None,
    build_command: str | None = None,
    build_command_json: str | None = None,
    nix_flake: str = ".",
    realize_nix: bool = False,
    copy_candidate_source: bool = True,
    force: bool = False,
) -> dict[str, Any]:
    defaults = _target_defaults(target)
    workspace = _workspace_dir(work_dir, target)
    workspace.mkdir(parents=True, exist_ok=True)
    logs_dir = workspace / "logs"
    logs_dir.mkdir(parents=True, exist_ok=True)

    realized: dict[str, Any] = {}
    if realize_nix:
        if reference_contract is None and stage_a_check_root is None and defaults.get("stage_a_check_attr"):
            stage_a_check_root = _nix_realize(
                flake=nix_flake,
                attr=str(defaults["stage_a_check_attr"]),
                logs_dir=logs_dir,
                label="stage-a-check-root",
            )
            realized["stage_a_check_root"] = str(stage_a_check_root)
        if candidate_dir is None and candidate_root is None and defaults.get("candidate_attr"):
            candidate_root = _nix_realize(
                flake=nix_flake,
                attr=str(defaults["candidate_attr"]),
                logs_dir=logs_dir,
                label="candidate-root",
            )
            realized["candidate_root"] = str(candidate_root)
        if skeleton_root is None and defaults.get("skeleton_attr"):
            realized_skeleton = _nix_realize(
                flake=nix_flake,
                attr=str(defaults["skeleton_attr"]),
                logs_dir=logs_dir,
                label="skeleton-root",
            )
            realized["skeleton_package_root"] = str(realized_skeleton)
            skeleton_root = Path(realized_skeleton) / Path(defaults.get("skeleton_root_dir") or ".")

    if reference_contract is None:
        if stage_a_check_root is None:
            raise SliceLoopInputError(
                "prepare requires --reference-contract, --stage-a-check-root, or --realize-nix for a known target"
            )
        reference_contract = Path(stage_a_check_root) / Path(defaults["stage_a_check_reference_contract"])
    if unit_contract_dir is None and stage_a_check_root is not None:
        unit_contract_dir = Path(stage_a_check_root) / Path(defaults["stage_a_check_unit_contract_dir"])
    if candidate_dir is None and candidate_root is not None:
        candidate_dir = Path(candidate_root) / Path(defaults["candidate_root_dir"])

    reference_contract = _require_file(Path(reference_contract), "reference contract")
    if unit_contract_dir is not None:
        unit_contract_dir = _require_dir(Path(unit_contract_dir), "unit-contract directory")
    if candidate_dir is not None:
        candidate_dir = _require_dir(Path(candidate_dir), "candidate directory")
    if skeleton_root is not None:
        skeleton_root = _require_dir(Path(skeleton_root), "skeleton root")
    if target_closure_manifest is not None:
        target_closure_manifest = _require_file(Path(target_closure_manifest), "target closure manifest")

    contracts_dir = workspace / "contracts"
    contracts_dir.mkdir(parents=True, exist_ok=True)
    cached_reference_contract = contracts_dir / "reference_contract.json"
    _link_or_copy(reference_contract, cached_reference_contract)
    _cache_reference_contract_sidecars(reference_contract, contracts_dir)
    cached_unit_contract_dir: Path | None = contracts_dir

    candidate = _candidate_artifacts(candidate_dir, defaults) if candidate_dir is not None else {}
    source_skeleton = _skeleton_artifacts(skeleton_root) if skeleton_root is not None else {}
    if source_skeleton:
        if not candidate:
            candidate.update(source_skeleton)
        else:
            for key, value in source_skeleton.items():
                candidate.setdefault(key, value)
    if candidate.get("source_dir") and copy_candidate_source:
        local_source_dir = workspace / "candidate" / "src"
        _copytree_once(Path(candidate["source_dir"]), local_source_dir, force=force)
        candidate["local_source_dir"] = str(local_source_dir)
    candidate["out_dir"] = str(workspace / "candidate" / "out")
    candidate["build_dir"] = str(workspace / "builds")
    (workspace / "candidate" / "out").mkdir(parents=True, exist_ok=True)
    (workspace / "builds").mkdir(parents=True, exist_ok=True)

    manifest = {
        "format": WORKSPACE_FORMAT,
        "target": target,
        "prepared_at": utc_now(),
        "workspace": str(workspace),
        "repo_root": str(Path.cwd()),
        "policy": {
            "stage_a_contract_first": True,
            "original_runtime_tracing": False,
            "candidate_runtime_tracing": "candidate_only_after_stage_a_pass",
            "acceptance": "canonical Stage A/B Nix gates still decide final compliance",
        },
        "nix": {
            "flake": nix_flake,
            "realized": realized,
            "attrs": {
                "stage_a_check": defaults.get("stage_a_check_attr"),
                "candidate": defaults.get("candidate_attr"),
                "skeleton": defaults.get("skeleton_attr"),
                "final_checks": defaults.get("final_check_attrs", []),
            },
        },
        "reference_contract": _artifact(reference_contract),
        "unit_contract_dir": None if unit_contract_dir is None else {"path": str(unit_contract_dir)},
        "cached": {
            "reference_contract": str(cached_reference_contract),
            "unit_contract_dir": None if cached_unit_contract_dir is None else str(cached_unit_contract_dir),
        },
        "current_candidate": candidate,
        "source_skeleton": source_skeleton or None,
        "build": {
            "command": build_command,
            "command_json": _parse_command_json(build_command_json)
            if build_command_json
            else list(defaults.get("build_command_json") or []),
            "target": defaults.get("build_target"),
            "compiler": defaults.get("build_compiler"),
        },
        "target_closure_manifest": None if target_closure_manifest is None else _artifact(target_closure_manifest),
    }
    write_json(_manifest_path(workspace), manifest)
    if candidate:
        write_json(_current_candidate_path(workspace), candidate)

    smoke = stage_a_smoke_contract(reference_contract=cached_reference_contract, out=contracts_dir / "contract-smoke.json")
    semantic = stage_b_contract_coverage(
        reference_contract=cached_reference_contract,
        unit_contract_dir=cached_unit_contract_dir,
        out=contracts_dir / "semantic-coverage.json",
    )
    work_items = stage_b_extract_work_items(
        reference_contract=cached_reference_contract,
        unit_contract_dir=cached_unit_contract_dir,
        out=contracts_dir / "work-items.json",
    )
    source_progress, source_anchors = _slice_source_progress(workspace, candidate, manifest)
    packet_index = _write_slice_packets(
        workspace=workspace,
        target=target,
        work_items=work_items,
        current_candidate=candidate,
        source_anchors=source_anchors,
    )
    if packet_index:
        manifest["cached"]["slice_packet_index"] = packet_index["path"]
        write_json(_manifest_path(workspace), manifest)

    result = {
        "format": PREPARE_FORMAT,
        "status": "pass" if smoke.get("status") == "pass" else "incomplete",
        "target": target,
        "workspace": str(workspace),
        "manifest": str(_manifest_path(workspace)),
        "reference_contract": str(cached_reference_contract),
        "unit_contract_dir": None if cached_unit_contract_dir is None else str(cached_unit_contract_dir),
        "candidate": candidate or None,
        "contract_smoke": {"status": smoke.get("status"), "path": str(contracts_dir / "contract-smoke.json")},
        "semantic_coverage": {"status": semantic.get("status"), "path": str(contracts_dir / "semantic-coverage.json")},
        "work_items": {
            "status": work_items.get("status"),
            "path": str(contracts_dir / "work-items.json"),
            "count": int(work_items.get("counts", {}).get("work_items", 0)),
        },
        "source_progress": {
            "status": source_progress.get("status"),
            "counts": source_progress.get("counts", {}),
        },
        "slice_packets": None
        if not packet_index
        else {
            "path": packet_index["path"],
            "count": packet_index.get("counts", {}).get("packets", 0),
            "by_pattern_family": packet_index.get("counts", {}).get("by_pattern_family", {}),
        },
        "next_action": "run wincr-slice next or wincr-slice check --region <id>",
    }
    write_json(workspace / "prepare.json", result)
    return result


def slice_next(
    *,
    target: str,
    work_dir: Path,
    top_k: int = 20,
    family: str | None = None,
    focus: str | None = None,
    source_progress_classes: list[str] | None = None,
    todo_only: bool = False,
    group_by: str | None = None,
    out: Path | None = None,
) -> dict[str, Any]:
    workspace = _workspace_dir(work_dir, target)
    manifest = _load_manifest(workspace)
    source_progress, source_anchors = _slice_source_progress(workspace, _load_current_candidate(workspace), manifest)
    work_items_path = workspace / "contracts" / "work-items.json"
    semantic_path = workspace / "contracts" / "semantic-coverage.json"
    items: list[dict[str, Any]] = []
    source = ""
    if work_items_path.exists():
        payload = _load_json(work_items_path)
        raw_items = payload.get("work_items") if isinstance(payload, dict) else []
        items = [item for item in raw_items if isinstance(item, dict)]
        source = str(work_items_path)
    elif semantic_path.exists():
        payload = _load_json(semantic_path)
        raw_items = payload.get("next_work") if isinstance(payload, dict) else []
        items = [item for item in raw_items if isinstance(item, dict)]
        source = str(semantic_path)
    else:
        raise SliceLoopInputError("workspace has no cached work-items.json or semantic-coverage.json; run prepare first")

    items = _slice_work_items_with_source_gaps(items, source_anchors)
    if family:
        family_lower = family.lower()
        items = [item for item in items if str(item.get("family") or item.get("category") or "").lower() == family_lower]
    if focus:
        focus_lower = focus.lower()
        items = [item for item in items if _matches_focus(item, focus_lower)]
    annotated_items = [_annotate_work_item_source_progress(item, source_anchors) for item in items]
    packet_index = _load_slice_packet_index(workspace)
    if packet_index:
        annotated_items = [_annotate_work_item_packet(item, packet_index) for item in annotated_items]
    source_class_filter = _source_progress_class_filter(source_progress_classes, todo_only=todo_only)
    if source_class_filter is not None:
        annotated_items = [
            item for item in annotated_items if _work_item_source_progress_class(item) in source_class_filter
        ]
    limited = annotated_items[: max(0, top_k)]
    status = "pass" if limited or (todo_only and not annotated_items) else "incomplete"
    result = {
        "format": NEXT_FORMAT,
        "status": status,
        "target": target,
        "workspace": str(workspace),
        "source": source,
        "source_progress": source_progress,
        "filters": {
            "family": family,
            "focus": focus,
            "source_progress_class": source_progress_classes or [],
            "todo_only": todo_only,
            "group_by": group_by,
            "top_k": top_k,
        },
        "items": limited,
        "groups": _slice_next_groups(annotated_items, group_by),
        "packet_index": packet_index.get("path") if packet_index else None,
        "counts": {"matched": len(annotated_items), "returned": len(limited)},
    }
    if out is not None:
        write_json(out, result)
    else:
        write_json(workspace / "next.json", result)
    return result


def slice_build(
    *,
    target: str,
    work_dir: Path,
    focus: str = "all",
    command: str | None = None,
    command_json: str | None = None,
    timeout_seconds: float | None = None,
    dry_run: bool = False,
    candidate: Path | None = None,
    linker_map_candidate: Path | None = None,
    skeleton_manifest: Path | None = None,
    candidate_provenance: Path | None = None,
    build_report: Path | None = None,
) -> dict[str, Any]:
    workspace = _workspace_dir(work_dir, target)
    manifest = _load_manifest(workspace)
    defaults = _target_defaults(target)
    safe_focus = _safe_name(focus or "all")
    build_dir = workspace / "builds" / safe_focus / "current"
    out_dir = workspace / "candidate" / "out"
    out_dir.mkdir(parents=True, exist_ok=True)
    build_dir.mkdir(parents=True, exist_ok=True)

    argv = _command_argv(command_json) if command_json else None
    shell_command = command
    if argv is None and shell_command is None:
        build_defaults = manifest.get("build") if isinstance(manifest.get("build"), dict) else {}
        default_argv = build_defaults.get("command_json")
        default_command = build_defaults.get("command")
        if isinstance(default_argv, list) and all(isinstance(item, str) for item in default_argv):
            argv = list(default_argv)
        elif isinstance(default_command, str) and default_command:
            shell_command = default_command

    report_path = build_dir / "build.json"
    stdout_path = build_dir / "stdout.txt"
    stderr_path = build_dir / "stderr.txt"
    command_info = {
        "argv": argv,
        "shell": shell_command,
        "timeout_seconds": timeout_seconds,
        "dry_run": dry_run,
    }
    if argv is None and shell_command is None:
        result = {
            "format": BUILD_FORMAT,
            "status": "incomplete",
            "target": target,
            "focus": focus,
            "workspace": str(workspace),
            "build_dir": str(build_dir),
            "out_dir": str(out_dir),
            "command": command_info,
            "blocker": "no local build command configured",
            "next_action": "rerun prepare with --build-command-json or pass wincr-slice build --command-json",
        }
        write_json(report_path, result)
        return result

    env = os.environ.copy()
    env.update(
        {
            "WINCR_SLICE_TARGET": target,
            "WINCR_SLICE_FOCUS": focus,
            "WINCR_SLICE_WORKSPACE": str(workspace),
            "WINCR_SLICE_BUILD_DIR": str(build_dir),
            "WINCR_SLICE_OUT_DIR": str(out_dir),
            "WINCR_SLICE_SOURCE_DIR": str(workspace / "candidate" / "src"),
            "WINCR_SLICE_REPO_ROOT": str(manifest.get("repo_root") or Path.cwd()),
        }
    )
    if dry_run:
        result = {
            "format": BUILD_FORMAT,
            "status": "not_run",
            "target": target,
            "focus": focus,
            "workspace": str(workspace),
            "build_dir": str(build_dir),
            "out_dir": str(out_dir),
            "command": command_info,
            "environment": _slice_env_summary(env),
        }
        write_json(report_path, result)
        return result

    started = time.monotonic()
    if argv is not None:
        proc = subprocess.run(
            argv,
            cwd=build_dir,
            env=env,
            check=False,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout_seconds,
        )
    else:
        proc = subprocess.run(
            shell_command or "",
            cwd=build_dir,
            env=env,
            shell=True,
            check=False,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout_seconds,
        )
    elapsed = time.monotonic() - started
    stdout_path.write_text(proc.stdout, encoding="utf-8")
    stderr_path.write_text(proc.stderr, encoding="utf-8")

    candidate_info = _build_candidate_info(
        target=target,
        defaults=defaults,
        out_dir=out_dir,
        fallback=_load_current_candidate(workspace),
        candidate=candidate,
        linker_map_candidate=linker_map_candidate,
        skeleton_manifest=skeleton_manifest,
        candidate_provenance=candidate_provenance,
        build_report=build_report,
    )
    missing = [
        label
        for label, value in (
            ("candidate", candidate_info.get("candidate")),
            ("linker_map", candidate_info.get("linker_map")),
            ("skeleton_manifest", candidate_info.get("skeleton_manifest")),
        )
        if not value or not Path(str(value)).exists()
    ]
    status = "pass" if proc.returncode == 0 and not missing else "incomplete"
    candidate_info["source"] = "local-build"
    candidate_info["build_invocation"] = str(report_path)
    write_json(_current_candidate_path(workspace), candidate_info)
    result = {
        "format": BUILD_FORMAT,
        "status": status,
        "target": target,
        "focus": focus,
        "workspace": str(workspace),
        "build_dir": str(build_dir),
        "out_dir": str(out_dir),
        "command": command_info,
        "returncode": proc.returncode,
        "elapsed_seconds": round(elapsed, 3),
        "stdout": str(stdout_path),
        "stderr": str(stderr_path),
        "candidate": candidate_info,
        "missing_outputs": missing,
        "next_action": "run wincr-slice check --region <id>" if status == "pass" else "fix the local build outputs before running contract checks",
    }
    write_json(report_path, result)
    return result


def slice_check(
    *,
    target: str,
    work_dir: Path,
    focus: str | None = None,
    mode: str = "fast",
    candidate: Path | None = None,
    linker_map_candidate: Path | None = None,
    skeleton_manifest: Path | None = None,
    candidate_provenance: Path | None = None,
    build_report: Path | None = None,
    target_closure_manifest: Path | None = None,
    candidate_module_args: list[str] | tuple[str, ...] = (),
    candidate_crash_report: Path | None = None,
    candidate_probe_report: Path | None = None,
    functional_report: Path | None = None,
    build_target: str | None = None,
    build_compiler: str | None = None,
    skip_delta: bool = False,
    refresh_validation: bool = False,
    use_cache: bool = True,
    write_full_delta: bool = False,
    canonical_nix: bool = False,
    nix_flake: str = ".",
) -> dict[str, Any]:
    workspace = _workspace_dir(work_dir, target)
    manifest = _load_manifest(workspace)
    defaults = _target_defaults(target)
    paths = _contract_paths(manifest, workspace)
    current = _load_current_candidate(workspace)
    candidate_info = _build_candidate_info(
        target=target,
        defaults=defaults,
        out_dir=workspace / "candidate" / "out",
        fallback=current,
        candidate=candidate,
        linker_map_candidate=linker_map_candidate,
        skeleton_manifest=skeleton_manifest,
        candidate_provenance=candidate_provenance,
        build_report=build_report,
    )
    if target_closure_manifest is None:
        stored_target_closure = manifest.get("target_closure_manifest")
        if isinstance(stored_target_closure, dict) and stored_target_closure.get("path"):
            target_closure_manifest = Path(str(stored_target_closure["path"]))

    check_dir = workspace / "checks" / _safe_name(focus or "all") / mode
    if check_dir.exists():
        shutil.rmtree(check_dir)
    check_dir.mkdir(parents=True, exist_ok=True)
    timings: dict[str, float] = {}
    issues: list[dict[str, Any]] = []

    smoke_started = time.monotonic()
    smoke = stage_a_smoke_contract(
        reference_contract=paths["reference_contract"],
        out=check_dir / "contract-smoke.json",
    )
    timings["contract_smoke"] = round(time.monotonic() - smoke_started, 3)
    if smoke.get("status") != "pass":
        result = _check_result(
            target=target,
            workspace=workspace,
            check_dir=check_dir,
            mode=mode,
            focus=focus,
            status="incomplete",
            timings=timings,
            candidate=candidate_info,
            artifacts={"contract_smoke": str(check_dir / "contract-smoke.json")},
            issues=[
                {
                    "category": "contract_smoke_failed",
                    "blocker": "Stage A reference contract smoke failed",
                    "next_action": "rerun prepare with a current reference_contract.json",
                }
            ],
            early_exit=True,
        )
        write_json(check_dir / "wincr-slice-check.json", result)
        return result

    missing_candidate = [
        label
        for label, value in (
            ("candidate", candidate_info.get("candidate")),
            ("linker_map", candidate_info.get("linker_map")),
            ("skeleton_manifest", candidate_info.get("skeleton_manifest")),
        )
        if not value or not Path(str(value)).exists()
    ]
    if missing_candidate:
        result = _check_result(
            target=target,
            workspace=workspace,
            check_dir=check_dir,
            mode=mode,
            focus=focus,
            status="incomplete",
            timings=timings,
            candidate=candidate_info,
            artifacts={"contract_smoke": str(check_dir / "contract-smoke.json")},
            issues=[
                {
                    "category": "missing_candidate_artifacts",
                    "blocker": f"missing candidate artifact(s): {', '.join(missing_candidate)}",
                    "next_action": "run wincr-slice build or pass explicit candidate paths",
                }
            ],
            early_exit=True,
        )
        write_json(check_dir / "wincr-slice-check.json", result)
        return result

    candidate_provenance_path = Path(str(candidate_info["candidate_provenance"])) if candidate_info.get("candidate_provenance") else None
    if candidate_provenance_path is None or not candidate_provenance_path.exists():
        if not candidate_info.get("build_report"):
            issues.append(
                {
                    "category": "missing_candidate_provenance",
                    "blocker": "no candidate provenance or build report is available",
                    "next_action": "run wincr-slice build with a build report or pass --candidate-provenance",
                }
            )
        else:
            prov_started = time.monotonic()
            try:
                provenance = stage_b_generate_candidate_provenance(
                    target_name=target,
                    skeleton_manifest=Path(str(candidate_info["skeleton_manifest"])),
                    candidate=Path(str(candidate_info["candidate"])),
                    build_target=build_target or str(manifest.get("build", {}).get("target") or defaults.get("build_target") or ""),
                    build_compiler=build_compiler or str(manifest.get("build", {}).get("compiler") or defaults.get("build_compiler") or ""),
                    build_output=Path(str(candidate_info["candidate"])).name,
                    build_report=Path(str(candidate_info["build_report"])),
                    target_closure_manifest=target_closure_manifest,
                    out=check_dir / "provenance",
                )
            except Exception as exc:  # noqa: BLE001 - iteration reports should survive lower-layer input errors.
                provenance = None
                issues.append(_exception_issue("candidate_provenance_error", exc, "fix build/provenance inputs and rerun check"))
            timings["candidate_provenance"] = round(time.monotonic() - prov_started, 3)
            if provenance is not None:
                candidate_provenance_path = check_dir / "provenance" / "candidate-provenance.json"
                candidate_info["candidate_provenance"] = str(candidate_provenance_path)
            if provenance is not None and provenance.get("status") != "pass":
                issues.append(
                    {
                        "category": "candidate_provenance_incomplete",
                        "blocker": "generated candidate provenance is incomplete",
                        "next_action": "inspect provenance/candidate-provenance.json",
                    }
                )

    artifacts: dict[str, Any] = {"contract_smoke": str(check_dir / "contract-smoke.json")}
    contract_candidate_validation: dict[str, Any] | None = None
    contract_candidate_cache: dict[str, Any] | None = None
    validation_started = time.monotonic()
    try:
        contract_candidate_validation, contract_candidate_cache = _contract_candidate_validation(
            target=target,
            workspace=workspace,
            check_dir=check_dir,
            reference_contract=paths["reference_contract"],
            candidate_info=candidate_info,
            model=REFERENCE_CONTRACT_MODEL_ID,
            refresh=refresh_validation,
            use_cache=use_cache,
        )
        artifacts["candidate_validation_fingerprint"] = str(contract_candidate_cache["fingerprint_path"])
        artifacts["contract_candidate_validation"] = str(contract_candidate_cache["validation_path"])
    except Exception as exc:  # noqa: BLE001
        issues.append(_exception_issue("contract_candidate_validation_error", exc, "inspect candidate/map inputs before focused iteration"))
    timings["contract_candidate_validation"] = round(time.monotonic() - validation_started, 3)
    contract_candidate_validation_input: dict[str, Any] | Path | None = contract_candidate_validation
    if contract_candidate_cache is not None and contract_candidate_cache.get("validation_path"):
        contract_candidate_validation_input = Path(str(contract_candidate_cache["validation_path"]))

    unit_validation: dict[str, Any] | None = None
    if focus:
        unit_started = time.monotonic()
        try:
            if contract_candidate_validation is None:
                raise SliceLoopInputError("Stage A candidate validation was not available for focused unit filtering")
            unit_validation = stage_b_check_unit(
                reference_contract=paths["reference_contract"],
                candidate=Path(str(candidate_info["candidate"])),
                linker_map_candidate=Path(str(candidate_info["linker_map"])),
                skeleton_manifest=Path(str(candidate_info["skeleton_manifest"])),
                unit_contract_dir=paths.get("unit_contract_dir"),
                focus=focus,
                model=REFERENCE_CONTRACT_MODEL_ID,
                contract_candidate_validation=contract_candidate_validation_input,
                embed_contract_candidate_validation=False,
                out=check_dir / "unit",
            )
        except Exception as exc:  # noqa: BLE001
            unit_validation = None
            issues.append(_exception_issue("focused_unit_validation_error", exc, "inspect candidate/map inputs for the selected focus"))
        timings["focused_unit_validation"] = round(time.monotonic() - unit_started, 3)
        artifacts["unit_validation"] = str(check_dir / "unit" / "unit-validation.json")

    validation: dict[str, Any] | None = None
    if mode == "full" and candidate_provenance_path is not None and candidate_provenance_path.exists():
        validation_started = time.monotonic()
        try:
            validation = stage_b_validate_candidate(
                candidate=Path(str(candidate_info["candidate"])),
                linker_map_candidate=Path(str(candidate_info["linker_map"])),
                skeleton_manifest=Path(str(candidate_info["skeleton_manifest"])),
                candidate_provenance=candidate_provenance_path,
                reference_contract=paths["reference_contract"],
                target_name=target,
                out=check_dir / "validate",
            )
        except Exception as exc:  # noqa: BLE001
            validation = None
            issues.append(_exception_issue("stage_b_validation_error", exc, "inspect validate inputs and rerun full check"))
        timings["stage_b_validate_candidate"] = round(time.monotonic() - validation_started, 3)
        artifacts["stage_b_validation"] = str(check_dir / "validate" / "stage-b.json")

    delta: dict[str, Any] | None = None
    focused_delta: dict[str, Any] | None = None
    if not skip_delta:
        module_specs = _candidate_module_specs(candidate_module_args, candidate_info)
        delta_started = time.monotonic()
        try:
            if contract_candidate_validation is None:
                raise SliceLoopInputError("Stage A candidate validation was not available for delta explanation")
            delta = stage_b_explain_delta(
                reference_contract=paths["reference_contract"],
                candidate=Path(str(candidate_info["candidate"])),
                linker_map_candidate=Path(str(candidate_info["linker_map"])),
                skeleton_manifest=Path(str(candidate_info["skeleton_manifest"])),
                candidate_modules=module_specs,
                candidate_crash_report=candidate_crash_report,
                candidate_probe_report=candidate_probe_report,
                functional_report=functional_report,
                unit_contract_dir=paths.get("unit_contract_dir"),
                model=REFERENCE_CONTRACT_MODEL_ID,
                contract_candidate_validation=contract_candidate_validation_input,
                focus=focus,
                focused_only=bool(focus and not write_full_delta),
                embed_contract_candidate_validation=False,
                out=check_dir / "delta",
            )
        except Exception as exc:  # noqa: BLE001
            delta = None
            issues.append(_exception_issue("stage_b_delta_error", exc, "inspect delta inputs and rerun focused check"))
        timings["stage_b_explain_delta"] = round(time.monotonic() - delta_started, 3)
        artifacts["stage_b_delta"] = str(check_dir / "delta" / "stage-b-delta.json")
        if delta is not None:
            focused_delta = _focused_delta(delta, focus)
            write_json(check_dir / "focused-delta.json", focused_delta)
            artifacts["focused_delta"] = str(check_dir / "focused-delta.json")

    nix_gates: list[dict[str, Any]] = []
    if canonical_nix:
        if mode != "full":
            issues.append(
                {
                    "category": "canonical_nix_requires_full_mode",
                    "blocker": "--canonical-nix is only valid with --mode full",
                    "next_action": "rerun with --mode full --canonical-nix",
                }
            )
        else:
            for attr in defaults.get("final_check_attrs", []):
                gate_started = time.monotonic()
                gate = _nix_gate(nix_flake, str(attr), check_dir / "nix")
                gate["elapsed_seconds"] = round(time.monotonic() - gate_started, 3)
                nix_gates.append(gate)
            artifacts["canonical_nix"] = str(check_dir / "nix")

    focus_repair_items = None
    if focused_delta is not None:
        focus_repair_items = int(focused_delta.get("counts", {}).get("repair_items", 0))
    if issues:
        status = "incomplete"
    elif mode == "full" and validation is not None and validation.get("status") != "pass":
        status = "incomplete"
    elif nix_gates and any(gate.get("status") != "pass" for gate in nix_gates):
        status = "incomplete"
    elif focus and focus_repair_items == 0:
        status = "pass"
    elif focus:
        status = "incomplete"
    elif delta is not None and delta.get("status") == "pass":
        status = "pass"
    elif mode == "full" and validation is not None and validation.get("status") == "pass":
        status = "pass"
    else:
        status = "incomplete"

    result = _check_result(
        target=target,
        workspace=workspace,
        check_dir=check_dir,
        mode=mode,
        focus=focus,
        status=status,
        timings=timings,
        candidate=candidate_info,
        artifacts=artifacts,
        issues=issues,
        early_exit=False,
        unit_validation=unit_validation,
        validation=validation,
        contract_candidate_validation=contract_candidate_validation,
        contract_candidate_cache=contract_candidate_cache,
        delta=delta,
        focused_delta=focused_delta,
        nix_gates=nix_gates,
    )
    write_json(check_dir / "wincr-slice-check.json", result)
    return result


def _check_result(
    *,
    target: str,
    workspace: Path,
    check_dir: Path,
    mode: str,
    focus: str | None,
    status: str,
    timings: dict[str, float],
    candidate: dict[str, Any],
    artifacts: dict[str, Any],
    issues: list[dict[str, Any]],
    early_exit: bool,
    unit_validation: dict[str, Any] | None = None,
    validation: dict[str, Any] | None = None,
    contract_candidate_validation: dict[str, Any] | None = None,
    contract_candidate_cache: dict[str, Any] | None = None,
    delta: dict[str, Any] | None = None,
    focused_delta: dict[str, Any] | None = None,
    nix_gates: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    return {
        "format": CHECK_FORMAT,
        "status": status,
        "target": target,
        "mode": mode,
        "focus": focus,
        "workspace": str(workspace),
        "check_dir": str(check_dir),
        "generated_at": utc_now(),
        "policy": {
            "stage_a_contract_first": True,
            "original_runtime_tracing": False,
            "runtime_tests": "not_run_by_wincr_slice_check",
            "acceptance": "full compliance still requires canonical Stage A pass",
        },
        "early_exit": early_exit,
        "timings_seconds": timings,
        "candidate": candidate,
        "contract_candidate_validation": None
        if contract_candidate_validation is None
        else {
            "status": contract_candidate_validation.get("status") or contract_candidate_validation.get("verdict"),
            "counts": contract_candidate_validation.get("counts", {}),
            "cache": contract_candidate_cache,
        },
        "artifacts": artifacts,
        "unit_validation": None
        if unit_validation is None
        else {
            "status": unit_validation.get("status"),
            "counts": unit_validation.get("counts", {}),
        },
        "stage_b_validation": None
        if validation is None
        else {
            "status": validation.get("status"),
            "stage_a_gate": validation.get("stage_a_gate"),
        },
        "stage_b_delta": None
        if delta is None
        else {
            "status": delta.get("status"),
            "counts": delta.get("counts", {}),
        },
        "focused_delta": None
        if focused_delta is None
        else {
            "status": focused_delta.get("status"),
            "counts": focused_delta.get("counts", {}),
        },
        "canonical_nix": nix_gates or [],
        "issues": issues,
        "next_action": _check_next_action(status=status, focus=focus, focused_delta=focused_delta),
    }


def _check_next_action(*, status: str, focus: str | None, focused_delta: dict[str, Any] | None) -> str:
    if status == "pass" and focus:
        return "pick the next Stage A work item or run --mode full before final acceptance"
    if status == "pass":
        return "run canonical Nix gates before claiming final compliance"
    if focused_delta is not None and focused_delta.get("items"):
        first = focused_delta["items"][0]
        if isinstance(first, dict) and first.get("concrete_next_action"):
            return str(first["concrete_next_action"])
        if isinstance(first, dict) and first.get("next_action"):
            return str(first["next_action"])
    return "inspect the generated check artifacts and repair the highest-ranked Stage A contract item"


def _exception_issue(category: str, exc: Exception, next_action: str) -> dict[str, str]:
    return {
        "category": category,
        "blocker": str(exc),
        "exception_type": type(exc).__name__,
        "next_action": next_action,
    }


def _focused_delta(delta: dict[str, Any], focus: str | None) -> dict[str, Any]:
    items = [item for item in delta.get("repair_items", []) if isinstance(item, dict)]
    if focus:
        focus_lower = focus.lower()
        items = [item for item in items if _matches_focus(item, focus_lower)]
    result = {
        "format": FOCUSED_DELTA_FORMAT,
        "status": "incomplete" if items else "pass",
        "focus": focus,
        "source_delta_status": delta.get("status"),
        "items": items,
        "counts": {
            "repair_items": len(items),
            "source_repair_items": int(
                delta.get("source_counts", {}).get(
                    "repair_items",
                    delta.get("counts", {}).get("source_repair_items", delta.get("counts", {}).get("repair_items", 0)),
                )
            ),
            "by_family": _count_by(items, "violated_contract_family"),
            "by_repair_class": _count_by(items, "likely_repair_class"),
        },
    }
    return result


def _slice_source_progress(
    workspace: Path,
    current_candidate: dict[str, Any],
    manifest: dict[str, Any],
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    manifest_path = current_candidate.get("skeleton_manifest")
    if not manifest_path:
        source_skeleton = manifest.get("source_skeleton") if isinstance(manifest.get("source_skeleton"), dict) else {}
        manifest_path = source_skeleton.get("skeleton_manifest")
    if not manifest_path:
        return _empty_slice_source_progress("not_available", "no current skeleton manifest"), []
    path = Path(str(manifest_path))
    if not path.exists():
        return _empty_slice_source_progress("not_available", f"skeleton manifest is missing: {path}"), []
    try:
        payload = _load_json(path)
    except SliceLoopInputError as exc:
        return _empty_slice_source_progress("not_available", str(exc)), []
    if not isinstance(payload, dict) or payload.get("format") != "stage-b-skeleton-v1":
        return _empty_slice_source_progress("not_available", f"{path} is not a stage-b-skeleton-v1 manifest"), []
    source_map = payload.get("source_map") if isinstance(payload.get("source_map"), dict) else {}
    raw_anchors = source_map.get("functions") if isinstance(source_map.get("functions"), list) else []
    anchors = [anchor for anchor in raw_anchors if isinstance(anchor, dict)]
    by_kind = _count_by(anchors, "source_kind")
    concrete = sum(1 for anchor in anchors if _source_kind_progress_class(str(anchor.get("source_kind") or "")) == "concrete")
    placeholders = sum(1 for anchor in anchors if _source_kind_progress_class(str(anchor.get("source_kind") or "")) == "placeholder")
    boundary = sum(1 for anchor in anchors if _source_kind_progress_class(str(anchor.get("source_kind") or "")) == "boundary")
    omitted = sum(1 for anchor in anchors if _source_kind_progress_class(str(anchor.get("source_kind") or "")) == "omitted")
    return (
        {
            "format": "wincr-slice-source-progress-v1",
            "status": "available",
            "workspace": str(workspace),
            "skeleton_manifest": str(path),
            "source": source_map.get("source"),
            "implementation_mode": payload.get("implementation_mode") or source_map.get("implementation_mode"),
            "counts": {
                "source_anchors": len(anchors),
                "concrete": concrete,
                "placeholder": placeholders,
                "boundary": boundary,
                "omitted": omitted,
                "other": len(anchors) - concrete - placeholders - boundary - omitted,
                "by_source_kind": by_kind,
            },
        },
        anchors,
    )


def _empty_slice_source_progress(status: str, reason: str) -> dict[str, Any]:
    return {
        "format": "wincr-slice-source-progress-v1",
        "status": status,
        "reason": reason,
        "counts": {
            "source_anchors": 0,
            "concrete": 0,
            "placeholder": 0,
            "boundary": 0,
            "omitted": 0,
            "other": 0,
            "by_source_kind": {},
        },
    }


def _slice_work_items_with_source_gaps(
    items: list[dict[str, Any]],
    source_anchors: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    if not source_anchors:
        return items
    covered = {
        _source_anchor_key(anchor)
        for item in items
        for anchor in [_source_anchor_for_work_item(item, source_anchors)]
        if anchor is not None
    }
    synthetic = [
        _source_progress_gap_work_item(anchor)
        for anchor in source_anchors
        if _source_anchor_key(anchor) not in covered
        and _source_kind_progress_class(str(anchor.get("source_kind") or "")) in {"placeholder", "other"}
    ]
    return [*items, *synthetic]


def _source_anchor_key(anchor: dict[str, Any]) -> tuple[str, int | None, int | None, str]:
    return (
        str(anchor.get("function") or ""),
        _optional_int(anchor.get("rva_start")),
        _optional_int(anchor.get("rva_end")),
        str(anchor.get("source_kind") or ""),
    )


def _source_progress_gap_work_item(anchor: dict[str, Any]) -> dict[str, Any]:
    function = str(anchor.get("function") or "unknown")
    source_kind = str(anchor.get("source_kind") or "unknown")
    rva_start = _optional_int(anchor.get("rva_start"))
    rva_end = _optional_int(anchor.get("rva_end"))
    rva_suffix = (
        f"{rva_start:x}-{rva_end:x}"
        if rva_start is not None and rva_end is not None
        else hashlib.sha256(json.dumps(anchor, sort_keys=True, default=str).encode("utf-8")).hexdigest()[:8]
    )
    aliases = [alias for alias in anchor.get("aliases", []) if isinstance(alias, str) and alias]
    original_name = next((alias for alias in aliases if alias.startswith("section-gap--")), function)
    return {
        "id": f"work:source-progress-gap:{_safe_name(function)}:{rva_suffix}",
        "family": "stage_b_source_progress",
        "category": source_kind,
        "severity": "incomplete",
        "original_function": original_name,
        "function": function,
        "expected": "Stage B source is backed by a concrete generated or hand-written representation",
        "observed": f"source map still classifies {function} as {source_kind}",
        "cause_hint": source_kind,
        "repair_class": "source_progress_gap",
        "next_action": "replace the placeholder with a contract-guided implementation or classify the region as a checked boundary",
        "stage_b_source_gap": {
            "function": function,
            "aliases": aliases,
            "source_kind": source_kind,
            "rva_start": rva_start,
            "rva_end": rva_end,
            "line_start": anchor.get("line_start"),
            "line_end": anchor.get("line_end"),
            "file": anchor.get("file"),
        },
    }


def _write_slice_packets(
    *,
    workspace: Path,
    target: str,
    work_items: dict[str, Any],
    current_candidate: dict[str, Any],
    source_anchors: list[dict[str, Any]],
) -> dict[str, Any] | None:
    raw_items = work_items.get("work_items") if isinstance(work_items, dict) else []
    items = [item for item in raw_items if isinstance(item, dict)] if isinstance(raw_items, list) else []
    items = _slice_work_items_with_source_gaps(items, source_anchors)
    if not items:
        return None
    packet_dir = workspace / "packets"
    if packet_dir.exists():
        _rmtree_force_writable(packet_dir)
    packet_dir.mkdir(parents=True, exist_ok=True)

    functions = _load_stage_b_functions(current_candidate)
    function_by_name, functions_by_range = _slice_packet_function_indexes(functions)
    packets: list[dict[str, Any]] = []
    for index, item in enumerate(items, start=1):
        annotated = _annotate_work_item_source_progress(item, source_anchors)
        source_anchor = _source_anchor_for_work_item(item, source_anchors)
        source_summary = annotated.get("stage_b_source") if isinstance(annotated.get("stage_b_source"), dict) else None
        if source_anchor is None:
            source_anchor = source_summary
        function = _slice_packet_function_for_item(item, source_anchor, function_by_name, functions_by_range)
        pattern_family = _slice_packet_pattern_family(item, source_anchor, function)
        packet_id = _work_item_id(item)
        packet_rel = Path("packets") / f"{index:05d}-{_safe_name(packet_id)}.json"
        packet_path = workspace / packet_rel
        packet = {
            "format": SLICE_PACKET_FORMAT,
            "id": packet_id,
            "target": target,
            "rank": index,
            "generated_at": utc_now(),
            "work_item": item,
            "source_anchor": source_anchor,
            "source_progress_class": _work_item_source_progress_class(annotated),
            "pattern_family": pattern_family,
            "function": _slice_packet_function_evidence(function, source_anchor=source_anchor),
            "stage_a_contract": {
                "acceptance": "guidance artifact only; final acceptance requires Stage A pass",
                "status": "evidence" if function is not None else "incomplete",
            },
            "implementation_hint": _slice_packet_implementation_hint(item, source_anchor, pattern_family),
        }
        write_json(packet_path, packet)
        packets.append(
            {
                "id": packet_id,
                "path": str(packet_path),
                "relative_path": str(packet_rel),
                "pattern_family": pattern_family,
                "function": None if source_anchor is None else source_anchor.get("function"),
                "source_progress_class": packet["source_progress_class"],
                "source_kind": None if source_anchor is None else source_anchor.get("source_kind"),
                "instruction_evidence": packet["function"]["instruction_evidence"],
            }
        )

    index_payload = {
        "format": SLICE_PACKET_INDEX_FORMAT,
        "target": target,
        "generated_at": utc_now(),
        "workspace": str(workspace),
        "path": str(packet_dir / "index.json"),
        "packets": packets,
        "counts": {
            "packets": len(packets),
            "by_pattern_family": _count_by(packets, "pattern_family"),
            "by_source_progress_class": _count_by(packets, "source_progress_class"),
            "by_source_kind": _count_by(packets, "source_kind"),
        },
    }
    write_json(packet_dir / "index.json", index_payload)
    return index_payload


def _load_stage_b_functions(current_candidate: dict[str, Any]) -> list[dict[str, Any]]:
    path_text = current_candidate.get("functions")
    if not path_text:
        return []
    path = Path(str(path_text))
    if not path.exists():
        return []
    try:
        payload = _load_json(path)
    except SliceLoopInputError:
        return []
    raw_functions = payload.get("functions") if isinstance(payload, dict) else []
    return [function for function in raw_functions if isinstance(function, dict)] if isinstance(raw_functions, list) else []


def _slice_packet_function_indexes(
    functions: list[dict[str, Any]],
) -> tuple[dict[str, dict[str, Any]], list[dict[str, Any]]]:
    by_name: dict[str, dict[str, Any]] = {}
    by_range: list[dict[str, Any]] = []
    for function in functions:
        names = [
            function.get("name"),
            function.get("id"),
            *(function.get("aliases") if isinstance(function.get("aliases"), list) else []),
        ]
        for value in names:
            if isinstance(value, str) and value:
                by_name.setdefault(value.lower(), function)
        start = _optional_int(function.get("rva_start"))
        end = _optional_int(function.get("rva_end"))
        if start is not None and end is not None:
            by_range.append(function)
    return by_name, by_range


def _slice_packet_function_for_item(
    item: dict[str, Any],
    source_anchor: dict[str, Any] | None,
    function_by_name: dict[str, dict[str, Any]],
    functions_by_range: list[dict[str, Any]],
) -> dict[str, Any] | None:
    names, rvas = _work_item_source_lookup_terms(item)
    if source_anchor is not None:
        for value in [source_anchor.get("function"), *(source_anchor.get("aliases") if isinstance(source_anchor.get("aliases"), list) else [])]:
            if isinstance(value, str) and value:
                names.add(value)
        start = _optional_int(source_anchor.get("rva_start"))
        if start is not None:
            rvas.add(start)
    for name in sorted(names):
        match = function_by_name.get(name.lower())
        if match is not None:
            return match
    for rva in sorted(rvas):
        for function in functions_by_range:
            start = _optional_int(function.get("rva_start"))
            end = _optional_int(function.get("rva_end"))
            if start is not None and end is not None and start <= rva < end:
                return function
    return None


def _slice_packet_function_evidence(
    function: dict[str, Any] | None,
    *,
    source_anchor: dict[str, Any] | None = None,
) -> dict[str, Any]:
    if function is None:
        section_gap = source_anchor.get("reference_section_gap") if isinstance(source_anchor, dict) else None
        if isinstance(section_gap, dict):
            callsites = section_gap.get("abi_callsites") if isinstance(section_gap.get("abi_callsites"), list) else []
            callsite_instructions = [
                callsite.get("instruction")
                for callsite in callsites
                if isinstance(callsite, dict) and isinstance(callsite.get("instruction"), dict)
            ]
            return {
                "status": "contract_gap",
                "id": source_anchor.get("function") if isinstance(source_anchor, dict) else None,
                "name": section_gap.get("name"),
                "aliases": section_gap.get("aliases") if isinstance(section_gap.get("aliases"), list) else [],
                "rva_start": section_gap.get("rva_start"),
                "rva_end": section_gap.get("rva_end"),
                "instructions": callsite_instructions,
                "instruction_preview": callsite_instructions[:12],
                "instruction_evidence": {
                    "status": "contract_callsite_only",
                    "instructions": len(callsite_instructions),
                    "preview_instructions": min(len(callsite_instructions), 12),
                },
                "reference_contract": section_gap,
            }
        return {
            "status": "missing",
            "instruction_evidence": {"status": "missing", "instructions": 0, "preview_instructions": 0},
        }
    instructions = function.get("instructions") if isinstance(function.get("instructions"), list) else []
    preview = function.get("instruction_preview") if isinstance(function.get("instruction_preview"), list) else []
    if not instructions:
        instructions = preview
    decompiler = function.get("decompiler") if isinstance(function.get("decompiler"), dict) else {}
    evidence = {
        "status": "available",
        "id": function.get("id"),
        "name": function.get("name"),
        "aliases": function.get("aliases") if isinstance(function.get("aliases"), list) else [],
        "section": function.get("section"),
        "rva_start": function.get("rva_start"),
        "rva_end": function.get("rva_end"),
        "size": function.get("size"),
        "bytes_sha256": function.get("bytes_sha256"),
        "decode_complete": function.get("decode_complete"),
        "decoded_bytes": function.get("decoded_bytes"),
        "instruction_count": function.get("instruction_count"),
        "direct_cfg_edges": function.get("direct_cfg_edges") if isinstance(function.get("direct_cfg_edges"), list) else [],
        "instructions": instructions,
        "instruction_preview": preview,
        "instruction_evidence": {
            "status": "full" if function.get("instructions") else ("preview_only" if preview else "missing"),
            "instructions": len(instructions),
            "preview_instructions": len(preview),
        },
        "reference_contract": function.get("reference_contract") if isinstance(function.get("reference_contract"), dict) else {},
    }
    if decompiler:
        evidence["decompiler"] = {
            "status": decompiler.get("status"),
            "signature": decompiler.get("signature"),
            "code_preview": decompiler.get("code_preview") if isinstance(decompiler.get("code_preview"), list) else [],
        }
    return evidence


def _slice_packet_pattern_family(
    item: dict[str, Any],
    source_anchor: dict[str, Any] | None,
    function: dict[str, Any] | None,
) -> str:
    source_kind = str((source_anchor or {}).get("source_kind") or "")
    if source_kind == "omitted_import_thunk":
        return "import_boundary"
    if source_kind.startswith("omitted_runtime"):
        return "runtime_boundary"
    if source_kind == "generated_contract_placeholder_from_section_gap":
        return "section_gap_helper"
    if source_kind == "generated_checked_semantic_region":
        return "checked_semantic_region"
    if item.get("family") == "stage_b_source_progress":
        return "source_progress_gap"
    if source_kind.startswith("generated_contract_guided"):
        return source_kind.removeprefix("generated_contract_guided_")
    function_name = str((source_anchor or {}).get("function") or item.get("original_function") or item.get("function") or item.get("name") or "")
    item_id = _work_item_id(item)
    text = " ".join(
        str(value)
        for value in (
            item_id,
            item.get("family"),
            item.get("category"),
            item.get("repair_class"),
            item.get("cause_hint"),
            item.get("next_action"),
            function_name,
        )
        if value is not None
    ).lower()
    if function_name.startswith("stage_b_contract_section_gap") or "section-gap" in text:
        return "section_gap_helper"
    if "_pei386_runtime_relocator" in text:
        return "relocation_runtime_helper"
    if "umain" in text or "wmain" in text:
        return "application_dispatch"
    if "__mingw_pformat" in text or "varargs" in text:
        return "varargs_bridge"
    if "hidden-sret" in text or "out-param" in text or "out_param" in text:
        return "hidden_sret_or_out_param"
    if "function-pointer" in text or "function_pointer" in text:
        return "function_pointer_call"
    if "switch" in text or "jump-table" in text or "jump_table" in text:
        return "switch_or_jump_table"
    if function is not None and str(function.get("section") or ""):
        return "function_body"
    return "unclassified"


def _slice_packet_implementation_hint(
    item: dict[str, Any],
    source_anchor: dict[str, Any] | None,
    pattern_family: str,
) -> dict[str, Any]:
    source_kind = str((source_anchor or {}).get("source_kind") or "")
    progress = _source_kind_progress_class(source_kind) if source_kind else "no-anchor"
    action_by_pattern = {
        "application_dispatch": "recover the dispatch/dataflow cluster before adding local source for this application-level function",
        "function_pointer_call": "recover the target set or represent the indirect call with a checked contract-guided bridge",
        "hidden_sret_or_out_param": "make the address-like argument explicit in the generated source or bridge",
        "import_boundary": "preserve as an import boundary; do not implement target-owned logic here",
        "relocation_runtime_helper": "model the relocation/protection loop as a reusable runtime-helper pattern",
        "section_gap_helper": "classify the executable section-gap helper and promote reusable helper code instead of a placeholder",
        "source_progress_gap": "replace the source-map placeholder with a contract-guided implementation or classify it as a checked boundary",
        "varargs_bridge": "recover the format/varargs bridge ABI before attempting source cleanup",
    }
    return {
        "progress_class": progress,
        "pattern_family": pattern_family,
        "next_action": action_by_pattern.get(pattern_family)
        or item.get("next_action")
        or item.get("concrete_next_action")
        or item.get("blocker")
        or "inspect the packet evidence and add a reusable pattern or source implementation",
    }


def _load_slice_packet_index(workspace: Path) -> dict[str, Any]:
    path = workspace / "packets" / "index.json"
    if not path.exists():
        return {}
    try:
        payload = _load_json(path)
    except SliceLoopInputError:
        return {}
    if not isinstance(payload, dict) or payload.get("format") != SLICE_PACKET_INDEX_FORMAT:
        return {}
    by_id = {
        str(packet.get("id")): packet
        for packet in payload.get("packets", [])
        if isinstance(packet, dict) and packet.get("id") is not None
    }
    payload["by_id"] = by_id
    return payload


def _annotate_work_item_packet(item: dict[str, Any], packet_index: dict[str, Any]) -> dict[str, Any]:
    packet = packet_index.get("by_id", {}).get(_work_item_id(item)) if isinstance(packet_index.get("by_id"), dict) else None
    if not isinstance(packet, dict):
        return item
    annotated = dict(item)
    annotated["stage_b_packet"] = {
        "path": packet.get("path"),
        "pattern_family": packet.get("pattern_family"),
        "function": packet.get("function"),
        "source_progress_class": packet.get("source_progress_class"),
        "source_kind": packet.get("source_kind"),
        "instruction_evidence": packet.get("instruction_evidence"),
    }
    return annotated


def _work_item_id(item: dict[str, Any]) -> str:
    for key in ("id", "obligation_id", "unit_contract_id", "category"):
        value = item.get(key)
        if isinstance(value, str) and value:
            return value
    return hashlib.sha256(json.dumps(item, sort_keys=True, default=str).encode("utf-8")).hexdigest()[:16]


def _annotate_work_item_source_progress(item: dict[str, Any], source_anchors: list[dict[str, Any]]) -> dict[str, Any]:
    if not source_anchors:
        return item
    anchor = _source_anchor_for_work_item(item, source_anchors)
    if anchor is None:
        return item
    annotated = dict(item)
    source_kind = str(anchor.get("source_kind") or "unknown")
    annotated["stage_b_source"] = {
        "function": anchor.get("function"),
        "source_kind": source_kind,
        "progress_class": _source_kind_progress_class(source_kind),
        "file": anchor.get("file"),
        "line_start": anchor.get("line_start"),
        "line_end": anchor.get("line_end"),
        "rva_start": anchor.get("rva_start"),
        "rva_end": anchor.get("rva_end"),
    }
    return annotated


def _source_progress_class_filter(
    source_progress_classes: list[str] | None,
    *,
    todo_only: bool,
) -> set[str] | None:
    selected = {str(item) for item in source_progress_classes or [] if str(item)}
    if todo_only:
        selected.update({"placeholder", "other", "no-anchor"})
    return selected or None


def _work_item_source_progress_class(item: dict[str, Any]) -> str:
    source = item.get("stage_b_source") if isinstance(item.get("stage_b_source"), dict) else None
    if source is None:
        return "no-anchor"
    progress_class = str(source.get("progress_class") or "")
    return progress_class if progress_class else "other"


def _slice_next_groups(items: list[dict[str, Any]], group_by: str | None) -> list[dict[str, Any]]:
    if not group_by:
        return []
    counts: dict[str, int] = {}
    examples: dict[str, str] = {}
    for item in items:
        key = _slice_next_group_key(item, group_by)
        counts[key] = counts.get(key, 0) + 1
        examples.setdefault(key, _work_item_id(item))
    return [
        {"key": key, "count": count, "example": examples.get(key)}
        for key, count in sorted(counts.items(), key=lambda entry: (-entry[1], entry[0]))
    ]


def _slice_next_group_key(item: dict[str, Any], group_by: str) -> str:
    source = item.get("stage_b_source") if isinstance(item.get("stage_b_source"), dict) else {}
    packet = item.get("stage_b_packet") if isinstance(item.get("stage_b_packet"), dict) else {}
    if group_by == "function":
        return str(
            source.get("function")
            or packet.get("function")
            or item.get("original_function")
            or item.get("function")
            or item.get("name")
            or "unknown"
        )
    if group_by == "pattern":
        return str(packet.get("pattern_family") or item.get("repair_class") or item.get("category") or "unknown")
    if group_by == "source-kind":
        return str(source.get("source_kind") or packet.get("source_kind") or "no-anchor")
    return "unknown"


def _source_anchor_for_work_item(item: dict[str, Any], source_anchors: list[dict[str, Any]]) -> dict[str, Any] | None:
    names, rvas = _work_item_source_lookup_terms(item)
    by_name: dict[str, dict[str, Any]] = {}
    for anchor in source_anchors:
        for value in [anchor.get("function"), *(anchor.get("aliases") if isinstance(anchor.get("aliases"), list) else [])]:
            if isinstance(value, str) and value:
                by_name.setdefault(value.lower(), anchor)
    for name in sorted(names):
        match = by_name.get(name.lower())
        if match is not None:
            return match
    for rva in sorted(rvas):
        for anchor in source_anchors:
            start = _optional_int(anchor.get("rva_start"))
            end = _optional_int(anchor.get("rva_end"))
            if start is not None and end is not None and start <= rva < end:
                return anchor
    return None


def _work_item_source_lookup_terms(value: Any) -> tuple[set[str], set[int]]:
    names: set[str] = set()
    rvas: set[int] = set()

    def visit(item: Any, key: str = "") -> None:
        key_lower = key.lower()
        if isinstance(item, dict):
            for child_key, child_value in item.items():
                visit(child_value, str(child_key))
            return
        if isinstance(item, list):
            for child in item:
                visit(child, key)
            return
        if isinstance(item, str):
            if key_lower in {"function", "function_name", "name", "symbol", "contract_function", "original_function"}:
                names.add(item)
            if "rva" in key_lower:
                parsed = _optional_int(item)
                if parsed is not None:
                    rvas.add(parsed)
            return
        if isinstance(item, int) and not isinstance(item, bool) and "rva" in key_lower:
            rvas.add(item)

    visit(value)
    return names, rvas


def _source_kind_progress_class(source_kind: str) -> str:
    if source_kind in CONCRETE_SOURCE_KINDS:
        return "concrete"
    if source_kind == "omitted_import_thunk":
        return "boundary"
    if source_kind.startswith("generated_contract_placeholder"):
        return "placeholder"
    if source_kind.startswith("omitted_"):
        return "omitted"
    return "other"


def _optional_int(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        text = value.strip()
        if not text:
            return None
        try:
            return int(text, 0)
        except ValueError:
            return None
    return None


def _contract_candidate_validation(
    *,
    target: str,
    workspace: Path,
    check_dir: Path,
    reference_contract: Path,
    candidate_info: dict[str, Any],
    model: str,
    refresh: bool,
    use_cache: bool,
) -> tuple[dict[str, Any], dict[str, Any]]:
    candidate = Path(str(candidate_info["candidate"]))
    linker_map_candidate = Path(str(candidate_info["linker_map"]))
    skeleton_manifest = Path(str(candidate_info["skeleton_manifest"]))
    fingerprint = _candidate_validation_fingerprint(
        target=target,
        reference_contract=reference_contract,
        candidate=candidate,
        linker_map_candidate=linker_map_candidate,
        skeleton_manifest=skeleton_manifest,
        model=model,
    )
    if use_cache:
        cache_dir = workspace / "candidate-validation-cache" / str(fingerprint["fingerprint_sha256"])
        cached = _load_cached_contract_candidate_validation(cache_dir, fingerprint, refresh=refresh)
        if cached is not None:
            return cached, {
                "status": "hit",
                "fingerprint_sha256": fingerprint["fingerprint_sha256"],
                "fingerprint_path": str(cache_dir / "fingerprint.json"),
                "validation_path": str(cache_dir / "stage-a-contract-candidate" / "contract-candidate.json"),
                "cache_dir": str(cache_dir),
            }
        out = cache_dir / "stage-a-contract-candidate"
    else:
        cache_dir = check_dir / "stage-a-contract-candidate-cache-disabled"
        out = cache_dir / "stage-a-contract-candidate"
    validation = stage_b_check_contract(
        reference_contract=reference_contract,
        candidate=candidate,
        linker_map_candidate=linker_map_candidate,
        skeleton_manifest=skeleton_manifest,
        model=model,
        out=out,
    )
    fingerprint_path = cache_dir / "fingerprint.json"
    validation_path = out / "contract-candidate.json"
    cache_dir.mkdir(parents=True, exist_ok=True)
    write_json(fingerprint_path, fingerprint)
    if use_cache:
        write_json(
            cache_dir / "cache.json",
            {
                "format": CANDIDATE_VALIDATION_CACHE_FORMAT,
                "fingerprint_sha256": fingerprint["fingerprint_sha256"],
                "fingerprint": fingerprint,
                "validation_path": str(validation_path),
                "generated_at": utc_now(),
            },
        )
    return validation, {
        "status": "refresh" if use_cache and refresh else ("miss" if use_cache else "disabled"),
        "fingerprint_sha256": fingerprint["fingerprint_sha256"],
        "fingerprint_path": str(fingerprint_path),
        "validation_path": str(validation_path),
        "cache_dir": str(cache_dir),
    }


def _load_cached_contract_candidate_validation(
    cache_dir: Path,
    fingerprint: dict[str, Any],
    *,
    refresh: bool,
) -> dict[str, Any] | None:
    if refresh:
        return None
    cache_path = cache_dir / "cache.json"
    validation_path = cache_dir / "stage-a-contract-candidate" / "contract-candidate.json"
    try:
        cache = _load_json(cache_path)
        validation = _load_json(validation_path)
    except SliceLoopInputError:
        return None
    if (
        not isinstance(cache, dict)
        or cache.get("format") != CANDIDATE_VALIDATION_CACHE_FORMAT
        or cache.get("fingerprint_sha256") != fingerprint.get("fingerprint_sha256")
    ):
        return None
    if not isinstance(validation, dict) or validation.get("format") != "stage-a-contract-candidate-validation-v1":
        return None
    return validation


def _candidate_validation_fingerprint(
    *,
    target: str,
    reference_contract: Path,
    candidate: Path,
    linker_map_candidate: Path,
    skeleton_manifest: Path,
    model: str,
) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "format": CANDIDATE_VALIDATION_FINGERPRINT_FORMAT,
        "target": target,
        "model": model,
        "inputs": {
            "reference_contract": _file_fingerprint(reference_contract),
            "candidate": _file_fingerprint(candidate),
            "linker_map_candidate": _file_fingerprint(linker_map_candidate),
            "skeleton_manifest": _file_fingerprint(skeleton_manifest),
        },
    }
    digest_payload = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    payload["fingerprint_sha256"] = hashlib.sha256(digest_payload).hexdigest()
    return payload


def _file_fingerprint(path: Path) -> dict[str, Any]:
    path = Path(path)
    artifact = {"path": str(path), "exists": path.exists(), "is_file": path.is_file()}
    if path.is_file():
        stat = path.stat()
        artifact["size"] = stat.st_size
        artifact["sha256"] = sha256_file(path)
    return artifact


def _skeleton_artifacts(skeleton_root: Path | None) -> dict[str, Any]:
    if skeleton_root is None:
        return {}
    skeleton_root = Path(skeleton_root)
    result: dict[str, Any] = {"source": "prepared-skeleton-root", "directory": str(skeleton_root)}
    manifest = skeleton_root / "manifest.json"
    if manifest.exists():
        result["skeleton_manifest"] = str(manifest)
        if manifest.is_file():
            result["skeleton_manifest_sha256"] = sha256_file(manifest)
    source_dir = skeleton_root / "src"
    if source_dir.is_dir():
        result["source_dir"] = str(source_dir)
    functions = skeleton_root / "functions.json"
    if functions.exists():
        result["functions"] = str(functions)
        if functions.is_file():
            result["functions_sha256"] = sha256_file(functions)
    return result


def _candidate_artifacts(candidate_dir: Path | None, defaults: dict[str, Any]) -> dict[str, Any]:
    if candidate_dir is None:
        return {}
    candidate_dir = Path(candidate_dir)
    result: dict[str, Any] = {"source": "prepared-candidate-dir", "directory": str(candidate_dir)}
    fields = {
        "candidate": defaults.get("candidate_exe"),
        "linker_map": defaults.get("candidate_map"),
        "skeleton_manifest": defaults.get("skeleton_manifest"),
        "candidate_provenance": defaults.get("candidate_provenance"),
        "build_report": defaults.get("build_report"),
    }
    for key, rel in fields.items():
        if not rel:
            continue
        path = candidate_dir / str(rel)
        if path.exists():
            result[key] = str(path)
            if path.is_file():
                result[f"{key}_sha256"] = sha256_file(path)
    source_dir = candidate_dir / "src"
    if source_dir.is_dir():
        result["source_dir"] = str(source_dir)
    functions = candidate_dir / "functions.json"
    if functions.exists():
        result["functions"] = str(functions)
        if functions.is_file():
            result["functions_sha256"] = sha256_file(functions)
    modules: list[dict[str, str]] = []
    for spec in defaults.get("candidate_modules", []):
        module: dict[str, str] = {}
        ok = True
        for key in ("name", "candidate", "linker_map", "skeleton_manifest"):
            value = spec.get(key)
            if value is None:
                continue
            if key == "name":
                module[key] = str(value)
                continue
            path = candidate_dir / str(value)
            if not path.exists():
                ok = False
                break
            module[key] = str(path)
        if ok:
            modules.append(module)
    if modules:
        result["candidate_modules"] = modules
    return result


def _build_candidate_info(
    *,
    target: str,
    defaults: dict[str, Any],
    out_dir: Path,
    fallback: dict[str, Any],
    candidate: Path | None = None,
    linker_map_candidate: Path | None = None,
    skeleton_manifest: Path | None = None,
    candidate_provenance: Path | None = None,
    build_report: Path | None = None,
) -> dict[str, Any]:
    info = dict(fallback)
    output_defaults = {
        "candidate": out_dir / str(defaults.get("candidate_exe") or f"{target}.exe"),
        "linker_map": out_dir / str(defaults.get("candidate_map") or f"{target}.map"),
        "skeleton_manifest": out_dir / str(defaults.get("skeleton_manifest") or "skeleton-manifest.json"),
        "candidate_provenance": out_dir / str(defaults.get("candidate_provenance") or "candidate-provenance.json"),
        "build_report": out_dir / str(defaults.get("build_report") or "build-report.json"),
    }
    explicit = {
        "candidate": candidate,
        "linker_map": linker_map_candidate,
        "skeleton_manifest": skeleton_manifest,
        "candidate_provenance": candidate_provenance,
        "build_report": build_report,
    }
    for key, path in output_defaults.items():
        if explicit[key] is not None:
            info[key] = str(explicit[key])
        elif path.exists():
            info[key] = str(path)
    return info


def _candidate_module_specs(args: list[str] | tuple[str, ...], candidate_info: dict[str, Any]) -> list[dict[str, Any]]:
    specs = list(candidate_info.get("candidate_modules") or [])
    for raw in args:
        spec: dict[str, Any] = {}
        for part in str(raw).split(","):
            if not part:
                continue
            if "=" not in part:
                raise SliceLoopInputError(f"--candidate-module fields must use key=value, got {part!r}")
            key, value = part.split("=", 1)
            key = key.strip().replace("-", "_")
            value = value.strip()
            if key in {"candidate", "linker_map", "skeleton_manifest"}:
                spec[key] = Path(value)
            elif key == "name":
                spec[key] = value
            else:
                raise SliceLoopInputError(f"unsupported --candidate-module field {key!r}")
        specs.append(spec)
    return specs


def _contract_paths(manifest: dict[str, Any], workspace: Path) -> dict[str, Path | None]:
    cached = manifest.get("cached") if isinstance(manifest.get("cached"), dict) else {}
    reference_contract = cached.get("reference_contract") or manifest.get("reference_contract", {}).get("path")
    unit_contract_dir = cached.get("unit_contract_dir")
    if not reference_contract:
        raise SliceLoopInputError("workspace manifest has no reference contract")
    result: dict[str, Path | None] = {"reference_contract": Path(str(reference_contract)), "unit_contract_dir": None}
    if unit_contract_dir:
        result["unit_contract_dir"] = Path(str(unit_contract_dir))
    elif (workspace / "contracts" / "unit-contracts").exists():
        result["unit_contract_dir"] = workspace / "contracts" / "unit-contracts"
    return result


def _load_manifest(workspace: Path) -> dict[str, Any]:
    manifest_path = _manifest_path(workspace)
    if not manifest_path.exists():
        raise SliceLoopInputError(f"workspace is not prepared at {workspace}; run wincr-slice prepare first")
    manifest = _load_json(manifest_path)
    if not isinstance(manifest, dict) or manifest.get("format") != WORKSPACE_FORMAT:
        raise SliceLoopInputError(f"{manifest_path} is not a {WORKSPACE_FORMAT} manifest")
    return manifest


def _load_current_candidate(workspace: Path) -> dict[str, Any]:
    path = _current_candidate_path(workspace)
    if not path.exists():
        return {}
    payload = _load_json(path)
    return payload if isinstance(payload, dict) else {}


def _nix_realize(*, flake: str, attr: str, logs_dir: Path, label: str) -> Path:
    logs_dir.mkdir(parents=True, exist_ok=True)
    installable = _nix_installable(flake, attr)
    stdout_path = logs_dir / f"nix-{_safe_name(label)}.stdout.txt"
    stderr_path = logs_dir / f"nix-{_safe_name(label)}.stderr.txt"
    proc = subprocess.run(
        ["nix", "build", "--no-link", "--print-out-paths", installable],
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    stdout_path.write_text(proc.stdout, encoding="utf-8")
    stderr_path.write_text(proc.stderr, encoding="utf-8")
    if proc.returncode != 0:
        raise SliceLoopInputError(f"nix build failed for {installable}; see {stderr_path}")
    lines = [line.strip() for line in proc.stdout.splitlines() if line.strip()]
    if not lines:
        raise SliceLoopInputError(f"nix build produced no output path for {installable}; see {stdout_path}")
    return Path(lines[-1])


def _nix_gate(flake: str, attr: str, out_dir: Path) -> dict[str, Any]:
    out_dir.mkdir(parents=True, exist_ok=True)
    installable = _nix_installable(flake, attr)
    stdout_path = out_dir / f"{_safe_name(attr)}.stdout.txt"
    stderr_path = out_dir / f"{_safe_name(attr)}.stderr.txt"
    proc = subprocess.run(
        ["nix", "build", "--no-link", installable],
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    stdout_path.write_text(proc.stdout, encoding="utf-8")
    stderr_path.write_text(proc.stderr, encoding="utf-8")
    return {
        "attr": attr,
        "installable": installable,
        "status": "pass" if proc.returncode == 0 else "incomplete",
        "returncode": proc.returncode,
        "stdout": str(stdout_path),
        "stderr": str(stderr_path),
    }


def _nix_installable(flake: str, attr: str) -> str:
    if attr.startswith(".#"):
        return attr if flake == "." else f"{flake}#{attr[2:]}"
    if attr.startswith("#"):
        return f"{flake}{attr}"
    if "#" in attr:
        return attr
    return f"{flake}#{attr}"


def _link_or_copy(source: Path, dest: Path) -> None:
    if source.absolute() == dest.absolute():
        return
    if dest.exists() or dest.is_symlink():
        if dest.is_dir() and not dest.is_symlink():
            shutil.rmtree(dest)
        else:
            dest.unlink()
    dest.parent.mkdir(parents=True, exist_ok=True)
    try:
        dest.symlink_to(source.resolve(), target_is_directory=source.is_dir())
    except OSError:
        if source.is_dir():
            shutil.copytree(source, dest)
        else:
            shutil.copy2(source, dest)


def _cache_reference_contract_sidecars(reference_contract: Path, contracts_dir: Path) -> None:
    payload = _load_json(reference_contract)
    if not isinstance(payload, dict):
        return
    sidecars = payload.get("sidecars")
    if not isinstance(sidecars, dict):
        return
    for path_text in _reference_contract_sidecar_paths(sidecars):
        source = _resolve_reference_sidecar(reference_contract, path_text)
        if not source.exists():
            continue
        dest = contracts_dir / Path(path_text)
        try:
            dest.relative_to(contracts_dir)
        except ValueError as exc:
            raise SliceLoopInputError(f"reference contract sidecar path escapes cache directory: {path_text}") from exc
        _link_or_copy(source, dest)


def _reference_contract_sidecar_paths(sidecars: dict[str, Any]) -> list[str]:
    paths: list[str] = []
    for name in ("coverage_gaps", "obligation_index", "contract_summary", "abi_callsites"):
        item = sidecars.get(name)
        path = item.get("path") if isinstance(item, dict) else None
        if isinstance(path, str) and path:
            paths.append(path)
    unit = sidecars.get("unit_contracts")
    if isinstance(unit, dict):
        directory = unit.get("directory")
        base = Path(str(directory)) if isinstance(directory, str) and directory else Path(".")
        for value in unit.values():
            if not isinstance(value, dict):
                continue
            path = value.get("path")
            if isinstance(path, str) and path:
                paths.append(str(base / path))
    return sorted(set(paths))


def _resolve_reference_sidecar(reference_contract: Path, path_text: str) -> Path:
    path = Path(path_text)
    if path.is_absolute():
        return path
    return reference_contract.parent / path


def _copytree_once(source: Path, dest: Path, *, force: bool = False) -> None:
    if dest.exists():
        if not force:
            return
        _rmtree_force_writable(dest)
    shutil.copytree(source, dest)
    _chmod_tree_owner_writable(dest)


def _rmtree_force_writable(path: Path) -> None:
    try:
        shutil.rmtree(path, onexc=_rmtree_make_writable)
    except TypeError:
        shutil.rmtree(path, onerror=_rmtree_make_writable_onerror)


def _rmtree_make_writable(function: Any, path: str | bytes | os.PathLike[str] | os.PathLike[bytes], exc: BaseException) -> None:
    path_obj = Path(path)
    parent = path_obj.parent
    for item in (parent, path_obj):
        try:
            mode = stat.S_IMODE(item.stat().st_mode)
            os.chmod(item, mode | stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR)
        except OSError:
            pass
    function(path)


def _rmtree_make_writable_onerror(function: Any, path: str, exc_info: Any) -> None:
    _rmtree_make_writable(function, path, exc_info[1] if isinstance(exc_info, tuple) and len(exc_info) > 1 else OSError())


def _chmod_tree_owner_writable(root: Path) -> None:
    if not root.exists():
        return
    for dirpath, dirnames, filenames in os.walk(root):
        current = Path(dirpath)
        _chmod_owner_writable(current, executable=True)
        for dirname in dirnames:
            _chmod_owner_writable(current / dirname, executable=True)
        for filename in filenames:
            _chmod_owner_writable(current / filename, executable=False)


def _chmod_owner_writable(path: Path, *, executable: bool) -> None:
    try:
        mode = stat.S_IMODE(path.stat().st_mode)
        requested = stat.S_IRUSR | stat.S_IWUSR
        if executable:
            requested |= stat.S_IXUSR
        os.chmod(path, mode | requested)
    except OSError:
        pass


def _artifact(path: Path) -> dict[str, Any]:
    result: dict[str, Any] = {"path": str(path), "exists": path.exists()}
    if path.is_file():
        result["sha256"] = sha256_file(path)
    return result


def _required_path(path: Path, label: str) -> Path:
    if not path.exists():
        raise SliceLoopInputError(f"{label} does not exist: {path}")
    return path


def _require_file(path: Path, label: str) -> Path:
    _required_path(path, label)
    if not path.is_file():
        raise SliceLoopInputError(f"{label} is not a file: {path}")
    return path


def _require_dir(path: Path, label: str) -> Path:
    _required_path(path, label)
    if not path.is_dir():
        raise SliceLoopInputError(f"{label} is not a directory: {path}")
    return path


def _workspace_dir(work_dir: Path, target: str) -> Path:
    return Path(work_dir) / _safe_name(target)


def _manifest_path(workspace: Path) -> Path:
    return workspace / "workspace.json"


def _current_candidate_path(workspace: Path) -> Path:
    return workspace / "candidate" / "current-candidate.json"


def _target_defaults(target: str) -> dict[str, Any]:
    return dict(TARGET_DEFAULTS.get(target, {}))


def _load_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise SliceLoopInputError(f"cannot read {path}: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise SliceLoopInputError(f"invalid JSON in {path}: {exc}") from exc


def _parse_command_json(value: str) -> list[str]:
    parsed = json.loads(value)
    if not isinstance(parsed, list) or not all(isinstance(item, str) for item in parsed):
        raise SliceLoopInputError("command JSON must be a JSON list of strings")
    return list(parsed)


def _command_argv(value: str) -> list[str]:
    try:
        return _parse_command_json(value)
    except json.JSONDecodeError as exc:
        raise SliceLoopInputError(f"invalid --command-json: {exc}") from exc


def _safe_name(value: str) -> str:
    safe = "".join(ch if ch.isalnum() or ch in "._-" else "-" for ch in str(value))
    return safe.strip("-") or "slice"


def _matches_focus(value: Any, focus_lower: str) -> bool:
    if isinstance(value, str):
        return focus_lower in value.lower()
    if isinstance(value, int):
        return focus_lower in {str(value), hex(value).lower()}
    if isinstance(value, dict):
        return any(_matches_focus(item, focus_lower) for item in value.values())
    if isinstance(value, list):
        return any(_matches_focus(item, focus_lower) for item in value)
    return False


def _count_by(items: list[dict[str, Any]], key: str) -> dict[str, int]:
    counts: dict[str, int] = {}
    for item in items:
        value = item.get(key)
        if not isinstance(value, str) or not value:
            value = "unknown"
        counts[value] = counts.get(value, 0) + 1
    return dict(sorted(counts.items()))


def _slice_env_summary(env: dict[str, str]) -> dict[str, str]:
    return {
        key: value
        for key, value in sorted(env.items())
        if key.startswith("WINCR_SLICE_")
    }


def _print_json(data: Any) -> None:
    json.dump(data, sys.stdout, indent=2, sort_keys=True)
    sys.stdout.write("\n")


def _print_next_table(result: dict[str, Any]) -> None:
    print(f"status={result['status']} target={result['target']} matched={result['counts']['matched']}")
    source_progress = result.get("source_progress") if isinstance(result.get("source_progress"), dict) else {}
    source_counts = source_progress.get("counts") if isinstance(source_progress.get("counts"), dict) else {}
    if source_progress.get("status") == "available":
        print(
            "source_progress="
            f"concrete:{source_counts.get('concrete', 0)} "
            f"placeholder:{source_counts.get('placeholder', 0)} "
            f"boundary:{source_counts.get('boundary', 0)} "
            f"omitted:{source_counts.get('omitted', 0)}"
        )
    groups = result.get("groups") if isinstance(result.get("groups"), list) else []
    if groups:
        print("groups=" + " ".join(f"{item.get('key')}:{item.get('count')}" for item in groups[:10] if isinstance(item, dict)))
    for index, item in enumerate(result.get("items", []), start=1):
        item_id = item.get("id") or item.get("obligation_id") or item.get("category") or "work-item"
        family = item.get("family") or item.get("category") or "unknown"
        action = item.get("next_action") or item.get("concrete_next_action") or item.get("blocker") or ""
        source = item.get("stage_b_source") if isinstance(item.get("stage_b_source"), dict) else {}
        packet = item.get("stage_b_packet") if isinstance(item.get("stage_b_packet"), dict) else {}
        source_suffix = ""
        if source:
            source_suffix = f" [{source.get('progress_class')}:{source.get('source_kind')}:{source.get('function')}]"
        if packet:
            source_suffix += f" <packet:{packet.get('pattern_family')}:{packet.get('path')}>"
        print(f"{index:02d} {family} {item_id}{source_suffix} {action}")


def _print_check_summary(result: dict[str, Any]) -> None:
    focused = result.get("focused_delta") or {}
    focused_count = focused.get("counts", {}).get("repair_items") if isinstance(focused, dict) else None
    suffix = "" if focused_count is None else f" focused_repair_items={focused_count}"
    print(f"status={result['status']} target={result['target']} mode={result['mode']}{suffix}")
    print(f"check_dir={result['check_dir']}")
    print(f"next_action={result['next_action']}")


if __name__ == "__main__":
    raise SystemExit(main())
