from __future__ import annotations

import json
import shlex
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .target import ExternalModuleRule, TargetConfig
from .util import json_dumps, sha256_file, utc_now


SUITE_FORMAT = "wincr-generated-block-suite-v1"
GAPS_FORMAT = "wincr-block-suite-gaps-v1"
NEXT_TRACES_FORMAT = "wincr-block-suite-next-traces-v1"
EXTERNAL_MODULES_FORMAT = "wincr-external-module-provenance-v1"
GATE_FORMAT = "wincr-block-suite-gate-v1"


@dataclass(frozen=True)
class IncludedBinary:
    path: Path
    filename: str
    sha256: str
    label: str


@dataclass(frozen=True)
class TraceModule:
    source_trace: str
    test_id: str
    module_name: str
    module_path: str
    module_sha256: str


def generate_block_suite(
    *,
    target_config: TargetConfig,
    binary_root: Path,
    trace_dir: Path | None,
    out_dir: Path,
    traces: list[Path] | None = None,
    binaries: list[Path] | None = None,
    wincr_block: str = "wincr-block",
    max_cases_per_block: int | None = None,
    clean: bool = True,
) -> dict[str, Any]:
    """Generate a private multi-binary block conformance suite from original traces."""

    binary_root = binary_root.resolve()
    out_dir = out_dir.resolve()
    trace_paths = _discover_traces(trace_dir, traces)
    included = _resolve_included_binaries(target_config, binary_root, binaries or [])

    if clean and out_dir.exists():
        shutil.rmtree(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    loaded_modules = _load_trace_modules(trace_paths)
    external_report = _classify_loaded_modules(target_config, included, loaded_modules)
    filtered_trace_root = out_dir / "filtered-traces"
    module_results = []
    coverage_gaps: list[dict[str, Any]] = []
    tool_failures: list[str] = []

    for binary in included:
        suite_dir = out_dir / "modules" / binary.label
        suite_dir.parent.mkdir(parents=True, exist_ok=True)
        filtered = _write_filtered_traces(filtered_trace_root / binary.label, trace_paths, binary.sha256)
        command = [
            *_wincr_block_command(wincr_block),
            "characterize",
            "--binary",
            str(binary.path),
            "--out",
            str(suite_dir),
        ]
        for trace in filtered:
            command.extend(["--trace", str(trace)])
        if max_cases_per_block is not None:
            command.extend(["--max-cases-per-block", str(max(1, max_cases_per_block))])
        proc = subprocess.run(command, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
        coverage_path = suite_dir / "coverage.json"
        coverage = _load_json(coverage_path, {})
        if proc.returncode != 0:
            tool_failures.append(f"{binary.filename}: wincr-block exited {proc.returncode}")
            coverage_gaps.append(
                {
                    "kind": "tool_failure",
                    "binary": binary.filename,
                    "module_sha256": binary.sha256,
                    "detail": _bounded_text(proc.stderr or proc.stdout),
                }
            )
        coverage_gaps.extend(_coverage_gaps(binary, coverage))
        module_results.append(
            {
                "filename": binary.filename,
                "path": str(binary.path),
                "sha256": binary.sha256,
                "label": binary.label,
                "suite_dir": _rel(out_dir, suite_dir),
                "filtered_traces": [_rel(out_dir, path) for path in filtered],
                "command": command,
                "returncode": proc.returncode,
                "stdout": _bounded_text(proc.stdout),
                "stderr": _bounded_text(proc.stderr),
                "coverage": coverage,
            }
        )

    external_gaps = [
        {
            "kind": item["status"],
            "module_name": item.get("module_name"),
            "module_path": item.get("module_path"),
            "module_sha256": item.get("module_sha256"),
            "test_id": item.get("test_id"),
            "source_trace": item.get("source_trace"),
            "detail": item.get("detail"),
        }
        for item in external_report["modules"]
        if item["status"] in {"unknown_loaded_module", "included_module_hash_mismatch"}
    ]
    all_gaps = [*external_gaps, *coverage_gaps]
    status = "pass" if not all_gaps and not tool_failures else "fail"

    manifest = {
        "format": SUITE_FORMAT,
        "artifact_role": "private_generated_block_conformance_suite",
        "taint_level": "private_high_taint",
        "status": status,
        "created_at": utc_now(),
        "target": {"id": target_config.project_id, "name": target_config.project_name},
        "binary_root": str(binary_root),
        "trace_dir": str(trace_dir.resolve()) if trace_dir is not None else None,
        "trace_count": len(trace_paths),
        "included_binaries": [
            {"filename": item.filename, "path": str(item.path), "sha256": item.sha256, "label": item.label}
            for item in included
        ],
        "modules": module_results,
        "external_modules": "external-modules.json",
        "gaps": "gaps.json",
        "next_traces": "next-traces.json",
        "tool_failures": tool_failures,
    }
    gaps_report = {
        "format": GAPS_FORMAT,
        "status": status,
        "gap_count": len(all_gaps),
        "gaps": all_gaps,
    }
    next_traces = _next_trace_plan(target_config, gaps_report)

    _write_json(out_dir / "external-modules.json", external_report)
    _write_json(out_dir / "gaps.json", gaps_report)
    _write_json(out_dir / "next-traces.json", next_traces)
    _write_json(out_dir / "manifest.json", manifest)
    return {
        "ok": status == "pass",
        "manifest": manifest,
        "gaps": gaps_report,
        "next_traces": next_traces,
        "external_modules": external_report,
    }


def gate_block_suite(suite_dir: Path) -> dict[str, Any]:
    suite_dir = suite_dir.resolve()
    manifest = _load_json(suite_dir / "manifest.json", {})
    gaps = _load_json(suite_dir / "gaps.json", {})
    failures: list[str] = []
    if manifest.get("format") != SUITE_FORMAT:
        failures.append(f"{suite_dir / 'manifest.json'} is not a generated block suite manifest")
    if manifest.get("status") != "pass":
        failures.append(f"block suite status is {manifest.get('status')!r}, expected 'pass'")
    if int(gaps.get("gap_count", 0)) > 0:
        failures.append(f"block suite has {gaps.get('gap_count')} unresolved gaps")
    for module in manifest.get("modules") or []:
        coverage = module.get("coverage") or {}
        if coverage.get("status") != "pass":
            failures.append(f"{module.get('filename')} coverage status is {coverage.get('status')!r}")
    return {
        "format": GATE_FORMAT,
        "suite_dir": str(suite_dir),
        "status": "pass" if not failures else "fail",
        "failures": failures,
        "manifest_status": manifest.get("status"),
        "gap_count": int(gaps.get("gap_count", 0)),
    }


def _resolve_included_binaries(
    target_config: TargetConfig,
    binary_root: Path,
    explicit_binaries: list[Path],
) -> list[IncludedBinary]:
    paths = [path.resolve() for path in explicit_binaries]
    if not paths:
        names = {
            name.lower()
            for rule in target_config.binary_rules
            if rule.scope == "included"
            for name in rule.names
        }
        for path in sorted(binary_root.rglob("*")):
            if path.is_file() and path.name.lower() in names:
                paths.append(path.resolve())
    result = []
    seen: set[Path] = set()
    for path in paths:
        if path in seen:
            continue
        if not path.is_file():
            raise FileNotFoundError(f"included binary does not exist: {path}")
        seen.add(path)
        digest = sha256_file(path)
        result.append(IncludedBinary(path=path, filename=path.name, sha256=digest, label=_module_label(path.name, digest)))
    if not result:
        raise ValueError("no included binaries resolved; pass --binary or add included binary_rules to the target manifest")
    return result


def _discover_traces(trace_dir: Path | None, traces: list[Path] | None) -> list[Path]:
    result = [path.resolve() for path in traces or []]
    if trace_dir is not None:
        result.extend(path.resolve() for path in sorted(trace_dir.glob("*.jsonl")) if path.is_file())
    deduped = []
    seen: set[Path] = set()
    for path in result:
        if path not in seen:
            if not path.is_file():
                raise FileNotFoundError(f"trace does not exist: {path}")
            seen.add(path)
            deduped.append(path)
    if not deduped:
        raise ValueError("no traces found; pass --trace or --trace-dir containing .jsonl files")
    return deduped


def _load_trace_modules(trace_paths: list[Path]) -> list[TraceModule]:
    modules = []
    seen: set[tuple[str, str, str, str, str]] = set()
    for path in trace_paths:
        with path.open("r", encoding="utf-8-sig", errors="replace") as handle:
            for line in handle:
                if not line.strip():
                    continue
                try:
                    record = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if record.get("kind") != "module":
                    continue
                module = TraceModule(
                    source_trace=str(path),
                    test_id=str(record.get("test_id") or ""),
                    module_name=str(record.get("module_name") or ""),
                    module_path=str(record.get("module_path") or record.get("module_name") or ""),
                    module_sha256=str(record.get("module_sha256") or ""),
                )
                key = (module.source_trace, module.test_id, module.module_name, module.module_path, module.module_sha256)
                if key not in seen:
                    seen.add(key)
                    modules.append(module)
    return modules


def _classify_loaded_modules(
    target_config: TargetConfig,
    included: list[IncludedBinary],
    modules: list[TraceModule],
) -> dict[str, Any]:
    included_by_name = {item.filename.lower(): item for item in included}
    included_by_sha = {item.sha256.lower(): item for item in included}
    rows = []
    for module in modules:
        filename = Path(module.module_name.replace("\\", "/")).name or Path(module.module_path.replace("\\", "/")).name
        filename_key = filename.lower()
        sha_key = module.module_sha256.lower()
        if sha_key in included_by_sha:
            included_binary = included_by_sha[sha_key]
            rows.append(_module_row(module, "included", included_binary=included_binary))
            continue
        if filename_key in included_by_name:
            included_binary = included_by_name[filename_key]
            rows.append(
                _module_row(
                    module,
                    "included_module_hash_mismatch",
                    included_binary=included_binary,
                    detail=f"loaded {filename} has sha256 {module.module_sha256}, expected {included_binary.sha256}",
                )
            )
            continue
        external = _matching_external_rule(target_config.external_module_rules, module)
        if external is not None:
            rows.append(_module_row(module, "external", external_rule=external))
        else:
            rows.append(_module_row(module, "unknown_loaded_module", detail="loaded module is not included or externally proven"))
    return {
        "format": EXTERNAL_MODULES_FORMAT,
        "status": "pass"
        if all(row["status"] in {"included", "external"} for row in rows)
        else "fail",
        "modules": rows,
    }


def _matching_external_rule(rules: tuple[ExternalModuleRule, ...], module: TraceModule) -> ExternalModuleRule | None:
    name = Path(module.module_name.replace("\\", "/")).name.lower()
    path = module.module_path.replace("\\", "/").lower()
    sha = module.module_sha256.lower()
    for rule in rules:
        if sha and sha in {item.lower() for item in rule.sha256}:
            return rule
        if name and name in {item.lower() for item in rule.names}:
            return rule
        if any(fragment.lower().replace("\\", "/") in path for fragment in rule.path_contains):
            return rule
    return None


def _module_row(
    module: TraceModule,
    status: str,
    *,
    included_binary: IncludedBinary | None = None,
    external_rule: ExternalModuleRule | None = None,
    detail: str | None = None,
) -> dict[str, Any]:
    row: dict[str, Any] = {
        "status": status,
        "module_name": module.module_name,
        "module_path": module.module_path,
        "module_sha256": module.module_sha256,
        "test_id": module.test_id,
        "source_trace": module.source_trace,
    }
    if included_binary is not None:
        row["included_binary"] = {
            "filename": included_binary.filename,
            "path": str(included_binary.path),
            "sha256": included_binary.sha256,
        }
    if external_rule is not None:
        row["provenance"] = {
            "kind": external_rule.kind,
            "source": external_rule.source,
            "version": external_rule.version,
            "reason": external_rule.reason,
        }
    if detail:
        row["detail"] = detail
    return row


def _write_filtered_traces(out_dir: Path, trace_paths: list[Path], module_sha256: str) -> list[Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    outputs = []
    for path in trace_paths:
        out_path = out_dir / path.name
        wrote = False
        with path.open("r", encoding="utf-8-sig", errors="replace") as src, out_path.open("w", encoding="utf-8") as dst:
            for line in src:
                if not line.strip():
                    continue
                try:
                    record = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if record.get("module_sha256") == module_sha256:
                    dst.write(json_dumps(record))
                    dst.write("\n")
                    wrote = True
        if wrote:
            outputs.append(out_path)
        else:
            out_path.unlink(missing_ok=True)
    return outputs


def _coverage_gaps(binary: IncludedBinary, coverage: dict[str, Any]) -> list[dict[str, Any]]:
    gaps = []
    for label in coverage.get("uncovered_blocks") or []:
        gaps.append(
            {
                "kind": "uncovered_block",
                "binary": binary.filename,
                "module_sha256": binary.sha256,
                "block_label": label,
                "detail": "block obligation has no complete original pre/post characterization case",
            }
        )
    for label in coverage.get("side_effect_incomplete_blocks") or []:
        gaps.append(
            {
                "kind": "incomplete_side_effects",
                "binary": binary.filename,
                "module_sha256": binary.sha256,
                "block_label": label,
                "detail": "block obligation has no complete side-effect characterization case",
            }
        )
    for issue in coverage.get("issues") or []:
        gaps.append(
            {
                "kind": "coverage_issue",
                "binary": binary.filename,
                "module_sha256": binary.sha256,
                "detail": str(issue),
            }
        )
    return gaps


def _wincr_block_command(value: str) -> list[str]:
    parts = shlex.split(value)
    if not parts:
        raise ValueError("wincr-block command cannot be empty")
    if len(parts) > 1:
        return parts
    if parts[0] != "wincr-block" or shutil.which(parts[0]) is not None:
        return parts
    if Path("Cargo.toml").exists() and Path("crates/wincr-block/Cargo.toml").exists():
        return ["cargo", "run", "--quiet", "-p", "wincr-block", "--"]
    return parts


def _next_trace_plan(target_config: TargetConfig, gaps_report: dict[str, Any]) -> dict[str, Any]:
    gaps = gaps_report.get("gaps") or []
    by_kind: dict[str, int] = {}
    by_binary: dict[str, int] = {}
    for gap in gaps:
        by_kind[str(gap.get("kind"))] = by_kind.get(str(gap.get("kind")), 0) + 1
        binary = gap.get("binary")
        if binary:
            by_binary[str(binary)] = by_binary.get(str(binary), 0) + 1
    suggestions = []
    if any(kind in by_kind for kind in ("unknown_loaded_module", "included_module_hash_mismatch")):
        suggestions.append(
            {
                "kind": "fix_external_provenance",
                "reason": "loaded modules are not fully classified",
                "gap_count": by_kind.get("unknown_loaded_module", 0) + by_kind.get("included_module_hash_mismatch", 0),
                "action": "add included binary rules or [[external_modules]] provenance with kind/source/version before treating the suite as complete",
            }
        )
    for binary, count in sorted(by_binary.items()):
        suggestions.append(
            {
                "kind": "capture_more_block_state_traces",
                "binary": binary,
                "gap_count": count,
                "trace_target_ids": [target.id for target in target_config.trace_targets],
                "action": "run additional manifest trace targets with block-state tracing enabled, then regenerate the suite",
            }
        )
    return {
        "format": NEXT_TRACES_FORMAT,
        "status": "complete" if not gaps else "needs_more_traces_or_policy",
        "gap_count": len(gaps),
        "suggestions": suggestions,
    }


def _load_json(path: Path, default: dict[str, Any]) -> dict[str, Any]:
    if not path.exists():
        return dict(default)
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return dict(default)
    return value if isinstance(value, dict) else dict(default)


def _write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json_dumps(value) + "\n", encoding="utf-8")


def _module_label(filename: str, digest: str) -> str:
    stem = "".join(ch if ch.isalnum() else "_" for ch in filename.lower()).strip("_")
    return f"{stem}_{digest[:12]}"


def _rel(root: Path, path: Path) -> str:
    try:
        return path.relative_to(root).as_posix()
    except ValueError:
        return str(path)


def _bounded_text(value: str, limit: int = 12000) -> str:
    if len(value) <= limit:
        return value
    half = limit // 2
    return value[:half] + "\n... truncated ...\n" + value[-half:]
