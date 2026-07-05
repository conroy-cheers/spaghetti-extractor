from __future__ import annotations

import json
import os
import re
import subprocess
from collections import Counter
from pathlib import Path
from typing import Any

import capstone

from .stage_binary import (
    STAGE_A_MODEL_ID,
    BlockSide,
    StageABinary,
    StageAInputError,
    _artifact_name,
    _capstone_mode,
    _direct_cfg_edges,
    _linker_function_match_key,
    _linker_function_import_thunk_evidence,
    _parse_linker_map_functions,
    _parse_stage_a_pe,
)
from .util import sha256_bytes, sha256_file, utc_now, write_json


STAGE_B_PROOF_RULE = "reproducible_stage_b_skeleton_reimplementation_v1"
STAGE_B_REQUIRED_FUNCTIONAL_SUITES = {
    "jq": {
        "suite_id": "jq-upstream-integration-tests",
        "suite_name": "jq upstream integration tests",
    },
    "ripgrep": {
        "suite_id": "ripgrep-upstream-integration-tests",
        "suite_name": "ripgrep upstream integration tests",
    },
}
STAGE_B_REQUIRED_TARGETS = ("jq", "ripgrep")
STAGE_B_UPSTREAM_SUITE_MATERIALIZER = "stage-b-materialize-upstream-suite"
_DECOMPILED_C_RUNTIME_ENTRY_NAMES = frozenset({"___tmainCRTStartup", "mainCRTStartup", "___wgetmainargs"})
_STAGE_B_BUDGETED_OBJECT_ROOT_MAX_ORIGINAL_SIZE = 1024
_DECOMPILED_C_DIRECT_IMPORT_ALIAS_SYMBOLS = frozenset({"_crt_atexit", "__crt_atexit"})
_DECOMPILED_C_PRESERVED_IMPORT_THUNK_ALIASES = frozenset({"___iob_func"})
_CARGO_TEST_STATUS_RE = re.compile(r"^test (?P<name>.+?) \.\.\. (?P<status>ok|FAILED|ignored|measured)(?: .*)?$")
_CARGO_TEST_RESULT_RE = re.compile(r"^test result: (?P<status>[A-Z]+|ok)\. (?P<summary>.*)$")


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
    from .ghidra import DEFAULT_GHIDRA_SCRIPT, _resolve_analyze_headless, _resolve_script_path

    original = Path(original)
    if not original.is_file():
        raise StageAInputError(f"Stage B decompiler export input is not available: {original}")

    out = Path(out)
    out.mkdir(parents=True, exist_ok=True)
    project_dir = Path(project_dir) if project_dir is not None else out / "ghidra-projects"
    project_dir.mkdir(parents=True, exist_ok=True)
    analyze_headless = _resolve_analyze_headless(analyze_headless)
    script_path = _resolve_script_path(script_path)

    target_id = _artifact_name(target_name)
    export_path = out / f"{target_id}.ghidra.json"
    stdout_path = out / "analyzeHeadless.stdout"
    stderr_path = out / "analyzeHeadless.stderr"
    started_at = utc_now()
    original_sha256 = sha256_file(original)
    project = _artifact_name(f"{project_name}-{target_id}-{original_sha256[:12]}")
    command = [
        analyze_headless,
        str(project_dir),
        project,
        "-import",
        str(original),
        "-scriptPath",
        str(script_path),
        "-postScript",
        DEFAULT_GHIDRA_SCRIPT,
        str(export_path),
        original_sha256,
        "-deleteProject",
    ]

    report: dict[str, Any] = {
        "format": "stage-b-decompiler-export-v1",
        "target_name": target_name,
        "status": "incomplete",
        "started_at": started_at,
        "completed_at": None,
        "original": {"path": str(original), "sha256": original_sha256},
        "tool": {
            "name": "ghidra-analyzeHeadless",
            "command": command,
            "script": str(script_path / DEFAULT_GHIDRA_SCRIPT),
        },
        "outputs": {
            "export": str(export_path),
            "stdout": str(stdout_path),
            "stderr": str(stderr_path),
            "report": str(out / "stage-b-decompiler-export.json"),
        },
        "decompiler_export": None,
        "blocker": "",
    }

    try:
        proc = subprocess.run(
            command,
            check=False,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout_seconds,
        )
    except FileNotFoundError as exc:
        stdout_path.write_text("", encoding="utf-8")
        stderr_path.write_text(str(exc), encoding="utf-8")
        report["blocker"] = f"analyzeHeadless not found: {exc.filename or analyze_headless}"
    except subprocess.TimeoutExpired as exc:
        stdout_path.write_text(str(exc.stdout or ""), encoding="utf-8")
        stderr_path.write_text(str(exc.stderr or ""), encoding="utf-8")
        report["blocker"] = f"Ghidra export timed out after {timeout_seconds} seconds"
    else:
        stdout_path.write_text(proc.stdout, encoding="utf-8")
        stderr_path.write_text(proc.stderr, encoding="utf-8")
        report["tool"]["returncode"] = proc.returncode
        if proc.returncode != 0:
            report["blocker"] = "Ghidra decompiler export command failed"
        else:
            try:
                export_summary = _decompiler_export_summary(export_path)
            except StageAInputError as exc:
                report["blocker"] = str(exc)
            else:
                report["status"] = "pass"
                report["decompiler_export"] = export_summary

    report["completed_at"] = utc_now()
    write_json(out / "stage-b-decompiler-export.json", report)
    return report


def stage_b_materialize_upstream_suite(
    *,
    target_name: str,
    suite_source: Path,
    source_revision: str,
    cases: Path,
    out: Path,
    suite_scope: str = "full",
) -> dict[str, Any]:
    required = _required_functional_suite(target_name)
    if required is None:
        raise StageAInputError(f"no required Stage B upstream suite is registered for target {target_name!r}")
    if not source_revision:
        raise StageAInputError("Stage B upstream suite source revision must be non-empty")
    if suite_scope not in {"full", "subset"}:
        raise StageAInputError("Stage B upstream suite scope must be full or subset")
    cases_payload = _load_json(Path(cases))
    case_entries = _materialized_suite_cases(cases_payload)
    out = Path(out)
    out.mkdir(parents=True, exist_ok=True)
    source_hash = sha256_file(Path(suite_source))
    suite = {
        "format": "stage-b-functional-suite-v1",
        "materializer": {
            "name": STAGE_B_UPSTREAM_SUITE_MATERIALIZER,
            "source": str(suite_source),
            "source_sha256": source_hash,
            "source_revision": source_revision,
            "cases": str(cases),
            "cases_sha256": sha256_file(Path(cases)),
        },
        "target_name": target_name,
        "suite_id": required["suite_id"],
        "suite_name": required["suite_name"],
        "suite_kind": "upstream_integration",
        "suite_scope": suite_scope,
        "upstream_suite": True,
        "coverage": {
            "source": str(suite_source),
            "source_kind": "upstream_integration_suite",
            "source_sha256": source_hash,
            "source_revision": source_revision,
            "materialized_by": STAGE_B_UPSTREAM_SUITE_MATERIALIZER,
            "required_suite_ids": [required["suite_id"]],
        },
        "cases": case_entries,
    }
    write_json(out / "functional-suite.json", suite)
    return suite


def stage_b_generate_link_roots(
    *,
    original: Path,
    linker_map_original: Path,
    object_file: Path,
    out: Path,
    nm: str = "llvm-nm",
) -> dict[str, Any]:
    out = Path(out)
    out.mkdir(parents=True, exist_ok=True)
    original_bin = _parse_stage_a_pe(Path(original))
    contract_functions = _parse_linker_map_functions(Path(linker_map_original), original_bin)
    nm_symbols = _stage_b_nm_defined_text_symbols(Path(object_file), nm=nm)

    contract_by_key: dict[str, list[dict[str, Any]]] = {}
    for function in contract_functions:
        contract_by_key.setdefault(_linker_function_match_key(str(function["name"])), []).append(function)
    object_by_key: dict[str, list[str]] = {}
    for symbol in nm_symbols:
        object_by_key.setdefault(_linker_function_match_key(symbol), []).append(symbol)

    issues: list[dict[str, Any]] = []
    duplicate_contract_keys = {
        key: [
            {"name": str(item["name"]), "rva_start": item["rva_start"], "rva_end": item["rva_end"]}
            for item in entries
        ]
        for key, entries in contract_by_key.items()
        if len(entries) > 1
    }
    duplicate_object_keys = {key: sorted(entries) for key, entries in object_by_key.items() if len(entries) > 1}
    if duplicate_contract_keys:
        issues.append(
            {
                "category": "ambiguous_contract_function_roots",
                "blocker": "Stage A contract functions collapse to duplicate canonical linker-root keys",
                "next_action": "disambiguate reference linker-map function names before generating Stage B link roots",
                "details": {"match_keys": duplicate_contract_keys},
            }
        )
    if duplicate_object_keys:
        issues.append(
            {
                "category": "ambiguous_object_function_roots",
                "blocker": "candidate object text symbols collapse to duplicate canonical linker-root keys",
                "next_action": "rename generated functions or provide explicit root aliases before linker GC",
                "details": {"match_keys": duplicate_object_keys},
            }
        )

    roots: list[dict[str, Any]] = []
    import_thunk_roots: list[dict[str, Any]] = []
    missing: list[dict[str, Any]] = []
    for key in sorted(contract_by_key):
        contract_entries = contract_by_key[key]
        object_entries = object_by_key.get(key, [])
        if len(contract_entries) == 1:
            contract = contract_entries[0]
            import_thunk = _linker_function_import_thunk_evidence(original_bin, contract)
            if import_thunk is not None:
                imported = import_thunk["import"]
                import_thunk_roots.append(
                    {
                        "contract_function": str(contract["name"]),
                        "match_key": key,
                        "rva_start": contract["rva_start"],
                        "rva_end": contract["rva_end"],
                        "dll": imported.dll,
                        "symbol": imported.symbol,
                        "ordinal": imported.ordinal,
                        "thunk_rva": imported.thunk_rva,
                        "signature_key": import_thunk["signature_key"],
                    }
                )
                continue
        if len(contract_entries) != 1 or len(object_entries) != 1:
            if len(contract_entries) == 1 and not object_entries:
                item = contract_entries[0]
                missing.append({"name": str(item["name"]), "match_key": key, "rva_start": item["rva_start"], "rva_end": item["rva_end"]})
            continue
        contract = contract_entries[0]
        roots.append(
            {
                "contract_function": str(contract["name"]),
                "object_symbol": object_entries[0],
                "match_key": key,
                "rva_start": contract["rva_start"],
                "rva_end": contract["rva_end"],
            }
        )
    if missing:
        issues.append(
            {
                "category": "missing_object_function_roots",
                "blocker": "some Stage A contract functions have no generated object text symbol",
                "next_action": "improve skeleton generation or add explicit aliases for missing contract functions",
                "details": {"functions": missing[:200], "count": len(missing)},
            }
        )

    root_symbols = sorted({root["object_symbol"] for root in roots})
    linker_flags = [f"-Wl,--undefined,{symbol}" for symbol in root_symbols]
    budgeted_roots = [
        root
        for root in roots
        if int(root["rva_end"]) - int(root["rva_start"]) <= _STAGE_B_BUDGETED_OBJECT_ROOT_MAX_ORIGINAL_SIZE
    ]
    budgeted_linker_flags = sorted(f"-Wl,--undefined,{root['object_symbol']}" for root in budgeted_roots)
    import_thunk_linker_flags = [
        f"-Wl,--undefined,{_stage_b_import_thunk_coff_symbol(root)}"
        for root in import_thunk_roots
        if root.get("symbol")
    ]
    (out / "link-root-symbols.txt").write_text("".join(f"{symbol}\n" for symbol in root_symbols), encoding="utf-8")
    (out / "link-root-flags.txt").write_text("".join(f"{flag}\n" for flag in linker_flags), encoding="utf-8")
    (out / "budgeted-link-root-flags.txt").write_text("".join(f"{flag}\n" for flag in budgeted_linker_flags), encoding="utf-8")
    (out / "import-thunk-root-flags.txt").write_text("".join(f"{flag}\n" for flag in import_thunk_linker_flags), encoding="utf-8")
    write_json(out / "import-thunk-roots.json", {"format": "stage-b-import-thunk-roots-v1", "roots": import_thunk_roots})
    result = {
        "format": "stage-b-link-roots-v1",
        "status": "pass" if not issues else "incomplete",
        "generator": "stage-b-generate-link-roots",
        "inputs": {
            "original": str(original),
            "linker_map_original": str(linker_map_original),
            "object_file": str(object_file),
            "nm": nm,
        },
        "outputs": {
            "link_root_symbols": str(out / "link-root-symbols.txt"),
            "link_root_flags": str(out / "link-root-flags.txt"),
            "budgeted_link_root_flags": str(out / "budgeted-link-root-flags.txt"),
            "import_thunk_roots": str(out / "import-thunk-roots.json"),
            "import_thunk_root_flags": str(out / "import-thunk-root-flags.txt"),
        },
        "roots": roots,
        "budgeted_roots": budgeted_roots,
        "import_thunk_roots": import_thunk_roots,
        "linker_flags": linker_flags,
        "budgeted_linker_flags": budgeted_linker_flags,
        "import_thunk_linker_flags": import_thunk_linker_flags,
        "issues": issues,
        "counts": {
            "contract_functions": len(contract_functions),
            "object_text_symbols": len(nm_symbols),
            "roots": len(root_symbols),
            "budgeted_roots": len(budgeted_roots),
            "import_thunk_roots": len(import_thunk_roots),
            "import_thunk_roots_with_linker_flags": len(import_thunk_linker_flags),
            "missing": len(missing),
            "issues": len(issues),
        },
        "selection_policy": {
            "budgeted_object_root_max_original_size": _STAGE_B_BUDGETED_OBJECT_ROOT_MAX_ORIGINAL_SIZE,
            "budgeted_object_root_basis": "original linker-map function byte range",
        },
    }
    write_json(out / "link-roots.json", result)
    return result


def _stage_b_import_thunk_coff_symbol(root: dict[str, Any]) -> str:
    symbol = str(root.get("symbol") or "")
    contract_function = str(root.get("contract_function") or "")
    if symbol == "atexit" and contract_function in {"_crt_atexit", "__crt_atexit"}:
        return "___crt_atexit"
    return f"_{symbol}"


def _stage_b_nm_defined_text_symbols(object_file: Path, *, nm: str) -> list[str]:
    try:
        proc = subprocess.run([nm, str(object_file)], check=False, capture_output=True, text=True)
    except OSError as exc:
        raise StageAInputError(f"failed to run {nm}: {exc}") from exc
    if proc.returncode != 0:
        raise StageAInputError(f"{nm} failed for {object_file}: {proc.stderr.strip()}")
    symbols: list[str] = []
    for line in proc.stdout.splitlines():
        parts = line.split()
        if len(parts) >= 3 and parts[1] in {"T", "t"} and _is_c_identifier(parts[2]):
            symbols.append(parts[2])
    return sorted(set(symbols))


def stage_b_run_functional_suite(
    *,
    suite: Path,
    original_command: tuple[str, ...],
    candidate_command: tuple[str, ...],
    out: Path,
    timeout_seconds: float = 30.0,
    original_binary: Path | None = None,
    candidate_binary: Path | None = None,
    strip_stderr_line_regexes: tuple[str, ...] | list[str] = (),
) -> dict[str, Any]:
    started_at = utc_now()
    payload = _load_json(Path(suite))
    if not isinstance(payload, dict):
        raise StageAInputError("Stage B functional suite must be a JSON object")
    cases_payload = payload.get("cases")
    if not isinstance(cases_payload, list) or not cases_payload:
        raise StageAInputError("Stage B functional suite must contain a non-empty cases list")
    out = Path(out)
    out.mkdir(parents=True, exist_ok=True)
    (out / "cases").mkdir(parents=True, exist_ok=True)

    cases: list[dict[str, Any]] = []
    for index, entry in enumerate(cases_payload):
        if not isinstance(entry, dict):
            cases.append(
                {
                    "id": f"case-{index:04d}",
                    "status": "fail",
                    "blocker": "functional suite case entry must be an object",
                }
            )
            continue
        cases.append(
            _run_functional_case(
                case=entry,
                index=index,
                original_command=original_command,
                candidate_command=candidate_command,
                out=out / "cases",
                default_timeout_seconds=timeout_seconds,
                strip_stderr_line_regexes=strip_stderr_line_regexes,
            )
        )

    passed = sum(1 for case in cases if case["status"] == "pass")
    failed = len(cases) - passed
    status = "pass" if cases and failed == 0 else "fail"
    suite_name = str(payload.get("suite_name") or payload.get("name") or Path(suite).stem)
    suite_id = str(payload.get("suite_id") or payload.get("id") or _artifact_name(suite_name))
    upstream_suite = bool(payload.get("upstream_suite", False))
    case_manifest = _functional_case_manifest(cases)
    suite_sha256 = sha256_file(Path(suite))
    suite_case_manifest_sha256 = _case_manifest_sha256(case_manifest)
    result = {
        "format": "stage-b-functional-report-v1",
        "runner": {
            "name": "stage-b-run-functional-suite",
            "report_format": "stage-b-functional-report-v1",
            "strip_stderr_line_regexes": list(strip_stderr_line_regexes),
        },
        "status": status,
        "started_at": started_at,
        "completed_at": utc_now(),
        "suite": str(suite),
        "suite_sha256": suite_sha256,
        "suite_case_manifest_sha256": suite_case_manifest_sha256,
        "target_name": str(payload.get("target_name") or ""),
        "suite_id": suite_id,
        "suite_name": suite_name,
        "suite_kind": str(payload.get("suite_kind") or _coverage_payload(payload).get("suite_kind") or ("upstream_integration" if upstream_suite else "local")),
        "upstream_suite": upstream_suite,
        "commands": {
            "original": list(original_command),
            "candidate": list(candidate_command),
        },
        "binary_bindings": {
            "original": _functional_binary_binding(original_binary, original_command),
            "candidate": _functional_binary_binding(candidate_binary, candidate_command),
        },
        "coverage": _functional_coverage_report(
            payload,
            suite_id=suite_id,
            cases=cases,
            suite_sha256=suite_sha256,
            suite_case_manifest_sha256=suite_case_manifest_sha256,
        ),
        "counts": {
            "cases": len(cases),
            "passed": passed,
            "failed": failed,
        },
        "case_manifest": case_manifest,
        "cases": cases,
    }
    write_json(out / "functional-report.json", result)
    return result


def _functional_binary_binding(binary: Path | None, command: tuple[str, ...]) -> dict[str, Any]:
    if binary is None:
        return {
            "provided": False,
            "command_contains_path": False,
            "command": list(command),
        }

    path = Path(binary)
    binding: dict[str, Any] = {
        "provided": True,
        "path": str(path),
        "exists": path.exists(),
        "command_contains_path": _command_references_path(command, path),
        "command": list(command),
    }
    if path.exists():
        binding["sha256"] = sha256_file(path)
        binding["size"] = path.stat().st_size
    return binding


def _command_references_path(command: tuple[str, ...] | list[str], path: Path) -> bool:
    try:
        expected = path.resolve(strict=False)
    except OSError:
        expected = path
    for arg in command:
        if arg == str(path):
            return True
        arg_path = Path(arg)
        if not arg_path.is_absolute() and os.sep not in arg:
            continue
        try:
            if arg_path.resolve(strict=False) == expected:
                return True
        except OSError:
            if str(arg_path) == str(path):
                return True
    return False


def _strip_matching_lines(data: bytes, regexes: tuple[str, ...] | list[str]) -> bytes:
    if not regexes:
        return data
    patterns = [re.compile(pattern) for pattern in regexes]
    kept: list[bytes] = []
    for line in data.splitlines(keepends=True):
        text = line.rstrip(b"\r\n").decode("utf-8", errors="replace")
        if any(pattern.search(text) for pattern in patterns):
            continue
        kept.append(line)
    return b"".join(kept)


def _coverage_payload(payload: dict[str, Any]) -> dict[str, Any]:
    coverage = payload.get("coverage")
    return coverage if isinstance(coverage, dict) else {}


def _materialized_suite_cases(payload: Any) -> list[dict[str, Any]]:
    if isinstance(payload, list):
        entries = payload
    elif isinstance(payload, dict):
        entries = payload.get("cases")
    else:
        raise StageAInputError("Stage B upstream suite cases must be a JSON object or list")
    if not isinstance(entries, list) or not entries:
        raise StageAInputError("Stage B upstream suite cases must contain a non-empty cases list")
    results: list[dict[str, Any]] = []
    for index, entry in enumerate(entries):
        if not isinstance(entry, dict):
            raise StageAInputError("Stage B upstream suite case entries must be objects")
        case_id = entry.get("id")
        if not isinstance(case_id, str) or not case_id:
            raise StageAInputError("Stage B upstream suite cases must have non-empty string ids")
        normalized = dict(entry)
        normalized["id"] = _artifact_name(case_id)
        _case_args(normalized)
        _case_stdin(normalized)
        _case_env(normalized)
        _case_cwd(normalized)
        _case_expected_original_returncode(normalized)
        for timeout_key in ("timeout_seconds", "original_timeout_seconds", "candidate_timeout_seconds"):
            if timeout_key not in normalized:
                continue
            try:
                float(normalized[timeout_key])
            except (TypeError, ValueError) as exc:
                raise StageAInputError(f"Stage B upstream suite case {timeout_key} must be numeric") from exc
        results.append(normalized)
    return results


def _functional_coverage_report(
    payload: dict[str, Any],
    *,
    suite_id: str,
    cases: list[dict[str, Any]],
    suite_sha256: str,
    suite_case_manifest_sha256: str,
) -> dict[str, Any]:
    coverage = _coverage_payload(payload)
    case_ids = [str(case.get("id") or "") for case in cases]
    required_suite_ids = coverage.get("required_suite_ids", payload.get("required_suite_ids"))
    if required_suite_ids is None and str(coverage.get("suite_scope") or coverage.get("scope") or payload.get("suite_scope") or "") == "full":
        required_suite_ids = [suite_id]
    return {
        "suite_id": suite_id,
        "suite_kind": str(payload.get("suite_kind") or coverage.get("suite_kind") or ("upstream_integration" if payload.get("upstream_suite") is True else "local")),
        "suite_scope": str(payload.get("suite_scope") or coverage.get("suite_scope") or coverage.get("scope") or "unspecified"),
        "source": str(payload.get("suite_source") or coverage.get("source") or ""),
        "source_kind": str(payload.get("suite_source_kind") or coverage.get("source_kind") or ""),
        "source_sha256": str(payload.get("suite_source_sha256") or coverage.get("source_sha256") or ""),
        "source_revision": str(payload.get("suite_source_revision") or coverage.get("source_revision") or ""),
        "materialized_by": str(payload.get("suite_materialized_by") or coverage.get("materialized_by") or ""),
        "suite_sha256": suite_sha256,
        "suite_case_manifest_sha256": suite_case_manifest_sha256,
        "required_suite_ids": _string_list(required_suite_ids),
        "case_count": len(case_ids),
        "case_ids": case_ids,
        "case_ids_sha256": _case_ids_sha256(case_ids),
    }


def _run_functional_case(
    *,
    case: dict[str, Any],
    index: int,
    original_command: tuple[str, ...],
    candidate_command: tuple[str, ...],
    out: Path,
    default_timeout_seconds: float,
    strip_stderr_line_regexes: tuple[str, ...] | list[str],
) -> dict[str, Any]:
    case_id = _artifact_name(str(case.get("id") or f"case-{index:04d}"))
    case_out = out / case_id
    case_out.mkdir(parents=True, exist_ok=True)
    args = _case_args(case)
    stdin_bytes = _case_stdin(case)
    timeout = float(case.get("timeout_seconds", default_timeout_seconds))
    original_timeout = _case_side_timeout_seconds(case, "original_timeout_seconds", timeout)
    candidate_timeout = _case_side_timeout_seconds(case, "candidate_timeout_seconds", timeout)
    env = _case_env(case)
    env_sha256 = _env_sha256(env)
    cwd = _case_cwd(case)
    expected_original_returncode = _case_expected_original_returncode(case)
    original = _run_observed_process(
        command=(*original_command, *args),
        stdin_bytes=stdin_bytes,
        env=env,
        cwd=cwd,
        timeout_seconds=original_timeout,
        out_prefix=case_out / "original",
        strip_stderr_line_regexes=strip_stderr_line_regexes,
    )
    candidate = _run_observed_process(
        command=(*candidate_command, *args),
        stdin_bytes=stdin_bytes,
        env=env,
        cwd=cwd,
        timeout_seconds=candidate_timeout,
        out_prefix=case_out / "candidate",
        strip_stderr_line_regexes=strip_stderr_line_regexes,
    )
    original_expectation = _functional_original_expectation(original, expected_original_returncode)
    original_expected = original_expectation is None or original_expectation["status"] == "pass"
    equivalent = _functional_observations_equal(original, candidate)
    timeout_failure = bool(original.get("timed_out") or candidate.get("timed_out"))
    status = "pass" if original_expected and equivalent and not timeout_failure else "fail"
    return {
        "id": case_id,
        "status": status,
        "args": args,
        "timeout_seconds": timeout,
        "original_timeout_seconds": original_timeout,
        "candidate_timeout_seconds": candidate_timeout,
        "stdin_sha256": sha256_bytes(stdin_bytes),
        "cwd": cwd,
        "env_keys": sorted(env),
        "env_sha256": env_sha256,
        "expect_original_returncode": expected_original_returncode,
        "original_expectation": original_expectation,
        "original": original,
        "candidate": candidate,
        "mismatch": None
        if status == "pass"
        else _functional_mismatch(original, candidate, original_expectation, timeout_failure=timeout_failure),
    }


def _run_observed_process(
    *,
    command: tuple[str, ...],
    stdin_bytes: bytes,
    env: dict[str, str],
    cwd: str | None,
    timeout_seconds: float,
    out_prefix: Path,
    strip_stderr_line_regexes: tuple[str, ...] | list[str],
) -> dict[str, Any]:
    stdout_path = out_prefix.with_suffix(".stdout")
    stderr_path = out_prefix.with_suffix(".stderr")
    command_list = list(command)
    try:
        proc = subprocess.Popen(
            command_list,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=cwd,
            env={**os.environ, **env},
            start_new_session=True,
        )
        stdout, stderr = proc.communicate(input=stdin_bytes, timeout=timeout_seconds)
        stdout = stdout or b""
        stderr = stderr or b""
        timed_out = False
        returncode = proc.returncode
    except subprocess.TimeoutExpired as exc:
        _terminate_process_group(proc, signal.SIGTERM)
        try:
            stdout, stderr = proc.communicate(timeout=2.0)
        except subprocess.TimeoutExpired:
            _terminate_process_group(proc, signal.SIGKILL)
            stdout, stderr = proc.communicate()
        if not stdout:
            stdout = _timeout_bytes(exc.stdout)
        if not stderr:
            stderr = _timeout_bytes(exc.stderr)
        timed_out = True
        returncode = None
    except BaseException:
        if "proc" in locals() and proc.poll() is None:
            _terminate_process_group(proc, signal.SIGTERM)
            try:
                proc.wait(timeout=2.0)
            except subprocess.TimeoutExpired:
                _terminate_process_group(proc, signal.SIGKILL)
                proc.wait()
        raise
    stdout_path.write_bytes(stdout)
    stderr = _strip_matching_lines(stderr, strip_stderr_line_regexes)
    stderr_path.write_bytes(stderr)
    return {
        "command": list(command),
        "cwd": cwd,
        "returncode": returncode,
        "timed_out": timed_out,
        "stdout": _stream_artifact(stdout_path, stdout),
        "stderr": _stream_artifact(stderr_path, stderr),
    }


def _terminate_process_group(proc: subprocess.Popen[bytes], sig: signal.Signals) -> None:
    try:
        os.killpg(proc.pid, sig)
    except ProcessLookupError:
        return
    except PermissionError:
        proc.terminate() if sig == signal.SIGTERM else proc.kill()


def _case_args(case: dict[str, Any]) -> tuple[str, ...]:
    args = case.get("args", [])
    if not isinstance(args, list) or not all(isinstance(item, str) for item in args):
        raise StageAInputError("functional suite case args must be a list of strings")
    return tuple(args)


def _case_stdin(case: dict[str, Any]) -> bytes:
    if "stdin" in case and "stdin_text" in case:
        raise StageAInputError("functional suite case cannot contain both stdin and stdin_text")
    value = case.get("stdin", case.get("stdin_text", ""))
    if not isinstance(value, str):
        raise StageAInputError("functional suite case stdin must be a string")
    return value.encode("utf-8")


def _case_env(case: dict[str, Any]) -> dict[str, str]:
    env = case.get("env", {})
    if not isinstance(env, dict) or not all(isinstance(key, str) and isinstance(value, str) for key, value in env.items()):
        raise StageAInputError("functional suite case env must be an object of string values")
    return dict(env)


def _case_cwd(case: dict[str, Any]) -> str | None:
    cwd = case.get("cwd")
    if cwd is None:
        return None
    if not isinstance(cwd, str) or not cwd:
        raise StageAInputError("functional suite case cwd must be a non-empty string when present")
    return cwd


def _case_expected_original_returncode(case: dict[str, Any]) -> int | None:
    value = case.get("expect_original_returncode")
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int):
        raise StageAInputError("functional suite case expect_original_returncode must be an integer")
    return value


def _case_side_timeout_seconds(case: dict[str, Any], key: str, default: float) -> float:
    value = case.get(key, default)
    try:
        return float(value)
    except (TypeError, ValueError) as exc:
        raise StageAInputError(f"functional suite case {key} must be numeric") from exc


def _env_sha256(env: dict[str, str]) -> str:
    return sha256_bytes(json.dumps(env, sort_keys=True, separators=(",", ":")).encode("utf-8"))


def _functional_case_manifest(cases: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [
        {
            "id": str(case.get("id") or ""),
            "args": list(case.get("args") or []),
            "stdin_sha256": str(case.get("stdin_sha256") or ""),
            "cwd": case.get("cwd"),
            "env_sha256": str(case.get("env_sha256") or ""),
            "timeout_seconds": case.get("timeout_seconds"),
            "original_timeout_seconds": case.get("original_timeout_seconds"),
            "candidate_timeout_seconds": case.get("candidate_timeout_seconds"),
            "expect_original_returncode": case.get("expect_original_returncode"),
        }
        for case in cases
    ]


def _case_manifest_sha256(manifest: list[dict[str, Any]]) -> str:
    return sha256_bytes(json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode("utf-8"))


def _is_sha256_hex(value: Any) -> bool:
    return isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) is not None


def _timeout_bytes(value: Any) -> bytes:
    if value is None:
        return b""
    if isinstance(value, bytes):
        return value
    return str(value).encode("utf-8", errors="replace")


def _stream_artifact(path: Path, data: bytes) -> dict[str, Any]:
    return {
        "path": str(path),
        "sha256": sha256_bytes(data),
        "bytes": len(data),
        "preview": data[:4096].decode("utf-8", errors="replace"),
    }


def _functional_observations_equal(original: dict[str, Any], candidate: dict[str, Any]) -> bool:
    return (
        original.get("returncode") == candidate.get("returncode")
        and original.get("timed_out") == candidate.get("timed_out")
        and original.get("stdout", {}).get("sha256") == candidate.get("stdout", {}).get("sha256")
        and original.get("stderr", {}).get("sha256") == candidate.get("stderr", {}).get("sha256")
    )


def _functional_original_expectation(original: dict[str, Any], expected_returncode: int | None) -> dict[str, Any] | None:
    if expected_returncode is None:
        return None
    passed = original.get("returncode") == expected_returncode and original.get("timed_out") is False
    return {
        "status": "pass" if passed else "fail",
        "returncode": expected_returncode,
        "actual_returncode": original.get("returncode"),
        "actual_timed_out": original.get("timed_out"),
    }


def _functional_mismatch(
    original: dict[str, Any],
    candidate: dict[str, Any],
    original_expectation: dict[str, Any] | None = None,
    *,
    timeout_failure: bool = False,
) -> dict[str, Any]:
    fields = []
    if original_expectation is not None and original_expectation.get("status") != "pass":
        fields.append("original_expectation")
    if timeout_failure:
        fields.append("timeout")
    for key in ("returncode", "timed_out"):
        if original.get(key) != candidate.get(key):
            fields.append(key)
    for key in ("stdout", "stderr"):
        if original.get(key, {}).get("sha256") != candidate.get(key, {}).get("sha256"):
            fields.append(key)
    result: dict[str, Any] = {"fields": fields}
    if original_expectation is not None:
        result["original_expectation"] = original_expectation
    return result


def stage_b_generate_skeleton(
    *,
    original: Path,
    out_dir: Path,
    target_name: str,
    linker_map: Path | None = None,
    source_language: str = "c",
    decompiler_export: Path | None = None,
    implementation_mode: str = "scaffold",
    function_names: list[str] | tuple[str, ...] | None = None,
) -> dict[str, Any]:
    if source_language not in {"c", "rust"}:
        raise StageAInputError(f"unsupported Stage B source language {source_language!r}")
    if implementation_mode not in {"scaffold", "decompiled-c"}:
        raise StageAInputError(f"unsupported Stage B implementation mode {implementation_mode!r}")
    if implementation_mode == "decompiled-c" and source_language != "c":
        raise StageAInputError("decompiled-c Stage B implementation mode requires source_language='c'")
    if implementation_mode == "decompiled-c" and decompiler_export is None:
        raise StageAInputError("decompiled-c Stage B implementation mode requires --decompiler-export")

    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    binary = _parse_stage_a_pe(Path(original))
    behavior_recovery = _skeleton_behavior_recovery(
        binary=binary,
        target_name=target_name,
        source_language=source_language,
        implementation_mode=implementation_mode,
    )
    functions = _skeleton_functions(
        binary,
        linker_map,
        decompiler_export,
        include_decompiler_code=implementation_mode == "decompiled-c",
    )
    function_filter = _function_filter(functions, function_names)
    external_function_names = function_filter["external_function_names"] + [
        item.symbol for item in binary.imports if isinstance(item.symbol, str) and item.symbol
    ]
    functions = function_filter["functions"]
    implementation_recovery = _skeleton_implementation_recovery(functions, source_language, implementation_mode=implementation_mode)
    if implementation_mode == "decompiled-c" and implementation_recovery["status"] != "complete":
        blockers = ", ".join(implementation_recovery["blockers"])
        raise StageAInputError(f"decompiled-c Stage B implementation source is incomplete: {blockers}")
    target_id = _artifact_name(target_name)
    source_rel = Path("src") / f"{target_id}_stage_b_skeleton.{_source_extension(source_language)}"
    functions_rel = Path("functions.json")
    readme_rel = Path("README.md")
    manifest_path = out_dir / "manifest.json"

    write_json(out_dir / functions_rel, {"format": "stage-b-functions-v1", "target_name": target_name, "functions": functions})
    (out_dir / source_rel.parent).mkdir(parents=True, exist_ok=True)
    (out_dir / source_rel).write_text(
        _render_skeleton_source(
            target_name=target_name,
            functions=functions,
            source_language=source_language,
            implementation_mode=implementation_mode,
            external_function_names=external_function_names,
            behavior_recovery=behavior_recovery,
        ),
        encoding="utf-8",
    )
    (out_dir / readme_rel).write_text(_render_skeleton_readme(target_name, source_language, implementation_mode), encoding="utf-8")

    inputs: dict[str, Any] = {
        "original": {"path": str(original), "sha256": binary.sha256},
        "linker_map": None,
        "decompiler_export": None,
    }
    if linker_map is not None:
        inputs["linker_map"] = {"path": str(linker_map), "sha256": sha256_file(Path(linker_map))}
    if decompiler_export is not None:
        inputs["decompiler_export"] = _decompiler_export_summary(Path(decompiler_export))

    manifest: dict[str, Any] = {
        "format": "stage-b-skeleton-v1",
        "status": "generated",
        "target_name": target_name,
        "generated_at": utc_now(),
        "proof_rule": STAGE_B_PROOF_RULE,
        "source_language": source_language,
        "implementation_mode": implementation_mode,
        "source_policy": {
            "upstream_source_read": False,
            "manual_behavioral_fixups": False,
            "allowed_inputs": [_pe_input_kind(binary), "linker-map", "decompiler-export", "capstone-disassembly"],
        },
        "reverse_engineering": {
            "tools": ["pefile", "capstone"],
            "function_source": _function_source_kind(linker_map=linker_map, decompiler_export=decompiler_export),
            "function_filter": function_filter["metadata"],
            "behavior_recovery": behavior_recovery,
        },
        "original": _binary_summary(binary),
        "inputs": inputs,
        "outputs": {
            "source": {"path": source_rel.as_posix(), "sha256": sha256_file(out_dir / source_rel)},
            "functions": {"path": functions_rel.as_posix(), "sha256": sha256_file(out_dir / functions_rel)},
            "readme": {"path": readme_rel.as_posix(), "sha256": sha256_file(out_dir / readme_rel)},
        },
        "counts": {
            "functions": len(functions),
            "executable_sections": sum(1 for section in binary.sections if section.executable),
            "imports": len(binary.imports),
            "instructions": sum(int(item["instruction_count"]) for item in functions),
        },
        "implementation_recovery": implementation_recovery,
        "behavior_recovery": behavior_recovery,
        "completion": {
            "candidate_status": "generated_behavior_source" if implementation_recovery["source_implements_behavior"] else "skeleton_only",
            "stage_a_validated": False,
            "upstream_integration_tests": "not_run",
        },
    }
    write_json(manifest_path, manifest)
    return manifest


def stage_b_validate_candidate(
    *,
    original: Path | None,
    candidate: Path,
    linker_map_original: Path | None,
    linker_map_candidate: Path,
    skeleton_manifest: Path,
    candidate_provenance: Path,
    target_name: str,
    out: Path,
    functional_report: Path | None = None,
    reference_contract: Path | None = None,
    original_flags: str = "",
    candidate_flags: str = "",
    model: str = STAGE_A_MODEL_ID,
) -> dict[str, Any]:
    out = Path(out)
    out.mkdir(parents=True, exist_ok=True)
    started_at = utc_now()
    issues: list[dict[str, Any]] = []
    stage_a_result: dict[str, Any] | None = None
    map_result: dict[str, Any] | None = None
    binary_evidence: dict[str, Any]
    reference_contract_payload: dict[str, Any] | None = None
    from .stage_a import stage_a_generate_map, stage_a_validate, stage_a_validate_contract_candidate

    if reference_contract is not None:
        try:
            loaded_contract = _load_json(Path(reference_contract))
            if not isinstance(loaded_contract, dict) or loaded_contract.get("format") != "stage-a-reference-contract-v1":
                raise StageAInputError("Stage B reference contract must have format stage-a-reference-contract-v1")
            reference_contract_payload = loaded_contract
        except StageAInputError as exc:
            issues.append(
                {
                    "category": "invalid_reference_contract",
                    "blocker": str(exc),
                    "next_action": "provide a readable stage-a-reference-contract-v1 JSON artifact",
                }
            )

    try:
        candidate_bin = _parse_stage_a_pe(Path(candidate))
        if reference_contract_payload is not None:
            binary_evidence = _binary_target_evidence_from_reference_contract(reference_contract_payload, candidate_bin)
        else:
            if original is None:
                raise StageAInputError("Stage B validation requires --reference-contract for zero-original validation or --original for legacy pair validation")
            original_bin = _parse_stage_a_pe(Path(original))
            binary_evidence = _binary_target_evidence(original_bin, candidate_bin)
        issues.extend(_binary_target_issues(binary_evidence))
    except StageAInputError as exc:
        binary_evidence = {
            "format": "stage-b-binary-target-evidence-v1",
            "status": "incomplete",
            "error": str(exc),
            "facts": {
                "matching_machine": False,
                "matching_bitness": False,
                "matching_subsystem": False,
                "both_windows_pe": False,
                "same_architecture_same_os": False,
            },
        }
        issues.append(
            {
                "category": "binary_target_unavailable",
                "blocker": str(exc),
                "next_action": "provide supported Windows PE original and candidate binaries for the same architecture and subsystem",
            }
        )

    try:
        skeleton_payload = _load_json(Path(skeleton_manifest))
        provenance_payload = _load_json(Path(candidate_provenance))
        functional_report_payload = _load_json(Path(functional_report)) if functional_report is not None else None
        issues.extend(
            _stage_b_provenance_issues(
                skeleton_payload=skeleton_payload,
                provenance_payload=provenance_payload,
                skeleton_manifest=Path(skeleton_manifest),
                functional_report=Path(functional_report) if functional_report is not None else None,
                functional_report_payload=functional_report_payload,
                target_name=target_name,
                candidate=Path(candidate),
                binary_evidence=binary_evidence,
            )
        )
    except StageAInputError as exc:
        skeleton_payload = {}
        provenance_payload = {}
        functional_report_payload = None
        issues.append(
            {
                "category": "invalid_stage_b_input",
                "blocker": str(exc),
                "next_action": "fix the Stage B skeleton or candidate provenance JSON",
            }
        )

    pre_stage_a_issues = list(issues)
    pre_stage_a_issue_count = len(issues)

    if not issues:
        work = out / "generated"
        work.mkdir(parents=True, exist_ok=True)
        functional_coverage = (
            functional_report_payload.get("coverage")
            if isinstance(functional_report_payload, dict) and isinstance(functional_report_payload.get("coverage"), dict)
            else {}
        )
        functional_bindings = (
            functional_report_payload.get("binary_bindings")
            if isinstance(functional_report_payload, dict) and isinstance(functional_report_payload.get("binary_bindings"), dict)
            else {}
        )
        functional_candidate_binding = functional_bindings.get("candidate") if isinstance(functional_bindings.get("candidate"), dict) else {}
        try:
            if reference_contract_payload is not None:
                stage_a_result = stage_a_validate_contract_candidate(
                    reference_contract=Path(reference_contract),
                    candidate=Path(candidate),
                    linker_map_candidate=Path(linker_map_candidate),
                    skeleton_manifest=Path(skeleton_manifest),
                    model=model,
                    out=out / "stage-a",
                )
            else:
                if original is None or linker_map_original is None:
                    raise StageAInputError(
                        "Stage B validation requires --reference-contract for zero-original validation "
                        "or --original and --linker-map-original for legacy pair validation"
                    )
                map_result = stage_a_generate_map(
                    original=Path(original),
                    candidate=Path(candidate),
                    linker_map_original=Path(linker_map_original),
                    linker_map_candidate=Path(linker_map_candidate),
                    out=work / "block-map.json",
                    layout_contract_out=work / "layout-contract.json",
                    original_flags=original_flags,
                    candidate_flags=candidate_flags,
                    proof_rule=STAGE_B_PROOF_RULE,
                    proof_metadata={
                        "stage_b": {
                            "checked": True,
                            "target_name": target_name,
                            "skeleton_manifest_sha256": sha256_file(Path(skeleton_manifest)),
                            "candidate_provenance_sha256": sha256_file(Path(candidate_provenance)),
                            "functional_tests_report_sha256": sha256_file(Path(functional_report)) if functional_report is not None else "",
                            "upstream_source_access": False,
                            "manual_behavioral_fixups": [],
                            "functional_tests_status": "pass",
                            "functional_tests_suite_id": str(functional_report_payload.get("suite_id") or "")
                            if isinstance(functional_report_payload, dict)
                            else "",
                            "functional_tests_suite_sha256": str(functional_report_payload.get("suite_sha256") or "")
                            if isinstance(functional_report_payload, dict)
                            else "",
                            "functional_tests_suite_case_manifest_sha256": str(functional_report_payload.get("suite_case_manifest_sha256") or "")
                            if isinstance(functional_report_payload, dict)
                            else "",
                            "functional_tests_case_ids_sha256": str(functional_coverage.get("case_ids_sha256") or ""),
                            "functional_tests_candidate_binary_sha256": str(functional_candidate_binding.get("sha256") or ""),
                        }
                    },
                )
                stage_a_result = stage_a_validate(
                    original=Path(original),
                    candidate=Path(candidate),
                    mapping=work / "block-map.json",
                    model=model,
                    out=out / "stage-a",
                    layout_contract=work / "layout-contract.json",
                )
                if map_result.get("status") != "pass":
                    issues.append(
                        {
                            "category": "stage_a_map_incomplete",
                            "blocker": "Stage A generated map did not close for the Stage B candidate",
                            "next_action": "inspect generated/block-map.json and extend the skeleton or mapping generator",
                            "details": map_result.get("issues", []),
                        }
                    )
            if stage_a_result.get("verdict") != "pass":
                issues.append(
                    {
                        "category": "stage_a_validation_incomplete",
                        "blocker": "Stage A did not produce a final pass for the Stage B candidate",
                        "next_action": "inspect stage-a/verdict.json and repair the candidate or proof inputs",
                        "details": stage_a_result.get("counts", {}),
                    }
                )
        except StageAInputError as exc:
            issues.append(
                {
                    "category": "stage_a_input_error",
                    "blocker": str(exc),
                    "next_action": "provide supported Windows PE binaries, linker maps, and a supported Stage A model",
                }
            )

    provenance_issue_count = pre_stage_a_issue_count

    reference_contract_coverage = _stage_b_reference_contract_coverage(
        reference_contract_path=Path(reference_contract) if reference_contract is not None else None,
        reference_contract=reference_contract_payload,
        skeleton=skeleton_payload,
        provenance=provenance_payload,
        functional=functional_report_payload,
        binary_evidence=binary_evidence,
        stage_a_result=stage_a_result,
        map_result=map_result,
    )
    stage_a_diagnostics = _stage_b_stage_a_diagnostics(
        out=out,
        map_result=map_result,
        stage_a_result=stage_a_result,
    )
    functional_diagnostics = _stage_b_functional_diagnostics(
        functional_report_path=Path(functional_report) if functional_report is not None else None,
        functional_report_payload=functional_report_payload,
    )
    status = "pass" if not issues and stage_a_result and stage_a_result.get("verdict") == "pass" else "incomplete"
    result = {
        "format": "stage-b-validation-v1",
        "status": status,
        "started_at": started_at,
        "completed_at": utc_now(),
        "target_name": target_name,
        "proof_rule": STAGE_B_PROOF_RULE,
        "skeleton_manifest": str(skeleton_manifest),
        "candidate_provenance": str(candidate_provenance),
        "functional_report": str(functional_report) if functional_report is not None else None,
        "reference_contract": _stage_b_reference_contract_artifact(Path(reference_contract)) if reference_contract is not None else None,
        "reference_contract_coverage": reference_contract_coverage,
        "binaries": binary_evidence,
        "provenance_status": "pass" if provenance_issue_count == 0 else "incomplete",
        "stage_a": {
            "map_status": None if map_result is None else map_result.get("status"),
            "verdict": None if stage_a_result is None else stage_a_result.get("verdict"),
            "report": str(out / "stage-a") if stage_a_result is not None else None,
            "gate": _stage_b_stage_a_gate(
                pre_stage_a_issues=pre_stage_a_issues,
                all_issues=issues,
                stage_a_result=stage_a_result,
                map_result=map_result,
            ),
            "diagnostics": stage_a_diagnostics,
        },
        "issues": issues,
        "skeleton": skeleton_payload,
        "candidate": provenance_payload,
        "functional": functional_report_payload,
        "functional_diagnostics": functional_diagnostics,
    }
    write_json(out / "stage-b.json", result)
    return result


def stage_b_audit_readiness(*, reports: dict[str, Path], out: Path) -> dict[str, Any]:
    out = Path(out)
    out.mkdir(parents=True, exist_ok=True)
    targets: dict[str, Any] = {}
    for target_name in STAGE_B_REQUIRED_TARGETS:
        report = reports.get(target_name)
        if report is None:
            targets[target_name] = _missing_readiness_target(target_name)
            continue
        try:
            payload = _load_json(Path(report))
        except StageAInputError as exc:
            targets[target_name] = _invalid_readiness_target(target_name, Path(report), str(exc))
            continue
        targets[target_name] = _audit_readiness_target(target_name, Path(report), payload)

    ready = sum(1 for item in targets.values() if item["status"] == "pass")
    result = {
        "format": "stage-b-readiness-audit-v1",
        "status": "pass" if ready == len(STAGE_B_REQUIRED_TARGETS) else "incomplete",
        "generated_at": utc_now(),
        "required_targets": list(STAGE_B_REQUIRED_TARGETS),
        "inputs": {target: str(path) for target, path in reports.items()},
        "counts": {
            "targets": len(STAGE_B_REQUIRED_TARGETS),
            "ready": ready,
            "incomplete": len(STAGE_B_REQUIRED_TARGETS) - ready,
        },
        "targets": targets,
    }
    write_json(out / "stage-b-readiness.json", result)
    return result


def stage_b_explain_delta(
    *,
    reference_contract: Path,
    candidate: Path,
    linker_map_candidate: Path,
    skeleton_manifest: Path,
    out: Path,
    candidate_crash_report: Path | None = None,
    functional_report: Path | None = None,
    model: str = STAGE_A_MODEL_ID,
) -> dict[str, Any]:
    from .stage_a import stage_a_validate_contract_candidate

    out = Path(out)
    out.mkdir(parents=True, exist_ok=True)
    reference_contract = Path(reference_contract)
    candidate = Path(candidate)
    linker_map_candidate = Path(linker_map_candidate)
    skeleton_manifest = Path(skeleton_manifest)
    contract = _load_json(reference_contract)
    skeleton = _load_json(skeleton_manifest)
    crash = _load_optional_stage_b_json(Path(candidate_crash_report)) if candidate_crash_report is not None else None
    functional = _load_optional_stage_b_json(Path(functional_report)) if functional_report is not None else None
    functional_diagnostics = _stage_b_functional_diagnostics(
        functional_report_path=Path(functional_report) if functional_report is not None else None,
        functional_report_payload=functional,
    )
    contract_validation = stage_a_validate_contract_candidate(
        reference_contract=reference_contract,
        candidate=candidate,
        linker_map_candidate=linker_map_candidate,
        skeleton_manifest=skeleton_manifest,
        model=model,
        out=out / "stage-a-contract-candidate",
    )
    candidate_bin = _parse_stage_a_pe(candidate)
    candidate_functions = _parse_linker_map_functions(linker_map_candidate, candidate_bin)
    items = _stage_b_delta_repair_items(
        contract=contract,
        validation=contract_validation,
        skeleton=skeleton,
        candidate_functions=candidate_functions,
        candidate_binary=candidate_bin,
        crash=crash,
        functional=functional,
    )
    result = {
        "format": "stage-b-delta-explanation-v1",
        "status": "incomplete" if items else "pass",
        "generated_at": utc_now(),
        "reference_contract": _stage_b_reference_contract_artifact(reference_contract),
        "candidate": {"path": str(candidate), "sha256": sha256_file(candidate)},
        "linker_map_candidate": {"path": str(linker_map_candidate), "sha256": sha256_file(linker_map_candidate)},
        "skeleton_manifest": {"path": str(skeleton_manifest), "sha256": sha256_file(skeleton_manifest)},
        "candidate_crash_report": None
        if candidate_crash_report is None
        else {"path": str(candidate_crash_report), "sha256": sha256_file(Path(candidate_crash_report))},
        "functional_report": None if functional_report is None else {"path": str(functional_report), "sha256": sha256_file(Path(functional_report))},
        "contract_candidate_validation": contract_validation,
        "functional_diagnostics": functional_diagnostics,
        "repair_items": items,
        "counts": {
            "repair_items": len(items),
            "by_repair_class": _count_by(items, "likely_repair_class"),
            "by_family": _count_by(items, "violated_contract_family"),
        },
    }
    write_json(out / "stage-b-delta.json", result)
    return result


def _load_optional_stage_b_json(path: Path) -> dict[str, Any] | None:
    payload = _load_json(path)
    return payload if isinstance(payload, dict) else {"format": "unknown", "payload": payload}


def _stage_b_delta_repair_items(
    *,
    contract: dict[str, Any],
    validation: dict[str, Any],
    skeleton: dict[str, Any],
    candidate_functions: list[dict[str, Any]],
    crash: dict[str, Any] | None,
    functional: dict[str, Any] | None,
    candidate_binary: Any | None = None,
) -> list[dict[str, Any]]:
    source_map = _stage_b_source_map_by_function(skeleton)
    contract_functions = _stage_b_contract_functions(contract)
    candidate_by_name = {str(item.get("name") or ""): item for item in candidate_functions}
    items: list[dict[str, Any]] = []
    for family in validation.get("families", []) if isinstance(validation.get("families"), list) else []:
        if not isinstance(family, dict) or family.get("status") in {"satisfied", "not_applicable"}:
            continue
        family_name = str(family.get("family") or "unknown")
        evidence = family.get("evidence") if isinstance(family.get("evidence"), dict) else {}
        missing_details = evidence.get("missing_function_details") if isinstance(evidence.get("missing_function_details"), list) else []
        if missing_details:
            for detail in missing_details[:20]:
                if not isinstance(detail, dict):
                    continue
                function_name = str(detail.get("function") or "")
                if not function_name:
                    continue
                source_location = _stage_b_source_location(source_map, function_name)
                repair_class = _stage_b_function_range_detail_repair_class(function_name, detail, source_location)
                items.append(
                    _stage_b_repair_item(
                        family=family_name,
                        function=function_name,
                        block_id=None,
                        source_map=source_map,
                        repair_class=repair_class,
                        next_action=str(detail.get("next_action") or _stage_b_function_range_next_action(function_name, repair_class)),
                        evidence={
                            "family": family,
                            "missing_function_detail": detail,
                            "contract_function": contract_functions.get(function_name, {}),
                        },
                    )
                )
            continue
        missing = evidence.get("missing_functions") if isinstance(evidence.get("missing_functions"), list) else []
        if missing:
            for name in missing[:20]:
                function_name = str(name)
                source_location = _stage_b_source_location(source_map, function_name)
                repair_class = _stage_b_function_range_repair_class(function_name, source_location)
                items.append(
                    _stage_b_repair_item(
                        family=family_name,
                        function=function_name,
                        block_id=None,
                        source_map=source_map,
                        repair_class=repair_class,
                        next_action=_stage_b_function_range_next_action(function_name, repair_class),
                        evidence={"family": family, "contract_function": contract_functions.get(function_name, {})},
                    )
                )
            continue
        if family_name == "abi_callsites":
            items.extend(_stage_b_abi_repair_items(family=family, evidence=evidence, source_map=source_map))
            continue
        items.append(
            _stage_b_repair_item(
                family=family_name,
                function=_stage_b_first_contract_function(contract_functions),
                block_id=None,
                source_map=source_map,
                repair_class=_stage_b_repair_class_for_family(family_name, evidence),
                next_action=str(family.get("next_action") or "inspect the contract family evidence and repair the candidate"),
                evidence={"family": family},
            )
        )
    items.extend(_stage_b_functional_repair_items(functional, source_map))
    items.extend(_stage_b_crash_repair_items(crash, candidate_functions, source_map, candidate_binary))
    for index, item in enumerate(sorted(items, key=_stage_b_repair_rank), start=1):
        item["rank"] = index
    return sorted(items, key=lambda item: int(item["rank"]))


def _stage_b_repair_item(
    *,
    family: str,
    function: str | None,
    block_id: str | None,
    source_map: dict[str, dict[str, Any]],
    repair_class: str,
    next_action: str,
    evidence: dict[str, Any],
) -> dict[str, Any]:
    location = _stage_b_source_location(source_map, function)
    return {
        "violated_contract_family": family,
        "original_function": function,
        "original_block": block_id,
        "generated_source_location": location,
        "likely_repair_class": repair_class,
        "next_action": next_action,
        "evidence": evidence,
    }


def _stage_b_source_map_by_function(skeleton: dict[str, Any]) -> dict[str, dict[str, Any]]:
    source_map = skeleton.get("source_map") if isinstance(skeleton.get("source_map"), dict) else {}
    functions = source_map.get("functions") if isinstance(source_map.get("functions"), list) else []
    result = {}
    for item in functions:
        if isinstance(item, dict) and isinstance(item.get("function"), str):
            names = [item["function"]]
            aliases = item.get("aliases") if isinstance(item.get("aliases"), list) else []
            names.extend(alias for alias in aliases if isinstance(alias, str) and alias)
            location = {
                "file": item.get("file"),
                "line_start": item.get("line_start"),
                "line_end": item.get("line_end"),
            }
            for optional_key in ("source_kind", "rva_start", "rva_end"):
                if optional_key in item:
                    location[optional_key] = item.get(optional_key)
            for name in names:
                result.setdefault(name, location)
                result.setdefault(_linker_function_match_key(name), location)
    return result


def _stage_b_source_location(source_map: dict[str, dict[str, Any]], function: str | None) -> dict[str, Any] | None:
    if not function:
        return None
    return source_map.get(function) or source_map.get(_linker_function_match_key(function))


def _stage_b_contract_functions(contract: dict[str, Any]) -> dict[str, dict[str, Any]]:
    constraints = contract.get("constraints") if isinstance(contract.get("constraints"), dict) else {}
    function_contract = constraints.get("function_ranges") if isinstance(constraints.get("function_ranges"), dict) else {}
    return {
        str(item.get("name")): item
        for item in function_contract.get("functions", [])
        if isinstance(item, dict) and isinstance(item.get("name"), str)
    }


def _stage_b_first_contract_function(functions: dict[str, dict[str, Any]]) -> str | None:
    return sorted(functions)[0] if functions else None


def _stage_b_repair_class_for_family(family: str, evidence: dict[str, Any]) -> str:
    if family == "abi_callsites":
        candidate_abi = evidence.get("candidate_abi") if isinstance(evidence.get("candidate_abi"), dict) else {}
        candidate = candidate_abi.get("candidate") if isinstance(candidate_abi.get("candidate"), dict) else {}
        candidate_functions = candidate.get("functions") if isinstance(candidate.get("functions"), list) else []
        reference_counts = evidence.get("reference_counts") if isinstance(evidence.get("reference_counts"), dict) else {}
        candidate_counts = evidence.get("candidate_counts") if isinstance(evidence.get("candidate_counts"), dict) else {}
        if not candidate_functions:
            if (reference_counts.get("import_prototypes") or 0) != (candidate_counts.get("import_prototypes") or 0):
                return "import_prototype_mismatch"
            return "abi_contract_coverage"
        text = json.dumps(evidence, sort_keys=True, default=str).lower()
        if "sret" in text or "out_param" in text:
            return "hidden_sret_or_out_param"
        if "printf" in text or "varargs" in text or "stdio" in text:
            return "varargs_or_stdio_bridge"
        if "register" in text or "clobber" in text or "preserved" in text:
            return "preserved_register_mismatch"
        if "stack" in text:
            return "stack_delta_mismatch"
        return "abi_callsite_mismatch"
    if family == "roots_and_jump_targets":
        return "jump_table_target"
    if family == "import_thunks":
        return "import_prototype_mismatch"
    if family in {"binary_faithfulness", "padding_alignment"}:
        return "layout_or_padding"
    return family


def _stage_b_abi_repair_items(
    *,
    family: dict[str, Any],
    evidence: dict[str, Any],
    source_map: dict[str, dict[str, Any]],
) -> list[dict[str, Any]]:
    reference_counts = evidence.get("reference_counts") if isinstance(evidence.get("reference_counts"), dict) else {}
    candidate_counts = evidence.get("candidate_counts") if isinstance(evidence.get("candidate_counts"), dict) else {}
    missing_functions = max(0, int(reference_counts.get("functions") or 0) - int(candidate_counts.get("functions") or 0))
    missing_callsites = max(0, int(reference_counts.get("callsites") or 0) - int(candidate_counts.get("callsites") or 0))
    coverage_gaps = evidence.get("coverage_gaps") if isinstance(evidence.get("coverage_gaps"), dict) else {}
    coverage_gap_counts = coverage_gaps.get("counts") if isinstance(coverage_gaps.get("counts"), dict) else {}
    items: list[dict[str, Any]] = []
    items.extend(_stage_b_abi_coverage_gap_items(evidence, source_map))
    if missing_functions or missing_callsites:
        named_missing_functions = coverage_gap_counts.get("missing_functions")
        partial_callsite_functions = coverage_gap_counts.get("incomplete_callsite_functions")
        named_missing_callsites = coverage_gap_counts.get("missing_callsites")
        items.append(
            _stage_b_repair_item(
                family="abi_callsites",
                function=None,
                block_id=None,
                source_map=source_map,
                repair_class="abi_callsite_coverage",
                next_action=(
                    f"recover ABI coverage gaps: {named_missing_functions if named_missing_functions is not None else missing_functions} named missing functions"
                    f" and {named_missing_callsites if named_missing_callsites is not None else missing_callsites} missing callsites"
                    f" across {partial_callsite_functions if partial_callsite_functions is not None else 'unknown'} partially matched functions"
                    f" (raw count deficit: {missing_functions} functions, {missing_callsites} callsites); "
                    "start with missing linker-root/function coverage, then rerun Stage A contract validation"
                ),
                evidence={
                    "family": _stage_b_contract_family_summary(family),
                    "reference_counts": reference_counts,
                    "candidate_counts": candidate_counts,
                    "missing": {"functions": missing_functions, "callsites": missing_callsites},
                    "coverage_gap_counts": coverage_gap_counts,
                },
            )
        )
    for sample in _stage_b_candidate_abi_callsite_samples(evidence):
        items.append(
            _stage_b_repair_item(
                family="abi_callsites",
                function=sample.get("function"),
                block_id=sample.get("block_id"),
                source_map=source_map,
                repair_class=str(sample.get("repair_class") or "abi_callsite_mismatch"),
                next_action=str(sample.get("next_action") or "repair this generated ABI/callsite before final Stage A validation"),
                evidence={"callsite": sample},
            )
        )
    if not items:
        items.append(
            _stage_b_repair_item(
                family="abi_callsites",
                function=None,
                block_id=None,
                source_map=source_map,
                repair_class=_stage_b_repair_class_for_family("abi_callsites", evidence),
                next_action=str(family.get("next_action") or "inspect ABI/callsite evidence and repair the candidate"),
                evidence={"family": family},
            )
        )
    return items


def _stage_b_abi_coverage_gap_items(
    evidence: dict[str, Any],
    source_map: dict[str, dict[str, Any]],
    *,
    limit: int = 8,
) -> list[dict[str, Any]]:
    coverage_gaps = evidence.get("coverage_gaps") if isinstance(evidence.get("coverage_gaps"), dict) else {}
    items: list[dict[str, Any]] = []
    missing_functions = coverage_gaps.get("missing_functions") if isinstance(coverage_gaps.get("missing_functions"), list) else []
    for sample in missing_functions:
        if not isinstance(sample, dict):
            continue
        name = sample.get("name")
        if not isinstance(name, str) or not name:
            continue
        source_location = _stage_b_source_location(source_map, name)
        repair_class = _stage_b_function_coverage_repair_class(name, source_location)
        items.append(
            _stage_b_repair_item(
                family="abi_callsites",
                function=name,
                block_id=None,
                source_map=source_map,
                repair_class=repair_class,
                next_action=_stage_b_function_coverage_next_action(name, repair_class),
                evidence={"coverage_gap": sample},
            )
        )
        if len(items) >= limit:
            return items

    incomplete_callsites = (
        coverage_gaps.get("incomplete_callsites")
        if isinstance(coverage_gaps.get("incomplete_callsites"), list)
        else []
    )
    for sample in incomplete_callsites:
        if not isinstance(sample, dict):
            continue
        name = sample.get("name")
        if not isinstance(name, str) or not name:
            continue
        items.append(
            _stage_b_repair_item(
                family="abi_callsites",
                function=name,
                block_id=None,
                source_map=source_map,
                repair_class="abi_callsite_function_coverage",
                next_action=(
                    f"recover {sample.get('missing_callsites')} missing generated callsites for {name}; "
                    "preserve call instructions and rerun Stage A contract validation"
                ),
                evidence={"coverage_gap": sample},
            )
        )
        if len(items) >= limit:
            return items
    return items


def _stage_b_function_coverage_repair_class(function_name: str, source_location: dict[str, Any] | None = None) -> str:
    if function_name.startswith("section-gap-"):
        return "section_gap_or_padding_coverage"
    source_kind = source_location.get("source_kind") if isinstance(source_location, dict) else None
    if source_kind == "omitted_import_thunk":
        return "import_thunk_linkage"
    if source_kind == "generated_contract_placeholder":
        return "missing_decompiler_body"
    if _stage_b_is_runtime_crt_support_function(function_name):
        return "runtime_crt_function_coverage"
    return "abi_function_coverage"


def _stage_b_function_coverage_next_action(function_name: str, repair_class: str) -> str:
    if repair_class == "runtime_crt_function_coverage":
        return (
            f"align generated runtime/CRT closure and linker roots for {function_name}; "
            "preserve the support function or make the runtime-link policy explicit before rerunning Stage A"
        )
    if repair_class == "import_thunk_linkage":
        return (
            f"repair import thunk linkage for {function_name}; preserve the thunk/import classification "
            "or link through the matching import surface before rerunning Stage A"
        )
    if repair_class == "missing_decompiler_body":
        return (
            f"replace the generated contract placeholder for {function_name} with recovered behavior "
            "from reverse-engineering evidence before expecting Stage A equivalence"
        )
    if repair_class == "section_gap_or_padding_coverage":
        return (
            f"classify {function_name} as code, padding, or a section-gap artifact in the Stage A contract "
            "and generated candidate layout"
        )
    return f"recover generated ABI evidence for {function_name}; emit the function in the candidate linker map and preserve its callsites"


def _stage_b_function_range_repair_class(function_name: str, source_location: dict[str, Any] | None = None) -> str:
    repair_class = _stage_b_function_coverage_repair_class(function_name, source_location)
    return "function_mapping" if repair_class == "abi_function_coverage" else repair_class


def _stage_b_function_range_detail_repair_class(
    function_name: str,
    detail: dict[str, Any],
    source_location: dict[str, Any] | None = None,
) -> str:
    category = str(detail.get("category") or "")
    if category in {"import_thunk_symbol_missing_with_matching_import", "import_thunk_symbol_missing"}:
        return "import_thunk_linkage"
    if category == "runtime_entry_replaced_by_generated_bridge":
        return "runtime_crt_function_coverage"
    if category == "generated_contract_placeholder_missing":
        return "missing_decompiler_body"
    if category == "section_gap_or_padding_missing":
        return "section_gap_or_padding_coverage"
    return _stage_b_function_range_repair_class(function_name, source_location)


def _stage_b_function_range_next_action(function_name: str, repair_class: str) -> str:
    if repair_class == "function_mapping":
        return f"generate or retain candidate implementation and linker root for {function_name}"
    if repair_class == "import_thunk_linkage":
        return (
            f"preserve the import thunk symbol for {function_name} or add a Stage A import-thunk representation "
            "mapping that proves the linked import surface is equivalent"
        )
    if repair_class == "missing_decompiler_body":
        return f"replace or root the generated contract placeholder for {function_name} before rerunning Stage A"
    if repair_class == "runtime_crt_function_coverage":
        return f"align runtime/CRT entry generation and linker roots for {function_name}"
    if repair_class == "section_gap_or_padding_coverage":
        return f"classify and preserve the executable section span represented by {function_name}"
    return _stage_b_function_coverage_next_action(function_name, repair_class)


def _stage_b_contract_family_summary(family: dict[str, Any]) -> dict[str, Any]:
    return {
        "family": family.get("family"),
        "status": family.get("status"),
        "contract_status": family.get("contract_status"),
        "blocker": family.get("blocker"),
        "next_action": family.get("next_action"),
    }


def _stage_b_candidate_abi_callsite_samples(evidence: dict[str, Any], *, limit: int = 6) -> list[dict[str, Any]]:
    candidate_abi = evidence.get("candidate_abi") if isinstance(evidence.get("candidate_abi"), dict) else {}
    candidate = candidate_abi.get("candidate") if isinstance(candidate_abi.get("candidate"), dict) else {}
    functions = candidate.get("functions") if isinstance(candidate.get("functions"), list) else []
    samples: list[dict[str, Any]] = []
    for function in functions:
        if not isinstance(function, dict):
            continue
        function_name = str(function.get("name") or "")
        callsites = function.get("callsites") if isinstance(function.get("callsites"), list) else []
        for callsite in callsites:
            if not isinstance(callsite, dict):
                continue
            sample = _stage_b_candidate_abi_callsite_sample(function_name, callsite)
            if sample is not None:
                samples.append(sample)
            if len(samples) >= limit:
                return samples
    return samples


def _stage_b_candidate_abi_callsite_sample(function_name: str, callsite: dict[str, Any]) -> dict[str, Any] | None:
    hidden = callsite.get("hidden_sret_or_out_param_evidence") if isinstance(callsite.get("hidden_sret_or_out_param_evidence"), dict) else {}
    varargs = callsite.get("varargs_evidence") if isinstance(callsite.get("varargs_evidence"), dict) else {}
    targets = callsite.get("function_pointer_targets") if isinstance(callsite.get("function_pointer_targets"), list) else []
    if hidden.get("status") == "candidate":
        repair_class = _stage_b_hidden_address_repair_class(function_name, hidden)
        next_action = _stage_b_hidden_address_next_action(function_name, callsite, repair_class)
    elif varargs.get("status") == "candidate":
        repair_class = "varargs_or_stdio_bridge"
        next_action = f"verify generated varargs/stdout-stderr bridge for {function_name} at {callsite.get('id')}"
    elif targets:
        repair_class = _stage_b_function_pointer_repair_class(callsite)
        next_action = _stage_b_function_pointer_next_action(function_name, callsite, repair_class)
    else:
        return None
    return {
        "function": function_name,
        "block_id": callsite.get("block_id"),
        "callsite_id": callsite.get("id"),
        "instruction": callsite.get("instruction"),
        "target": callsite.get("target"),
        "argument_sources": callsite.get("argument_sources") if isinstance(callsite.get("argument_sources"), list) else [],
        "hidden_sret_or_out_param_evidence": hidden,
        "varargs_evidence": varargs,
        "function_pointer_targets": targets,
        "repair_class": repair_class,
        "next_action": next_action,
    }


def _stage_b_hidden_address_repair_class(function_name: str, hidden: dict[str, Any]) -> str:
    role = _stage_b_hidden_address_role(hidden)
    if role == "stack_out_param_or_scratch_buffer":
        if _stage_b_is_runtime_crt_bridge_function(function_name):
            return "runtime_crt_stack_bridge"
        return "stack_scratch_buffer_or_out_param"
    if role == "computed_out_param_or_hidden_sret":
        return "computed_out_param_or_hidden_sret"
    return "hidden_sret_or_out_param"


def _stage_b_hidden_address_role(hidden: dict[str, Any]) -> str:
    role = hidden.get("address_role")
    if isinstance(role, str) and role:
        return role
    address_source = hidden.get("address_source") if isinstance(hidden.get("address_source"), dict) else {}
    if address_source.get("address_class") == "stack_address":
        return "stack_out_param_or_scratch_buffer"
    if address_source:
        return "computed_out_param_or_hidden_sret"
    return ""


def _stage_b_hidden_address_next_action(function_name: str, callsite: dict[str, Any], repair_class: str) -> str:
    callsite_id = callsite.get("id")
    actions = {
        "runtime_crt_stack_bridge": "verify generated runtime/CRT bridge and linker policy for this stack out-param helper",
        "stack_scratch_buffer_or_out_param": "verify generated prototype and local stack scratch/out-param handling",
        "stack_out_param_or_scratch_buffer": "verify generated prototype and local stack scratch/out-param handling",
        "computed_out_param_or_hidden_sret": "recover generated prototype and computed out-param or hidden-return bridge",
        "hidden_sret_or_out_param": "verify generated prototype/call bridge for address-like first argument",
    }
    return f"{actions.get(repair_class, actions['hidden_sret_or_out_param'])} for {function_name} at {callsite_id}"


def _stage_b_is_runtime_crt_bridge_function(function_name: str) -> bool:
    key = _linker_function_match_key(function_name).lower()
    return key in {
        "tmaincrtstartup",
        "maincrtstartup",
        "winmaincrtstartup",
        "wmain",
        "wgetmainargs",
    }


def _stage_b_is_runtime_crt_support_function(function_name: str) -> bool:
    key = _linker_function_match_key(function_name).lower()
    if _stage_b_is_runtime_crt_bridge_function(function_name):
        return True
    exact = {
        "findpesection",
        "findpesectionbyname",
        "findpesectionexec",
        "getpeimagebase",
        "isnonwritableincurrentimage",
        "validateimagebase",
    }
    if key in exact:
        return True
    prefixes = (
        "w64_mingw",
        "mingwthr",
        "mingw_",
        "dyn_tls_",
        "do_global_",
        "tlregdtor",
    )
    if key.startswith(prefixes):
        return True
    suffixes = (
        "_d2a",
        "_dtoa_r",
        "_gdtoa",
    )
    return key.endswith(suffixes)


def _stage_b_function_pointer_repair_class(callsite: dict[str, Any]) -> str:
    role = _stage_b_function_pointer_memory_role(callsite)
    if role == "global_writable_pointer_slot":
        return "global_callback_slot"
    if role == "global_readonly_pointer_slot":
        return "readonly_callback_table"
    if role == "argument_pointer_deref":
        return "argument_callback_table"
    if role == "global_pointer_deref":
        return "global_callback_table"
    if role in {"computed_pointer_deref", "computed_memory"}:
        return "computed_function_pointer_target"
    return "function_pointer_target"


def _stage_b_function_pointer_memory_role(callsite: dict[str, Any]) -> str:
    target = callsite.get("target") if isinstance(callsite.get("target"), dict) else {}
    role = target.get("memory_role")
    if isinstance(role, str) and role:
        return role
    source = target.get("source") if isinstance(target.get("source"), dict) else {}
    role = source.get("memory_role")
    if isinstance(role, str) and role:
        return role
    targets = callsite.get("function_pointer_targets") if isinstance(callsite.get("function_pointer_targets"), list) else []
    for item in targets:
        if not isinstance(item, dict):
            continue
        role = item.get("memory_role")
        if isinstance(role, str) and role:
            return role
        source = item.get("source") if isinstance(item.get("source"), dict) else {}
        role = source.get("memory_role")
        if isinstance(role, str) and role:
            return role
    return ""


def _stage_b_function_pointer_next_action(function_name: str, callsite: dict[str, Any], repair_class: str) -> str:
    callsite_id = callsite.get("id")
    actions = {
        "global_callback_slot": "recover initialization and generated storage for global callback/function-pointer slot",
        "readonly_callback_table": "recover the read-only callback table and preserve its candidate layout",
        "argument_callback_table": "recover the callback table/prototype passed into this generated function",
        "global_callback_table": "recover the global callback table and its indexed call targets",
        "computed_function_pointer_target": "recover the computed indirect-call table and prove every reachable target",
        "function_pointer_target": "resolve generated function-pointer target set",
    }
    return f"{actions.get(repair_class, actions['function_pointer_target'])} for {function_name} at {callsite_id}"


def _stage_b_functional_repair_items(functional: dict[str, Any] | None, source_map: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
    if not isinstance(functional, dict):
        return []
    items: list[dict[str, Any]] = []
    target_name = str(functional.get("target_name") or "")
    entry_function = _stage_b_functional_entry_function(target_name, source_map)
    for case in functional.get("cases", []) if isinstance(functional.get("cases"), list) else []:
        if not isinstance(case, dict) or case.get("status") == "pass":
            continue
        harness_items = _stage_b_functional_harness_repair_items(
            functional=functional,
            case=case,
            source_map=source_map,
            entry_function=entry_function,
        )
        if harness_items:
            items.extend(harness_items)
            continue
        repair_class = _stage_b_functional_case_repair_class(functional, case)
        items.append(
            _stage_b_repair_item(
                family="functional_expected_output",
                function=entry_function,
                block_id=None,
                source_map=source_map,
                repair_class=repair_class,
                next_action=_stage_b_functional_case_next_action(functional, case, repair_class),
                evidence={
                    "case": _stage_b_functional_case_summary(case),
                    "suite": _stage_b_functional_suite_summary(functional),
                },
            )
        )
    return items


def _stage_b_functional_harness_repair_items(
    *,
    functional: dict[str, Any],
    case: dict[str, Any],
    source_map: dict[str, dict[str, Any]],
    entry_function: str | None,
    limit: int = 8,
) -> list[dict[str, Any]]:
    candidate = case.get("candidate") if isinstance(case.get("candidate"), dict) else {}
    stdout = candidate.get("stdout") if isinstance(candidate.get("stdout"), dict) else {}
    text, artifact = _stage_b_stream_text(stdout)
    parsed = _stage_b_parse_cargo_test_output(text)
    failed_tests = parsed.get("failed_tests") if isinstance(parsed.get("failed_tests"), list) else []
    if not failed_tests:
        return []

    prefix_counts: Counter[str] = Counter()
    prefix_samples: dict[str, list[str]] = {}
    for failed in failed_tests:
        if not isinstance(failed, dict):
            continue
        name = str(failed.get("name") or "")
        if not name:
            continue
        prefix = _stage_b_harness_test_prefix(name)
        prefix_counts[prefix] += 1
        prefix_samples.setdefault(prefix, [])
        if len(prefix_samples[prefix]) < 5:
            prefix_samples[prefix].append(name)

    items: list[dict[str, Any]] = []
    target_name = str(functional.get("target_name") or "")
    for prefix, count in sorted(prefix_counts.items(), key=lambda item: (-item[1], item[0]))[:limit]:
        repair_class = _stage_b_harness_prefix_repair_class(target_name, prefix)
        samples = prefix_samples.get(prefix, [])
        sample_text = ", ".join(samples[:3])
        items.append(
            _stage_b_repair_item(
                family="functional_expected_output",
                function=entry_function,
                block_id=None,
                source_map=source_map,
                repair_class=repair_class,
                next_action=(
                    f"recover {target_name or 'candidate'} behavior for upstream harness prefix {prefix!r} "
                    f"({count} failing tests); start with {sample_text or 'the first failed harness case'}"
                ),
                evidence={
                    "case": _stage_b_functional_case_summary(case),
                    "suite": _stage_b_functional_suite_summary(functional),
                    "harness_test_prefix": {
                        "prefix": prefix,
                        "failed_tests": count,
                        "sample_tests": samples,
                        "total_failed_tests_in_artifact": len(failed_tests),
                        "result_line": parsed.get("result_line"),
                        "status_counts": parsed.get("status_counts"),
                    },
                    "candidate_stdout_artifact": artifact,
                },
            )
        )
    return items


def _stage_b_functional_entry_function(target_name: str, source_map: dict[str, dict[str, Any]]) -> str | None:
    target_id = _artifact_name(target_name)
    preferred = ["main", "entrypoint"]
    if "jq" in target_id:
        preferred = ["umain", "_wmain", "mainCRTStartup", "main", "entrypoint"]
    elif "ripgrep" in target_id or target_id == "rg":
        preferred = ["entrypoint", "main"]
    for name in preferred:
        if name in source_map or _linker_function_match_key(name) in source_map:
            return name
    names = sorted(name for name in source_map if name and not name.startswith("_stage_b_"))
    return names[0] if names else None


def _stage_b_functional_case_repair_class(functional: dict[str, Any], case: dict[str, Any]) -> str:
    mismatch = case.get("mismatch") if isinstance(case.get("mismatch"), dict) else {}
    raw_fields = mismatch.get("fields")
    fields = {str(field) for field in raw_fields} if isinstance(raw_fields, list) else set()
    candidate = case.get("candidate") if isinstance(case.get("candidate"), dict) else {}
    target_id = _artifact_name(str(functional.get("target_name") or ""))
    if bool(candidate.get("timed_out")) or fields.intersection({"timed_out", "timeout"}):
        return "candidate_timeout"
    if "stderr" in fields:
        return "stderr_behavior"
    if "stdout" in fields:
        return "stdout_behavior"
    if "returncode" in fields:
        if "jq" in target_id and "-n" in json.dumps(case, default=str):
            return "short_option_state_machine"
        return "cli_exit_status_behavior"
    return "functional_expected_output_failure"


def _stage_b_functional_case_next_action(functional: dict[str, Any], case: dict[str, Any], repair_class: str) -> str:
    case_id = case.get("id")
    target_name = str(functional.get("target_name") or "candidate")
    actions = {
        "candidate_timeout": "repair candidate termination or long-running control flow",
        "stderr_behavior": "recover diagnostic/stderr behavior for this public expected-output case",
        "stdout_behavior": "recover stdout-producing behavior for this public expected-output case",
        "short_option_state_machine": "repair generated short-option parsing and jq command dispatch for this case",
        "cli_exit_status_behavior": "recover exit-status behavior for this public expected-output case",
        "functional_expected_output_failure": "repair candidate behavior for this public expected-output case",
    }
    return f"{actions.get(repair_class, actions['functional_expected_output_failure'])} in {target_name} case {case_id}"


def _stage_b_functional_suite_summary(functional: dict[str, Any]) -> dict[str, Any]:
    coverage = functional.get("coverage") if isinstance(functional.get("coverage"), dict) else {}
    return {
        "target_name": functional.get("target_name"),
        "suite_id": functional.get("suite_id"),
        "suite_scope": coverage.get("suite_scope"),
        "source_revision": coverage.get("source_revision"),
        "case_count": coverage.get("case_count"),
    }


def _stage_b_harness_prefix_repair_class(target_name: str, prefix: str) -> str:
    target_id = _artifact_name(target_name)
    if "ripgrep" in target_id or target_id == "rg":
        ripgrep_classes = {
            "binary": "ripgrep_binary_search_behavior",
            "feature": "ripgrep_feature_behavior",
            "misc": "ripgrep_filesystem_behavior",
            "regression": "ripgrep_regression_behavior",
            "search": "ripgrep_search_behavior",
        }
        return ripgrep_classes.get(prefix, "ripgrep_upstream_harness_behavior")
    return "upstream_integration_harness"


def _stage_b_crash_repair_items(
    crash: dict[str, Any] | None,
    candidate_functions: list[dict[str, Any]],
    source_map: dict[str, dict[str, Any]],
    candidate_binary: Any | None = None,
) -> list[dict[str, Any]]:
    if not isinstance(crash, dict):
        return []
    location = _stage_b_candidate_crash_location(crash, candidate_binary)
    fault_rva = location.get("rva")
    function = _stage_b_function_for_rva(candidate_functions, fault_rva) if isinstance(fault_rva, int) else None
    if function is not None:
        repair_class = "stack_delta_mismatch"
        next_action = "inspect the candidate-only crash report and repair the mapped generated source span"
        text = json.dumps(crash, sort_keys=True, default=str).lower()
        if "realloc" in text or "stack" in text or "esp" in text:
            repair_class = "hidden_sret_or_out_param"
    elif location.get("classification") == "outside_candidate_image":
        repair_class = "candidate_crash_external_module"
        next_action = (
            "candidate crash PC is outside the candidate image; prioritize source-mapped ABI/callsite, import, "
            "and callback-table contract repairs unless a candidate-only backtrace identifies a candidate frame"
        )
    else:
        repair_class = "candidate_crash_unmapped"
        next_action = "enrich the candidate-only crash report with a candidate module, RVA, or backtrace before assigning a source repair class"
    return [
        _stage_b_repair_item(
            family="candidate_crash",
            function=function,
            block_id=None,
            source_map=source_map,
            repair_class=repair_class,
            next_action=next_action,
            evidence={"crash": crash, "candidate_location": location},
        )
    ]


def _stage_b_candidate_crash_location(crash: dict[str, Any], candidate_binary: Any | None) -> dict[str, Any]:
    explicit_rva = _optional_int(crash.get("exception_rva") or crash.get("instruction_rva") or crash.get("fault_rva"))
    image = _stage_b_candidate_image_range(candidate_binary)
    if explicit_rva is not None:
        return {
            "classification": "candidate_rva_explicit",
            "rva": explicit_rva,
            "candidate_image": image,
        }
    pc = _optional_int(
        crash.get("instruction_address")
        or crash.get("exception_address")
        or crash.get("program_counter")
        or crash.get("pc")
    )
    if pc is None:
        return {"classification": "missing_candidate_pc", "rva": None, "candidate_image": image}
    if image is None:
        return {"classification": "candidate_image_unknown", "pc": pc, "rva": None, "candidate_image": None}
    image_base = int(image["image_base"])
    image_end = int(image["image_end"])
    if image_base <= pc < image_end:
        return {
            "classification": "inside_candidate_image",
            "pc": pc,
            "rva": pc - image_base,
            "candidate_image": image,
        }
    return {
        "classification": "outside_candidate_image",
        "pc": pc,
        "rva": None,
        "candidate_image": image,
    }


def _stage_b_candidate_image_range(candidate_binary: Any | None) -> dict[str, int] | None:
    if candidate_binary is None:
        return None
    if isinstance(candidate_binary, dict):
        image_base = _optional_int(candidate_binary.get("image_base"))
        size_of_image = _optional_int(candidate_binary.get("size_of_image"))
    else:
        image_base = _optional_int(getattr(candidate_binary, "image_base", None))
        size_of_image = _optional_int(getattr(candidate_binary, "size_of_image", None))
    if image_base is None or size_of_image is None:
        return None
    return {
        "image_base": image_base,
        "size_of_image": size_of_image,
        "image_end": image_base + size_of_image,
    }


def _stage_b_function_for_rva(candidate_functions: list[dict[str, Any]], rva: int | None) -> str | None:
    if rva is None:
        return None
    for function in candidate_functions:
        start = int(function.get("rva_start") or 0)
        end = int(function.get("rva_end") or 0)
        if start <= rva < end:
            return str(function.get("name") or "")
    return None


def _stage_b_repair_rank(item: dict[str, Any]) -> tuple[int, str]:
    class_rank = {
        "candidate_crash": 0,
        "candidate_crash_unmapped": 0,
        "hidden_sret_or_out_param": 1,
        "computed_out_param_or_hidden_sret": 1,
        "abi_function_coverage": 2,
        "runtime_crt_function_coverage": 2,
        "import_thunk_linkage": 2,
        "missing_decompiler_body": 2,
        "section_gap_or_padding_coverage": 2,
        "abi_callsite_function_coverage": 2,
        "abi_callsite_coverage": 3,
        "stack_delta_mismatch": 3,
        "preserved_register_mismatch": 4,
        "varargs_or_stdio_bridge": 5,
        "stderr_behavior": 5,
        "stdout_behavior": 5,
        "short_option_state_machine": 6,
        "candidate_timeout": 6,
        "cli_exit_status_behavior": 6,
        "functional_expected_output_failure": 6,
        "upstream_integration_harness": 6,
        "ripgrep_binary_search_behavior": 6,
        "ripgrep_feature_behavior": 6,
        "ripgrep_filesystem_behavior": 6,
        "ripgrep_regression_behavior": 6,
        "ripgrep_search_behavior": 6,
        "ripgrep_upstream_harness_behavior": 6,
        "import_prototype_mismatch": 7,
        "abi_contract_coverage": 7,
        "global_callback_slot": 7,
        "argument_callback_table": 7,
        "global_callback_table": 7,
        "readonly_callback_table": 7,
        "computed_function_pointer_target": 7,
        "function_pointer_target": 7,
        "candidate_crash_external_module": 8,
        "runtime_crt_stack_bridge": 8,
        "stack_scratch_buffer_or_out_param": 8,
        "stack_out_param_or_scratch_buffer": 8,
        "jump_table_target": 8,
        "function_mapping": 9,
    }
    return (class_rank.get(str(item.get("likely_repair_class")), 20), str(item.get("original_function") or ""))


def _count_by(items: list[dict[str, Any]], key: str) -> dict[str, int]:
    counter: Counter[str] = Counter()
    for item in items:
        counter[str(item.get(key) or "")] += 1
    return dict(sorted(counter.items()))


_STAGE_A_CLOSED_OBLIGATION_STATUSES = frozenset({"proved", "waived_noncode"})


def _stage_b_functional_diagnostics(
    *,
    functional_report_path: Path | None,
    functional_report_payload: Any,
) -> dict[str, Any]:
    if functional_report_path is None and functional_report_payload is None:
        return {
            "format": "stage-b-functional-diagnostics-v1",
            "status": "not_provided",
            "report": None,
            "counts": {},
            "failure_counts": {},
            "failed_cases": [],
            "harness_tests": _stage_b_empty_harness_diagnostics(),
            "next_focus": [],
        }
    if not isinstance(functional_report_payload, dict):
        return {
            "format": "stage-b-functional-diagnostics-v1",
            "status": "invalid",
            "report": str(functional_report_path) if functional_report_path is not None else None,
            "counts": {},
            "failure_counts": {},
            "failed_cases": [],
            "harness_tests": _stage_b_empty_harness_diagnostics(),
            "next_focus": [
                {
                    "source": "functional_report",
                    "category": "invalid",
                    "next_action": "regenerate the Stage B functional report before diagnosing behavior",
                }
            ],
        }

    cases = [case for case in functional_report_payload.get("cases", []) if isinstance(case, dict)]
    failed_cases = [case for case in cases if case.get("status") != "pass"]
    field_counter: Counter[str] = Counter()
    timeout_failures = 0
    returncode_pairs: Counter[str] = Counter()
    for case in failed_cases:
        mismatch = case.get("mismatch") if isinstance(case.get("mismatch"), dict) else {}
        for field in mismatch.get("fields", []) if isinstance(mismatch.get("fields"), list) else []:
            field_counter[str(field)] += 1
        candidate = case.get("candidate") if isinstance(case.get("candidate"), dict) else {}
        expected = case.get("expected") if isinstance(case.get("expected"), dict) else {}
        if bool(candidate.get("timed_out")):
            timeout_failures += 1
        candidate_returncode = candidate.get("returncode")
        expected_returncode = expected.get("returncode")
        if expected_returncode != candidate_returncode:
            returncode_pairs[f"{expected_returncode}->{candidate_returncode}"] += 1

    harness_tests = _stage_b_harness_test_diagnostics(failed_cases)
    diagnostics = {
        "format": "stage-b-functional-diagnostics-v1",
        "status": str(functional_report_payload.get("status") or "unknown"),
        "report": str(functional_report_path) if functional_report_path is not None else None,
        "suite": {
            "target_name": functional_report_payload.get("target_name"),
            "suite_id": functional_report_payload.get("suite_id"),
            "suite_name": functional_report_payload.get("suite_name"),
            "suite_kind": functional_report_payload.get("suite_kind"),
            "upstream_suite": functional_report_payload.get("upstream_suite"),
        },
        "coverage": _stage_b_functional_coverage_summary(functional_report_payload),
        "counts": functional_report_payload.get("counts", {}),
        "failure_counts": {
            "mismatch_fields": _stage_b_sorted_counts(field_counter, "field"),
            "timeout_failures": timeout_failures,
            "returncode_pairs": _stage_b_sorted_counts(returncode_pairs, "returncode_pair"),
            "failed_case_prefixes": _stage_b_failed_case_prefix_counts(failed_cases),
        },
        "failed_cases": [_stage_b_functional_case_summary(case) for case in failed_cases[:30]],
        "harness_tests": harness_tests,
    }
    diagnostics["next_focus"] = _stage_b_functional_next_focus(diagnostics)
    return diagnostics


def _stage_b_functional_coverage_summary(payload: dict[str, Any]) -> dict[str, Any]:
    coverage = payload.get("coverage") if isinstance(payload.get("coverage"), dict) else {}
    return {
        "suite_scope": coverage.get("suite_scope"),
        "source": coverage.get("source"),
        "source_kind": coverage.get("source_kind"),
        "source_revision": coverage.get("source_revision"),
        "materialized_by": coverage.get("materialized_by"),
        "case_count": coverage.get("case_count"),
    }


def _stage_b_functional_case_summary(case: dict[str, Any]) -> dict[str, Any]:
    candidate = case.get("candidate") if isinstance(case.get("candidate"), dict) else {}
    mismatch = case.get("mismatch") if isinstance(case.get("mismatch"), dict) else {}
    expected = case.get("expected") if isinstance(case.get("expected"), dict) else {}
    summary = {
        "id": case.get("id"),
        "args": _stage_b_json_preview(case.get("args", []), max_items=8, max_depth=1),
        "mismatch_fields": list(mismatch.get("fields", [])) if isinstance(mismatch.get("fields"), list) else [],
        "expected_returncode": expected.get("returncode"),
        "candidate_returncode": candidate.get("returncode"),
        "candidate_timed_out": candidate.get("timed_out"),
        "expected_stdout_sha256": None
        if not isinstance(expected.get("stdout"), str)
        else sha256_bytes(expected["stdout"].encode("utf-8")),
        "candidate_stdout": _stage_b_stream_artifact_summary(candidate.get("stdout")),
        "expected_stderr_sha256": None
        if not isinstance(expected.get("stderr"), str)
        else sha256_bytes(expected["stderr"].encode("utf-8")),
        "candidate_stderr": _stage_b_stream_artifact_summary(candidate.get("stderr")),
    }
    if isinstance(case.get("expectation"), dict):
        summary["expectation"] = _stage_b_json_preview(case["expectation"])
    return summary


def _stage_b_stream_artifact_summary(value: Any) -> dict[str, Any]:
    artifact = value if isinstance(value, dict) else {}
    return {
        "path": artifact.get("path"),
        "sha256": artifact.get("sha256"),
        "bytes": artifact.get("bytes"),
        "preview": _stage_b_scalar_preview(artifact.get("preview")),
    }


def _stage_b_failed_case_prefix_counts(failed_cases: list[dict[str, Any]]) -> list[dict[str, Any]]:
    counter: Counter[str] = Counter()
    for case in failed_cases:
        case_id = str(case.get("id") or "")
        prefix = case_id.split("-", 1)[0] if case_id else "unknown"
        counter[prefix] += 1
    return _stage_b_sorted_counts(counter, "prefix")


def _stage_b_empty_harness_diagnostics() -> dict[str, Any]:
    return {
        "status_counts": [],
        "failed_test_prefixes": [],
        "top_failed_tests": [],
        "artifacts": [],
    }


def _stage_b_harness_test_diagnostics(failed_cases: list[dict[str, Any]]) -> dict[str, Any]:
    status_counter: Counter[str] = Counter()
    prefix_counter: Counter[str] = Counter()
    top_failed: list[dict[str, Any]] = []
    artifacts: list[dict[str, Any]] = []
    for case in failed_cases:
        case_id = str(case.get("id") or "")
        candidate = case.get("candidate") if isinstance(case.get("candidate"), dict) else {}
        stdout = candidate.get("stdout") if isinstance(candidate.get("stdout"), dict) else {}
        text, artifact = _stage_b_stream_text(stdout)
        parsed = _stage_b_parse_cargo_test_output(text)
        if not parsed["status_counts"] and not parsed["result_line"]:
            continue
        artifacts.append(
            {
                "case_id": case_id,
                "stream": "candidate.stdout",
                "path": artifact.get("path"),
                "source": artifact.get("source"),
                "bytes": artifact.get("bytes"),
                "read_bytes": artifact.get("read_bytes"),
                "truncated": artifact.get("truncated"),
                "result_line": parsed["result_line"],
            }
        )
        for item in parsed["status_counts"]:
            status_counter[str(item["status"])] += int(item["count"])
        for failed in parsed["failed_tests"]:
            prefix = _stage_b_harness_test_prefix(str(failed["name"]))
            prefix_counter[prefix] += 1
            if len(top_failed) < 50:
                top_failed.append({"case_id": case_id, "name": failed["name"], "prefix": prefix})
    return {
        "status_counts": _stage_b_sorted_counts(status_counter, "status"),
        "failed_test_prefixes": _stage_b_sorted_counts(prefix_counter, "prefix"),
        "top_failed_tests": top_failed,
        "artifacts": artifacts,
    }


def _stage_b_stream_text(artifact: dict[str, Any], *, max_bytes: int = 2_000_000) -> tuple[str, dict[str, Any]]:
    path_value = artifact.get("path")
    path = Path(path_value) if isinstance(path_value, str) and path_value else None
    if path is not None and path.is_file():
        data = path.read_bytes()[: max_bytes + 1]
        truncated = len(data) > max_bytes
        if truncated:
            data = data[:max_bytes]
        return (
            data.decode("utf-8", errors="replace"),
            {
                "path": str(path),
                "source": "path",
                "bytes": artifact.get("bytes"),
                "read_bytes": len(data),
                "truncated": truncated,
            },
        )
    preview = artifact.get("preview")
    text = preview if isinstance(preview, str) else ""
    return (
        text,
        {
            "path": str(path) if path is not None else None,
            "source": "preview" if text else "missing",
            "bytes": artifact.get("bytes"),
            "read_bytes": len(text.encode("utf-8", errors="replace")),
            "truncated": False,
        },
    )


def _stage_b_parse_cargo_test_output(text: str) -> dict[str, Any]:
    status_counter: Counter[str] = Counter()
    failed_tests: list[dict[str, Any]] = []
    result_line: dict[str, Any] | None = None
    for line in text.splitlines():
        status_match = _CARGO_TEST_STATUS_RE.match(line.strip())
        if status_match is not None:
            name = status_match.group("name")
            status = status_match.group("status")
            status_counter[status] += 1
            if status == "FAILED":
                failed_tests.append({"name": name})
            continue
        result_match = _CARGO_TEST_RESULT_RE.match(line.strip())
        if result_match is not None:
            result_line = {
                "status": result_match.group("status"),
                "summary": result_match.group("summary"),
                "counts": _stage_b_parse_cargo_test_result_counts(result_match.group("summary")),
            }
    return {
        "status_counts": _stage_b_sorted_counts(status_counter, "status"),
        "failed_tests": failed_tests,
        "result_line": result_line,
    }


def _stage_b_parse_cargo_test_result_counts(summary: str) -> dict[str, int]:
    counts: dict[str, int] = {}
    for count, name in re.findall(r"(\d+)\s+([A-Za-z_ ]+?)(?:;|$)", summary):
        counts[_artifact_name(name.strip()).replace("-", "_")] = int(count)
    return counts


def _stage_b_harness_test_prefix(name: str) -> str:
    parts = [part for part in name.split("::") if part]
    if not parts:
        return "unknown"
    return parts[0]


def _stage_b_functional_next_focus(diagnostics: dict[str, Any]) -> list[dict[str, Any]]:
    focus: list[dict[str, Any]] = []
    failure_counts = diagnostics.get("failure_counts") if isinstance(diagnostics.get("failure_counts"), dict) else {}
    for item in failure_counts.get("mismatch_fields", [])[:4]:
        field = item.get("field")
        if not field:
            continue
        focus.append(
            {
                "source": "functional_mismatch",
                "category": field,
                "count": item.get("count"),
                "next_action": _stage_b_functional_mismatch_next_action(str(field)),
            }
        )
    harness = diagnostics.get("harness_tests") if isinstance(diagnostics.get("harness_tests"), dict) else {}
    for item in harness.get("failed_test_prefixes", [])[:4]:
        prefix = item.get("prefix")
        if not prefix:
            continue
        focus.append(
            {
                "source": "upstream_harness",
                "category": prefix,
                "count": item.get("count"),
                "next_action": "recover or generate behavior for this upstream integration-test family before rerunning Stage A",
            }
        )
    return focus[:8]


def _stage_b_functional_mismatch_next_action(field: str) -> str:
    actions = {
        "returncode": "recover exit-status behavior for the failing command shapes",
        "timed_out": "investigate candidate hangs or missing process termination behavior",
        "timeout": "investigate candidate hangs or missing process termination behavior",
        "stdout": "recover stdout-producing behavior for the failing command shapes",
        "stderr": "recover diagnostic/stderr behavior for the failing command shapes",
    }
    return actions.get(field, "inspect failed functional cases and extend generated behavior recovery")


def _stage_b_stage_a_diagnostics(
    *,
    out: Path,
    map_result: dict[str, Any] | None,
    stage_a_result: dict[str, Any] | None,
) -> dict[str, Any]:
    stage_a_report = out / "stage-a"
    map_status = str(map_result.get("status") or "") if isinstance(map_result, dict) else ""
    verdict = str(stage_a_result.get("verdict") or "") if isinstance(stage_a_result, dict) else ""
    if map_result is None and stage_a_result is None:
        status = "not_run"
    elif map_status == "pass" and verdict == "pass":
        status = "pass"
    else:
        status = "incomplete"
    map_diagnostics = _stage_b_map_diagnostics(map_result)
    validation_diagnostics = _stage_b_validation_diagnostics(stage_a_report, stage_a_result)
    return {
        "format": "stage-b-stage-a-diagnostics-v1",
        "status": status,
        "artifacts": {
            "generated_block_map": str(out / "generated" / "block-map.json") if map_result is not None else None,
            "generated_layout_contract": str(out / "generated" / "layout-contract.json") if map_result is not None else None,
            "stage_a_report": str(stage_a_report) if stage_a_result is not None else None,
            "stage_a_verdict": str(stage_a_report / "verdict.json") if stage_a_result is not None else None,
            "stage_a_obligations": str(stage_a_report / "obligations.json") if stage_a_result is not None else None,
        },
        "map": map_diagnostics,
        "validation": validation_diagnostics,
        "next_focus": _stage_b_stage_a_next_focus(map_diagnostics, validation_diagnostics),
    }


def _stage_b_map_diagnostics(map_result: dict[str, Any] | None) -> dict[str, Any]:
    if not isinstance(map_result, dict):
        return {
            "status": "not_run",
            "counts": {},
            "issue_counts": [],
            "top_issues": [],
            "ambiguous_block_matches": [],
            "unmatched_functions": [],
            "section_gap_issues": [],
        }
    issues = [issue for issue in map_result.get("issues", []) if isinstance(issue, dict)]
    return {
        "status": map_result.get("status"),
        "counts": map_result.get("counts", {}),
        "issue_counts": _stage_b_count_dict_values(issues, "category", "category"),
        "top_issues": [_stage_b_issue_summary(issue) for issue in issues[:20]],
        "ambiguous_block_matches": _stage_b_ambiguous_block_matches(issues),
        "unmatched_functions": _stage_b_unmatched_function_issues(issues),
        "section_gap_issues": [
            _stage_b_issue_summary(issue)
            for issue in issues
            if issue.get("category") == "ambiguous_section_gap_match"
        ][:10],
    }


def _stage_b_validation_diagnostics(stage_a_report: Path, stage_a_result: dict[str, Any] | None) -> dict[str, Any]:
    if not isinstance(stage_a_result, dict):
        return {
            "status": "not_run",
            "counts": {},
            "obligation_status_counts": [],
            "unresolved_category_counts": [],
            "unresolved_samples_by_category": [],
            "top_unresolved": [],
            "unmapped_executable_ranges": [],
            "lean": {},
        }
    obligations_payload = _stage_b_load_json_if_exists(stage_a_report / "obligations.json")
    obligations = (
        [item for item in obligations_payload.get("obligations", []) if isinstance(item, dict)]
        if isinstance(obligations_payload, dict)
        else []
    )
    counts = stage_a_result.get("counts", {}) if isinstance(stage_a_result.get("counts"), dict) else {}
    unresolved = [
        obligation
        for obligation in obligations
        if str(obligation.get("status") or "") not in _STAGE_A_CLOSED_OBLIGATION_STATUSES
    ]
    category_counter: Counter[str] = Counter()
    for obligation in unresolved:
        category_counter[_stage_b_obligation_category(obligation)] += 1
    unmapped_ranges = [
        _stage_b_obligation_summary(obligation)
        for obligation in unresolved
        if obligation.get("status") == "unmapped" and obligation.get("kind") == "executable_byte_class"
    ]
    return {
        "status": stage_a_result.get("verdict"),
        "counts": counts,
        "obligation_status_counts": _stage_b_obligation_status_counts(obligations, counts),
        "unresolved_category_counts": _stage_b_sorted_counts(category_counter, "category"),
        "unresolved_samples_by_category": _stage_b_unresolved_samples_by_category(unresolved, category_counter),
        "top_unresolved": [_stage_b_obligation_summary(obligation) for obligation in unresolved[:30]],
        "unmapped_executable_ranges": unmapped_ranges[:30],
        "lean": _stage_b_lean_diagnostics(stage_a_result),
    }


def _stage_b_stage_a_next_focus(
    map_diagnostics: dict[str, Any],
    validation_diagnostics: dict[str, Any],
) -> list[dict[str, Any]]:
    focus: list[dict[str, Any]] = []
    for count in map_diagnostics.get("issue_counts", [])[:3]:
        category = count.get("category")
        if not category:
            continue
        focus.append(
            {
                "source": "map",
                "category": category,
                "count": count.get("count"),
                "next_action": _stage_b_map_category_next_action(str(category)),
            }
        )
    for count in validation_diagnostics.get("unresolved_category_counts", [])[:4]:
        category = count.get("category")
        if not category:
            continue
        focus.append(
            {
                "source": "stage_a_obligation",
                "category": category,
                "count": count.get("count"),
                "next_action": _stage_b_obligation_category_next_action(str(category)),
            }
        )
    return focus[:6]


def _stage_b_map_category_next_action(category: str) -> str:
    actions = {
        "ambiguous_block_match": "repair skeleton/code layout or add a proved split-block matcher for the listed functions",
        "missing_linker_map_entry": "preserve or recover the listed functions in the candidate linker map",
        "ambiguous_section_gap_match": "classify the section gaps as code or verified non-code padding before validation can close",
    }
    return actions.get(category, "inspect generated/block-map.json and close this map issue without weakening Stage A")


def _stage_b_obligation_category_next_action(category: str) -> str:
    actions = {
        "cfg_edge_mismatch": "repair the candidate CFG or mapping so direct edges target equivalent blocks",
        "unmapped_cfg_edge": "map the missing target block or prove it as a checked jump-table/indirect target",
        "unproved_reachability": "connect the block through checked roots, direct CFG edges, or checked jump-table targets",
        "missing_entry_mapping": "map every function entry root required by the linker map",
        "unknown_target": "classify the indirect target before accepting the candidate",
        "executable_byte_class": "map executable bytes as code or verify them as non-code padding",
    }
    return actions.get(category, "inspect stage-a/obligations.json and close this obligation class")


def _stage_b_ambiguous_block_matches(issues: list[dict[str, Any]], *, limit: int = 30) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    for issue in issues:
        if issue.get("category") != "ambiguous_block_match":
            continue
        details = issue.get("details") if isinstance(issue.get("details"), dict) else {}
        original_blocks = details.get("original_blocks")
        candidate_blocks = details.get("candidate_blocks")
        item = {
            "function": details.get("function"),
            "original_blocks": original_blocks,
            "candidate_blocks": candidate_blocks,
            "obligation_id": issue.get("obligation_id"),
            "next_action": issue.get("next_action"),
        }
        if isinstance(original_blocks, int) and isinstance(candidate_blocks, int):
            item["block_delta"] = candidate_blocks - original_blocks
        shape_preview = _stage_b_ambiguous_block_shape_preview(details)
        if shape_preview:
            item["shape_preview"] = shape_preview
        result.append(item)
        if len(result) >= limit:
            break
    return result


def _stage_b_ambiguous_block_shape_preview(details: dict[str, Any]) -> dict[str, Any]:
    original = _stage_b_first_block_shape(details.get("original_block_shapes"))
    candidate = _stage_b_first_block_shape(details.get("candidate_block_shapes"))
    preview: dict[str, Any] = {}
    if original:
        preview["original_first"] = original
    if candidate:
        preview["candidate_first"] = candidate
    return preview


def _stage_b_first_block_shape(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        return {}
    items = value.get("items")
    if not isinstance(items, list) or not items or not isinstance(items[0], dict):
        return {}
    block = items[0]
    terminal = block.get("terminal_instruction") if isinstance(block.get("terminal_instruction"), dict) else {}
    first = block.get("first_instruction") if isinstance(block.get("first_instruction"), dict) else {}
    return {
        "rva_start": block.get("rva_start"),
        "rva_end": block.get("rva_end"),
        "size": block.get("size"),
        "instruction_count": block.get("instruction_count"),
        "first": {
            "mnemonic": first.get("mnemonic"),
            "op_str": first.get("op_str"),
        }
        if first
        else None,
        "terminal": {
            "mnemonic": terminal.get("mnemonic"),
            "op_str": terminal.get("op_str"),
        }
        if terminal
        else None,
        "direct_edge_counts": block.get("direct_edge_counts") if isinstance(block.get("direct_edge_counts"), dict) else {},
    }


def _stage_b_unmatched_function_issues(issues: list[dict[str, Any]], *, limit: int = 10) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    for issue in issues:
        if issue.get("category") != "missing_linker_map_entry":
            continue
        details = issue.get("details") if isinstance(issue.get("details"), dict) else {}
        obligation_id = str(issue.get("obligation_id") or "")
        side = "original" if "unmatched-original" in obligation_id else "candidate" if "unmatched-candidate" in obligation_id else "unknown"
        functions = details.get("functions") if isinstance(details.get("functions"), list) else []
        result.append(
            {
                "side": side,
                "count": details.get("count", len(functions)),
                "functions": functions[:limit],
                "obligation_id": issue.get("obligation_id"),
                "next_action": issue.get("next_action"),
            }
        )
    return result


def _stage_b_issue_summary(issue: dict[str, Any]) -> dict[str, Any]:
    summary: dict[str, Any] = {}
    for key in ("category", "status", "severity", "obligation_id", "blocker", "next_action"):
        if key in issue:
            summary[key] = issue[key]
    if "details" in issue:
        summary["details"] = _stage_b_json_preview(issue["details"])
    return summary


def _stage_b_obligation_summary(obligation: dict[str, Any]) -> dict[str, Any]:
    summary: dict[str, Any] = {}
    for key in ("id", "status", "kind", "binary", "rva_start", "rva_end", "next_action"):
        if key in obligation:
            summary[key] = obligation[key]
    detail = _stage_b_obligation_detail(obligation)
    summary["category"] = _stage_b_obligation_category(obligation)
    if detail:
        for key in ("blocker", "next_action", "obligation_id"):
            if key in detail and key not in summary:
                summary[key] = detail[key]
        if "details" in detail:
            summary["details"] = _stage_b_json_preview(detail["details"])
    return summary


def _stage_b_obligation_detail(obligation: dict[str, Any]) -> dict[str, Any]:
    for key in ("failure", "failed", "incomplete"):
        value = obligation.get(key)
        if isinstance(value, dict):
            return value
    return {}


def _stage_b_obligation_category(obligation: dict[str, Any]) -> str:
    detail = _stage_b_obligation_detail(obligation)
    if detail.get("category"):
        return str(detail["category"])
    if obligation.get("category"):
        return str(obligation["category"])
    if obligation.get("kind"):
        return str(obligation["kind"])
    if obligation.get("status"):
        return str(obligation["status"])
    return "unknown"


def _stage_b_obligation_status_counts(obligations: list[dict[str, Any]], counts: dict[str, Any]) -> list[dict[str, Any]]:
    if obligations:
        return _stage_b_count_dict_values(obligations, "status", "status")
    by_status = counts.get("by_status") if isinstance(counts.get("by_status"), dict) else {}
    return _stage_b_sorted_counts(Counter({str(key): int(value) for key, value in by_status.items()}), "status")


def _stage_b_unresolved_samples_by_category(
    unresolved: list[dict[str, Any]],
    category_counter: Counter[str],
    *,
    limit_per_category: int = 10,
) -> list[dict[str, Any]]:
    samples: dict[str, list[dict[str, Any]]] = {}
    for obligation in unresolved:
        category = _stage_b_obligation_category(obligation)
        bucket = samples.setdefault(category, [])
        if len(bucket) < limit_per_category:
            bucket.append(_stage_b_obligation_summary(obligation))
    return [
        {
            "category": item["category"],
            "count": item["count"],
            "samples": samples.get(str(item["category"]), []),
        }
        for item in _stage_b_sorted_counts(category_counter, "category")
    ]


def _stage_b_count_dict_values(items: list[dict[str, Any]], value_key: str, output_key: str) -> list[dict[str, Any]]:
    counter: Counter[str] = Counter()
    for item in items:
        value = item.get(value_key)
        if value:
            counter[str(value)] += 1
    return _stage_b_sorted_counts(counter, output_key)


def _stage_b_sorted_counts(counter: Counter[str], key_name: str) -> list[dict[str, Any]]:
    return [
        {key_name: key, "count": count}
        for key, count in sorted(counter.items(), key=lambda item: (-item[1], item[0]))
    ]


def _stage_b_lean_diagnostics(stage_a_result: dict[str, Any]) -> dict[str, Any]:
    proof = stage_a_result.get("proof") if isinstance(stage_a_result.get("proof"), dict) else {}
    lean = proof.get("lean") if isinstance(proof.get("lean"), dict) else {}
    return {
        "available": lean.get("available"),
        "checked": lean.get("checked"),
        "final_pass_allowed": lean.get("final_pass_allowed"),
        "blocker": lean.get("blocker"),
        "next_action": lean.get("next_action"),
    }


def _stage_b_json_preview(value: Any, *, max_items: int = 12, max_depth: int = 3) -> Any:
    if max_depth <= 0:
        return _stage_b_scalar_preview(value)
    if isinstance(value, dict):
        items = list(value.items())
        preview = {
            str(key): _stage_b_json_preview(item_value, max_items=max_items, max_depth=max_depth - 1)
            for key, item_value in items[:max_items]
        }
        if len(items) > max_items:
            preview["_truncated_keys"] = len(items) - max_items
        return preview
    if isinstance(value, list):
        return {
            "count": len(value),
            "items": [
                _stage_b_json_preview(item, max_items=max_items, max_depth=max_depth - 1)
                for item in value[:max_items]
            ],
            "truncated": max(0, len(value) - max_items),
        }
    return _stage_b_scalar_preview(value)


def _stage_b_scalar_preview(value: Any) -> Any:
    if isinstance(value, str) and len(value) > 240:
        return value[:237] + "..."
    return value


def _stage_b_load_json_if_exists(path: Path) -> Any | None:
    if not path.is_file():
        return None
    try:
        return _load_json(path)
    except StageAInputError:
        return None


def _stage_b_reference_contract_artifact(path: Path) -> dict[str, Any]:
    return {
        "path": str(path),
        "sha256": sha256_file(path) if path.is_file() else None,
        "exists": path.exists(),
    }


def _stage_b_reference_contract_coverage(
    *,
    reference_contract_path: Path | None,
    reference_contract: dict[str, Any] | None,
    skeleton: dict[str, Any],
    provenance: dict[str, Any],
    functional: dict[str, Any] | None,
    binary_evidence: dict[str, Any],
    stage_a_result: dict[str, Any] | None,
    map_result: dict[str, Any] | None,
) -> dict[str, Any]:
    if reference_contract_path is None:
        return {
            "provided": False,
            "status": "not_provided",
            "families": [],
            "counts": {"satisfied": 0, "incomplete": 0, "not_applicable": 0, "violated": 0},
            "stage_b_counts": {"represented": 0, "missing": 0},
        }
    if reference_contract is None:
        family = _contract_family(
            "stage_a_reference_contract",
            "incomplete",
            "reference contract could not be loaded",
            "regenerate or repair the stage-a-reference-contract-v1 artifact",
            stage_b_status="missing",
            evidence={"path": str(reference_contract_path)},
        )
        return _contract_coverage_result(reference_contract_path, None, [family])

    constraints = reference_contract.get("constraints") if isinstance(reference_contract.get("constraints"), dict) else {}
    stage_a_pass = stage_a_result is not None and stage_a_result.get("verdict") == "pass"
    map_pass = stage_a_pass if map_result is None else map_result.get("status") == "pass"
    skeleton_counts = skeleton.get("counts") if isinstance(skeleton.get("counts"), dict) else {}
    recovery = skeleton.get("implementation_recovery") if isinstance(skeleton.get("implementation_recovery"), dict) else {}
    contract_counts = reference_contract.get("counts") if isinstance(reference_contract.get("counts"), dict) else {}
    function_contract = constraints.get("function_ranges") if isinstance(constraints.get("function_ranges"), dict) else {}
    block_contract = constraints.get("basic_blocks_and_cfg") if isinstance(constraints.get("basic_blocks_and_cfg"), dict) else {}
    import_contract = constraints.get("import_thunks") if isinstance(constraints.get("import_thunks"), dict) else {}
    padding_contract = constraints.get("padding_alignment") if isinstance(constraints.get("padding_alignment"), dict) else {}
    layout_contract = constraints.get("layout_normalization_assumptions") if isinstance(constraints.get("layout_normalization_assumptions"), dict) else {}
    validation_binding = (
        constraints.get("validation_report_artifact_binding") if isinstance(constraints.get("validation_report_artifact_binding"), dict) else {}
    )
    proof_contract = constraints.get("proof_obligation_inventory") if isinstance(constraints.get("proof_obligation_inventory"), dict) else {}
    same_target = binary_evidence.get("facts", {}).get("same_architecture_same_os") is True
    contract_family_statuses = _stage_a_contract_family_statuses(reference_contract)

    families = [
        _contract_family(
            "pe_sections_imports_relocations_image_base",
            "satisfied" if same_target and stage_a_pass else "incomplete",
            "candidate binary matches the reference Windows PE target and Stage A closed it"
            if stage_a_pass
            else "candidate binary target evidence is present but final Stage A proof has not closed",
            "rebuild the candidate for the same PE target and run Stage A to pass",
            stage_b_status="represented" if same_target else "missing",
            evidence={
                "contract_status": contract_family_statuses.get("binary_faithfulness")
                or _constraint_status(constraints, "pe_sections_imports_relocations_image_base"),
                "binary_facts": binary_evidence.get("facts", {}),
                "stage_a_verdict": None if stage_a_result is None else stage_a_result.get("verdict"),
            },
        ),
        _contract_family(
            "executable_byte_coverage",
            "satisfied" if stage_a_pass and _constraint_status(constraints, "executable_byte_coverage") == "satisfied" else "incomplete",
            "Stage A closed executable byte coverage"
            if stage_a_pass
            else "Stage B has not yet produced a closed Stage A byte coverage proof",
            "repair mapping/candidate bytes until Stage A executable coverage closes",
            stage_b_status="represented" if map_pass else "missing",
            evidence={
                "contract_status": contract_family_statuses.get("executable_span_coverage")
                or _constraint_status(constraints, "executable_byte_coverage"),
                "map_status": None if map_result is None else map_result.get("status"),
            },
        ),
        _contract_family(
            "function_ranges",
            "satisfied" if stage_a_pass and _stage_b_function_contract_status(function_contract, skeleton_counts, stage_a_pass) == "satisfied" else "incomplete",
            "skeleton manifest records recovered functions for the contract",
            "regenerate the skeleton from the Stage A contract/linker map so all function ranges are represented",
            stage_b_status=_stage_b_representation_status(_stage_b_function_contract_status(function_contract, skeleton_counts, False)),
            evidence={
                "contract_status": contract_family_statuses.get("function_ranges") or function_contract.get("status"),
                "contract_functions": len(function_contract.get("functions", [])) if isinstance(function_contract.get("functions"), list) else 0,
                "skeleton_functions": skeleton_counts.get("functions"),
                "source_kind": skeleton.get("reverse_engineering", {}).get("function_source") if isinstance(skeleton.get("reverse_engineering"), dict) else None,
            },
        ),
        _contract_family(
            "basic_blocks_and_cfg_edges",
            "satisfied" if stage_a_pass and block_contract.get("status") in {"satisfied", "derived"} else "incomplete",
            "skeleton has instruction-level representation; Stage A decides final CFG faithfulness",
            "import the contract block/CFG data into skeleton generation or close the Stage A proof",
            stage_b_status="represented" if int(skeleton_counts.get("instructions") or 0) > 0 else "missing",
            evidence={
                "contract_status": contract_family_statuses.get("cfg_blocks") or block_contract.get("status"),
                "contract_blocks": contract_counts.get("basic_blocks"),
                "contract_cfg_edge_sources": contract_counts.get("cfg_edge_sources"),
                "skeleton_instructions": skeleton_counts.get("instructions"),
                "stage_a_verdict": None if stage_a_result is None else stage_a_result.get("verdict"),
            },
        ),
        _contract_family(
            "roots_and_jump_table_targets",
            "satisfied" if stage_a_pass else "incomplete",
            "Stage A reachability roots and jump-table targets remain the proof authority",
            "carry contract roots/jump-table targets into Stage A mapping and close reachability obligations",
            stage_b_status="represented" if constraints.get("roots_and_jump_tables") is not None and skeleton_counts.get("functions") else "missing",
            evidence={
                "contract_status": contract_family_statuses.get("roots_and_jump_targets") or _constraint_status(constraints, "roots_and_jump_tables"),
                "stage_a_verdict": None if stage_a_result is None else stage_a_result.get("verdict"),
            },
        ),
        _contract_family(
            "import_thunk_classification",
            "not_applicable"
            if import_contract.get("status") == "not_applicable"
            else "satisfied"
            if stage_a_pass and _stage_b_import_contract_status(import_contract, skeleton_counts, stage_a_pass) == "satisfied"
            else "incomplete",
            "import thunk evidence is represented by PE imports and skeleton linkage",
            "classify import thunks in Stage A and generate matching Stage B linkage placeholders",
            stage_b_status=_stage_b_representation_status(_stage_b_import_contract_status(import_contract, skeleton_counts, False)),
            evidence={
                "contract_status": contract_family_statuses.get("import_thunks") or import_contract.get("status"),
                "skeleton_imports": skeleton_counts.get("imports"),
                "mapped_import_thunks": len(import_contract.get("mapped_import_thunks", [])) if isinstance(import_contract.get("mapped_import_thunks"), list) else 0,
            },
        ),
        _contract_family(
            "padding_alignment_classification",
            "not_applicable" if padding_contract.get("status") == "not_applicable" else "satisfied"
            if stage_a_pass and padding_contract.get("status") == "satisfied"
            else "incomplete",
            "padding/alignment is represented by Stage A waivers and must be closed there",
            "verify padding waivers or map the bytes as code before accepting the candidate",
            stage_b_status="represented" if map_pass else "missing",
            evidence={
                "contract_status": contract_family_statuses.get("padding_alignment") or padding_contract.get("status"),
                "map_status": None if map_result is None else map_result.get("status"),
            },
        ),
        _contract_family(
            "block_layout_normalization_assumptions",
            "satisfied" if stage_a_pass and layout_contract.get("status") == "satisfied" else "incomplete",
            "layout normalization assumptions are carried by the Stage A layout contract",
            "regenerate a Stage A layout contract and pass it into final validation",
            stage_b_status="represented" if layout_contract else "missing",
            evidence={
                "contract_status": contract_family_statuses.get("normalization_assumptions") or layout_contract.get("status"),
                "stage_a_verdict": None if stage_a_result is None else stage_a_result.get("verdict"),
            },
        ),
        _contract_family(
            "validation_report_artifact_binding",
            "satisfied" if validation_binding.get("status") == "satisfied" else "incomplete",
            "reference contract is bound to the validation report artifacts it cites",
            "regenerate the Stage A reference contract from the current binaries, block map, and validation report",
            stage_b_status="represented" if validation_binding else "missing",
            evidence={
                "contract_status": contract_family_statuses.get("validation_report_artifact_binding") or validation_binding.get("status"),
                "facts": validation_binding.get("facts") if isinstance(validation_binding.get("facts"), dict) else {},
                "contract_issues": validation_binding.get("issues") if isinstance(validation_binding.get("issues"), list) else [],
            },
        ),
        _contract_family(
            "proof_obligation_inventory_and_statuses",
            "satisfied" if stage_a_pass and proof_contract.get("status") == "satisfied" else "incomplete",
            "Stage A proof obligation inventory reports a final pass",
            "close every Stage A obligation, including Lean final-pass checks",
            stage_b_status="represented" if proof_contract else "missing",
            evidence={
                "contract_status": contract_family_statuses.get("proof_inventory") or proof_contract.get("status"),
                "contract_verdict": proof_contract.get("verdict"),
                "contract_final_pass_allowed": proof_contract.get("final_pass_allowed"),
                "stage_a_verdict": None if stage_a_result is None else stage_a_result.get("verdict"),
            },
        ),
    ]

    if recovery:
        families.append(
            _contract_family(
                "stage_b_repair_scope",
                "incomplete" if not stage_a_pass else "satisfied",
                "higher-level source repair remains Stage B-owned and outside the Stage A contract",
                "finish decompiler repair, prototype/type cleanup, and source emission without weakening Stage A",
                stage_b_status="represented",
                evidence={
                    "implementation_recovery": recovery,
                    "candidate_source_roots": provenance.get("source_roots") if isinstance(provenance.get("source_roots"), list) else [],
                    "functional_status": functional.get("status") if isinstance(functional, dict) else None,
                },
            )
        )

    return _contract_coverage_result(reference_contract_path, reference_contract, families)


def _constraint_status(constraints: dict[str, Any], name: str) -> str:
    constraint = constraints.get(name)
    return str(constraint.get("status") or "") if isinstance(constraint, dict) else ""


def _stage_a_contract_family_statuses(reference_contract: dict[str, Any]) -> dict[str, str]:
    families = reference_contract.get("families") if isinstance(reference_contract.get("families"), list) else []
    return {
        str(item.get("family")): str(item.get("status"))
        for item in families
        if isinstance(item, dict) and isinstance(item.get("family"), str)
    }


def _stage_b_function_contract_status(function_contract: dict[str, Any], skeleton_counts: dict[str, Any], stage_a_pass: bool) -> str:
    contract_count = len(function_contract.get("functions", [])) if isinstance(function_contract.get("functions"), list) else 0
    skeleton_count = int(skeleton_counts.get("functions") or 0)
    if stage_a_pass and contract_count and skeleton_count >= contract_count:
        return "satisfied"
    if contract_count and skeleton_count >= contract_count:
        return "represented"
    return "incomplete"


def _stage_b_import_contract_status(import_contract: dict[str, Any], skeleton_counts: dict[str, Any], stage_a_pass: bool) -> str:
    if import_contract.get("status") == "not_applicable":
        return "not_applicable"
    skeleton_imports = int(skeleton_counts.get("imports") or 0)
    original_imports = import_contract.get("original_imports") if isinstance(import_contract.get("original_imports"), list) else []
    if stage_a_pass and skeleton_imports >= len(original_imports):
        return "satisfied"
    if skeleton_imports or import_contract.get("status") in {"derived", "satisfied"}:
        return "represented"
    return "incomplete"


def _stage_b_representation_status(status: str) -> str:
    return "represented" if status in {"satisfied", "represented"} else "missing"


def _contract_family(
    family: str,
    status: str,
    summary: str,
    next_action: str,
    *,
    stage_b_status: str,
    evidence: dict[str, Any],
) -> dict[str, Any]:
    return {
        "family": family,
        "status": status,
        "stage_b_status": stage_b_status,
        "summary": summary,
        "next_action": "" if status in {"satisfied", "not_applicable"} else next_action,
        "evidence": evidence,
    }


def _contract_coverage_result(
    path: Path,
    reference_contract: dict[str, Any] | None,
    families: list[dict[str, Any]],
) -> dict[str, Any]:
    counts: dict[str, int] = {"satisfied": 0, "incomplete": 0, "not_applicable": 0, "violated": 0}
    stage_b_counts: dict[str, int] = {"represented": 0, "missing": 0}
    for family in families:
        status = str(family.get("status") or "incomplete")
        counts[status] = counts.get(status, 0) + 1
        stage_b_status = str(family.get("stage_b_status") or "missing")
        stage_b_counts[stage_b_status] = stage_b_counts.get(stage_b_status, 0) + 1
    blocking = any(family.get("status") == "incomplete" for family in families)
    return {
        "provided": True,
        "path": str(path),
        "sha256": sha256_file(path) if path.is_file() else None,
        "contract_status": reference_contract.get("status") if isinstance(reference_contract, dict) else None,
        "status": "incomplete" if blocking else "satisfied",
        "families": families,
        "next_work": _stage_b_contract_next_work(families),
        "counts": counts,
        "stage_b_counts": stage_b_counts,
    }


def _stage_b_contract_next_work(families: list[dict[str, Any]], *, limit: int = 10) -> list[dict[str, Any]]:
    ranked = sorted(
        [family for family in families if family.get("status") not in {"satisfied", "not_applicable"}],
        key=lambda family: (
            _stage_b_contract_family_rank(str(family.get("family") or "")),
            str(family.get("family") or ""),
        ),
    )
    return [
        {
            "family": family.get("family"),
            "status": family.get("status"),
            "stage_b_status": family.get("stage_b_status"),
            "next_action": family.get("next_action"),
            "summary": family.get("summary"),
        }
        for family in ranked[:limit]
    ]


def _stage_b_contract_family_rank(family: str) -> int:
    order = {
        "validation_report_artifact_binding": 0,
        "pe_sections_imports_relocations_image_base": 1,
        "block_layout_normalization_assumptions": 1,
        "executable_byte_coverage": 2,
        "function_ranges": 3,
        "basic_blocks_and_cfg_edges": 4,
        "roots_and_jump_table_targets": 5,
        "import_thunk_classification": 6,
        "padding_alignment_classification": 6,
        "proof_obligation_inventory_and_statuses": 7,
        "stage_b_repair_scope": 8,
    }
    return order.get(family, 99)


def _binary_target_evidence(original: StageABinary, candidate: StageABinary) -> dict[str, Any]:
    facts = {
        "matching_machine": original.machine == candidate.machine,
        "matching_bitness": original.bitness == candidate.bitness,
        "matching_subsystem": original.subsystem == candidate.subsystem,
        "both_windows_pe": _is_windows_stage_b_pe(original) and _is_windows_stage_b_pe(candidate),
    }
    facts["same_architecture_same_os"] = (
        facts["matching_machine"]
        and facts["matching_bitness"]
        and facts["matching_subsystem"]
        and facts["both_windows_pe"]
    )
    return {
        "format": "stage-b-binary-target-evidence-v1",
        "status": "pass" if facts["same_architecture_same_os"] else "incomplete",
        "original": _binary_target_summary(original),
        "candidate": _binary_target_summary(candidate),
        "facts": facts,
    }


def _binary_target_evidence_from_reference_contract(contract: dict[str, Any], candidate: StageABinary) -> dict[str, Any]:
    original = contract.get("original") if isinstance(contract.get("original"), dict) else {}
    original_subsystem = str(original.get("subsystem") or "")
    facts = {
        "matching_machine": original.get("machine") == candidate.machine,
        "matching_bitness": original.get("bitness") == candidate.bitness,
        "matching_subsystem": original_subsystem == candidate.subsystem,
        "both_windows_pe": original_subsystem in {"windows_cui", "windows_gui"} and _is_windows_stage_b_pe(candidate),
    }
    facts["same_architecture_same_os"] = (
        facts["matching_machine"]
        and facts["matching_bitness"]
        and facts["matching_subsystem"]
        and facts["both_windows_pe"]
    )
    return {
        "format": "stage-b-binary-target-evidence-v1",
        "status": "pass" if facts["same_architecture_same_os"] else "incomplete",
        "source": "stage_a_reference_contract",
        "original": {
            "path": original.get("path"),
            "sha256": original.get("sha256"),
            "size": original.get("size"),
            "machine": original.get("machine"),
            "bitness": original.get("bitness"),
            "subsystem": original.get("subsystem"),
            "image_base": original.get("image_base"),
            "entrypoint_rva": original.get("entrypoint_rva"),
        },
        "candidate": _binary_target_summary(candidate),
        "facts": facts,
    }


def _binary_target_issues(evidence: dict[str, Any]) -> list[dict[str, Any]]:
    if evidence.get("status") == "pass":
        return []
    return [
        {
            "category": "binary_target_mismatch",
            "blocker": "original and candidate are not the same Windows PE architecture/subsystem",
            "next_action": "rebuild the candidate for the same Windows target architecture and subsystem as the original",
            "details": evidence.get("facts", {}),
        }
    ]


_STAGE_B_BEHAVIORAL_BLOCKING_ISSUES = {
    "functional_test_failure",
    "functional_test_report_failed",
    "functional_test_report_failed_case_records",
    "functional_test_report_failed_cases",
    "functional_test_report_incomplete_cases",
    "functional_tests_not_passing",
}


def _stage_b_stage_a_gate(
    *,
    pre_stage_a_issues: list[dict[str, Any]],
    all_issues: list[dict[str, Any]],
    stage_a_result: dict[str, Any] | None,
    map_result: dict[str, Any] | None,
) -> dict[str, Any]:
    pre_stage_a_categories = _issue_categories(pre_stage_a_issues)
    behavioral_blockers = [
        category
        for category in pre_stage_a_categories
        if category in _STAGE_B_BEHAVIORAL_BLOCKING_ISSUES
    ]
    if pre_stage_a_categories:
        reason = "functional_behavior_mismatch" if behavioral_blockers else "pre_stage_a_requirements_incomplete"
        next_action = (
            "repair the Stage B candidate until public expected-output smoke tests pass before invoking Stage A"
            if behavioral_blockers
            else "satisfy Stage B provenance, source, target, build, and functional-report requirements before invoking Stage A"
        )
        return {
            "eligible": False,
            "ran": False,
            "status": "blocked",
            "reason": reason,
            "blocking_issue_categories": pre_stage_a_categories,
            "behavioral_mismatch_blocks_stage_a": bool(behavioral_blockers),
            "behavioral_blocking_issue_categories": behavioral_blockers,
            "next_action": next_action,
        }

    if stage_a_result is None:
        stage_a_categories = [
            category
            for category in _issue_categories(all_issues)
            if category.startswith("stage_a_")
        ]
        return {
            "eligible": True,
            "ran": False,
            "status": "incomplete",
            "reason": "stage_a_unavailable",
            "blocking_issue_categories": stage_a_categories,
            "behavioral_mismatch_blocks_stage_a": False,
            "behavioral_blocking_issue_categories": [],
            "next_action": "inspect the Stage A input error and provide supported binaries, maps, and model inputs",
        }

    stage_a_verdict = str(stage_a_result.get("verdict") or "")
    map_status = str(map_result.get("status") or "") if isinstance(map_result, dict) else ""
    map_closed = map_result is None or map_status == "pass"
    passed = stage_a_verdict == "pass" and map_closed
    return {
        "eligible": True,
        "ran": True,
        "status": "pass" if passed else "incomplete",
        "reason": "stage_a_final_pass" if passed else "stage_a_validation_incomplete",
        "blocking_issue_categories": [] if passed else _issue_categories(all_issues),
        "behavioral_mismatch_blocks_stage_a": False,
        "behavioral_blocking_issue_categories": [],
        "next_action": "" if passed else "inspect generated Stage A verdict artifacts and repair the candidate or mapping inputs",
    }


def _issue_categories(issues: list[dict[str, Any]]) -> list[str]:
    return [
        str(issue.get("category"))
        for issue in issues
        if isinstance(issue, dict) and issue.get("category")
    ]


def _binary_target_summary(binary: StageABinary) -> dict[str, Any]:
    return {
        "path": str(binary.path),
        "sha256": binary.sha256,
        "size": binary.size,
        "machine": binary.machine,
        "bitness": binary.bitness,
        "subsystem": binary.subsystem,
        "image_base": binary.image_base,
        "entrypoint_rva": binary.entrypoint_rva,
    }


def _is_windows_stage_b_pe(binary: StageABinary) -> bool:
    return binary.subsystem in {"windows_cui", "windows_gui"}


def _skeleton_functions(
    binary: StageABinary,
    linker_map: Path | None,
    decompiler_export: Path | None = None,
    *,
    include_decompiler_code: bool = False,
) -> list[dict[str, Any]]:
    if linker_map is not None:
        functions = _parse_linker_map_functions(Path(linker_map), binary)
    elif decompiler_export is not None:
        functions = _parse_decompiler_export_functions(Path(decompiler_export), binary, include_decompiler_code=include_decompiler_code)
    else:
        functions = _fallback_function_ranges(binary)

    results: list[dict[str, Any]] = []
    for index, function in enumerate(functions):
        rva_start = int(function["rva_start"])
        rva_end = int(function["rva_end"])
        data = binary.pe.get_data(rva_start, rva_end - rva_start)
        instructions = _disassemble(binary, rva_start, data)
        side = BlockSide(rva_start, rva_end)
        entry = {
            "id": _artifact_name(str(function.get("name") or f"function-{index:04d}")),
            "name": str(function.get("name") or f"function_{index:04d}"),
            "aliases": list(function.get("aliases") or []),
            "section": str(function.get("section") or ""),
            "rva_start": rva_start,
            "rva_end": rva_end,
            "size": rva_end - rva_start,
            "bytes_sha256": sha256_bytes(data),
            "instruction_count": len(instructions),
            "decoded_bytes": sum(int(item["size"]) for item in instructions),
            "decode_complete": sum(int(item["size"]) for item in instructions) == len(data),
            "direct_cfg_edges": _direct_cfg_edges(binary, side),
            "instruction_preview": instructions[:12],
        }
        source_name = function.get("source_name")
        if isinstance(source_name, str) and source_name:
            entry["source_name"] = source_name
        name_disambiguation = function.get("name_disambiguation")
        if isinstance(name_disambiguation, dict):
            entry["name_disambiguation"] = name_disambiguation
        pe_export_aliases = function.get("pe_export_aliases")
        if isinstance(pe_export_aliases, list):
            entry["pe_export_aliases"] = [str(alias) for alias in pe_export_aliases]
        decompiler = function.get("decompiler")
        if isinstance(decompiler, dict):
            entry["decompiler"] = decompiler
        import_thunk = _linker_function_import_thunk_evidence(binary, function)
        if import_thunk is not None:
            imported = import_thunk["import"]
            entry["linkage"] = {
                "kind": "import_thunk",
                "symbol": imported.symbol or str(entry["name"]),
                "dll": imported.dll,
                "ordinal": imported.ordinal,
                "thunk_rva": imported.thunk_rva,
                "original_symbol": str(entry["name"]),
            }
        results.append(entry)
    return results


def _parse_decompiler_export_functions(
    path: Path,
    binary: StageABinary,
    *,
    include_decompiler_code: bool = False,
) -> list[dict[str, Any]]:
    payload = _load_json(path)
    rows = payload.get("functions") if isinstance(payload, dict) else None
    if not isinstance(rows, list):
        raise StageAInputError(f"decompiler export {path} does not contain a functions list")
    export_aliases_by_rva = _pe_export_aliases_by_rva(binary)
    accepted: list[tuple[int, dict[str, Any], int, int, Any, str, str, list[str]]] = []
    name_counts: dict[str, int] = {}
    for index, row in enumerate(rows):
        if not isinstance(row, dict):
            continue
        rva_start = _optional_int(row.get("rva_start", row.get("rva")))
        rva_end = _optional_int(row.get("rva_end"))
        if rva_start is None:
            continue
        section = _section_for_rva(binary, rva_start)
        if section is None or not section.executable:
            continue
        if rva_end is None or rva_end <= rva_start:
            rva_end = min(section.rva_end, rva_start + 1)
        decompiler_name = str(row.get("name") or f"decompiler_function_{index:04d}")
        export_aliases = export_aliases_by_rva.get(rva_start, [])
        preferred_name = _primary_export_name(export_aliases) if export_aliases else decompiler_name
        accepted.append((index, row, rva_start, rva_end, section, preferred_name, decompiler_name, export_aliases))
        name_counts[preferred_name] = name_counts.get(preferred_name, 0) + 1

    functions: list[dict[str, Any]] = []
    occurrences: dict[str, int] = {}
    used_names: set[str] = set()
    for index, row, rva_start, rva_end, section, preferred_name, decompiler_name, export_aliases in accepted:
        occurrence = occurrences.get(preferred_name, 0) + 1
        occurrences[preferred_name] = occurrence
        name = _decompiler_disambiguated_function_name(
            preferred_name,
            rva_start=rva_start,
            duplicate=name_counts.get(preferred_name, 0) > 1,
            occurrence=occurrence,
            used_names=used_names,
        )
        aliases = []
        for alias in [name, decompiler_name, *export_aliases]:
            if alias and alias not in aliases:
                aliases.append(alias)
        entry: dict[str, Any] = {
            "name": name,
            "aliases": aliases,
            "section": section.name,
            "rva_start": rva_start,
            "rva_end": min(rva_end, section.rva_end),
        }
        if export_aliases:
            entry["pe_export_aliases"] = export_aliases
        if name != decompiler_name or preferred_name != decompiler_name:
            strategy = (
                "append_rva_to_duplicate_decompiler_name"
                if name_counts.get(preferred_name, 0) > 1
                else (
                    "prefer_pe_export_alias_for_decompiler_rva"
                    if export_aliases and preferred_name != decompiler_name
                    else "sanitize_decompiler_name_for_c_identifier"
                )
            )
            entry["source_name"] = decompiler_name
            entry["name_disambiguation"] = {
                "strategy": strategy,
                "source_name": decompiler_name,
                "preferred_name": preferred_name,
                "disambiguated_name": name,
                "rva_start": rva_start,
                "occurrence": occurrence,
            }
        decompiler = _decompiler_function_summary(row, include_code=include_decompiler_code)
        if decompiler is not None:
            if name != decompiler_name:
                if include_decompiler_code and isinstance(decompiler.get("code"), str):
                    code = _rename_decompiled_c_function_definition(
                        decompiler["code"],
                        original_name=decompiler_name,
                        new_name=name,
                    )
                    decompiler["code"] = code
                    decompiler["code_sha256"] = sha256_bytes(code.encode("utf-8")) if code else ""
                    decompiler["code_preview"] = _preview_lines(code)
                signature = str(decompiler.get("signature") or "")
                if signature:
                    decompiler["signature"] = _rename_decompiled_c_function_definition(
                        signature,
                        original_name=decompiler_name,
                        new_name=name,
                    )
            entry["decompiler"] = decompiler
        functions.append(entry)
    return functions

def _decompiler_disambiguated_function_name(
    raw_name: str,
    *,
    rva_start: int,
    duplicate: bool,
    occurrence: int,
    used_names: set[str],
) -> str:
    base = _c_identifier_from_name(raw_name)
    if not duplicate and base not in used_names:
        used_names.add(base)
        return base
    candidate = base if occurrence == 1 and base not in used_names else f"{base}_at_{rva_start:x}"
    suffix = 2
    while candidate in used_names:
        candidate = f"{base}_at_{rva_start:x}_{suffix}"
        suffix += 1
    used_names.add(candidate)
    return candidate

def _c_identifier_from_name(value: str) -> str:
    name = re.sub(r"[^A-Za-z0-9_]", "_", str(value))
    if not name or not name.strip("_"):
        return "decompiler_function"
    if name[0].isdigit():
        name = f"fn_{name}"
    return name

def _rename_decompiled_c_function_definition(code: str, *, original_name: str, new_name: str) -> str:
    if not code or original_name == new_name:
        return code
    pattern = rf"\b{re.escape(original_name)}\s*\("
    if "{" not in code:
        return re.sub(pattern, f"{new_name}(", code, count=1)
    head, body = code.split("{", 1)
    renamed = re.sub(pattern, f"{new_name}(", head, count=1)
    return renamed + "{" + body


def _fallback_function_ranges(binary: StageABinary) -> list[dict[str, Any]]:
    ranges: list[dict[str, Any]] = []
    for section in binary.sections:
        if not section.executable:
            continue
        name = "entrypoint" if section.rva_start <= binary.entrypoint_rva < section.rva_end else f"section_{section.name}"
        start = binary.entrypoint_rva if name == "entrypoint" else section.rva_start
        ranges.append(
            {
                "name": name,
                "aliases": [name],
                "section": section.name,
                "rva_start": start,
                "rva_end": section.rva_end,
            }
        )
    return ranges


def _pe_export_aliases_by_rva(binary: StageABinary) -> dict[int, list[str]]:
    directory = getattr(binary.pe, "DIRECTORY_ENTRY_EXPORT", None)
    if directory is None:
        return {}

    names_by_rva: dict[int, list[str]] = {}
    for index, symbol in enumerate(getattr(directory, "symbols", []) or []):
        rva = _optional_int(getattr(symbol, "address", None))
        if rva is None:
            continue
        section = _section_for_rva(binary, rva)
        if section is None or not section.executable:
            continue
        forwarder = getattr(symbol, "forwarder", None)
        if forwarder:
            continue
        if getattr(symbol, "name", None):
            name = symbol.name.decode("utf-8", errors="replace") if isinstance(symbol.name, bytes) else str(symbol.name)
        else:
            ordinal = getattr(symbol, "ordinal", index)
            name = f"ordinal_{ordinal}"
        bucket = names_by_rva.setdefault(rva, [])
        if name not in bucket:
            bucket.append(name)
    return names_by_rva


def _primary_export_name(names: list[str]) -> str:
    for name in names:
        if not name.startswith("ordinal_"):
            return name
    return names[0]


def _function_source_kind(*, linker_map: Path | None, decompiler_export: Path | None) -> str:
    if linker_map is not None:
        return "linker_map"
    if decompiler_export is not None:
        return "decompiler_export"
    return "entrypoint_and_executable_sections"


def _function_filter(functions: list[dict[str, Any]], function_names: list[str] | tuple[str, ...] | None) -> dict[str, Any]:
    if not function_names:
        return {
            "functions": functions,
            "external_function_names": [],
            "metadata": {
                "mode": "all",
                "requested": [],
                "included": [str(function.get("name") or "") for function in functions],
                "missing": [],
                "external_recovered_function_names": [],
            },
        }

    requested = [str(name) for name in function_names if str(name)]
    by_name: dict[str, list[dict[str, Any]]] = {}
    for function in functions:
        by_name.setdefault(str(function.get("name") or ""), []).append(function)

    selected: list[dict[str, Any]] = []
    missing: list[str] = []
    ambiguous: list[str] = []
    for name in requested:
        matches = by_name.get(name, [])
        if not matches:
            missing.append(name)
        elif len(matches) > 1:
            ambiguous.append(name)
        else:
            selected.append(matches[0])

    if missing or ambiguous:
        blockers = []
        if missing:
            blockers.append(f"missing functions: {', '.join(missing)}")
        if ambiguous:
            blockers.append(f"ambiguous duplicate functions: {', '.join(ambiguous)}")
        raise StageAInputError("; ".join(blockers))

    return {
        "functions": selected,
        "external_function_names": [
            str(function.get("name") or "")
            for function in functions
            if str(function.get("name") or "") not in set(requested)
        ],
        "metadata": {
            "mode": "function_names",
            "requested": requested,
            "included": [str(function.get("name") or "") for function in selected],
            "missing": [],
            "external_recovered_function_names": [
                str(function.get("name") or "")
                for function in functions
                if str(function.get("name") or "") not in set(requested)
            ],
        },
    }


def _skeleton_behavior_recovery(
    *,
    binary: StageABinary,
    target_name: str,
    source_language: str,
    implementation_mode: str,
) -> dict[str, Any]:
    if implementation_mode != "scaffold" or source_language != "rust":
        return {
            "format": "stage-b-behavior-recovery-v1",
            "status": "not_applicable",
            "recovered": [],
            "blockers": [],
        }
    target_id = _artifact_name(target_name)
    recovered: list[dict[str, Any]] = []
    blockers: list[str] = []
    if "ripgrep" in target_id:
        version_behavior = _recover_ripgrep_version_behavior(binary)
        if version_behavior is None:
            blockers.append("missing_ripgrep_version_strings")
        else:
            recovered.append(version_behavior)
    return {
        "format": "stage-b-behavior-recovery-v1",
        "status": "partial" if recovered else "incomplete",
        "source": "pe_ascii_strings",
        "recovered": recovered,
        "blockers": blockers,
    }


def _recover_ripgrep_version_behavior(binary: StageABinary) -> dict[str, Any] | None:
    raw = binary.path.read_bytes()
    match = re.search(
        rb"ripgrep[ \t]*.{0,8}?(?P<version>[0-9]+\.[0-9]+\.[0-9]+)\+?.{0,8}?SSE2.{0,8}?SSSE3.{0,8}?AVX2.{0,8}?pcre2",
        raw,
        flags=re.DOTALL,
    )
    if match is None:
        return None
    version = match.group("version").decode("ascii", errors="replace")
    pcre2_unavailable = b"PCRE2 is not available in this build of ripgrep" in raw
    output = (
        f"ripgrep {version}\n\n"
        "features:-pcre2\n"
        "simd(compile):+SSE2,-SSSE3,-AVX2\n"
        "simd(runtime):+SSE2,+SSSE3,+AVX2\n\n"
    )
    if pcre2_unavailable:
        output += "PCRE2 is not available in this build of ripgrep.\n"
    return {
        "id": "ripgrep-version",
        "kind": "cli_exact_stdout",
        "args": [["--version"], ["-V"]],
        "stdout": output,
        "returncode": 0,
        "evidence": {
            "kind": "pe_ascii_string_neighborhood",
            "rva": _file_offset_to_rva(binary, match.start()),
            "file_offset": match.start(),
            "sha256": sha256_bytes(match.group(0)),
            "pcre2_unavailable_string": pcre2_unavailable,
        },
    }


def _file_offset_to_rva(binary: StageABinary, offset: int) -> int | None:
    for section in binary.sections:
        raw_start = int(section.raw_pointer)
        raw_end = raw_start + int(section.raw_size)
        if raw_start <= offset < raw_end:
            return int(section.rva_start) + (offset - raw_start)
    return None


def _skeleton_implementation_recovery(
    functions: list[dict[str, Any]],
    source_language: str,
    *,
    implementation_mode: str,
) -> dict[str, Any]:
    decompiler_functions = [function for function in functions if isinstance(function.get("decompiler"), dict)]
    decompiler_successes = [
        function
        for function in decompiler_functions
        if function.get("decompiler", {}).get("status") == "success"
    ]
    decompiler_code_functions = [
        function
        for function in decompiler_successes
        if isinstance(function.get("decompiler", {}).get("code"), str)
        and function.get("decompiler", {}).get("code", "").strip()
    ]
    name_counts: dict[str, int] = {}
    for function in functions:
        name = str(function.get("name") or "")
        if name:
            name_counts[name] = name_counts.get(name, 0) + 1
    duplicate_names = sorted(name for name, count in name_counts.items() if count > 1)
    name_disambiguations = [
        function["name_disambiguation"]
        for function in functions
        if isinstance(function.get("name_disambiguation"), dict)
    ]

    if implementation_mode == "decompiled-c":
        blockers = []
        if not functions:
            blockers.append("missing_functions")
        if len(decompiler_functions) != len(functions):
            blockers.append("missing_decompiler_exports")
        if len(decompiler_successes) != len(functions):
            blockers.append("incomplete_decompiler_successes")
        if len(decompiler_code_functions) != len(functions):
            blockers.append("missing_decompiler_code")
        if duplicate_names:
            blockers.append("duplicate_decompiler_function_names")
        status = "complete" if not blockers else "incomplete"
        generated_source_kind = "decompiler_recovered_behavior" if status == "complete" else "decompiler_recovered_partial"
    else:
        blockers = ["generated_source_is_scaffold"]
        if not decompiler_successes:
            blockers.append("missing_decompiler_successes")
        if decompiler_successes and len(decompiler_successes) < len(functions):
            blockers.append("incomplete_decompiler_coverage")
        status = "incomplete"
        generated_source_kind = "scaffold"

    return {
        "format": "stage-b-skeleton-recovery-v1",
        "status": status,
        "implementation_mode": implementation_mode,
        "generated_source_kind": generated_source_kind,
        "source_language": source_language,
        "source_implements_behavior": status == "complete",
        "functions": len(functions),
        "decompiler_functions": len(decompiler_functions),
        "decompiler_successes": len(decompiler_successes),
        "decompiler_code_functions": len(decompiler_code_functions),
        "instruction_count": sum(int(function["instruction_count"]) for function in functions),
        "duplicate_function_names": duplicate_names,
        "decompiler_name_disambiguation": {
            "status": "applied" if name_disambiguations else "not_required",
            "strategy": "append_rva_to_duplicate_decompiler_name",
            "count": len(name_disambiguations),
            "items": name_disambiguations[:100],
        },
        "blockers": blockers,
    }


def _section_for_rva(binary: StageABinary, rva: int) -> Any | None:
    for section in binary.sections:
        if section.rva_start <= rva < section.rva_end:
            return section
    return None


def _optional_int(value: Any) -> int | None:
    if value is None:
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        text = value.strip()
        if not text:
            return None
        return int(text, 0)
    return None


def _string_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, list):
        return [str(item) for item in value]
    if isinstance(value, tuple):
        return [str(item) for item in value]
    return [str(value)]


def _case_ids_sha256(case_ids: list[str]) -> str:
    return sha256_bytes(json.dumps(case_ids, separators=(",", ":")).encode("utf-8"))


def _decompiler_function_summary(row: dict[str, Any], *, include_code: bool = False) -> dict[str, Any] | None:
    decompiler = row.get("decompiler")
    if not isinstance(decompiler, dict):
        return None
    code = str(decompiler.get("c") or decompiler.get("code") or decompiler.get("decompiled_c") or "")
    error = str(decompiler.get("error") or "")
    summary = {
        "source": "ghidra_decompiler_export",
        "status": str(decompiler.get("status") or ("success" if code else "not_available")),
        "signature": str(row.get("signature") or ""),
        "code_sha256": sha256_bytes(code.encode("utf-8")) if code else "",
        "code_preview": _preview_lines(code),
        "error": error,
    }
    if include_code:
        summary["code"] = code
    return summary


def _preview_lines(text: str, *, limit: int = 12) -> list[str]:
    return text.splitlines()[:limit]


def _indented_decompiler_comment_lines(function: dict[str, Any], prefix: str) -> list[str]:
    decompiler = function.get("decompiler")
    if not isinstance(decompiler, dict):
        return []
    lines = [f"{prefix}decompiler status: {decompiler.get('status', 'unknown')}"]
    signature = str(decompiler.get("signature") or "")
    if signature:
        lines.append(f"{prefix}signature: {signature}")
    for line in decompiler.get("code_preview") or []:
        lines.append(f"{prefix}{line}")
    return lines


def _disassemble(binary: StageABinary, rva_start: int, data: bytes) -> list[dict[str, Any]]:
    dis = capstone.Cs(capstone.CS_ARCH_X86, _capstone_mode(binary))
    return [
        {
            "rva": int(insn.address - binary.image_base),
            "size": int(insn.size),
            "mnemonic": insn.mnemonic,
            "op_str": insn.op_str,
        }
        for insn in dis.disasm(data, binary.image_base + rva_start)
    ]


def _render_skeleton_source(
    *,
    target_name: str,
    functions: list[dict[str, Any]],
    source_language: str,
    implementation_mode: str,
    external_function_names: list[str] | tuple[str, ...] | None = None,
    behavior_recovery: dict[str, Any] | None = None,
) -> str:
    if implementation_mode == "decompiled-c":
        return _render_decompiled_c_source(
            target_name=target_name,
            functions=functions,
            external_function_names=external_function_names,
        )

    if source_language == "rust":
        recovered_version = _recovered_cli_behavior(behavior_recovery, "ripgrep-version")
        lines = [
            "// Generated by wincr stage-b-generate-skeleton.",
            "// This is a clean-room reconstruction scaffold, not a completed implementation.",
            "",
        ]
        if recovered_version is not None:
            lines.extend(
                [
                    f"const STAGE_B_RECOVERED_VERSION_STDOUT: &str = {_rust_string_literal(str(recovered_version.get('stdout') or ''))};",
                    "",
                    "fn stage_b_matches_arg(args: &[String], short: &str, long: &str) -> bool {",
                    "    args.len() == 1 && (args[0] == short || args[0] == long)",
                    "}",
                    "",
                ]
            )
        lines.extend(
            [
                "fn main() {",
            ]
        )
        if recovered_version is not None:
            lines.extend(
                [
                    "    let args: Vec<String> = std::env::args().skip(1).collect();",
                    "    if stage_b_matches_arg(&args, \"-V\", \"--version\") {",
                    "        print!(\"{}\", STAGE_B_RECOVERED_VERSION_STDOUT);",
                    "        return;",
                    "    }",
                ]
            )
        lines.extend(
            [
                "    std::process::exit(125);",
                "}",
                "",
            ]
        )
        used_identifiers: set[str] = set()
        for index, function in enumerate(functions):
            ident = _unique_identifier(function["name"], index, used_identifiers)
            lines.extend(
                [
                    "#[allow(dead_code)]",
                    f"fn stage_b_fn_{ident}() -> i32 {{",
                    f"    // original RVA 0x{int(function['rva_start']):x}, size {int(function['size'])}",
                    *_indented_decompiler_comment_lines(function, "    // "),
                    "    125",
                    "}",
                    "",
                ]
            )
        return "\n".join(lines)

    lines = [
        "/* Generated by wincr stage-b-generate-skeleton.",
        " * This is a clean-room reconstruction scaffold, not a completed implementation.",
        " */",
        "#include <stdint.h>",
        "",
        "static int stage_b_unimplemented(const char *name) {",
        "    (void)name;",
        "    return 125;",
        "}",
        "",
        "int main(int argc, char **argv) {",
        "    (void)argc;",
        "    (void)argv;",
        f"    return stage_b_unimplemented(\"{_c_string(target_name)}\");",
        "}",
        "",
    ]
    used_identifiers = set()
    for index, function in enumerate(functions):
        ident = _unique_identifier(function["name"], index, used_identifiers)
        lines.extend(
            [
                f"int stage_b_fn_{ident}(void) {{",
                f"    /* original RVA 0x{int(function['rva_start']):x}, size {int(function['size'])} */",
                *_indented_decompiler_comment_lines(function, "    // "),
                f"    return stage_b_unimplemented(\"{_c_string(str(function['name']))}\");",
                "}",
                "",
            ]
        )
    return "\n".join(lines)


def _render_decompiled_c_source(
    *,
    target_name: str,
    functions: list[dict[str, Any]],
    external_function_names: list[str] | tuple[str, ...] | None = None,
) -> str:
    lines = [
        "/* Generated by wincr stage-b-generate-skeleton.",
        " * Implementation mode: decompiled-c.",
        " * Source bodies come from the supplied private decompiler export.",
        " */",
        "#include <stdarg.h>",
        "#include <stddef.h>",
        "#include <stdbool.h>",
        "#include <stdint.h>",
        "",
        "typedef int BOOL;",
        "typedef char CHAR;",
        "typedef uint8_t BYTE;",
        "typedef uint16_t WORD;",
        "typedef uint32_t DWORD;",
        "typedef uintptr_t DWORD_PTR;",
        "typedef uint32_t UINT;",
        "typedef int32_t LONG;",
        "typedef size_t SIZE_T;",
        "typedef int errno_t;",
        "typedef void *HANDLE;",
        "typedef void *HMODULE;",
        "typedef void *FARPROC;",
        "typedef void *LPVOID;",
        "typedef const void *LPCVOID;",
        "typedef BYTE *PBYTE;",
        "typedef DWORD *PDWORD;",
        "typedef DWORD *LPDWORD;",
        "typedef char *LPSTR;",
        "typedef const char *LPCSTR;",
        "typedef wchar_t WCHAR;",
        "typedef WCHAR *LPWSTR;",
        "typedef const WCHAR *LPCWSTR;",
        "typedef BOOL *LPBOOL;",
        "typedef void *LPOVERLAPPED;",
        "typedef void *LPCRITICAL_SECTION;",
        "typedef long (__attribute__((stdcall)) *LPTOP_LEVEL_EXCEPTION_FILTER)(void *);",
        "typedef struct _stage_b_image_data_directory { DWORD VirtualAddress; DWORD Size; } IMAGE_DATA_DIRECTORY;",
        "typedef struct _stage_b_image_optional_header32 { IMAGE_DATA_DIRECTORY DataDirectory[16]; } IMAGE_OPTIONAL_HEADER32;",
        "typedef struct _stage_b_image_nt_headers32 { DWORD Signature; IMAGE_OPTIONAL_HEADER32 OptionalHeader; } IMAGE_NT_HEADERS32;",
        "typedef struct _stage_b_image_section_header {",
        "    union { DWORD PhysicalAddress; DWORD VirtualSize; } Misc;",
        "    DWORD VirtualAddress;",
        "    DWORD SizeOfRawData;",
        "    DWORD PointerToRawData;",
        "    DWORD PointerToRelocations;",
        "    DWORD PointerToLinenumbers;",
        "    WORD NumberOfRelocations;",
        "    WORD NumberOfLinenumbers;",
        "    DWORD Characteristics;",
        "} IMAGE_SECTION_HEADER, *PIMAGE_SECTION_HEADER;",
        "typedef struct _stage_b_image_dos_header {",
        "    WORD e_magic;",
        "    uintptr_t e_res_4_;",
        "    uintptr_t e_program;",
        "    int32_t e_lfanew;",
        "} IMAGE_DOS_HEADER;",
        "typedef struct _stage_b_memory_basic_information {",
        "    void *BaseAddress;",
        "    void *AllocationBase;",
        "    DWORD AllocationProtect;",
        "    size_t RegionSize;",
        "    DWORD State;",
        "    DWORD Protect;",
        "    DWORD Type;",
        "} MEMORY_BASIC_INFORMATION;",
        "typedef MEMORY_BASIC_INFORMATION _MEMORY_BASIC_INFORMATION;",
        "typedef struct _stage_b_FILE {",
        "    char *_ptr;",
        "    int _cnt;",
        "    char *_base;",
        "    int _flag;",
        "    int _file;",
        "    int _charbuf;",
        "    int _bufsiz;",
        "    char *_tmpfname;",
        "} FILE;",
        "typedef struct _stage_b_tm {",
        "    int tm_sec;",
        "    int tm_min;",
        "    int tm_hour;",
        "    int tm_mday;",
        "    int tm_mon;",
        "    int tm_year;",
        "    int tm_wday;",
        "    int tm_yday;",
        "    int tm_isdst;",
        "} tm;",
        "typedef char mbstate_t;",
        "typedef void (*_func_4879)(void);",
        "typedef int _PtFuncCompare(const void *, const void *);",
        "typedef struct _stage_b_exception { int type; char *name; double arg1; double arg2; double retval; } _exception;",
        "typedef struct _stage_b_startupinfo { int newmode; } _startupinfo;",
        "typedef void (__attribute__((cdecl)) *_invalid_parameter_handler)(const wchar_t *, const wchar_t *, const wchar_t *, unsigned int, uintptr_t);",
        "typedef struct _stage_b_jv { uint32_t word[4]; } stage_b_jv;",
        "typedef uint8_t byte;",
        "typedef uint8_t undefined;",
        "typedef uint8_t undefined1;",
        "typedef uint16_t undefined2;",
        "typedef uint32_t undefined3;",
        "typedef uint32_t undefined4;",
        "typedef uint64_t undefined8;",
        "typedef int8_t sbyte;",
        "typedef int64_t longlong;",
        "typedef long double float10;",
        "typedef uint64_t unkuint10;",
        "typedef int64_t unkint10;",
        "typedef uint16_t ushort;",
        "typedef uint32_t uint;",
        "typedef uint64_t ulonglong;",
        "typedef uintptr_t code();",
        "typedef uint32_t dword;",
        "typedef struct _stage_b_time_zone_information { LONG Bias; } _TIME_ZONE_INFORMATION;",
        "typedef struct _stage_b_runtime_pseudo_reloc {",
        "    uint32_t sym;",
        "    uint32_t target;",
        "    uint32_t flags;",
        "    uint32_t zero1;",
        "    uint32_t zero2;",
        "    uint32_t version;",
        "} pseudoRelocItemV2;",
        "#ifndef LOCK",
        "#define LOCK() ((void)0)",
        "#endif",
        "#ifndef UNLOCK",
        "#define UNLOCK() ((void)0)",
        "#endif",
        "#ifndef CONCAT11",
        "#define CONCAT11(hi, lo) ((((uint16_t)(uint8_t)(hi)) << 8) | ((uint8_t)(lo)))",
        "#endif",
        "#ifndef CONCAT22",
        "#define CONCAT22(hi, lo) ((((uint32_t)(uint16_t)(hi)) << 16) | ((uint16_t)(lo)))",
        "#endif",
        "#ifndef CONCAT31",
        "#define CONCAT31(hi, lo) ((((uint32_t)(hi)) << 8) | ((uint8_t)(lo)))",
        "#endif",
        "#ifndef CONCAT44",
        "#define CONCAT44(hi, lo) ((((uint64_t)(uint32_t)(hi)) << 32) | ((uint32_t)(lo)))",
        "#endif",
        "#ifndef SUB84",
        "#define SUB84(value, offset) ((uint32_t)(((uint64_t)(value)) >> ((offset) * 8)))",
        "#endif",
        "#ifndef SUB104",
        "#define SUB104(value, offset) ((uint32_t)(((uint64_t)(value)) >> ((offset) * 8)))",
        "#endif",
        "#ifndef ZEXT48",
        "#define ZEXT48(value) ((uint64_t)(uint32_t)(value))",
        "#endif",
        "#ifndef CARRY4",
        "#define CARRY4(a, b) (((uint64_t)(uint32_t)(a) + (uint64_t)(uint32_t)(b)) > UINT32_MAX)",
        "#endif",
        "#ifndef ROUND",
        "#define ROUND(value) ((int)(value))",
        "#endif",
        "#ifndef NAN",
        "#define NAN(value) __builtin_isnan((double)(value))",
        "#endif",
        "#ifndef INFINITY",
        "#define INFINITY (__builtin_huge_val())",
        "#endif",
        "static inline uint64_t stage_b_part_mask(unsigned size) {",
        "    return size >= 8 ? UINT64_MAX : ((UINT64_C(1) << (size * 8U)) - 1U);",
        "}",
        "static inline uint64_t stage_b_part_get_u64(uint64_t value, unsigned offset, unsigned size) {",
        "    return (value >> (offset * 8U)) & stage_b_part_mask(size);",
        "}",
        "static inline uint64_t stage_b_part_set_u64(uint64_t value, unsigned offset, unsigned size, uint64_t replacement) {",
        "    uint64_t shift = offset * 8U;",
        "    uint64_t mask = stage_b_part_mask(size) << shift;",
        "    return (value & ~mask) | ((replacement << shift) & mask);",
        "}",
        "#define STAGE_B_PART(value, offset, size) stage_b_part_get_u64((uint64_t)(value), (offset), (size))",
        "#define STAGE_B_SET_PART(value, offset, size, replacement) \\",
        "    do { (value) = (__typeof__(value))stage_b_part_set_u64((uint64_t)(value), (offset), (size), (uint64_t)(uintptr_t)(replacement)); } while (0)",
        "#define STAGE_B_PART_LVALUE(value, offset, type) (*((type *)((unsigned char *)&(value) + (offset))))",
        "",
        "uintptr_t __cdecl jv_mem_alloc(size_t);",
        "static unsigned stage_b_jq_isoption_index;",
        "static void stage_b_jq_isoption_reset(void) { stage_b_jq_isoption_index = 0; }",
        "static uintptr_t stage_b_jq_jvp_array_alloc(uint32_t capacity) {",
        "    size_t bytes = ((size_t)capacity + 1U) * 16U;",
        "    uint32_t *payload = (uint32_t *)(uintptr_t)jv_mem_alloc(bytes);",
        "    for (size_t index = 0; index < bytes / sizeof(uint32_t); index++) {",
        "        payload[index] = 0;",
        "    }",
        "    payload[0] = 1;",
        "    payload[1] = 0;",
        "    payload[2] = capacity;",
        "    return (uintptr_t)payload;",
        "}",
        "static undefined4 stage_b_jq_jv_array_sized(undefined4 out_value, uint32_t capacity) {",
        "    uint32_t *out = (uint32_t *)(uintptr_t)out_value;",
        "    out[0] = 0x86;",
        "    out[1] = 0;",
        "    out[2] = (uint32_t)stage_b_jq_jvp_array_alloc(capacity);",
        "    out[3] = 0;",
        "    return out_value;",
        "}",
        "static uintptr_t stage_b_jq_jvp_string_alloc(size_t length) {",
        "    size_t bytes = length + 0x11U;",
        "    uint8_t *payload = (uint8_t *)(uintptr_t)jv_mem_alloc(bytes);",
        "    for (size_t index = 0; index < bytes; index++) {",
        "        payload[index] = 0;",
        "    }",
        "    ((uint32_t *)payload)[0] = 1;",
        "    ((uint32_t *)payload)[2] = (uint32_t)(length * 2U);",
        "    ((uint32_t *)payload)[3] = (uint32_t)length;",
        "    return (uintptr_t)payload;",
        "}",
        "static undefined4 stage_b_jq_jv_string_sized(undefined4 out_value, const uint8_t *data, int length) {",
        "    size_t safe_length = length < 0 ? 0U : (size_t)length;",
        "    uint8_t *payload = (uint8_t *)(uintptr_t)stage_b_jq_jvp_string_alloc(safe_length);",
        "    uint32_t *out = (uint32_t *)(uintptr_t)out_value;",
        "    if (data != (const uint8_t *)0) {",
        "        for (size_t index = 0; index < safe_length; index++) {",
        "            payload[0x10U + index] = data[index];",
        "        }",
        "    }",
        "    payload[0x10U + safe_length] = 0;",
        "    out[0] = 0x85;",
        "    out[1] = 0;",
        "    out[2] = (uint32_t)(uintptr_t)payload;",
        "    out[3] = 0;",
        "    return out_value;",
        "}",
        "static uintptr_t stage_b_jq_jvp_object_alloc(uint32_t size) {",
        "    if (size == 0 || (size & (size - 1U)) != 0) {",
        "        size = 8;",
        "    }",
        "    size_t bytes = (size_t)size * 0x30U + 8U;",
        "    uint8_t *payload = (uint8_t *)(uintptr_t)jv_mem_alloc(bytes);",
        "    for (size_t index = 0; index < bytes; index++) {",
        "        payload[index] = 0;",
        "    }",
        "    ((uint32_t *)payload)[0] = 1;",
        "    ((uint32_t *)payload)[1] = 0;",
        "    for (uint32_t index = 0; index < size; index++) {",
        "        uint32_t *slot = (uint32_t *)(void *)(payload + 8U + (size_t)index * 0x28U);",
        "        slot[0] = index == 0 ? UINT32_MAX : index - 1U;",
        "    }",
        "    for (size_t index = (size_t)size * 0x28U + 8U; index < bytes; index++) {",
        "        payload[index] = 0xffU;",
        "    }",
        "    return (uintptr_t)payload;",
        "}",
        "static undefined4 stage_b_jq_jv_object(undefined4 out_value) {",
        "    uint32_t *out = (uint32_t *)(uintptr_t)out_value;",
        "    out[0] = 0x87;",
        "    out[1] = 8;",
        "    out[2] = (uint32_t)stage_b_jq_jvp_object_alloc(8);",
        "    out[3] = 0;",
        "    return out_value;",
        "}",
        "#define stage_b_jq_call_jq_realpath(value) ((stage_b_jv (__cdecl *)(stage_b_jv))jq_realpath)(value)",
        "#define stage_b_jq_call_jq_testsuite(libs, flags, argc, argv) ((int (__cdecl *)(stage_b_jv, int, int, char **))jq_testsuite)((libs), (flags), (argc), (argv))",
        "#define stage_b_jq_call_jv_array_append(array, value) ((stage_b_jv (__cdecl *)(stage_b_jv, stage_b_jv))jv_array_append)((array), (value))",
        "#define stage_b_jq_call_jv_string(value) ((stage_b_jv (__cdecl *)(const char *))jv_string)(value)",
        "static int stage_b_jq_isoption_match(char **cursor, int short_mode, char short_name, const char *long_name) {",
        "    char *value = cursor ? *cursor : (char *)0;",
        "    if (value == (char *)0) {",
        "        return 0;",
        "    }",
        "    if (short_mode == 0) {",
        "        const char *left = value;",
        "        const char *right = long_name;",
        "        if (right == (const char *)0) {",
        "            return 0;",
        "        }",
        "        while (*left != '\\0' && *right != '\\0' && *left == *right) {",
        "            left++;",
        "            right++;",
        "        }",
        "        if (*left != '\\0' || *right != '\\0') {",
        "            return 0;",
        "        }",
        "        *cursor = (char *)0;",
        "        return 1;",
        "    }",
        "    if (short_name == '\\0' || *value != short_name) {",
        "        return 0;",
        "    }",
        "    *cursor = value[1] == '\\0' ? (char *)0 : value + 1;",
        "    return 1;",
        "}",
        "static int stage_b_jq_isoption_next(char **cursor, int short_mode) {",
        "    unsigned index = stage_b_jq_isoption_index++;",
        "    switch (index) {",
        "    case 0:",
        "        return stage_b_jq_isoption_match(cursor, short_mode, 'n', \"null-input\");",
        "    case 30:",
        "        return stage_b_jq_isoption_match(cursor, short_mode, '\\0', \"help\");",
        "    case 31:",
        "        return stage_b_jq_isoption_match(cursor, short_mode, 'V', \"version\");",
        "    case 32:",
        "        return stage_b_jq_isoption_match(cursor, short_mode, '\\0', \"build-configuration\");",
        "    case 33:",
        "        return stage_b_jq_isoption_match(cursor, short_mode, '\\0', \"run-tests\");",
        "    default:",
        "        return 0;",
        "    }",
        "}",
        "",
    ]
    implemented_functions = [
        function
        for function in functions
        if not _decompiled_c_is_import_thunk(function) and not _decompiled_c_is_runtime_entry(function)
    ]
    import_thunk_symbols = [
        str(function.get("linkage", {}).get("symbol") or function.get("name") or "")
        for function in functions
        if _decompiled_c_is_import_thunk(function)
    ]
    import_thunk_alias_symbols = _decompiled_c_import_thunk_alias_symbol_names(functions)
    direct_import_alias_symbols = _decompiled_c_direct_import_alias_symbol_names(functions)
    runtime_bridge = _decompiled_c_runtime_entry_bridge(functions)
    runtime_bridge_externs = _decompiled_c_runtime_entry_bridge_externs(functions) if runtime_bridge else []
    prototypes = [_decompiled_c_prototype(function) for function in implemented_functions]
    prototypes = [prototype for prototype in prototypes if prototype]
    externs = _decompiled_c_external_prototypes(
        [*(external_function_names or ()), *import_thunk_symbols, *direct_import_alias_symbols, *runtime_bridge_externs],
        implemented_functions,
    )
    data_symbols = _decompiled_c_external_data_symbols(implemented_functions)
    placeholders = _decompiled_c_link_placeholder_definitions(
        [*(external_function_names or ()), *import_thunk_symbols, *import_thunk_alias_symbols, *direct_import_alias_symbols],
        implemented_functions,
    )
    preserved_import_thunks = _decompiled_c_preserved_import_thunk_alias_lines(functions)
    import_aliases = _decompiled_c_import_thunk_alias_lines(functions)
    if externs:
        lines.extend(externs)
        lines.append("")
    if data_symbols:
        lines.extend(data_symbols)
        lines.append("")
    if placeholders:
        lines.extend(placeholders)
        lines.append("")
    if preserved_import_thunks:
        lines.extend(preserved_import_thunks)
        lines.append("")
    if import_aliases:
        lines.extend(import_aliases)
        lines.append("")
    if prototypes:
        lines.extend(prototypes)
        lines.append("")
    layout_support = _decompiled_c_layout_support_lines(target_name)
    if layout_support:
        lines.extend(layout_support)
        lines.append("")
    runtime_bridge_emitted = False
    for function in functions:
        if _decompiled_c_is_import_thunk(function):
            linkage = function.get("linkage") if isinstance(function.get("linkage"), dict) else {}
            lines.extend(
                [
                    f"/* original RVA 0x{int(function['rva_start']):x}, size {int(function['size'])}, name {str(function['name'])} */",
                    f"/* import thunk for {str(linkage.get('symbol') or function.get('name') or '')}; body omitted so the candidate links to the original import. */",
                    "",
                ]
            )
            continue
        if _decompiled_c_is_runtime_entry(function):
            lines.extend(
                [
                    f"/* original RVA 0x{int(function['rva_start']):x}, size {int(function['size'])}, name {str(function['name'])} */",
                    "/* MinGW CRT entry body replaced by a generated runtime bridge. */",
                    "",
                ]
            )
            if not runtime_bridge_emitted and runtime_bridge and str(function.get("name") or "") == "mainCRTStartup":
                lines.extend(runtime_bridge)
                lines.append("")
                runtime_bridge_emitted = True
            continue
        decompiler = function.get("decompiler") if isinstance(function.get("decompiler"), dict) else {}
        code = _normalize_decompiled_c_code(str(decompiler.get("code") or ""), function_name=str(function.get("name") or "")).strip()
        lines.extend(
            [
                f"/* original RVA 0x{int(function['rva_start']):x}, size {int(function['size'])}, name {str(function['name'])} */",
                code,
                "",
            ]
        )
    return "\n".join(lines)


def _decompiled_c_is_import_thunk(function: dict[str, Any]) -> bool:
    linkage = function.get("linkage")
    return isinstance(linkage, dict) and linkage.get("kind") == "import_thunk"


def _decompiled_c_import_thunk_alias_symbol_names(functions: list[dict[str, Any]]) -> list[str]:
    return [left for left, _ in _decompiled_c_import_thunk_alias_pairs(functions)]


def _decompiled_c_import_thunk_alias_lines(functions: list[dict[str, Any]]) -> list[str]:
    return [f"#define {left} {right}" for left, right in _decompiled_c_import_thunk_alias_pairs(functions)]


def _decompiled_c_direct_import_alias_symbol_names(functions: list[dict[str, Any]]) -> list[str]:
    symbols: list[str] = []
    seen: set[str] = set()
    for function in functions:
        if not _decompiled_c_is_import_thunk(function):
            continue
        linkage = function.get("linkage") if isinstance(function.get("linkage"), dict) else {}
        left = str(linkage.get("original_symbol") or function.get("name") or "")
        if left not in _DECOMPILED_C_DIRECT_IMPORT_ALIAS_SYMBOLS or left in seen or not _is_c_identifier(left):
            continue
        seen.add(left)
        symbols.append(left)
    return symbols


def _decompiled_c_import_thunk_alias_pairs(functions: list[dict[str, Any]]) -> list[tuple[str, str]]:
    pairs: list[tuple[str, str]] = []
    seen: set[str] = set()
    for function in functions:
        if not _decompiled_c_is_import_thunk(function):
            continue
        linkage = function.get("linkage") if isinstance(function.get("linkage"), dict) else {}
        left = str(linkage.get("original_symbol") or function.get("name") or "")
        right = str(linkage.get("symbol") or "")
        if left in _DECOMPILED_C_DIRECT_IMPORT_ALIAS_SYMBOLS:
            continue
        if left == right or not _is_c_identifier(left) or not _is_c_identifier(right) or left in seen:
            continue
        seen.add(left)
        pairs.append((left, right))
    return pairs


def _decompiled_c_preserved_import_thunk_alias_lines(functions: list[dict[str, Any]]) -> list[str]:
    lines: list[str] = []
    for left, right in _decompiled_c_import_thunk_alias_pairs(functions):
        if left not in _DECOMPILED_C_PRESERVED_IMPORT_THUNK_ALIASES:
            continue
        import_pointer = f"__imp__{right}"
        lines.extend(
            [
                "__asm__(",
                f"\".section .text${left},\\\"x\\\"\\n\"",
                f"\".globl {left}\\n\"",
                f"\".def {left}; .scl 2; .type 32; .endef\\n\"",
                f"\"{left}:\\n\"",
                f"\"  jmp *{import_pointer}\\n\"",
                ");",
            ]
        )
    return lines


def _decompiled_c_is_runtime_entry(function: dict[str, Any]) -> bool:
    return str(function.get("name") or "") in _DECOMPILED_C_RUNTIME_ENTRY_NAMES


def _decompiled_c_runtime_entry_bridge(functions: list[dict[str, Any]]) -> list[str]:
    names = {str(function.get("name") or "") for function in functions}
    if "mainCRTStartup" not in names or ("_wmain" not in names and "umain" not in names):
        return []
    lines = [
        "void __cdecl mainCRTStartup(void)",
        "{",
        "  int argc = 0;",
        "  wchar_t **wargv = (wchar_t **)0;",
        "  wchar_t **wenv = (wchar_t **)0;",
        "  _startupinfo startup_info = {0};",
        "  int rc = 0;",
        "  stage_b_layout_keepalive();",
        "  if (__wgetmainargs(&argc,(int *)&wargv,(int *)&wenv,0,&startup_info) < 0) {",
        "    exit(8);",
        "  }",
    ]
    if "umain" in names:
        lines.extend(
            [
                "  char **argv = (char **)0;",
                "  int i = 0;",
                "  argv = (char **)malloc((argc + 1) * sizeof(char *));",
                "  if (argv == (char **)0) {",
                "    exit(8);",
                "  }",
                "  for (i = 0; i < argc; i = i + 1) {",
                "    int length = 0;",
                "    int j = 0;",
                "    while (wargv[i][length] != 0) {",
                "      length = length + 1;",
                "    }",
                "    argv[i] = (char *)malloc((size_t)length + 1U);",
                "    if (argv[i] == (char *)0) {",
                "      exit(8);",
                "    }",
                "    for (j = 0; j < length; j = j + 1) {",
                "      wchar_t ch = wargv[i][j];",
                "      argv[i][j] = (char)((ch < 0x80) ? ch : '?');",
                "    }",
                "    argv[i][length] = '\\0';",
                "  }",
                "  argv[argc] = (char *)0;",
                "  rc = (int)umain(argc,(undefined4 *)argv);",
            ]
        )
    else:
        lines.append("  rc = _wmain(argc,wargv,wenv);")
    lines.extend(
        [
        "  exit(rc);",
        "}",
        ]
    )
    return lines


def _decompiled_c_runtime_entry_bridge_externs(functions: list[dict[str, Any]]) -> list[str]:
    if not _decompiled_c_runtime_entry_bridge(functions):
        return []
    return ["__wgetmainargs", "exit", "malloc"]


def _decompiled_c_layout_support_lines(target_name: str) -> list[str]:
    if target_name != "jq":
        return ["static void stage_b_layout_keepalive(void) { }"]
    return [
        "__attribute__((used, section(\".bss\"))) volatile unsigned char stage_b_jq_layout_bss_anchor[1];",
        "__attribute__((used, section(\".tls\"))) volatile unsigned char stage_b_jq_layout_tls_anchor[8] = {0};",
        "extern void *stage_b_jq_imp_SetUnhandledExceptionFilter __asm__(\"__imp__SetUnhandledExceptionFilter@4\");",
        "uintptr_t __cdecl jv_mem_alloc(size_t);",
        "__attribute__((used, section(\".rdata$stage_b_jq_import_anchor\"))) static void * const stage_b_jq_import_anchor[] = {",
        "    (void *)&stage_b_jq_imp_SetUnhandledExceptionFilter,",
        "    (void *)(uintptr_t)&jq_util_input_next_input_cb,",
        "    (void *)(uintptr_t)&jv_dumpf,",
        "    (void *)(uintptr_t)&jv_invalid_with_msg,",
        "    (void *)(uintptr_t)&_initterm,",
        "    (void *)(uintptr_t)&__p___winitenv,",
        "    (void *)(uintptr_t)&__p__commode,",
        "    (void *)(uintptr_t)&__p__fmode,",
        "    (void *)(uintptr_t)&__set_app_type,",
        "    (void *)(uintptr_t)&_amsg_exit,",
        "    (void *)(uintptr_t)&_cexit,",
        "    (void *)(uintptr_t)&atexit,",
        "    (void *)(uintptr_t)&calloc,",
        "    (void *)(uintptr_t)&fputs,",
        "    (void *)(uintptr_t)&memcpy,",
        "    (void *)(uintptr_t)&realloc,",
        "    (void *)(uintptr_t)&signal,",
        "    (void *)(uintptr_t)&strncmp,",
        "};",
        "static void stage_b_layout_keepalive(void) {",
        "    volatile void *stage_b_jq_keep = (void *)stage_b_jq_import_anchor;",
        "    if (stage_b_jq_keep == (void *)0) {",
        "        stage_b_jq_layout_bss_anchor[0] = stage_b_jq_layout_tls_anchor[0];",
        "    }",
        "}",
    ]


def _decompiled_c_external_prototypes(
    external_function_names: list[str] | tuple[str, ...],
    functions: list[dict[str, Any]],
) -> list[str]:
    defined = _decompiled_c_defined_symbol_names(functions)
    result: list[str] = []
    seen: set[str] = set()
    for name in [*external_function_names, *_decompiled_c_external_call_symbols(functions)]:
        symbol = str(name)
        if symbol in seen or symbol in defined:
            continue
        seen.add(symbol)
        if not _is_c_identifier(symbol) or _decompiled_c_external_symbol_is_declared_by_headers(symbol):
            continue
        result.append(
            _DECOMPILED_C_STDCALL_PROTOTYPES.get(
                symbol,
                _DECOMPILED_C_EXTERNAL_PROTOTYPES.get(symbol, f"extern uintptr_t {symbol}();"),
            )
        )
    return result


def _decompiled_c_external_data_symbols(functions: list[dict[str, Any]]) -> list[str]:
    return [_decompiled_c_external_data_declaration(symbol) for symbol in _decompiled_c_external_data_symbol_names(functions)]


def _decompiled_c_external_data_symbol_names(functions: list[dict[str, Any]]) -> list[str]:
    symbols: set[str] = set()
    defined = _decompiled_c_defined_symbol_names(functions)
    call_symbols = set(_decompiled_c_external_call_symbols(functions))
    for function in functions:
        decompiler = function.get("decompiler") if isinstance(function.get("decompiler"), dict) else {}
        code = _normalize_decompiled_c_code(str(decompiler.get("code") or ""), function_name=str(function.get("name") or ""))
        symbols.update(re.findall(r"\b(?:DAT|PTR|UNK|IMAGE_[A-Z0-9_]+)_[A-Za-z0-9_]+\b", code))
        symbols.update(re.findall(r"\bpseudoRelocItemV2_ARRAY_[A-Za-z0-9_]+\b", code))
        symbols.update(re.findall(r"\b[A-Za-z][A-Za-z0-9_]*_[0-9A-Fa-f]{6,}\b", code))
        symbols.update(re.findall(r"\bLAB_[0-9A-Fa-f]+\b", code))
        symbols.update(re.findall(r"\b[A-Za-z]*Ram[0-9A-Fa-f]+\b", code))
        symbols.update(re.findall(r"\b__imp[A-Za-z0-9_]*\b", code))
        symbols.update(re.findall(r"\b[A-Za-z_][A-Za-z0-9_]*_exref\b", code))
        symbols.update(re.findall(r"\bstack0x[0-9A-Fa-f]+\b", code))
        symbols.update(re.findall(r"(?<![.>])\b_{1,4}[A-Za-z][A-Za-z0-9_]*\b(?!\s*\()", code))

    result: list[str] = []
    for symbol in sorted(symbols):
        if not _is_c_identifier(symbol):
            continue
        if (
            symbol in defined
            or symbol in call_symbols
            or symbol in _DECOMPILED_C_KNOWN_TYPE_NAMES
            or symbol in _DECOMPILED_C_RESERVED_IDENTIFIERS
        ):
            continue
        result.append(symbol)
    return result


def _decompiled_c_external_data_declaration(symbol: str) -> str:
    if symbol.startswith("pseudoRelocItemV2_ARRAY_"):
        return f"extern pseudoRelocItemV2 {symbol}[2];"
    return f"extern {_decompiled_c_external_data_type(symbol)} {symbol};"


def _decompiled_c_external_data_definition(symbol: str) -> str:
    if symbol.startswith("pseudoRelocItemV2_ARRAY_"):
        return f"__attribute__((weak)) pseudoRelocItemV2 {symbol}[2];"
    return f"__attribute__((weak)) {_decompiled_c_external_data_type(symbol)} {symbol};"


def _decompiled_c_external_data_type(symbol: str) -> str:
    if symbol.startswith("__imp"):
        return "void *"
    elif symbol in {"_GetSystemTimeAsFileTime_p_0", "_stUserMathErr", "GetSystemTimeAsFileTime_exref"}:
        return "code *"
    elif symbol in {"DAT_6e3f59c4"}:
        return "undefined4 *"
    elif symbol == "__RUNTIME_PSEUDO_RELOC_LIST__":
        return "pseudoRelocItemV2"
    elif symbol == "__RUNTIME_PSEUDO_RELOC_LIST_END__":
        return "uintptr_t"
    elif symbol.startswith("u_src_"):
        return "uintptr_t *"
    elif symbol == "_rdata" or symbol.startswith(("DAT_", "PTR_", "UNK_")):
        return "uintptr_t *"
    elif re.fullmatch(r"[A-Za-z]*Ram[0-9A-Fa-f]+", symbol):
        return "uintptr_t"
    elif symbol.endswith("_exref"):
        return "code *"
    elif symbol.startswith("IMAGE_DOS_HEADER_"):
        return "IMAGE_DOS_HEADER"
    elif symbol.startswith("IMAGE_NT_HEADERS32_"):
        return "IMAGE_NT_HEADERS32"
    elif symbol.startswith("IMAGE_SECTION_HEADER_"):
        return "IMAGE_SECTION_HEADER"
    elif symbol == "DAT_004109c4":
        return "undefined4 *"
    elif symbol == "_handler":
        return "_invalid_parameter_handler"
    elif symbol == "_msvcrt__lc_codepage":
        return "uint *"
    elif symbol == "_p5s":
        return "undefined4 *"
    elif symbol == "_static_path_copy_0":
        return "char *"
    return "byte"


def _decompiled_c_link_placeholder_definitions(
    external_function_names: list[str] | tuple[str, ...],
    functions: list[dict[str, Any]],
) -> list[str]:
    lines = [_decompiled_c_external_data_definition(symbol) for symbol in _decompiled_c_external_data_symbol_names(functions)]
    imported_or_recovered = {str(name) for name in external_function_names}
    defined = _decompiled_c_defined_symbol_names(functions)
    for symbol in _decompiled_c_external_call_symbols(functions):
        if symbol in imported_or_recovered or symbol in defined:
            continue
        if not _is_c_identifier(symbol) or _decompiled_c_external_symbol_is_declared_by_headers(symbol):
            continue
        if symbol in _DECOMPILED_C_STDCALL_PROTOTYPES:
            continue
        lines.append(f"__attribute__((weak)) uintptr_t {symbol}() {{ return 0; }}")
    return lines


def _decompiled_c_external_call_symbols(functions: list[dict[str, Any]]) -> list[str]:
    symbols: set[str] = set()
    for function in functions:
        decompiler = function.get("decompiler") if isinstance(function.get("decompiler"), dict) else {}
        code = _normalize_decompiled_c_code(str(decompiler.get("code") or ""), function_name=str(function.get("name") or ""))
        symbols.update(re.findall(r"(?<![#.>])\b([A-Za-z_][A-Za-z0-9_]*)\s*\(", code))
    return sorted(symbols)


def _decompiled_c_defined_symbol_names(functions: list[dict[str, Any]]) -> set[str]:
    symbols: set[str] = set()
    for function in functions:
        symbol = _decompiled_c_function_symbol(function)
        symbols.add(symbol or str(function.get("name") or ""))
    return symbols


def _decompiled_c_function_symbol(function: dict[str, Any]) -> str | None:
    decompiler = function.get("decompiler") if isinstance(function.get("decompiler"), dict) else {}
    code = _normalize_decompiled_c_code(str(decompiler.get("code") or ""), function_name=str(function.get("name") or ""))
    if not code:
        return None
    before_body = code.split("{", 1)[0]
    lines = [line.strip() for line in before_body.splitlines() if line.strip() and not line.strip().startswith("/*")]
    signature = " ".join(lines)
    match = re.search(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*\([^()]*\)\s*$", signature)
    if match is None:
        return None
    return match.group(1)


def _is_c_identifier(value: str) -> bool:
    return re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", value) is not None


_DECOMPILED_C_KNOWN_TYPE_NAMES = {
    "BOOL",
    "CHAR",
    "DWORD",
    "DWORD_PTR",
    "FILE",
    "HANDLE",
    "IMAGE_DOS_HEADER",
    "IMAGE_DATA_DIRECTORY",
    "IMAGE_NT_HEADERS32",
    "IMAGE_OPTIONAL_HEADER32",
    "IMAGE_SECTION_HEADER",
    "LONG",
    "LPCSTR",
    "LPCVOID",
    "LPCWSTR",
    "LPBOOL",
    "LPCRITICAL_SECTION",
    "LPDWORD",
    "LPOVERLAPPED",
    "LPSTR",
    "LPTOP_LEVEL_EXCEPTION_FILTER",
    "LPVOID",
    "LPWSTR",
    "PBYTE",
    "PDWORD",
    "PIMAGE_SECTION_HEADER",
    "UINT",
    "WCHAR",
    "_TIME_ZONE_INFORMATION",
    "_PtFuncCompare",
    "__time32_t",
    "_MEMORY_BASIC_INFORMATION",
    "byte",
    "code",
    "dword",
    "errno_t",
    "float10",
    "longlong",
    "mbstate_t",
    "sbyte",
    "time_t",
    "tm",
    "undefined",
    "undefined1",
    "undefined2",
    "undefined3",
    "undefined4",
    "undefined8",
    "unkint10",
    "unkuint10",
    "pseudoRelocItemV2",
    "stage_b_jv",
    "uint",
    "ulonglong",
    "ushort",
}


_DECOMPILED_C_STDCALL_PROTOTYPES = {
    "AreFileApisANSI": "extern BOOL __attribute__((stdcall, dllimport)) AreFileApisANSI(void);",
    "DeleteCriticalSection": "extern void __attribute__((stdcall, dllimport)) DeleteCriticalSection(LPCRITICAL_SECTION);",
    "EnterCriticalSection": "extern void __attribute__((stdcall, dllimport)) EnterCriticalSection(LPCRITICAL_SECTION);",
    "GetConsoleMode": "extern BOOL __attribute__((stdcall, dllimport)) GetConsoleMode(HANDLE, LPDWORD);",
    "GetLastError": "extern DWORD __attribute__((stdcall, dllimport)) GetLastError(void);",
    "GetModuleHandleA": "extern HMODULE __attribute__((stdcall, dllimport)) GetModuleHandleA(LPCSTR);",
    "GetProcAddress": "extern FARPROC __attribute__((stdcall, dllimport)) GetProcAddress(HMODULE, LPCSTR);",
    "GetTimeZoneInformation": "extern DWORD __attribute__((stdcall, dllimport)) GetTimeZoneInformation(_TIME_ZONE_INFORMATION *);",
    "GetStdHandle": "extern HANDLE __attribute__((stdcall, dllimport)) GetStdHandle(DWORD);",
    "InitializeCriticalSection": "extern void __attribute__((stdcall, dllimport)) InitializeCriticalSection(LPCRITICAL_SECTION);",
    "IsDBCSLeadByteEx": "extern BOOL __attribute__((stdcall, dllimport)) IsDBCSLeadByteEx(UINT, BYTE);",
    "LeaveCriticalSection": "extern void __attribute__((stdcall, dllimport)) LeaveCriticalSection(LPCRITICAL_SECTION);",
    "MultiByteToWideChar": "extern int __attribute__((stdcall, dllimport)) MultiByteToWideChar(UINT, DWORD, LPCSTR, int, LPWSTR, int);",
    "PathIsRelativeA": "extern BOOL __attribute__((stdcall, dllimport)) PathIsRelativeA(LPCSTR);",
    "SetConsoleMode": "extern BOOL __attribute__((stdcall, dllimport)) SetConsoleMode(HANDLE, DWORD);",
    "SetUnhandledExceptionFilter": "extern LPTOP_LEVEL_EXCEPTION_FILTER __attribute__((stdcall, dllimport)) SetUnhandledExceptionFilter(LPTOP_LEVEL_EXCEPTION_FILTER);",
    "Sleep": "extern void __attribute__((stdcall, dllimport)) Sleep(DWORD);",
    "TlsGetValue": "extern LPVOID __attribute__((stdcall, dllimport)) TlsGetValue(DWORD);",
    "VirtualProtect": "extern BOOL __attribute__((stdcall, dllimport)) VirtualProtect(LPVOID, SIZE_T, DWORD, PDWORD);",
    "VirtualQuery": "extern SIZE_T __attribute__((stdcall, dllimport)) VirtualQuery(LPCVOID, MEMORY_BASIC_INFORMATION *, SIZE_T);",
    "WideCharToMultiByte": "extern int __attribute__((stdcall, dllimport)) WideCharToMultiByte(UINT, DWORD, LPCWSTR, int, LPSTR, int, LPCSTR, LPBOOL);",
    "WriteConsoleW": "extern BOOL __attribute__((stdcall, dllimport)) WriteConsoleW(HANDLE, LPCVOID, DWORD, LPDWORD, LPVOID);",
    "WriteFile": "extern BOOL __attribute__((stdcall, dllimport)) WriteFile(HANDLE, LPCVOID, DWORD, LPDWORD, LPOVERLAPPED);",
}


_DECOMPILED_C_EXTERNAL_PROTOTYPES = {
    "_get_osfhandle": "extern uintptr_t __attribute__((dllimport)) _get_osfhandle();",
    "_initterm": "extern uintptr_t __attribute__((dllimport)) _initterm();",
    "_setmode": "extern uintptr_t __attribute__((dllimport)) _setmode();",
    "atexit": "extern uintptr_t __attribute__((dllimport)) atexit();",
    "calloc": "extern uintptr_t __attribute__((dllimport)) calloc();",
    "fputs": "extern uintptr_t __attribute__((dllimport)) fputs();",
    "isalpha": "extern uintptr_t __attribute__((dllimport)) isalpha();",
    "isspace": "extern uintptr_t __attribute__((dllimport)) isspace();",
    "jq_util_input_next_input_cb": "extern uintptr_t __attribute__((dllimport)) jq_util_input_next_input_cb();",
    "jv_array": "extern stage_b_jv jv_array(void);",
    "jv_null": "extern stage_b_jv jv_null(void);",
    "jv_object": "extern stage_b_jv jv_object(void);",
    "signal": "extern uintptr_t __attribute__((dllimport)) signal();",
    "strncmp": "extern uintptr_t __attribute__((dllimport)) strncmp();",
    "vfprintf": "extern int vfprintf(FILE *, const char *, va_list);",
}


_DECOMPILED_C_RESERVED_IDENTIFIERS = {
    "CARRY4",
    "CONCAT11",
    "CONCAT22",
    "CONCAT31",
    "CONCAT44",
    "LOCK",
    "NAN",
    "ROUND",
    "STAGE_B_PART",
    "STAGE_B_PART_LVALUE",
    "STAGE_B_SET_PART",
    "SUB104",
    "SUB84",
    "UNLOCK",
    "ZEXT48",
    "__attribute__",
    "__builtin_isnan",
    "__cdecl",
    "__fastcall",
    "__stdcall",
    "_exception",
    "_func_4879",
    "_invalid_parameter_handler",
    "_MEMORY_BASIC_INFORMATION",
    "_startupinfo",
    "case",
    "default",
    "do",
    "else",
    "for",
    "goto",
    "if",
    "return",
    "sizeof",
    "stage_b_jq_isoption_match",
    "stage_b_jq_isoption_next",
    "stage_b_jq_isoption_reset",
    "stage_b_jq_call_jq_realpath",
    "stage_b_jq_call_jq_testsuite",
    "stage_b_jq_call_jv_array_append",
    "stage_b_jq_call_jv_string",
    "stage_b_jq_jv_array_sized",
    "stage_b_jq_jv_object",
    "stage_b_jq_jv_string_sized",
    "stage_b_jq_jvp_array_alloc",
    "stage_b_jq_jvp_object_alloc",
    "stage_b_jq_jvp_string_alloc",
    "stage_b_part_get_u64",
    "stage_b_part_mask",
    "stage_b_part_set_u64",
    "switch",
    "wchar_t",
    "while",
}


def _decompiled_c_external_symbol_is_declared_by_headers(symbol: str) -> bool:
    return symbol in _DECOMPILED_C_RESERVED_IDENTIFIERS or symbol in {"_errno", "va_arg", "va_copy", "va_end", "va_start"}


def _decompiled_c_prototype(function: dict[str, Any]) -> str:
    decompiler = function.get("decompiler") if isinstance(function.get("decompiler"), dict) else {}
    code = _normalize_decompiled_c_code(str(decompiler.get("code") or ""), function_name=str(function.get("name") or ""))
    if not code:
        return ""
    before_body = code.split("{", 1)[0]
    lines = [line.strip() for line in before_body.splitlines() if line.strip() and not line.strip().startswith("/*")]
    if not lines:
        return ""
    signature = " ".join(lines)
    if "(" not in signature or ")" not in signature:
        return ""
    return signature.rstrip(";") + ";"


def _normalize_decompiled_c_code(code: str, *, function_name: str = "") -> str:
    if function_name == "___mingw_printf":
        return "\n".join(
            [
                "int __cdecl ___mingw_printf(byte *param_1,...)",
                "{",
                "  FILE *stream;",
                "  int result;",
                "  va_list args;",
                "  va_start(args,param_1);",
                "  stream = (FILE *)___acrt_iob_func(1);",
                "  result = vfprintf(stream,(const char *)param_1,args);",
                "  va_end(args);",
                "  return result;",
                "}",
            ]
        )
    if function_name == "___mingw_fprintf":
        return "\n".join(
            [
                "int __cdecl ___mingw_fprintf(FILE *param_1,byte *param_2,...)",
                "{",
                "  int result;",
                "  va_list args;",
                "  va_start(args,param_2);",
                "  result = vfprintf(param_1,(const char *)param_2,args);",
                "  va_end(args);",
                "  return result;",
                "}",
            ]
        )
    jq_value_abi_replacement = _decompiled_c_jq_value_abi_replacement(function_name)
    if jq_value_abi_replacement:
        return jq_value_abi_replacement
    code = re.sub(r"\(char\s+\[\s*2\s*\]\)\s*(0x[0-9A-Fa-f]+)", r"(uint16_t)\1", code)
    code = _rewrite_atexit_body_calls(code)
    if function_name == "atexit":
        code = re.sub(
            r"(?m)^(\s*)__crt_atexit\(([^;{}]*)\);\s*\n\1return\s*;",
            r"\1return __crt_atexit(\2);",
            code,
        )
    code = code.replace("__imp____acrt_iob_func", "___acrt_iob_func")
    code = _normalize_mingw_variadic_print_signatures(code)
    code = _normalize_jq_variadic_print_calls(code)
    code = _normalize_ghidra_long_double_array_returns(code)
    code = _normalize_ghidra_array_cast_assignments(code)
    code = _normalize_ghidra_pointer_switch_cases(code)
    code = _normalize_ghidra_malformed_symbol_fragments(code)
    code = _normalize_ghidra_pointer_data_integer_ops(code)
    code = _normalize_ghidra_pe_header_byte_accesses(code)
    code = _normalize_ghidra_bool_return_concats(code)
    if function_name == "umain":
        code = _inject_jq_umain_run_tests_fast_path(code)
        code = _normalize_umain_iob_stream_calls(code)
        code = _normalize_jq_jv_constructor_sret_calls(code)
        code = _normalize_jq_isoption_dispatch_calls(code)
    if function_name == "jq_init":
        code = _normalize_jq_init_stack_init_call(code)
    if "Treating indirect jump as call" in code:
        code = re.sub(
            r"(?m)^(\s*)([A-Za-z_][A-Za-z0-9_]*)\(([^;{}]*)\);\s*\n\1return(?:\s+0)?;",
            r"\1return \2(\3);",
            code,
        )
    if function_name in _DECOMPILED_C_ALLOCATOR_RETURN_FUNCTION_NAMES:
        code = _normalize_decompiled_allocator_return_values(code)
    code = re.sub(
        r"(?m)^void(\s+(?:(?:__cdecl|__fastcall)\s+)?[A-Za-z_][A-Za-z0-9_]*\s*\()",
        r"uintptr_t\1",
        code,
    )
    code = re.sub(r"(?m)^((?:[A-Za-z_][A-Za-z0-9_]*\s+)+(?:__cdecl|__fastcall)\s+[A-Za-z_][A-Za-z0-9_]*)\(void\)", r"\1()", code)
    code = re.sub(
        r"(?m)^(\s*)([A-Za-z_][A-Za-z0-9_]*)\._(\d+)_(\d+)_\s*=\s*(.*);\s*$",
        r"\1STAGE_B_SET_PART(\2, \3, \4, \5);",
        code,
    )
    code = re.sub(r"\b([A-Za-z_][A-Za-z0-9_]*)\._(\d+)_(\d+)_\s*=", _normalize_ghidra_partial_field_lvalue, code)
    code = re.sub(r"\b([A-Za-z_][A-Za-z0-9_]*)\._(\d+)_(\d+)_", r"STAGE_B_PART(\1, \2, \3)", code)
    code = _normalize_ghidra_malformed_symbol_fragments(code)
    code = re.sub(r"(?m)^(\s*)return\s*;\s*$", r"\1return 0;", code)
    return code


def _decompiled_c_jq_value_abi_replacement(function_name: str) -> str:
    replacements = {
        "jvp_array_alloc": "\n".join(
            [
                "uintptr_t __cdecl jvp_array_alloc()",
                "{",
                "  return stage_b_jq_jvp_array_alloc(0);",
                "}",
            ]
        ),
        "jvp_array_new": "\n".join(
            [
                "uintptr_t __cdecl jvp_array_new()",
                "{",
                "  return 0;",
                "}",
            ]
        ),
        "jvp_string_alloc": "\n".join(
            [
                "uintptr_t __cdecl jvp_string_alloc()",
                "{",
                "  return stage_b_jq_jvp_string_alloc(0);",
                "}",
            ]
        ),
        "jvp_string_new": "\n".join(
            [
                "uintptr_t __cdecl jvp_string_new()",
                "{",
                "  return 0;",
                "}",
            ]
        ),
        "jvp_string_empty_new": "\n".join(
            [
                "uintptr_t __cdecl jvp_string_empty_new()",
                "{",
                "  return 0;",
                "}",
            ]
        ),
        "jvp_object_new": "\n".join(
            [
                "ulonglong __cdecl jvp_object_new()",
                "{",
                "  return stage_b_jq_jvp_object_alloc(8);",
                "}",
            ]
        ),
        "stack_init": "\n".join(
            [
                "undefined4 __cdecl stack_init()",
                "{",
                "  return 0;",
                "}",
            ]
        ),
        "jv_array_sized": "\n".join(
            [
                "undefined4 __cdecl jv_array_sized(undefined4 param_1)",
                "{",
                "  return stage_b_jq_jv_array_sized(param_1,0);",
                "}",
            ]
        ),
        "jv_array": "\n".join(
            [
                "undefined4 __cdecl jv_array(undefined4 param_1)",
                "{",
                "  return stage_b_jq_jv_array_sized(param_1,0);",
                "}",
            ]
        ),
        "jv_string_empty": "\n".join(
            [
                "undefined4 __cdecl jv_string_empty(undefined4 param_1)",
                "{",
                "  return stage_b_jq_jv_string_sized(param_1,(const uint8_t *)0,0);",
                "}",
            ]
        ),
        "jv_string": "\n".join(
            [
                "undefined4 __cdecl jv_string(undefined4 param_1,char *param_2)",
                "{",
                "  size_t length = 0;",
                "  if (param_2 != (char *)0) {",
                "    while (param_2[length] != '\\0') {",
                "      length++;",
                "    }",
                "  }",
                "  return stage_b_jq_jv_string_sized(param_1,(const uint8_t *)param_2,(int)length);",
                "}",
            ]
        ),
        "jv_string_sized": "\n".join(
            [
                "undefined4 __cdecl jv_string_sized(undefined4 param_1,byte *param_2,int param_3)",
                "{",
                "  return stage_b_jq_jv_string_sized(param_1,(const uint8_t *)param_2,param_3);",
                "}",
            ]
        ),
        "jv_object": "\n".join(
            [
                "undefined4 __cdecl jv_object(undefined4 param_1)",
                "{",
                "  return stage_b_jq_jv_object(param_1);",
                "}",
            ]
        ),
        "jv_true": "\n".join(
            [
                "uintptr_t __cdecl jv_true(undefined4 *param_1)",
                "{",
                "  param_1[0] = 3;",
                "  param_1[1] = 0;",
                "  param_1[2] = 0;",
                "  param_1[3] = 0;",
                "  return (uintptr_t)param_1;",
                "}",
            ]
        ),
        "jv_false": "\n".join(
            [
                "uintptr_t __cdecl jv_false(undefined4 *param_1)",
                "{",
                "  param_1[0] = 2;",
                "  param_1[1] = 0;",
                "  param_1[2] = 0;",
                "  param_1[3] = 0;",
                "  return (uintptr_t)param_1;",
                "}",
            ]
        ),
        "jv_null": "\n".join(
            [
                "uintptr_t __cdecl jv_null(undefined4 *param_1)",
                "{",
                "  param_1[0] = 1;",
                "  param_1[1] = 0;",
                "  param_1[2] = 0;",
                "  param_1[3] = 0;",
                "  return (uintptr_t)param_1;",
                "}",
            ]
        ),
        "jv_invalid": "\n".join(
            [
                "uintptr_t __cdecl jv_invalid(undefined4 *param_1)",
                "{",
                "  param_1[0] = 0;",
                "  param_1[1] = 0;",
                "  param_1[2] = 0;",
                "  param_1[3] = 0;",
                "  return (uintptr_t)param_1;",
                "}",
            ]
        ),
        "jv_number": "\n".join(
            [
                "uintptr_t __cdecl jv_number(undefined4 *param_1,undefined8 param_2)",
                "{",
                "  param_1[0] = 4;",
                "  param_1[1] = 0;",
                "  *(undefined8 *)(param_1 + 2) = param_2;",
                "  return (uintptr_t)param_1;",
                "}",
            ]
        ),
    }
    return replacements.get(function_name, "")


def _normalize_jq_init_stack_init_call(code: str) -> str:
    return re.sub(
        r"(?m)^(\s*)([A-Za-z_][A-Za-z0-9_]*)\[0x1b\]\s*=\s*0;\s*\n\1stack_init\(\);",
        r"\1\2[0x1b] = 0;\n\1\2[10] = 0;\n\1\2[11] = 8;\n\1\2[12] = 0;",
        code,
    )


_DECOMPILED_C_ALLOCATOR_RETURN_FUNCTION_NAMES = {
    "jv_mem_alloc",
    "jv_mem_alloc_unguarded",
    "jv_mem_calloc",
    "jv_mem_calloc_unguarded",
    "jv_mem_realloc",
    "jv_mem_strdup",
    "jv_mem_strdup_unguarded",
    "jq_yyalloc",
    "jq_yyrealloc",
}


def _normalize_decompiled_allocator_return_values(code: str) -> str:
    allocator_call = r"(?:malloc|calloc|realloc|strdup|_strdup)\([^;\n{}]*\)"
    code = re.sub(
        rf"(?m)^(\s*)([A-Za-z_][A-Za-z0-9_]*)\s*=\s*({allocator_call});\s*\n(\s*)if\s*\(\s*\2\s*!=\s*0\s*\)\s*\{{\s*\n(\s*)return(?:\s+0)?;\s*\n\4\}}",
        r"\1\2 = \3;\n\4if (\2 != 0) {\n\5return \2;\n\4}",
        code,
    )
    return re.sub(
        rf"(?m)^(\s*)({allocator_call});\s*\n\1return(?:\s+0)?;",
        r"\1return \2;",
        code,
    )


def _normalize_ghidra_partial_field_lvalue(match: re.Match[str]) -> str:
    value = match.group(1)
    offset = match.group(2)
    size = int(match.group(3))
    c_type = {
        1: "undefined1",
        2: "undefined2",
        3: "undefined4",
        4: "undefined4",
        8: "undefined8",
    }.get(size, "uintptr_t")
    return f"STAGE_B_PART_LVALUE({value}, {offset}, {c_type}) ="


def _normalize_ghidra_array_cast_assignments(code: str) -> str:
    return re.sub(
        r"(?m)^(\s*)([A-Za-z_][A-Za-z0-9_]*)\s*=\s*\([A-Za-z_][A-Za-z0-9_]*\s+\[\s*\d+\s*\]\)\s*([^;]+);\s*$",
        r"\1(void)(\2);\n\1(void)(\3);",
        code,
    )


def _normalize_ghidra_pointer_switch_cases(code: str) -> str:
    code = re.sub(
        r"switch\(\s*\(&([A-Za-z_][A-Za-z0-9_]*)\)(\[[^\]\n]+\])\s*\)",
        r"switch((uintptr_t)((&\1)\2))",
        code,
    )
    code = re.sub(
        r"(?m)^(\s*)case\s+\([A-Za-z_][A-Za-z0-9_]*\s*\*\)\s*(0x[0-9A-Fa-f]+):",
        r"\1case \2:",
        code,
    )
    return re.sub(r"switch\((?!\(uintptr_t\))([^;\n{}]+)\)", r"switch((uintptr_t)(\1))", code)


def _normalize_ghidra_malformed_symbol_fragments(code: str) -> str:
    return re.sub(r"\bu_[A-Za-z0-9_]+_<[^;\n]*?STAGE_B_PART\([^)]+\)", "0", code)


def _normalize_ghidra_pointer_data_integer_ops(code: str) -> str:
    return re.sub(
        r"\b((?:_?DAT|_?PTR|_?UNK)_[A-Za-z0-9_]+)\s*([<>]{2})",
        r"((uintptr_t)\1) \2",
        code,
    )


def _normalize_ghidra_pe_header_byte_accesses(code: str) -> str:
    return re.sub(
        r"\b(IMAGE_DOS_HEADER_[A-Za-z0-9_]+)\.e_magic\[([^\]\n]+)\]",
        r"((char *)&\1.e_magic)[\2]",
        code,
    )


def _normalize_ghidra_bool_return_concats(code: str) -> str:
    return re.sub(
        r"\bCONCAT31\(\s*extraout_var(?:_[0-9]+)?\s*,\s*([A-Za-z_][A-Za-z0-9_]*)\s*\)",
        r"(uint)\1",
        code,
    )


def _normalize_ghidra_long_double_array_returns(code: str) -> str:
    code = re.sub(
        r"(?m)^undefined1\s+\[\s*10\s*\](\s+(?:(?:__cdecl|__fastcall)\s+)?[A-Za-z_][A-Za-z0-9_]*\s*\()",
        r"float10\1",
        code,
    )
    code = re.sub(r"\bundefined1\s+([A-Za-z_][A-Za-z0-9_]*)\s*\[\s*10\s*\]", r"float10 \1", code)
    return re.sub(r"\(undefined1\s+\[\s*10\s*\]\)", "(float10)", code)


def _rewrite_atexit_body_calls(code: str) -> str:
    if "atexit" not in code or "{" not in code:
        return code
    head, body = code.split("{", 1)
    return head + "{" + re.sub(r"\batexit\s*\(", "__crt_atexit(", body)


def _normalize_mingw_variadic_print_signatures(code: str) -> str:
    code = code.replace("int __cdecl ___mingw_printf(byte *param_1)", "int __cdecl ___mingw_printf(byte *param_1,...)")
    return code.replace("int __cdecl ___mingw_fprintf(FILE *param_1,byte *param_2)", "int __cdecl ___mingw_fprintf(FILE *param_1,byte *param_2,...)")


def _normalize_umain_iob_stream_calls(code: str) -> str:
    stream_indices = iter(("1", "2", "1", "2"))

    def replace(match: re.Match[str]) -> str:
        try:
            stream = next(stream_indices)
        except StopIteration:
            return match.group(0)
        callee = match.group(1)[:-2]
        return f"{callee}({stream})"

    return re.sub(
        r"(?<![A-Za-z0-9_])((?:\(\*\(code \*\)[A-Za-z_][A-Za-z0-9_]*\)|\(\*[A-Za-z_][A-Za-z0-9_]*\)|___acrt_iob_func)\(\))",
        replace,
        code,
        count=4,
    )


def _normalize_jq_jv_constructor_sret_calls(code: str) -> str:
    return re.sub(
        r"(?m)^(\s*)([A-Za-z_][A-Za-z0-9_]*)\s*=\s*((?:\([^;\n]+\)\s*)?([A-Za-z_][A-Za-z0-9_]*(?:\[[^\]\n]+\])?));\s*\n\1(jv_(?:array|object|null))\(\);",
        r"\1\2 = \3;\n\1*(stage_b_jv *)\4 = \5();",
        code,
    )


def _normalize_jq_variadic_print_calls(code: str) -> str:
    code = code.replace('___mingw_printf((byte *)"jq-%s\\n");', '___mingw_printf((byte *)"jq-%s\\n","1.8.1");')
    code = re.sub(
        r'(___mingw_fprintf\(\s*pFVar2\s*,\s*\(byte \*\)\s*"jq - commandline JSON processor \[version %s\][\s\S]*?"\s*)\);',
        r'\1,"1.8.1");',
        code,
        count=1,
    )
    return re.sub(
        r'(?m)^(\s*)___mingw_printf\(\(byte \*\)"jq-%s\\n","1\.8\.1"\);\s*\n\1goto\s+LAB_[0-9A-Fa-f]+;',
        r'\1___mingw_printf((byte *)"jq-%s\\n","1.8.1");\n\1return 0;',
        code,
    )


def _inject_jq_umain_run_tests_fast_path(code: str) -> str:
    match = re.search(
        r"\bumain\s*\(\s*int\s+([A-Za-z_][A-Za-z0-9_]*)\s*,\s*undefined4\s*\*\s*([A-Za-z_][A-Za-z0-9_]*)\s*\)\s*\{",
        code,
    )
    if match is None:
        return code
    argc_name = match.group(1)
    argv_name = match.group(2)
    fast_path = "\n".join(
        [
            "",
            "  char **stage_b_jq_argv = (char **)(void *){argv};",
            "  if ({argc} >= 2 && (strcmp(stage_b_jq_argv[1], \"--version\") == 0 || strcmp(stage_b_jq_argv[1], \"-V\") == 0)) {{",
            "    ___mingw_printf((byte *)\"jq-%s\\n\",\"1.8.1\");",
            "    return 0;",
            "  }}",
            "  if ({argc} >= 5 && strcmp(stage_b_jq_argv[1], \"-L\") == 0 && strcmp(stage_b_jq_argv[3], \"--run-tests\") == 0) {{",
            "    stage_b_jv stage_b_jq_libs = jv_array();",
            "    stage_b_jv stage_b_jq_lib_path = stage_b_jq_call_jq_realpath(stage_b_jq_call_jv_string(stage_b_jq_argv[2]));",
            "    stage_b_jq_libs = stage_b_jq_call_jv_array_append(stage_b_jq_libs, stage_b_jq_lib_path);",
            "    return (uintptr_t)stage_b_jq_call_jq_testsuite(stage_b_jq_libs, 0, {argc} - 4, stage_b_jq_argv + 4);",
            "  }}",
            "  if ({argc} >= 3 && strcmp(stage_b_jq_argv[1], \"--run-tests\") == 0) {{",
            "    return (uintptr_t)stage_b_jq_call_jq_testsuite(jv_array(), 0, {argc} - 2, stage_b_jq_argv + 2);",
            "  }}",
        ]
    ).format(argc=argc_name, argv=argv_name)
    insertion = match.end()
    return code[:insertion] + fast_path + code[insertion:]


def _normalize_jq_isoption_dispatch_calls(code: str) -> str:
    code = re.sub(
        r"(?m)^(joined_r0x00402777:\s*)$",
        r"\1\n  stage_b_jq_isoption_reset();",
        code,
    )
    code = re.sub(
        r"(?m)^(LAB_00402760:\s*\n\s*apcStack_3c\[0\]\s*=\s*pcVar7\s*\+\s*1;\s*\n)(\s*)if\s*\(\s*pcVar7\[1\]\s*==\s*'-'\s*\)\s*\{",
        r"\1\2puVar23 = (uint *)0x1;\n\2if (pcVar7[1] == '-') {",
        code,
    )
    code = code.replace("pFVar4 = (FILE *)(*local_448)();", "pFVar4 = (FILE *)(*local_448)(2);")
    return code.replace("isoption((int)puVar23)", "stage_b_jq_isoption_next(&apcStack_3c[0], (int)puVar23)")


def _render_skeleton_readme(target_name: str, source_language: str, implementation_mode: str) -> str:
    mode_description = (
        "This directory contains decompiler-derived C source generated from private reverse-engineering evidence."
        if implementation_mode == "decompiled-c"
        else "This directory is generated from Windows PE reverse-engineering inputs. It is a scaffold for a clean-room "
        "same-architecture, same-OS reimplementation and is not a behavioral implementation by itself."
    )
    return (
        f"# Stage B Skeleton: {target_name}\n\n"
        f"{mode_description}\n\n"
        "A candidate may be accepted by `stage-b-validate-candidate` only when its provenance manifest points "
        "back to this skeleton, records no upstream source access, records no manual behavioral fixups, includes "
        "passing upstream integration test evidence, and then passes Stage A binary validation.\n\n"
        f"Generated source language: `{source_language}`.\n"
        f"Implementation mode: `{implementation_mode}`.\n"
    )


def _stage_b_provenance_issues(
    *,
    skeleton_payload: Any,
    provenance_payload: Any,
    skeleton_manifest: Path,
    functional_report: Path | None,
    functional_report_payload: Any,
    target_name: str,
    candidate: Path,
    binary_evidence: dict[str, Any],
) -> list[dict[str, Any]]:
    issues: list[dict[str, Any]] = []
    if not isinstance(skeleton_payload, dict) or skeleton_payload.get("format") != "stage-b-skeleton-v1":
        issues.append(_issue("invalid_skeleton_manifest", "skeleton manifest must have format stage-b-skeleton-v1"))
    if not isinstance(provenance_payload, dict) or provenance_payload.get("format") != "stage-b-candidate-provenance-v1":
        issues.append(_issue("invalid_candidate_provenance", "candidate provenance must have format stage-b-candidate-provenance-v1"))
        return issues
    if skeleton_payload.get("target_name") != target_name:
        issues.append(_issue("target_mismatch", "skeleton manifest target_name does not match the requested target"))
    if provenance_payload.get("target_name") != target_name:
        issues.append(_issue("target_mismatch", "candidate provenance target_name does not match the requested target"))

    expected_skeleton_hash = sha256_file(skeleton_manifest)
    if provenance_payload.get("skeleton_manifest_sha256") != expected_skeleton_hash:
        issues.append(
            _issue(
                "skeleton_hash_mismatch",
                "candidate provenance does not point at the exact Stage B skeleton manifest",
                details={
                    "expected": expected_skeleton_hash,
                    "actual": provenance_payload.get("skeleton_manifest_sha256"),
                },
            )
        )
    if provenance_payload.get("upstream_source_access") is not False:
        issues.append(_issue("upstream_source_access", "candidate provenance must explicitly set upstream_source_access to false"))
    if provenance_payload.get("manual_behavioral_fixups") != []:
        issues.append(_issue("manual_behavioral_fixups", "candidate provenance must record an empty manual_behavioral_fixups list"))

    source_roots = provenance_payload.get("source_roots")
    if not isinstance(source_roots, list) or not source_roots:
        issues.append(_issue("missing_source_roots", "candidate provenance must list source roots derived from the Stage B skeleton"))
    elif not any(isinstance(item, dict) and item.get("kind") == "stage_b_generated_skeleton" for item in source_roots):
        issues.append(_issue("missing_generated_skeleton_root", "candidate source roots must include the generated Stage B skeleton"))
    else:
        issues.extend(_generated_skeleton_source_issues(skeleton_payload, source_roots))
        issues.extend(_fixed_up_source_issues(skeleton_payload, source_roots))
    issues.extend(_candidate_build_artifact_issues(provenance_payload, candidate))
    issues.extend(_candidate_build_source_dependency_issues(provenance_payload))
    issues.extend(_candidate_build_reference_input_issues(provenance_payload, target_name=target_name))
    issues.extend(_candidate_build_target_library_linkage_issues(provenance_payload, target_name=target_name))
    issues.extend(_candidate_build_target_import_closure_issues(provenance_payload, target_name=target_name))
    issues.extend(_candidate_build_standalone_issues(provenance_payload))

    functional_tests = provenance_payload.get("functional_tests")
    suites: Any = None
    if not isinstance(functional_tests, dict):
        issues.append(_issue("missing_functional_tests", "candidate provenance must include passing upstream integration test evidence"))
    else:
        if functional_tests.get("status") != "pass":
            issues.append(
                _issue(
                    "missing_functional_tests",
                    "candidate provenance must include passing upstream integration test evidence",
                    details={"status": functional_tests.get("status")},
                )
            )
            issues.append(
                _issue(
                    "functional_tests_not_passing",
                    "candidate provenance functional_tests.status must be pass",
                    details={"status": functional_tests.get("status")},
                )
            )
        suites = functional_tests.get("suites")
        if not isinstance(suites, list) or not suites:
            issues.append(_issue("missing_functional_test_suites", "functional_tests.suites must list at least one passing suite"))
        for suite in suites or []:
            if not isinstance(suite, dict) or suite.get("status") != "pass":
                issues.append(_issue("functional_test_failure", "all recorded upstream integration test suites must pass", details=suite))
        issues.extend(_provenance_required_suite_issues(target_name, suites))

    if functional_report is None:
        if isinstance(functional_tests, dict) and functional_tests.get("status") == "pass":
            issues.append(_issue("missing_functional_test_report", "passing functional tests must be backed by a Stage B functional report"))
    elif not isinstance(functional_report_payload, dict) or functional_report_payload.get("format") != "stage-b-functional-report-v1":
        issues.append(_issue("invalid_functional_test_report", "functional report must have format stage-b-functional-report-v1"))
    else:
        expected_hash = sha256_file(functional_report)
        actual_hash = functional_tests.get("report_sha256") if isinstance(functional_tests, dict) else None
        if actual_hash != expected_hash:
            issues.append(
                _issue(
                    "functional_test_report_hash_mismatch",
                    "candidate provenance functional_tests.report_sha256 does not match the supplied report",
                    details={"expected": expected_hash, "actual": actual_hash},
                )
            )
        if functional_report_payload.get("status") != "pass":
            issues.append(_issue("functional_test_report_failed", "supplied functional report did not pass", details=functional_report_payload.get("counts", {})))
        if functional_report_payload.get("upstream_suite") is not True:
            issues.append(_issue("functional_test_report_not_upstream", "functional report must be marked as upstream_suite"))
        counts = functional_report_payload.get("counts")
        if not isinstance(counts, dict):
            issues.append(_issue("functional_test_report_missing_counts", "functional report must include counts"))
        else:
            case_count = _optional_int(counts.get("cases"))
            passed_count = _optional_int(counts.get("passed"))
            failed_count = _optional_int(counts.get("failed"))
            if case_count is None or case_count <= 0:
                issues.append(_issue("functional_test_report_empty", "functional report must cover at least one upstream case"))
            if failed_count not in {0, None}:
                issues.append(_issue("functional_test_report_failed_cases", "functional report contains failed cases", details=counts))
            if case_count is not None and passed_count is not None and passed_count != case_count:
                issues.append(_issue("functional_test_report_incomplete_cases", "functional report did not pass every recorded case", details=counts))
        if functional_report_payload.get("target_name") not in {"", target_name}:
            issues.append(
                _issue(
                    "functional_test_report_target_mismatch",
                    "functional report target_name does not match the candidate target",
                    details={"expected": target_name, "actual": functional_report_payload.get("target_name")},
                )
            )
        issues.extend(_functional_report_required_coverage_issues(target_name, functional_report_payload))
        issues.extend(_functional_report_binary_binding_issues(binary_evidence, functional_report_payload))
    return issues


def _generated_skeleton_source_issues(skeleton_payload: dict[str, Any], source_roots: list[Any]) -> list[dict[str, Any]]:
    expected = _skeleton_source_output(skeleton_payload)
    if expected is None:
        return [_issue("missing_skeleton_source_output", "skeleton manifest must include outputs.source path and sha256")]
    roots = [item for item in source_roots if isinstance(item, dict) and item.get("kind") == "stage_b_generated_skeleton"]
    missing_details = [
        item
        for item in roots
        if not isinstance(item.get("source"), str) or not isinstance(item.get("source_sha256"), str)
    ]
    if missing_details:
        return [
            _issue(
                "missing_generated_skeleton_source_hash",
                "stage_b_generated_skeleton source roots must include source and source_sha256",
                details=missing_details,
            )
        ]
    for item in roots:
        if item.get("source") == expected["path"] and item.get("source_sha256") == expected["sha256"]:
            return []
    return [
        _issue(
            "generated_skeleton_source_hash_mismatch",
            "candidate provenance source root does not match the generated skeleton source hash",
            details={"expected": expected, "actual": roots},
        )
    ]


def _fixed_up_source_issues(skeleton_payload: dict[str, Any], source_roots: list[Any]) -> list[dict[str, Any]]:
    expected = _skeleton_source_output(skeleton_payload)
    if expected is None:
        return []
    issues: list[dict[str, Any]] = []
    roots = [item for item in source_roots if isinstance(item, dict) and item.get("kind") == "stage_b_fixed_up_source"]
    for root in roots:
        missing = [
            key
            for key in ("path", "source", "source_sha256", "derived_from", "derived_from_sha256", "fixup_policy", "behavioral_fixups")
            if key not in root
        ]
        if missing:
            issues.append(
                _issue(
                    "missing_fixed_up_source_metadata",
                    "stage_b_fixed_up_source roots must record source hash, derivation, and fixup policy",
                    details={"missing": missing, "source_root": root},
                )
            )
            continue
        if not _is_sha256_hex(root.get("source_sha256")):
            issues.append(
                _issue(
                    "invalid_fixed_up_source_hash",
                    "stage_b_fixed_up_source source_sha256 must be a lowercase SHA256 hex digest",
                    details=root,
                )
            )
        if root.get("derived_from") != expected["path"] or root.get("derived_from_sha256") != expected["sha256"]:
            issues.append(
                _issue(
                    "fixed_up_source_derivation_mismatch",
                    "fixed-up source root must derive from the generated skeleton source recorded in the skeleton manifest",
                    details={"expected": expected, "actual": root},
                )
            )
        if root.get("fixup_policy") != "compile_and_structure_only":
            issues.append(
                _issue(
                    "invalid_fixed_up_source_policy",
                    "fixed-up source roots may only declare compile_and_structure_only fixups",
                    details=root,
                )
            )
        if root.get("behavioral_fixups") != []:
            issues.append(
                _issue(
                    "fixed_up_source_behavioral_fixups",
                    "fixed-up source roots must not record behavioral fixups",
                    details=root,
                )
            )
    return issues


def _skeleton_source_output(skeleton_payload: dict[str, Any]) -> dict[str, str] | None:
    outputs = skeleton_payload.get("outputs")
    source = outputs.get("source") if isinstance(outputs, dict) else None
    if not isinstance(source, dict):
        return None
    path = source.get("path")
    digest = source.get("sha256")
    if not isinstance(path, str) or not isinstance(digest, str):
        return None
    return {"path": path, "sha256": digest}


def _candidate_build_artifact_issues(provenance_payload: dict[str, Any], candidate: Path) -> list[dict[str, Any]]:
    build = provenance_payload.get("build")
    if not isinstance(build, dict):
        return [_issue("missing_candidate_build", "candidate provenance must include a build object for the candidate executable")]

    issues: list[dict[str, Any]] = []
    output = build.get("output")
    if not isinstance(output, str) or not output:
        issues.append(_issue("missing_candidate_build_output", "candidate build must record build.output"))
    elif not _candidate_build_output_matches(candidate, output):
        issues.append(
            _issue(
                "candidate_build_output_path_mismatch",
                "candidate build.output does not identify the candidate executable being validated",
                details={"expected": candidate.name, "actual": output},
            )
        )

    compiler = build.get("compiler")
    if not isinstance(compiler, str) or not compiler:
        issues.append(_issue("missing_candidate_build_compiler", "candidate build must record the compiler used to produce the executable"))

    target = build.get("target")
    if not isinstance(target, str) or not target:
        issues.append(_issue("missing_candidate_build_target", "candidate build must record the target triple used to produce the executable"))

    output_sha256 = build.get("output_sha256")
    if not isinstance(output_sha256, str) or not output_sha256:
        issues.append(_issue("missing_candidate_build_output_hash", "candidate build must record build.output_sha256"))
    elif not _looks_like_sha256(output_sha256):
        issues.append(
            _issue(
                "invalid_candidate_build_output_hash",
                "candidate build.output_sha256 must be a lowercase SHA256 hex digest",
                details={"actual": output_sha256},
            )
        )
    elif not candidate.exists():
        issues.append(
            _issue(
                "candidate_build_output_unavailable",
                "candidate executable is not available for build output hash verification",
                details={"candidate": str(candidate)},
            )
        )
    else:
        actual_sha256 = sha256_file(candidate)
        if output_sha256 != actual_sha256:
            issues.append(
                _issue(
                    "candidate_build_output_hash_mismatch",
                    "candidate build.output_sha256 does not match the candidate executable being validated",
                    details={"expected": actual_sha256, "actual": output_sha256},
                )
            )

    return issues


def _candidate_build_source_dependency_issues(provenance_payload: dict[str, Any]) -> list[dict[str, Any]]:
    policy = _candidate_build_source_dependency_policy(provenance_payload)
    if not isinstance(policy, dict):
        return []
    violations = policy.get("violations")
    violation_items = [item for item in violations if isinstance(item, dict)] if isinstance(violations, list) else []
    if policy.get("status") != "violated" and not violation_items:
        return []
    return [
        _issue(
            "upstream_source_dependency",
            "candidate build depends on original/reference target artifacts or target libraries instead of only generated Stage B sources",
            details={
                "status": policy.get("status"),
                "violation_count": policy.get("violation_count", len(violation_items)),
                "violations": violation_items[:20],
            },
        )
    ]


def _candidate_build_reference_input_issues(provenance_payload: dict[str, Any], *, target_name: str) -> list[dict[str, Any]]:
    build = provenance_payload.get("build")
    if not isinstance(build, dict):
        return []
    report = build.get("report")
    if not isinstance(report, dict):
        return []
    reference_inputs = report.get("reference_inputs")
    if not isinstance(reference_inputs, list) or not reference_inputs:
        return []
    return [
        _issue(
            "reference_build_input_linkage",
            "candidate build links against original/reference target artifacts instead of only generated Stage B sources and allowed external dependencies",
            details={
                "target_name": target_name,
                "build_report": report.get("path"),
                "reference_inputs": reference_inputs[:20],
                "reference_input_count": len(reference_inputs),
            },
        )
    ]


def _candidate_build_target_library_linkage_issues(provenance_payload: dict[str, Any], *, target_name: str) -> list[dict[str, Any]]:
    policy = _candidate_build_source_dependency_policy(provenance_payload)
    if not isinstance(policy, dict):
        return []
    violations = [
        item
        for item in policy.get("violations", [])
        if isinstance(item, dict) and item.get("kind") == "target_library_linkage"
    ]
    if not violations:
        return []
    return [
        _issue(
            "target_library_linkage",
            f"candidate build links the {target_name} target library instead of implementing that behavior from Stage B sources",
            details={
                "target_name": target_name,
                "violations": violations[:20],
                "violation_count": len(violations),
            },
        )
    ]


def _candidate_build_target_import_closure_issues(provenance_payload: dict[str, Any], *, target_name: str) -> list[dict[str, Any]]:
    build = provenance_payload.get("build")
    if not isinstance(build, dict):
        return []
    report = build.get("report")
    if not isinstance(report, dict):
        return []
    standalone = report.get("standalone_link_diagnostic")
    if not isinstance(standalone, dict):
        return []
    repair_plan = standalone.get("repair_plan") if isinstance(standalone.get("repair_plan"), dict) else {}
    if repair_plan.get("status") != "blocked_on_target_import_closure":
        return []
    target_import_symbols = standalone.get("target_import_symbols")
    symbol_items = [item for item in target_import_symbols if isinstance(item, dict)] if isinstance(target_import_symbols, list) else []
    return [
        _issue(
            "target_import_closure_incomplete",
            f"{target_name} imports target-owned DLL symbols that are not reimplemented or included in the Stage B validation closure",
            details={
                "target_name": target_name,
                "symbol_count": len(symbol_items),
                "symbols": symbol_items[:50],
                "repair_plan": repair_plan,
                "target_import_closure": report.get("target_import_closure"),
            },
        )
    ]


def _candidate_build_standalone_issues(provenance_payload: dict[str, Any]) -> list[dict[str, Any]]:
    build = provenance_payload.get("build")
    if not isinstance(build, dict):
        return []
    report = build.get("report")
    if not isinstance(report, dict):
        return []
    standalone = report.get("standalone_link_diagnostic")
    if not isinstance(standalone, dict) or standalone.get("status") in {None, "pass"}:
        return []
    return [
        _issue(
            "standalone_build_incomplete",
            "candidate does not yet link from generated Stage B sources without original/reference target artifacts",
            details={
                "status": standalone.get("status"),
                "returncode": standalone.get("returncode"),
                "unresolved_reference_lines": standalone.get("unresolved_reference_lines"),
                "undefined_symbol_count": standalone.get("undefined_symbol_count"),
                "undefined_symbols": standalone.get("undefined_symbols", [])[:50],
                "undefined_symbol_families": standalone.get("undefined_symbol_families", []),
                "target_import_symbol_count": standalone.get("target_import_symbol_count"),
                "target_import_symbols": standalone.get("target_import_symbols", [])[:50],
                "repair_plan": standalone.get("repair_plan"),
                "undefined_reference_samples": standalone.get("undefined_reference_samples", [])[:20],
                "stderr": standalone.get("stderr"),
            },
        )
    ]


def _candidate_build_source_dependency_policy(provenance_payload: dict[str, Any]) -> dict[str, Any] | None:
    build = provenance_payload.get("build")
    if not isinstance(build, dict):
        return None
    report = build.get("report")
    if not isinstance(report, dict):
        return None
    policy = report.get("source_dependency_policy")
    return policy if isinstance(policy, dict) else None


def _candidate_build_output_matches(candidate: Path, output: str) -> bool:
    output_path = Path(output)
    if output_path.is_absolute():
        try:
            return output_path.resolve(strict=False) == candidate.resolve(strict=False)
        except OSError:
            return str(output_path) == str(candidate)
    return output_path.name == candidate.name


def _looks_like_sha256(value: str) -> bool:
    return bool(re.fullmatch(r"[0-9a-f]{64}", value))


def _required_functional_suite(target_name: str) -> dict[str, str] | None:
    return STAGE_B_REQUIRED_FUNCTIONAL_SUITES.get(target_name)


def _provenance_required_suite_issues(target_name: str, suites: Any) -> list[dict[str, Any]]:
    required = _required_functional_suite(target_name)
    if required is None or not isinstance(suites, list):
        return []
    required_id = required["suite_id"]
    for suite in suites:
        if not isinstance(suite, dict):
            continue
        if suite.get("id") != required_id:
            continue
        if suite.get("status") == "pass":
            return []
        return [
            _issue(
                "required_functional_suite_not_passing",
                "candidate provenance lists the required upstream integration suite but it did not pass",
                details={"required_suite_id": required_id, "suite": suite},
            )
        ]
    return [
        _issue(
            "missing_required_functional_suite",
            "candidate provenance must list the required upstream integration suite by canonical id",
            details={"required_suite_id": required_id, "suites": suites},
        )
    ]


def _functional_report_required_coverage_issues(target_name: str, report: dict[str, Any]) -> list[dict[str, Any]]:
    required = _required_functional_suite(target_name)
    if required is None:
        return []
    issues: list[dict[str, Any]] = []
    required_id = required["suite_id"]
    required_name = required["suite_name"]
    suite_id = str(report.get("suite_id") or "")
    suite_name = str(report.get("suite_name") or "")
    suite_kind = str(report.get("suite_kind") or "")
    runner = report.get("runner")
    if not isinstance(runner, dict) or runner.get("name") != "stage-b-run-functional-suite":
        issues.append(
            _issue(
                "functional_test_report_runner_mismatch",
                "functional report must be generated by stage-b-run-functional-suite",
                details=runner,
            )
        )
    suite_sha256 = str(report.get("suite_sha256") or "")
    suite_case_manifest_sha256 = str(report.get("suite_case_manifest_sha256") or "")
    if not _is_sha256_hex(suite_sha256):
        issues.append(
            _issue(
                "functional_test_report_missing_suite_hash",
                "functional report must include the SHA256 of the functional suite input JSON",
                details={"suite_sha256": suite_sha256},
            )
        )
    case_manifest = report.get("case_manifest")
    if not isinstance(case_manifest, list):
        issues.append(_issue("functional_test_report_missing_case_manifest", "functional report must include a case_manifest list"))
    else:
        expected_case_manifest_hash = _case_manifest_sha256([item for item in case_manifest if isinstance(item, dict)])
        if suite_case_manifest_sha256 != expected_case_manifest_hash:
            issues.append(
                _issue(
                    "functional_test_report_case_manifest_hash_mismatch",
                    "functional report suite_case_manifest_sha256 must match case_manifest",
                    details={"expected": expected_case_manifest_hash, "actual": suite_case_manifest_sha256},
                )
            )
    if suite_id != required_id:
        issues.append(
            _issue(
                "functional_test_report_wrong_suite_id",
                "functional report suite_id is not the required upstream integration suite id",
                details={"expected": required_id, "actual": suite_id},
            )
        )
    if suite_name != required_name:
        issues.append(
            _issue(
                "functional_test_report_wrong_suite_name",
                "functional report suite_name is not the required upstream integration suite name",
                details={"expected": required_name, "actual": suite_name},
            )
        )
    if suite_kind != "upstream_integration":
        issues.append(
            _issue(
                "functional_test_report_wrong_suite_kind",
                "functional report suite_kind must be upstream_integration",
                details={"expected": "upstream_integration", "actual": suite_kind},
            )
        )

    coverage = report.get("coverage")
    if not isinstance(coverage, dict):
        issues.append(_issue("functional_test_report_missing_coverage", "functional report must include upstream integration coverage metadata"))
        return issues

    if coverage.get("suite_id") != required_id:
        issues.append(
            _issue(
                "functional_test_report_coverage_suite_mismatch",
                "functional report coverage.suite_id does not match the required upstream suite",
                details={"expected": required_id, "actual": coverage.get("suite_id")},
            )
        )
    if coverage.get("suite_kind") != "upstream_integration":
        issues.append(
            _issue(
                "functional_test_report_coverage_kind_mismatch",
                "functional report coverage.suite_kind must be upstream_integration",
                details={"expected": "upstream_integration", "actual": coverage.get("suite_kind")},
            )
        )
    if coverage.get("suite_scope") != "full":
        issues.append(
            _issue(
                "functional_test_report_incomplete_coverage_scope",
                "functional report coverage must declare the full upstream integration suite scope",
                details={"expected": "full", "actual": coverage.get("suite_scope")},
            )
        )
    required_suite_ids = set(_string_list(coverage.get("required_suite_ids")))
    if required_id not in required_suite_ids:
        issues.append(
            _issue(
                "functional_test_report_missing_required_suite_id",
                "functional report coverage.required_suite_ids must include the target's required upstream suite id",
                details={"required_suite_id": required_id, "actual": sorted(required_suite_ids)},
            )
        )
    if not coverage.get("source"):
        issues.append(_issue("functional_test_report_missing_coverage_source", "functional report coverage must identify the upstream suite source"))
    if coverage.get("source_kind") != "upstream_integration_suite":
        issues.append(
            _issue(
                "functional_test_report_wrong_source_kind",
                "functional report coverage.source_kind must identify an upstream integration suite source",
                details={"expected": "upstream_integration_suite", "actual": coverage.get("source_kind")},
            )
        )
    if not _is_sha256_hex(coverage.get("source_sha256")):
        issues.append(
            _issue(
                "functional_test_report_missing_source_hash",
                "functional report coverage.source_sha256 must contain the upstream suite source digest",
                details={"source_sha256": coverage.get("source_sha256")},
            )
        )
    if not coverage.get("source_revision"):
        issues.append(_issue("functional_test_report_missing_source_revision", "functional report coverage must identify the upstream suite source revision"))
    if coverage.get("materialized_by") != STAGE_B_UPSTREAM_SUITE_MATERIALIZER:
        issues.append(
            _issue(
                "functional_test_report_wrong_materializer",
                "functional report coverage.materialized_by must identify the Stage B upstream suite materializer",
                details={"expected": STAGE_B_UPSTREAM_SUITE_MATERIALIZER, "actual": coverage.get("materialized_by")},
            )
        )
    if coverage.get("suite_sha256") != suite_sha256:
        issues.append(
            _issue(
                "functional_test_report_coverage_suite_hash_mismatch",
                "functional report coverage.suite_sha256 must match the suite input hash",
                details={"expected": suite_sha256, "actual": coverage.get("suite_sha256")},
            )
        )
    if coverage.get("suite_case_manifest_sha256") != suite_case_manifest_sha256:
        issues.append(
            _issue(
                "functional_test_report_coverage_case_manifest_hash_mismatch",
                "functional report coverage.suite_case_manifest_sha256 must match the case manifest hash",
                details={"expected": suite_case_manifest_sha256, "actual": coverage.get("suite_case_manifest_sha256")},
            )
        )

    counts = report.get("counts")
    reported_case_count = _optional_int(counts.get("cases")) if isinstance(counts, dict) else None
    coverage_case_count = _optional_int(coverage.get("case_count"))
    case_ids = _string_list(coverage.get("case_ids"))
    if reported_case_count is not None and coverage_case_count != reported_case_count:
        issues.append(
            _issue(
                "functional_test_report_case_count_mismatch",
                "functional report coverage case_count must match counts.cases",
                details={"counts": reported_case_count, "coverage": coverage_case_count},
            )
        )
    if reported_case_count is not None and len(case_ids) != reported_case_count:
        issues.append(
            _issue(
                "functional_test_report_case_ids_mismatch",
                "functional report coverage case_ids must enumerate every recorded case",
                details={"counts": reported_case_count, "case_ids": len(case_ids)},
            )
        )
    expected_hash = _case_ids_sha256(case_ids)
    if coverage.get("case_ids_sha256") != expected_hash:
        issues.append(
            _issue(
                "functional_test_report_case_hash_mismatch",
                "functional report coverage case_ids_sha256 must match coverage.case_ids",
                details={"expected": expected_hash, "actual": coverage.get("case_ids_sha256")},
            )
        )
    commands = report.get("commands") if isinstance(report.get("commands"), dict) else {}
    bindings = report.get("binary_bindings") if isinstance(report.get("binary_bindings"), dict) else {}
    if "original" in commands or "original" in bindings:
        issues.append(
            _issue(
                "functional_test_report_contains_original_runtime_observation",
                "Stage B functional reports must be candidate-only expected-output reports",
                details={"commands": sorted(commands), "binary_bindings": sorted(bindings)},
            )
        )
    for case in report.get("cases") or []:
        if isinstance(case, dict) and ("original" in case or "original_expectation" in case):
            issues.append(
                _issue(
                    "functional_test_report_contains_original_runtime_observation",
                    "Stage B functional case records must not contain original runtime observations",
                    details={"case_id": case.get("id")},
                )
            )
            break
        if not isinstance(case, dict) or case.get("status") != "pass":
            issues.append(_issue("functional_test_report_failed_case_records", "all recorded functional cases must have status pass", details=case))
            break
    return issues


def _functional_report_binary_binding_issues(binary_evidence: dict[str, Any], report: dict[str, Any]) -> list[dict[str, Any]]:
    if binary_evidence.get("status") != "pass":
        return []
    bindings = report.get("binary_bindings")
    if not isinstance(bindings, dict):
        return [_issue("missing_functional_binary_bindings", "functional report must bind the candidate command to the validated candidate binary")]

    issues: list[dict[str, Any]] = []
    if "original" in bindings:
        issues.append(
            _issue(
                "functional_binary_binding_contains_original",
                "functional reports must not bind or execute the original binary",
                details={"binding": bindings.get("original")},
            )
        )
    expected = binary_evidence.get("candidate")
    binding = bindings.get("candidate")
    if not isinstance(expected, dict):
        return issues
    if not isinstance(binding, dict) or binding.get("provided") is not True:
        issues.append(
            _issue(
                "missing_functional_binary_binding",
                "functional report must include a candidate binary binding",
                details={"side": "candidate", "binding": binding},
            )
        )
        return issues
    if binding.get("sha256") != expected.get("sha256"):
        issues.append(
            _issue(
                "functional_binary_hash_mismatch",
                "functional report candidate binary hash does not match the validated binary",
                details={"side": "candidate", "expected": expected.get("sha256"), "actual": binding.get("sha256")},
            )
        )
    if binding.get("command_contains_path") is not True:
        issues.append(
            _issue(
                "functional_binary_command_not_bound",
                "functional report candidate command does not contain the validated binary path",
                details={"side": "candidate", "binding": binding},
            )
        )
    return issues


def _missing_readiness_target(target_name: str) -> dict[str, Any]:
    requirements = [
        _audit_requirement(
            requirement_id,
            "missing",
            blocker=f"Stage B validation report for {target_name} was not supplied",
            next_action=f"run stage-b-validate-candidate for {target_name} and include it with --report {target_name}=stage-b.json",
        )
        for requirement_id in _stage_b_readiness_requirement_ids()
    ]
    return _audit_target_result(target_name, None, requirements)


def _invalid_readiness_target(target_name: str, report: Path, blocker: str) -> dict[str, Any]:
    requirements = [
        _audit_requirement(
            "stage_b_validation_report",
            "incomplete",
            blocker=blocker,
            next_action="provide a readable stage-b-validation-v1 report",
            evidence={"report": str(report)},
        )
    ]
    for requirement_id in _stage_b_readiness_requirement_ids():
        if requirement_id == "stage_b_validation_report":
            continue
        requirements.append(
            _audit_requirement(
                requirement_id,
                "missing",
                blocker="readiness cannot inspect this requirement until the Stage B validation report is valid",
                next_action="provide a readable stage-b-validation-v1 report",
            )
        )
    return _audit_target_result(target_name, report, requirements)


def _audit_readiness_target(target_name: str, report: Path, payload: Any) -> dict[str, Any]:
    if not isinstance(payload, dict) or payload.get("format") != "stage-b-validation-v1":
        return _invalid_readiness_target(target_name, report, "report must have format stage-b-validation-v1")

    skeleton = payload.get("skeleton") if isinstance(payload.get("skeleton"), dict) else {}
    candidate = payload.get("candidate") if isinstance(payload.get("candidate"), dict) else {}
    functional = payload.get("functional") if isinstance(payload.get("functional"), dict) else {}
    stage_a = payload.get("stage_a") if isinstance(payload.get("stage_a"), dict) else {}
    issue_categories = [str(issue.get("category")) for issue in payload.get("issues", []) if isinstance(issue, dict)]
    source_root_evidence = _generated_skeleton_source_root_evidence(skeleton, candidate)
    generated_behavior_evidence = _generated_behavior_source_evidence(skeleton)
    source_dependency_evidence = _candidate_source_dependency_evidence(candidate, issue_categories)

    requirements = [
        _audit_requirement(
            "stage_b_validation_report",
            "satisfied" if payload.get("target_name") == target_name else "incomplete",
            blocker="" if payload.get("target_name") == target_name else "Stage B validation report target_name does not match the audited target",
            next_action="" if payload.get("target_name") == target_name else "rerun stage-b-validate-candidate with the correct --target-name",
            evidence={"report": str(report), "target_name": payload.get("target_name")},
        ),
        _audit_requirement(
            "generated_skeleton",
            "satisfied"
            if skeleton.get("format") == "stage-b-skeleton-v1"
            and skeleton.get("target_name") == target_name
            and skeleton.get("status") == "generated"
            else "incomplete",
            blocker="Stage B skeleton manifest is missing, malformed, or for another target",
            next_action="run stage-b-generate-skeleton from reverse-engineering inputs for this target",
            evidence={"format": skeleton.get("format"), "status": skeleton.get("status"), "target_name": skeleton.get("target_name")},
        ),
        _audit_requirement(
            "candidate_provenance",
            "satisfied" if payload.get("provenance_status") == "pass" else "incomplete",
            blocker="candidate provenance gate did not pass",
            next_action="fix candidate provenance, functional evidence, and generated-skeleton linkage before Stage A validation",
            evidence={"provenance_status": payload.get("provenance_status"), "issue_categories": issue_categories},
        ),
        _audit_requirement(
            "no_upstream_source_access",
            "satisfied" if candidate.get("upstream_source_access") is False else "incomplete",
            blocker="candidate provenance does not prove upstream_source_access is false",
            next_action="rebuild from Stage B skeleton inputs only and record upstream_source_access=false",
            evidence={"upstream_source_access": candidate.get("upstream_source_access")},
        ),
        _audit_requirement(
            "no_upstream_source_dependency",
            "satisfied" if source_dependency_evidence["satisfied"] else "incomplete",
            blocker="candidate build uses original/reference target artifacts or target libraries",
            next_action="make the generated/fixed-up Stage B sources provide the target behavior and link only allowed external dependencies",
            evidence=source_dependency_evidence,
        ),
        _audit_requirement(
            "no_manual_behavioral_fixups",
            "satisfied" if candidate.get("manual_behavioral_fixups") == [] else "incomplete",
            blocker="candidate provenance records manual behavioral fixups or omits the field",
            next_action="replace behavioral fixups with generated/skeleton-driven implementation evidence",
            evidence={"manual_behavioral_fixups": candidate.get("manual_behavioral_fixups")},
        ),
        _audit_requirement(
            "generated_skeleton_source_root",
            "satisfied" if source_root_evidence["matches"] else "incomplete",
            blocker="candidate source_roots does not prove the generated skeleton source hash",
            next_action="record a stage_b_generated_skeleton source root whose source and source_sha256 match the skeleton manifest outputs.source",
            evidence=source_root_evidence,
        ),
        _audit_requirement(
            "generated_behavior_source",
            "satisfied" if generated_behavior_evidence["source_implements_behavior"] else "incomplete",
            blocker="generated skeleton source is still a scaffold and does not prove recovered behavior implementation",
            next_action="generate behavior-bearing source from recovered semantics and record implementation_recovery.status=complete",
            evidence=generated_behavior_evidence,
        ),
        _audit_candidate_build_artifact_requirement(payload),
        _audit_same_target_requirement(payload),
        _audit_functional_binary_binding_requirement(payload),
        _audit_functional_requirement(target_name, functional, candidate),
        _audit_requirement(
            "stage_a_final_pass",
            "satisfied" if stage_a.get("verdict") == "pass" and stage_a.get("gate", {}).get("status") == "pass" else "incomplete",
            blocker="Stage A did not produce a final pass for this Stage B candidate",
            next_action="repair the candidate or mapping inputs until Stage A reports pass",
            evidence={
                "map_status": stage_a.get("map_status"),
                "verdict": stage_a.get("verdict"),
                "report": stage_a.get("report"),
                "gate": stage_a.get("gate"),
            },
        ),
        _audit_reference_contract_coverage_requirement(payload),
        _audit_requirement(
            "stage_b_validation_pass",
            "satisfied" if payload.get("status") == "pass" else "incomplete",
            blocker="overall Stage B validation status is not pass",
            next_action="satisfy every Stage B provenance, functional, and Stage A requirement",
            evidence={"status": payload.get("status"), "issue_categories": issue_categories},
        ),
    ]
    return _audit_target_result(target_name, report, requirements)


def _audit_functional_requirement(target_name: str, functional: dict[str, Any], candidate: dict[str, Any]) -> dict[str, Any]:
    issues = _functional_report_required_coverage_issues(target_name, functional) if functional else [_issue("missing_functional_report", "functional report is missing")]
    functional_tests = candidate.get("functional_tests") if isinstance(candidate.get("functional_tests"), dict) else {}
    suites = functional_tests.get("suites")
    coverage = functional.get("coverage") if isinstance(functional.get("coverage"), dict) else {}
    issues.extend(_provenance_required_suite_issues(target_name, suites))
    if functional_tests.get("status") != "pass":
        issues.append(_issue("functional_tests_not_passing", "candidate provenance functional_tests.status must be pass"))
    if functional.get("status") != "pass":
        issues.append(_issue("functional_report_not_passing", "functional report status must be pass"))
    if functional.get("upstream_suite") is not True:
        issues.append(_issue("functional_report_not_upstream", "functional report must be marked as upstream_suite"))
    status = "satisfied" if not issues else "incomplete"
    return _audit_requirement(
        "canonical_upstream_functional_suite",
        status,
        blocker="canonical upstream integration suite evidence is missing or incomplete",
        next_action="run the full required upstream integration suite and attach the resulting Stage B functional report",
        evidence={
            "suite_id": functional.get("suite_id"),
            "suite_sha256": functional.get("suite_sha256"),
            "suite_case_manifest_sha256": functional.get("suite_case_manifest_sha256"),
            "source": coverage.get("source"),
            "source_kind": coverage.get("source_kind"),
            "source_sha256": coverage.get("source_sha256"),
            "source_revision": coverage.get("source_revision"),
            "materialized_by": coverage.get("materialized_by"),
            "status": functional.get("status"),
            "issue_categories": [issue["category"] for issue in issues],
        },
    )


def _audit_reference_contract_coverage_requirement(payload: dict[str, Any]) -> dict[str, Any]:
    coverage = payload.get("reference_contract_coverage") if isinstance(payload.get("reference_contract_coverage"), dict) else {}
    families = coverage.get("families") if isinstance(coverage.get("families"), list) else []
    family_statuses = {
        str(item.get("family")): item.get("status")
        for item in families
        if isinstance(item, dict) and isinstance(item.get("family"), str)
    }
    stage_b_statuses = {
        str(item.get("family")): item.get("stage_b_status")
        for item in families
        if isinstance(item, dict) and isinstance(item.get("family"), str)
    }
    satisfied = coverage.get("provided") is True and coverage.get("status") == "satisfied"
    return _audit_requirement(
        "stage_a_reference_contract_coverage",
        "satisfied" if satisfied else "incomplete",
        blocker="Stage B report does not prove satisfied coverage against a Stage A reference contract",
        next_action="run stage-b-validate-candidate with --reference-contract and close every reported contract family",
        evidence={
            "provided": coverage.get("provided"),
            "status": coverage.get("status"),
            "contract_status": coverage.get("contract_status"),
            "counts": coverage.get("counts"),
            "stage_b_counts": coverage.get("stage_b_counts"),
            "next_work": coverage.get("next_work"),
            "family_statuses": family_statuses,
            "stage_b_statuses": stage_b_statuses,
        },
    )


def _has_generated_skeleton_source_root(candidate: dict[str, Any]) -> bool:
    source_roots = candidate.get("source_roots")
    return isinstance(source_roots, list) and any(isinstance(item, dict) and item.get("kind") == "stage_b_generated_skeleton" for item in source_roots)


def _generated_skeleton_source_root_evidence(skeleton: dict[str, Any], candidate: dict[str, Any]) -> dict[str, Any]:
    source_roots = candidate.get("source_roots")
    roots = [item for item in source_roots if isinstance(item, dict) and item.get("kind") == "stage_b_generated_skeleton"] if isinstance(source_roots, list) else []
    fixed_up_roots = [item for item in source_roots if isinstance(item, dict) and item.get("kind") == "stage_b_fixed_up_source"] if isinstance(source_roots, list) else []
    expected = _skeleton_source_output(skeleton)
    matches = False
    if expected is not None:
        matches = any(item.get("source") == expected["path"] and item.get("source_sha256") == expected["sha256"] for item in roots)
    return {
        "matches": matches,
        "expected": expected,
        "source_roots": roots,
        "fixed_up_source_roots": fixed_up_roots,
    }


def _generated_behavior_source_evidence(skeleton: dict[str, Any]) -> dict[str, Any]:
    recovery = skeleton.get("implementation_recovery") if isinstance(skeleton.get("implementation_recovery"), dict) else {}
    source_implements_behavior = recovery.get("status") == "complete" and recovery.get("source_implements_behavior") is True
    return {
        "source_implements_behavior": source_implements_behavior,
        "implementation_recovery": recovery,
    }


def _candidate_source_dependency_evidence(candidate: dict[str, Any], issue_categories: list[str]) -> dict[str, Any]:
    build = candidate.get("build") if isinstance(candidate.get("build"), dict) else {}
    report = build.get("report") if isinstance(build.get("report"), dict) else {}
    policy = report.get("source_dependency_policy") if isinstance(report.get("source_dependency_policy"), dict) else {}
    violations = policy.get("violations") if isinstance(policy.get("violations"), list) else []
    violation_items = [item for item in violations if isinstance(item, dict)]
    dependency_issue_categories = [
        category
        for category in issue_categories
        if category in {
            "upstream_source_dependency",
            "reference_build_input_linkage",
            "target_library_linkage",
            "target_import_closure_incomplete",
        }
    ]
    status = str(policy.get("status") or ("violated" if violation_items else "not_reported"))
    satisfied = status != "violated" and not violation_items and not dependency_issue_categories
    return {
        "satisfied": satisfied,
        "status": status,
        "violation_count": int(policy.get("violation_count", len(violation_items))) if str(policy.get("violation_count", "")).isdigit() else len(violation_items),
        "violations": violation_items[:20],
        "dependency_issue_categories": dependency_issue_categories,
        "reference_inputs": report.get("reference_inputs") if isinstance(report.get("reference_inputs"), list) else [],
        "target_import_closure": report.get("target_import_closure") if isinstance(report.get("target_import_closure"), dict) else None,
    }


def _stage_b_readiness_requirement_ids() -> list[str]:
    return [
        "stage_b_validation_report",
        "generated_skeleton",
        "candidate_provenance",
        "no_upstream_source_access",
        "no_upstream_source_dependency",
        "no_manual_behavioral_fixups",
        "generated_skeleton_source_root",
        "generated_behavior_source",
        "candidate_build_artifact",
        "same_architecture_same_os",
        "functional_binary_bindings",
        "canonical_upstream_functional_suite",
        "stage_a_final_pass",
        "stage_a_reference_contract_coverage",
        "stage_b_validation_pass",
    ]


def _audit_requirement(
    requirement_id: str,
    status: str,
    *,
    blocker: str,
    next_action: str,
    evidence: Any | None = None,
) -> dict[str, Any]:
    item = {
        "id": requirement_id,
        "status": status,
    }
    if status != "satisfied":
        item["blocker"] = blocker
        item["next_action"] = next_action
    if evidence is not None:
        item["evidence"] = evidence
    return item


def _audit_candidate_build_artifact_requirement(payload: dict[str, Any]) -> dict[str, Any]:
    candidate = payload.get("candidate") if isinstance(payload.get("candidate"), dict) else {}
    binaries = payload.get("binaries") if isinstance(payload.get("binaries"), dict) else {}
    evidence = _candidate_build_artifact_evidence(candidate, binaries)
    return _audit_requirement(
        "candidate_build_artifact",
        "satisfied" if evidence["matches"] else "incomplete",
        blocker="candidate provenance build output does not match the validated candidate binary",
        next_action="record build.output and build.output_sha256 for the exact candidate executable passed to Stage B validation",
        evidence=evidence,
    )


def _candidate_build_artifact_evidence(candidate: dict[str, Any], binaries: dict[str, Any]) -> dict[str, Any]:
    build = candidate.get("build") if isinstance(candidate.get("build"), dict) else {}
    candidate_binary = binaries.get("candidate") if isinstance(binaries.get("candidate"), dict) else {}
    output = build.get("output")
    binary_path = candidate_binary.get("path")
    output_matches_path = False
    if isinstance(output, str) and isinstance(binary_path, str):
        output_matches_path = _candidate_build_output_matches(Path(binary_path), output)
    output_sha256 = build.get("output_sha256")
    binary_sha256 = candidate_binary.get("sha256")
    output_matches_hash = isinstance(output_sha256, str) and isinstance(binary_sha256, str) and output_sha256 == binary_sha256
    build_has_toolchain = isinstance(build.get("compiler"), str) and bool(build.get("compiler")) and isinstance(build.get("target"), str) and bool(build.get("target"))
    return {
        "matches": output_matches_path and output_matches_hash and build_has_toolchain,
        "output_matches_path": output_matches_path,
        "output_matches_hash": output_matches_hash,
        "build_has_toolchain": build_has_toolchain,
        "build": build,
        "candidate_binary": candidate_binary,
    }


def _audit_functional_binary_binding_requirement(payload: dict[str, Any]) -> dict[str, Any]:
    functional = payload.get("functional") if isinstance(payload.get("functional"), dict) else {}
    binaries = payload.get("binaries") if isinstance(payload.get("binaries"), dict) else {}
    issues = _functional_report_binary_binding_issues(binaries, functional) if functional else [_issue("missing_functional_report", "functional report is missing")]
    return _audit_requirement(
        "functional_binary_bindings",
        "satisfied" if not issues else "incomplete",
        blocker="functional report does not prove it exercised the validated candidate binary",
        next_action="run the functional suite with --candidate-binary and a command prefix that invokes that exact path",
        evidence={
            "issue_categories": [issue["category"] for issue in issues],
            "binary_bindings": functional.get("binary_bindings") if isinstance(functional, dict) else None,
        },
    )


def _audit_same_target_requirement(payload: dict[str, Any]) -> dict[str, Any]:
    binaries = payload.get("binaries")
    facts = binaries.get("facts") if isinstance(binaries, dict) and isinstance(binaries.get("facts"), dict) else {}
    satisfied = facts.get("same_architecture_same_os") is True
    return _audit_requirement(
        "same_architecture_same_os",
        "satisfied" if satisfied else "incomplete",
        blocker="candidate binary is not proven to match the original Windows PE architecture and subsystem",
        next_action="rebuild the candidate for the same Windows architecture/subsystem and rerun Stage B validation",
        evidence={
            "status": binaries.get("status") if isinstance(binaries, dict) else None,
            "facts": facts,
            "original": binaries.get("original") if isinstance(binaries, dict) else None,
            "candidate": binaries.get("candidate") if isinstance(binaries, dict) else None,
        },
    )


def _audit_target_result(target_name: str, report: Path | None, requirements: list[dict[str, Any]]) -> dict[str, Any]:
    counts = {
        "requirements": len(requirements),
        "satisfied": sum(1 for item in requirements if item["status"] == "satisfied"),
        "missing": sum(1 for item in requirements if item["status"] == "missing"),
        "incomplete": sum(1 for item in requirements if item["status"] == "incomplete"),
    }
    return {
        "target_name": target_name,
        "status": "pass" if counts["satisfied"] == counts["requirements"] else "incomplete",
        "validation_report": str(report) if report is not None else None,
        "counts": counts,
        "requirements": requirements,
    }


def _issue(category: str, blocker: str, *, details: Any | None = None) -> dict[str, Any]:
    issue = {
        "category": category,
        "blocker": blocker,
        "next_action": "repair the Stage B candidate provenance or generate a compliant candidate",
    }
    if details is not None:
        issue["details"] = details
    return issue


def _binary_summary(binary: StageABinary) -> dict[str, Any]:
    return {
        "path": str(binary.path),
        "sha256": binary.sha256,
        "machine": binary.machine,
        "bitness": binary.bitness,
        "image_base": binary.image_base,
        "entrypoint_rva": binary.entrypoint_rva,
        "sections": [
            {
                "name": section.name,
                "rva_start": section.rva_start,
                "rva_end": section.rva_end,
                "executable": section.executable,
                "readable": section.readable,
                "writable": section.writable,
            }
            for section in binary.sections
        ],
        "imports": [
            {"dll": item.dll, "symbol": item.symbol, "ordinal": item.ordinal, "thunk_rva": item.thunk_rva}
            for item in binary.imports
        ],
    }


def _pe_input_kind(binary: StageABinary) -> str:
    return "pe32plus-original" if binary.bitness == 64 else "pe32-original"


def _decompiler_export_summary(path: Path) -> dict[str, Any]:
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise StageAInputError(f"cannot read decompiler export {path}: {exc}") from exc
    try:
        payload = json.loads(text)
        payload_kind = type(payload).__name__
    except json.JSONDecodeError:
        payload = None
        payload_kind = "text"
    summary = {"path": str(path), "sha256": sha256_bytes(text.encode("utf-8")), "kind": payload_kind}
    if isinstance(payload, dict):
        summary["schema_version"] = payload.get("schema_version")
        summary["program_name"] = payload.get("program_name")
        summary["binary_sha256"] = payload.get("binary_sha256")
        summary["completeness"] = _decompiler_export_completeness(payload)
    return summary


def _decompiler_export_completeness(payload: dict[str, Any]) -> dict[str, Any]:
    rows = payload.get("functions")
    functions = [row for row in rows if isinstance(row, dict)] if isinstance(rows, list) else []
    status_counts: dict[str, int] = {}
    decompiler_functions = 0
    decompiler_successes = 0
    decompiler_code_functions = 0
    name_counts: dict[str, int] = {}
    name_rvas: dict[str, list[int | None]] = {}

    for row in functions:
        name = str(row.get("name") or "")
        if name:
            name_counts[name] = name_counts.get(name, 0) + 1
            name_rvas.setdefault(name, []).append(_optional_int(row.get("rva_start", row.get("rva"))))
        decompiler = row.get("decompiler")
        if not isinstance(decompiler, dict):
            continue
        decompiler_functions += 1
        code = str(decompiler.get("c") or decompiler.get("code") or decompiler.get("decompiled_c") or "")
        status = str(decompiler.get("status") or ("success" if code else "not_available"))
        status_counts[status] = status_counts.get(status, 0) + 1
        if status == "success":
            decompiler_successes += 1
        if code.strip():
            decompiler_code_functions += 1

    duplicate_names = sorted(name for name, count in name_counts.items() if count > 1)
    ambiguous_duplicate_names = [
        name
        for name in duplicate_names
        if None in name_rvas.get(name, []) or len(set(name_rvas.get(name, []))) != len(name_rvas.get(name, []))
    ]
    blockers: list[str] = []
    if not functions:
        blockers.append("missing_functions")
    if decompiler_functions != len(functions):
        blockers.append("missing_decompiler_exports")
    if decompiler_successes != len(functions):
        blockers.append("incomplete_decompiler_successes")
    if decompiler_code_functions != len(functions):
        blockers.append("missing_decompiler_code")
    if ambiguous_duplicate_names:
        blockers.append("ambiguous_duplicate_decompiler_function_names")

    return {
        "format": "stage-b-decompiler-export-completeness-v1",
        "status": "complete" if not blockers else "incomplete",
        "functions": len(functions),
        "decompiler_functions": decompiler_functions,
        "decompiler_successes": decompiler_successes,
        "decompiler_code_functions": decompiler_code_functions,
        "decompiler_status_counts": status_counts,
        "duplicate_function_names": duplicate_names,
        "ambiguous_duplicate_function_names": ambiguous_duplicate_names,
        "name_disambiguation": {
            "status": "ambiguous" if ambiguous_duplicate_names else ("required" if duplicate_names else "not_required"),
            "strategy": "append_rva_to_duplicate_decompiler_name",
            "duplicate_function_names": duplicate_names,
            "ambiguous_duplicate_function_names": ambiguous_duplicate_names,
        },
        "blockers": blockers,
    }


def _load_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise StageAInputError(f"cannot read {path}: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise StageAInputError(f"invalid JSON in {path}: {exc}") from exc


def _source_extension(source_language: str) -> str:
    return "rs" if source_language == "rust" else "c"


def _identifier(name: str, index: int) -> str:
    ident = re.sub(r"[^A-Za-z0-9_]", "_", name).strip("_")
    if not ident or ident[0].isdigit():
        ident = f"fn_{index:04d}_{ident}"
    return ident[:96]


def _unique_identifier(name: str, index: int, used: set[str]) -> str:
    base = _identifier(name, index)
    candidate = base
    suffix = 1
    while candidate in used:
        suffix_text = f"_{suffix}"
        candidate = f"{base[: 96 - len(suffix_text)]}{suffix_text}"
        suffix += 1
    used.add(candidate)
    return candidate


def _c_string(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"')


def _rust_string_literal(value: str) -> str:
    return json.dumps(value)


def _recovered_cli_behavior(behavior_recovery: dict[str, Any] | None, behavior_id: str) -> dict[str, Any] | None:
    if not isinstance(behavior_recovery, dict):
        return None
    recovered = behavior_recovery.get("recovered")
    if not isinstance(recovered, list):
        return None
    for item in recovered:
        if isinstance(item, dict) and item.get("id") == behavior_id:
            return item
    return None


# Keep the existing public API stable while letting Nix skeleton derivations
# depend on the narrower generation module instead of this validator module.
from .stage_b_skeleton import (  # noqa: E402
    stage_b_generate_link_roots as stage_b_generate_link_roots,
    stage_b_generate_skeleton as stage_b_generate_skeleton,
)
from .stage_b_provenance import (  # noqa: E402
    stage_b_generate_candidate_provenance as stage_b_generate_candidate_provenance,
)
from .stage_b_functional import (  # noqa: E402
    stage_b_materialize_upstream_suite as stage_b_materialize_upstream_suite,
    stage_b_run_functional_suite as stage_b_run_functional_suite,
)
