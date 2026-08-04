from __future__ import annotations

import json
import re
import subprocess
from collections import Counter
from pathlib import Path
from typing import Any

import capstone

from .stage_binary import (
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
from .stage_b_contract import REFERENCE_CONTRACT_MODEL_ID, stage_b_check_contract
from .util import sha256_bytes, sha256_file, utc_now, write_json


STAGE_B_PROOF_RULE = "stage_b_skeleton_reimplementation_contract_v1"
STAGE_B_UPSTREAM_SUITE_MATERIALIZER = "stage-b-materialize-upstream-suite"
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
























def _case_manifest_sha256(manifest: list[dict[str, Any]]) -> str:
    return sha256_bytes(json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode("utf-8"))


def _is_sha256_hex(value: Any) -> bool:
    return isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) is not None




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
    out = Path(out)
    out.mkdir(parents=True, exist_ok=True)
    started_at = utc_now()
    issues: list[dict[str, Any]] = []
    stage_a_result: dict[str, Any] | None = None
    map_result: dict[str, Any] | None = None
    binary_evidence: dict[str, Any]
    reference_contract_payload: dict[str, Any] | None = None
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
        if reference_contract_payload is None:
            raise StageAInputError("Stage B candidate validation requires a valid reference contract")
        binary_evidence = _binary_target_evidence_from_reference_contract(reference_contract_payload, candidate_bin)
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
                "next_action": "provide a supported candidate PE and a matching Stage A reference contract",
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
                require_functional_evidence=require_functional_evidence,
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
    stage_a_blocking_preissues = _stage_b_stage_a_blocking_preissues(pre_stage_a_issues)

    if not stage_a_blocking_preissues:
        try:
            stage_a_result = stage_b_check_contract(
                reference_contract=Path(reference_contract),
                candidate=Path(candidate),
                linker_map_candidate=Path(linker_map_candidate),
                skeleton_manifest=Path(skeleton_manifest),
                model=model,
                out=out / "stage-a",
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
                    "next_action": "provide a valid reference contract, candidate PE, linker map, and skeleton manifest",
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
    stage_a_gate = _stage_b_stage_a_gate(
        pre_stage_a_issues=pre_stage_a_issues,
        all_issues=issues,
        stage_a_result=stage_a_result,
        map_result=map_result,
    )
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
        "stage_a_gate": stage_a_gate,
        "iteration_policy": stage_a_gate.get("iteration_policy"),
        "runtime_validation_policy": stage_a_gate.get("runtime_validation_policy"),
        "stage_a": {
            "map_status": None if map_result is None else map_result.get("status"),
            "verdict": None if stage_a_result is None else stage_a_result.get("verdict"),
            "report": str(out / "stage-a") if stage_a_result is not None else None,
            "gate": stage_a_gate,
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


def stage_b_extract_candidate_crash(
    *,
    functional_report: Path,
    out: Path,
    candidate: Path | None = None,
    target_name: str | None = None,
    diagnostic_functional_report: Path | None = None,
) -> dict[str, Any]:
    functional_report = Path(functional_report)
    report = _load_json(functional_report)
    if not isinstance(report, dict) or report.get("format") != "stage-b-functional-report-v1":
        raise StageAInputError("Stage B candidate crash extraction requires a stage-b-functional-report-v1 report")
    out = Path(out)
    out.mkdir(parents=True, exist_ok=True)
    failed_case = _stage_b_first_failed_functional_case(report)
    stderr_artifact = _stage_b_failed_case_stream_artifact(failed_case, "stderr")
    stderr_text = _stage_b_stream_artifact_text(functional_report, stderr_artifact)
    diagnostic_report = _stage_b_optional_functional_report(diagnostic_functional_report)
    diagnostic_stderr_artifact: dict[str, Any] = {}
    diagnostic_stderr_text = ""
    if diagnostic_report is not None and diagnostic_functional_report is not None:
        diagnostic_case = _stage_b_matching_failed_functional_case(
            diagnostic_report,
            str(failed_case.get("id") or ""),
        )
        diagnostic_stderr_artifact = _stage_b_failed_case_stream_artifact(diagnostic_case, "stderr")
        diagnostic_stderr_text = _stage_b_stream_artifact_text(Path(diagnostic_functional_report), diagnostic_stderr_artifact)
    combined_stderr_text = stderr_text + ("\n" + diagnostic_stderr_text if diagnostic_stderr_text else "")
    crash = _stage_b_wine_crash_signature(combined_stderr_text)
    frames = _stage_b_wine_backtrace_frames(combined_stderr_text)
    loaded_modules = _stage_b_wine_loaded_modules(combined_stderr_text)
    seh_exception = _stage_b_wine_seh_exception(combined_stderr_text)
    result = {
        "format": "stage-b-candidate-crash-v1",
        "source": "stage-b-functional-report",
        "target_name": target_name or str(report.get("target_name") or ""),
        "original_runtime_observations": False,
        "candidate": _stage_b_candidate_artifact_from_functional_report(report, candidate),
        "functional_report": {"path": str(functional_report), "sha256": sha256_file(functional_report)},
        "diagnostic_functional_report": None
        if diagnostic_functional_report is None
        else {"path": str(diagnostic_functional_report), "sha256": sha256_file(Path(diagnostic_functional_report))},
        "case_id": str(failed_case.get("id") or ""),
        "status": "detected" if crash else "not_detected",
        "crash_kind": str(crash.get("crash_kind") or "") if crash else "",
        "access": str(crash.get("access") or "") if crash else "",
        "fault_address": crash.get("fault_address") if crash else None,
        "instruction_address": crash.get("instruction_address") if crash else None,
        "thread": str(crash.get("thread") or "") if crash else "",
        "stderr_artifact": stderr_artifact or None,
        "diagnostic_stderr_artifact": diagnostic_stderr_artifact or None,
        "stderr_preview": stderr_text[:4096],
        "stderr_crash_excerpt": _stage_b_stderr_crash_excerpt(combined_stderr_text, crash),
        "backtrace": frames,
        "loaded_modules": loaded_modules,
        "seh_exception": seh_exception,
        "repair_hints": _stage_b_candidate_crash_repair_hints(crash),
    }
    write_json(out / "candidate-crash.json", result)
    return result


def _stage_b_optional_functional_report(path: Path | None) -> dict[str, Any] | None:
    if path is None:
        return None
    payload = _load_json(Path(path))
    if not isinstance(payload, dict) or payload.get("format") != "stage-b-functional-report-v1":
        raise StageAInputError("Stage B diagnostic crash extraction requires a stage-b-functional-report-v1 report")
    return payload


def _stage_b_first_failed_functional_case(report: dict[str, Any]) -> dict[str, Any]:
    cases = report.get("cases") if isinstance(report.get("cases"), list) else []
    for case in cases:
        if isinstance(case, dict) and case.get("status") != "pass":
            return case
    return {}


def _stage_b_matching_failed_functional_case(report: dict[str, Any], case_id: str) -> dict[str, Any]:
    cases = report.get("cases") if isinstance(report.get("cases"), list) else []
    if case_id:
        for case in cases:
            if isinstance(case, dict) and case.get("id") == case_id and case.get("status") != "pass":
                return case
    return _stage_b_first_failed_functional_case(report)


def _stage_b_failed_case_stream_artifact(case: dict[str, Any], stream: str) -> dict[str, Any]:
    candidate = case.get("candidate") if isinstance(case.get("candidate"), dict) else {}
    artifact = candidate.get(stream) if isinstance(candidate.get(stream), dict) else {}
    return dict(artifact)


def _stage_b_stream_artifact_text(report_path: Path, artifact: dict[str, Any]) -> str:
    path_value = artifact.get("path") if isinstance(artifact, dict) else None
    if isinstance(path_value, str) and path_value:
        paths = [Path(path_value)]
        if not Path(path_value).is_absolute():
            paths.append(report_path.parent / path_value)
        for path in paths:
            try:
                if path.is_file():
                    return path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
    preview = artifact.get("preview") if isinstance(artifact, dict) else ""
    return preview if isinstance(preview, str) else ""


def _stage_b_candidate_artifact_from_functional_report(report: dict[str, Any], candidate: Path | None) -> dict[str, Any]:
    if candidate is not None:
        path = Path(candidate)
        artifact: dict[str, Any] = {"path": str(path)}
        if path.exists():
            artifact["sha256"] = sha256_file(path)
        return artifact
    bindings = report.get("binary_bindings") if isinstance(report.get("binary_bindings"), dict) else {}
    binding = bindings.get("candidate") if isinstance(bindings.get("candidate"), dict) else {}
    artifact = {}
    for key in ("path", "sha256", "size"):
        if key in binding:
            artifact[key] = binding[key]
    return artifact


def _stage_b_candidate_crash_repair_hints(crash: dict[str, Any] | None) -> list[str]:
    if not crash:
        return [
            "no candidate crash signature detected in failed functional case",
            "inspect functional mismatch fields and Stage A contract deltas",
        ]
    kind = str(crash.get("crash_kind") or "")
    if kind == "wine_unhandled_stack_overflow":
        failure_kind = "stack overflow during public functional suite"
    elif kind == "wine_unhandled_page_fault":
        failure_kind = "page fault during public functional suite"
    else:
        failure_kind = "candidate runtime crash during public functional suite"
    return [
        "candidate-only crash",
        failure_kind,
        "inspect ABI, stack, hidden sret/out-param, and recovered function-pointer evidence",
    ]


def _stage_b_stderr_crash_excerpt(stderr_text: str, crash: dict[str, Any] | None) -> str:
    if not crash:
        return ""
    needle = str(crash.get("instruction_address") or "").removeprefix("0x").removeprefix("0X")
    for line in stderr_text.splitlines():
        if needle and needle.lower() in line.lower():
            return line[:1000]
    for line in stderr_text.splitlines():
        if "Unhandled page fault" in line or "Unhandled stack overflow" in line or "Unhandled exception" in line:
            return line[:1000]
    return ""


_WINE_PAGE_FAULT_RE = re.compile(
    r"wine: Unhandled page fault on (?P<access>\S+) access to (?P<fault_address>0x[0-9A-Fa-f]+|[0-9A-Fa-f]+) "
    r"at address (?P<instruction_address>0x[0-9A-Fa-f]+|[0-9A-Fa-f]+)(?: \(thread (?P<thread>[0-9A-Fa-f]+)\))?"
)
_WINE_STACK_OVERFLOW_RE = re.compile(
    r"wine: Unhandled stack overflow at address (?P<instruction_address>0x[0-9A-Fa-f]+|[0-9A-Fa-f]+)"
    r"(?: \(thread (?P<thread>[0-9A-Fa-f]+)\))?"
)
_WINE_UNHANDLED_EXCEPTION_RE = re.compile(
    r"Unhandled exception: page fault on (?P<access>\S+) access to (?P<fault_address>0x[0-9A-Fa-f]+|[0-9A-Fa-f]+) "
    r"in .* code \((?P<instruction_address>0x[0-9A-Fa-f]+|[0-9A-Fa-f]+)\)"
)
_WINE_BACKTRACE_FRAME_RE = re.compile(
    r"^\s*(?P<current>=>)?\s*(?P<index>\d+)\s+(?P<address>0x[0-9A-Fa-f]+|[0-9A-Fa-f]{6,16})(?P<rest>.*)$"
)
_WINE_MODULE_LINE_RE = re.compile(
    r"^\s*(?P<kind>PE|ELF)\s+(?P<start>[0-9A-Fa-f]+)-(?P<end>[0-9A-Fa-f]+)\s+\S+\s+(?P<name>\S+)"
)
_WINE_SEH_DISPATCH_RE = re.compile(
    r"^(?P<thread>[0-9A-Fa-f]+):trace:seh:dispatch_exception code=(?P<code>[0-9A-Fa-f]+)"
    r"(?: \((?P<code_name>[^)]+)\))? flags=(?P<flags>[0-9A-Fa-f]+) addr=(?P<addr>[0-9A-Fa-f]+)"
)
_WINE_SEH_INFO_RE = re.compile(
    r"^(?P<thread>[0-9A-Fa-f]+):trace:seh:dispatch_exception\s+info\[(?P<index>\d+)\]=(?P<value>[0-9A-Fa-f]+)"
)
_WINE_SEH_REGS_RE = re.compile(
    r"^(?P<thread>[0-9A-Fa-f]+):trace:seh:dispatch_exception\s+(?P<body>(?:[a-z]{2,6}=[0-9A-Fa-f]+\s*)+)$"
)


def _stage_b_wine_crash_signature(stderr_text: str) -> dict[str, Any] | None:
    for pattern, kind in (
        (_WINE_PAGE_FAULT_RE, "wine_unhandled_page_fault"),
        (_WINE_STACK_OVERFLOW_RE, "wine_unhandled_stack_overflow"),
        (_WINE_UNHANDLED_EXCEPTION_RE, "wine_unhandled_page_fault"),
    ):
        match = pattern.search(stderr_text)
        if match is None:
            continue
        groups = match.groupdict()
        return {
            "crash_kind": kind,
            "access": groups.get("access") or "",
            "fault_address": _stage_b_prefixed_hex(groups.get("fault_address")),
            "instruction_address": _stage_b_prefixed_hex(groups.get("instruction_address")),
            "thread": groups.get("thread") or "",
        }
    return None


def _stage_b_wine_backtrace_frames(stderr_text: str) -> list[dict[str, Any]]:
    frames: list[dict[str, Any]] = []
    for line in stderr_text.splitlines():
        match = _WINE_BACKTRACE_FRAME_RE.match(line)
        if match is None:
            continue
        rest = match.group("rest") or ""
        frame: dict[str, Any] = {
            "index": int(match.group("index")),
            "address": _stage_b_prefixed_hex(match.group("address")),
        }
        module = _stage_b_wine_frame_module(rest)
        if module:
            frame["module"] = module
        symbol = _stage_b_wine_frame_symbol(rest)
        if symbol:
            frame["symbol"] = symbol
        rva = _stage_b_wine_frame_rva(rest, module)
        if rva:
            frame["rva"] = rva
        if match.group("current"):
            frame["current"] = True
        frames.append(frame)
    return frames


def _stage_b_wine_frame_module(rest: str) -> str:
    module_match = re.search(r"\bin\s+(?P<module>[A-Za-z0-9_.+-]+)(?:\s|$)", rest)
    if module_match is not None:
        return module_match.group("module")
    bang_match = re.search(r"\b(?P<module>[A-Za-z0-9_.+-]+)!", rest)
    if bang_match is not None:
        return bang_match.group("module")
    plus_match = re.search(r"\b(?P<module>[A-Za-z0-9_.+-]+\.(?:dll|exe))\+0x[0-9A-Fa-f]+", rest, flags=re.IGNORECASE)
    if plus_match is not None:
        return plus_match.group("module")
    return ""


def _stage_b_wine_frame_symbol(rest: str) -> str:
    symbol_match = re.match(r"\s*(?P<symbol>[A-Za-z_.$?@][A-Za-z0-9_.$?@<>~-]*)(?:\+0x[0-9A-Fa-f]+)?", rest)
    if symbol_match is not None:
        symbol = symbol_match.group("symbol")
        if symbol not in {"in", "at"}:
            return symbol
    bang_match = re.search(r"!(?P<symbol>[A-Za-z_.$?@][A-Za-z0-9_.$?@<>~-]*)", rest)
    if bang_match is not None:
        return bang_match.group("symbol")
    return ""


def _stage_b_wine_frame_rva(rest: str, module: str) -> str:
    rva_match = re.search(r"\(\+(?P<rva>0x[0-9A-Fa-f]+|[0-9A-Fa-f]+)\)", rest)
    if rva_match is not None:
        return _stage_b_prefixed_hex(rva_match.group("rva")) or ""
    if module:
        escaped = re.escape(module)
        module_rva = re.search(rf"\b{escaped}\+(?P<rva>0x[0-9A-Fa-f]+|[0-9A-Fa-f]+)", rest, flags=re.IGNORECASE)
        if module_rva is not None:
            return _stage_b_prefixed_hex(module_rva.group("rva")) or ""
    return ""


def _stage_b_wine_loaded_modules(stderr_text: str) -> list[dict[str, Any]]:
    modules: list[dict[str, Any]] = []
    for line in stderr_text.splitlines():
        match = _WINE_MODULE_LINE_RE.match(line)
        if match is None:
            continue
        modules.append(
            {
                "kind": match.group("kind"),
                "name": match.group("name"),
                "image_base": _stage_b_prefixed_hex(match.group("start")),
                "image_end": _stage_b_prefixed_hex(match.group("end")),
            }
        )
    return modules


def _stage_b_wine_seh_exception(stderr_text: str) -> dict[str, Any] | None:
    active: dict[str, Any] | None = None
    best: dict[str, Any] | None = None
    for line in stderr_text.splitlines():
        dispatch = _WINE_SEH_DISPATCH_RE.match(line)
        if dispatch is not None:
            code = dispatch.group("code").lower()
            active = {
                "thread": dispatch.group("thread"),
                "code": "0x" + code.upper(),
                "code_name": dispatch.group("code_name") or "",
                "flags": "0x" + dispatch.group("flags").upper(),
                "address": _stage_b_prefixed_hex(dispatch.group("addr")),
                "info": {},
                "registers": {},
            }
            if code == "c0000005":
                best = active
            continue
        if active is None:
            continue
        info = _WINE_SEH_INFO_RE.match(line)
        if info is not None and info.group("thread").lower() == str(active.get("thread", "")).lower():
            active["info"][str(info.group("index"))] = _stage_b_prefixed_hex(info.group("value"))
            continue
        regs = _WINE_SEH_REGS_RE.match(line)
        if regs is not None and regs.group("thread").lower() == str(active.get("thread", "")).lower():
            active["registers"].update(_stage_b_wine_register_assignments(regs.group("body")))
            continue
        if "Unhandled page fault" in line or "Unhandled stack overflow" in line:
            best = active
    if best is None:
        return None
    info = best.get("info") if isinstance(best.get("info"), dict) else {}
    if info.get("0") == "0x00000001":
        best["access"] = "write"
    elif info.get("0") == "0x00000000":
        best["access"] = "read"
    if "1" in info:
        best["fault_address"] = info["1"]
    return best


def _stage_b_wine_register_assignments(text: str) -> dict[str, str]:
    registers: dict[str, str] = {}
    for name, value in re.findall(r"\b([a-z]{2,6})=([0-9A-Fa-f]+)\b", text):
        registers[name] = _stage_b_prefixed_hex(value) or value
    return registers


def _stage_b_prefixed_hex(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    text = value.strip()
    if not text:
        return None
    if text.lower().startswith("0x"):
        return "0x" + text[2:].upper()
    if re.fullmatch(r"[0-9A-Fa-f]+", text):
        return "0x" + text.upper()
    return text


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
    if focused_only and focus is None:
        raise StageAInputError("focused_only delta explanation requires --focus")
    out = Path(out)
    out.mkdir(parents=True, exist_ok=True)
    reference_contract = Path(reference_contract)
    candidate = Path(candidate)
    linker_map_candidate = Path(linker_map_candidate)
    skeleton_manifest = Path(skeleton_manifest)
    contract = _load_json(reference_contract)
    skeleton = _load_json(skeleton_manifest)
    crash = _load_optional_stage_b_json(Path(candidate_crash_report)) if candidate_crash_report is not None else None
    candidate_probe = _load_optional_stage_b_json(Path(candidate_probe_report)) if candidate_probe_report is not None else None
    functional = _load_optional_stage_b_json(Path(functional_report)) if functional_report is not None else None
    unit_contracts = _stage_b_load_unit_contracts(
        reference_contract=reference_contract,
        contract=contract,
        unit_contract_dir=Path(unit_contract_dir) if unit_contract_dir is not None else None,
    )
    functional_diagnostics = _stage_b_functional_diagnostics(
        functional_report_path=Path(functional_report) if functional_report is not None else None,
        functional_report_payload=functional,
    )
    contract_validation = _stage_b_load_contract_candidate_validation(contract_candidate_validation)
    contract_validation_source = "provided"
    if contract_validation is None:
        contract_validation_source = "computed"
        contract_validation = stage_b_check_contract(
            reference_contract=reference_contract,
            candidate=candidate,
            linker_map_candidate=linker_map_candidate,
            skeleton_manifest=skeleton_manifest,
            model=model,
            out=out / "stage-a-contract-candidate",
        )
    candidate_bin = _parse_stage_a_pe(candidate)
    candidate_functions = _parse_linker_map_functions(linker_map_candidate, candidate_bin)
    candidate_symbols = _stage_b_parse_linker_map_symbols(linker_map_candidate, candidate_bin)
    candidate_module_contexts = _stage_b_candidate_module_contexts(candidate_modules)
    items = _stage_b_delta_repair_items(
        contract=contract,
        validation=contract_validation,
        skeleton=skeleton,
        candidate_functions=candidate_functions,
        candidate_symbols=candidate_symbols,
        candidate_binary=candidate_bin,
        candidate_modules=candidate_module_contexts,
        crash=crash,
        unit_contracts=unit_contracts,
        candidate_probe=candidate_probe,
        functional=functional,
    )
    source_items = items
    emitted_items = source_items
    if focused_only:
        focus_lower = focus.lower()
        emitted_items = [item for item in source_items if _stage_b_matches_focus(item, focus_lower)]
    source_counts = _stage_b_delta_counts(source_items)
    counts = _stage_b_delta_counts(emitted_items)
    if focused_only:
        counts["source_repair_items"] = source_counts["repair_items"]
    result = {
        "format": "stage-b-delta-explanation-v1",
        "status": "incomplete" if emitted_items else "pass",
        "scope": "focused" if focused_only else "full",
        "focus": focus,
        "generated_at": utc_now(),
        "reference_contract": _stage_b_reference_contract_artifact(reference_contract),
        "candidate": {"path": str(candidate), "sha256": sha256_file(candidate)},
        "linker_map_candidate": {"path": str(linker_map_candidate), "sha256": sha256_file(linker_map_candidate)},
        "skeleton_manifest": {"path": str(skeleton_manifest), "sha256": sha256_file(skeleton_manifest)},
        "candidate_modules": [_stage_b_candidate_module_artifact(module) for module in candidate_module_contexts],
        "candidate_crash_report": None
        if candidate_crash_report is None
        else _stage_b_candidate_crash_report_artifact(Path(candidate_crash_report), crash),
        "candidate_probe_report": None
        if candidate_probe_report is None
        else _stage_b_candidate_probe_report_artifact(Path(candidate_probe_report), candidate_probe),
        "unit_contracts": unit_contracts.get("artifact") if isinstance(unit_contracts, dict) else None,
        "functional_report": None if functional_report is None else {"path": str(functional_report), "sha256": sha256_file(Path(functional_report))},
        "candidate_contract_status": contract_validation.get("status") or contract_validation.get("verdict"),
        "contract_candidate_validation_source": contract_validation_source,
        "contract_candidate_validation_embedded": embed_contract_candidate_validation,
        "contract_candidate_validation_artifact": _stage_b_contract_candidate_validation_artifact(contract_candidate_validation),
        "contract_candidate_validation": contract_validation
        if embed_contract_candidate_validation
        else _stage_b_contract_candidate_validation_summary(contract_validation),
        "functional_diagnostics": functional_diagnostics,
        "layout_synthesis": _stage_b_layout_synthesis(_stage_b_layout_section_deltas_from_items(emitted_items)),
        "repair_items": emitted_items,
        "counts": counts,
    }
    if focused_only:
        result["source_counts"] = source_counts
    write_json(out / "stage-b-delta.json", result)
    return result


def _stage_b_contract_candidate_validation_summary(validation: dict[str, Any]) -> dict[str, Any]:
    families = [item for item in validation.get("families", []) if isinstance(item, dict)]
    return {
        "format": validation.get("format"),
        "status": validation.get("status") or validation.get("verdict"),
        "verdict": validation.get("verdict") or validation.get("status"),
        "model": validation.get("model"),
        "counts": validation.get("counts", {}),
        "family_statuses": _count_by(families, "status"),
    }


def _stage_b_contract_candidate_validation_artifact(value: dict[str, Any] | Path | None) -> dict[str, Any] | None:
    if value is None or isinstance(value, dict):
        return None
    path = Path(value)
    if not path.is_file():
        return {"path": str(path), "exists": False}
    return {"path": str(path), "sha256": sha256_file(path)}


def _stage_b_load_contract_candidate_validation(value: dict[str, Any] | Path | None) -> dict[str, Any] | None:
    if value is None:
        return None
    if isinstance(value, dict):
        payload = value
    else:
        payload = _load_json(Path(value))
    if not isinstance(payload, dict) or payload.get("format") != "stage-a-contract-candidate-validation-v1":
        raise StageAInputError("contract candidate validation must have format stage-a-contract-candidate-validation-v1")
    return payload


def _stage_b_matches_focus(value: Any, focus_lower: str) -> bool:
    if isinstance(value, str):
        return focus_lower in value.lower()
    if isinstance(value, int):
        return focus_lower in {str(value), hex(value).lower()}
    if isinstance(value, dict):
        return any(_stage_b_matches_focus(item, focus_lower) for item in value.values())
    if isinstance(value, list):
        return any(_stage_b_matches_focus(item, focus_lower) for item in value)
    return False


def _stage_b_delta_counts(items: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "repair_items": len(items),
        "by_repair_class": _count_by(items, "likely_repair_class"),
        "by_family": _count_by(items, "violated_contract_family"),
        "by_evidence_source": _count_by_evidence_source(items),
    }


def stage_b_diff_delta(*, before: Path, after: Path, out: Path) -> dict[str, Any]:
    before = Path(before)
    after = Path(after)
    out = Path(out)
    out.mkdir(parents=True, exist_ok=True)
    before_payload = _load_json(before)
    after_payload = _load_json(after)
    if not isinstance(before_payload, dict) or before_payload.get("format") != "stage-b-delta-explanation-v1":
        raise StageAInputError("before delta must have format stage-b-delta-explanation-v1")
    if not isinstance(after_payload, dict) or after_payload.get("format") != "stage-b-delta-explanation-v1":
        raise StageAInputError("after delta must have format stage-b-delta-explanation-v1")

    before_items = [item for item in before_payload.get("repair_items", []) if isinstance(item, dict)]
    after_items = [item for item in after_payload.get("repair_items", []) if isinstance(item, dict)]
    before_by_key = {_stage_b_repair_item_stable_key(item): item for item in before_items}
    after_by_key = {_stage_b_repair_item_stable_key(item): item for item in after_items}
    before_keys = set(before_by_key)
    after_keys = set(after_by_key)
    resolved_keys = sorted(before_keys - after_keys)
    introduced_keys = sorted(after_keys - before_keys)
    persisted_keys = sorted(before_keys & after_keys)
    changed_keys = [
        key
        for key in persisted_keys
        if _stage_b_repair_item_change_fingerprint(before_by_key[key])
        != _stage_b_repair_item_change_fingerprint(after_by_key[key])
    ]
    before_layout = _stage_b_layout_section_deltas_from_items(before_items)
    after_layout = _stage_b_layout_section_deltas_from_items(after_items)

    result = {
        "format": "stage-b-delta-diff-v1",
        "status": "pass" if after_payload.get("status") == "pass" else "incomplete",
        "generated_at": utc_now(),
        "before": _stage_b_delta_artifact(before, before_payload),
        "after": _stage_b_delta_artifact(after, after_payload),
        "counts": {
            "before_repair_items": len(before_items),
            "after_repair_items": len(after_items),
            "repair_items_delta": len(after_items) - len(before_items),
            "resolved": len(resolved_keys),
            "introduced": len(introduced_keys),
            "persisted": len(persisted_keys),
            "changed": len(changed_keys),
            "before_by_family": _count_by(before_items, "violated_contract_family"),
            "after_by_family": _count_by(after_items, "violated_contract_family"),
            "family_delta": _stage_b_count_delta(
                _count_by(before_items, "violated_contract_family"),
                _count_by(after_items, "violated_contract_family"),
            ),
            "before_by_repair_class": _count_by(before_items, "likely_repair_class"),
            "after_by_repair_class": _count_by(after_items, "likely_repair_class"),
            "repair_class_delta": _stage_b_count_delta(
                _count_by(before_items, "likely_repair_class"),
                _count_by(after_items, "likely_repair_class"),
            ),
        },
        "resolved": [_stage_b_repair_item_diff_summary(before_by_key[key], key=key) for key in resolved_keys[:100]],
        "introduced": [_stage_b_repair_item_diff_summary(after_by_key[key], key=key) for key in introduced_keys[:100]],
        "persisted": [
            _stage_b_repair_item_diff_summary(after_by_key[key], key=key, before=before_by_key.get(key))
            for key in persisted_keys[:200]
        ],
        "changed": [
            {
                "key": key,
                "before": _stage_b_repair_item_diff_summary(before_by_key[key], key=key),
                "after": _stage_b_repair_item_diff_summary(after_by_key[key], key=key),
            }
            for key in changed_keys[:100]
        ],
        "layout_synthesis": _stage_b_layout_synthesis(after_layout, before_layout=before_layout),
    }
    write_json(out / "stage-b-delta-diff.json", result)
    return result


def _stage_b_delta_artifact(path: Path, payload: dict[str, Any]) -> dict[str, Any]:
    return {
        "path": str(path),
        "sha256": sha256_file(path),
        "status": payload.get("status"),
        "counts": payload.get("counts") if isinstance(payload.get("counts"), dict) else {},
    }


def _stage_b_repair_item_stable_key(item: dict[str, Any]) -> str:
    evidence = item.get("evidence") if isinstance(item.get("evidence"), dict) else {}
    section_delta = evidence.get("section_delta") if isinstance(evidence.get("section_delta"), dict) else None
    if section_delta is not None:
        return f"section:{section_delta.get('name')}"
    coverage_gap = evidence.get("coverage_gap") if isinstance(evidence.get("coverage_gap"), dict) else None
    if coverage_gap is not None:
        gap_id = coverage_gap.get("callsite_id") or coverage_gap.get("block_id") or coverage_gap.get("name")
        if gap_id:
            return f"coverage:{item.get('violated_contract_family')}:{item.get('likely_repair_class')}:{gap_id}"
    work_item = evidence.get("work_item") if isinstance(evidence.get("work_item"), dict) else None
    if isinstance(work_item, dict) and work_item.get("id"):
        return f"work:{work_item.get('id')}"
    missing_detail = evidence.get("missing_function_detail") if isinstance(evidence.get("missing_function_detail"), dict) else None
    if missing_detail is not None:
        return f"missing-function:{missing_detail.get('function') or item.get('original_function')}"
    parts = [
        str(item.get("violated_contract_family") or ""),
        str(item.get("likely_repair_class") or ""),
        str(item.get("original_function") or ""),
        str(item.get("original_block") or ""),
        str(item.get("next_action") or ""),
    ]
    return "item:" + ":".join(parts)


def _stage_b_repair_item_change_fingerprint(item: dict[str, Any]) -> str:
    evidence = item.get("evidence") if isinstance(item.get("evidence"), dict) else {}
    section_delta = evidence.get("section_delta") if isinstance(evidence.get("section_delta"), dict) else None
    payload = {
        "family": item.get("violated_contract_family"),
        "repair_class": item.get("likely_repair_class"),
        "section_delta": _stage_b_layout_section_summary(section_delta) if section_delta is not None else None,
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":"))


def _stage_b_repair_item_diff_summary(
    item: dict[str, Any],
    *,
    key: str,
    before: dict[str, Any] | None = None,
) -> dict[str, Any]:
    summary: dict[str, Any] = {
        "key": key,
        "family": item.get("violated_contract_family"),
        "repair_class": item.get("likely_repair_class"),
        "original_function": item.get("original_function"),
        "source_location": item.get("generated_source_location"),
        "next_action": item.get("next_action"),
    }
    evidence = item.get("evidence") if isinstance(item.get("evidence"), dict) else {}
    section_delta = evidence.get("section_delta") if isinstance(evidence.get("section_delta"), dict) else None
    if section_delta is not None:
        summary["section_delta"] = _stage_b_layout_section_summary(section_delta)
    if before is not None:
        before_evidence = before.get("evidence") if isinstance(before.get("evidence"), dict) else {}
        before_section = before_evidence.get("section_delta") if isinstance(before_evidence.get("section_delta"), dict) else None
        if section_delta is not None and before_section is not None:
            before_delta = _stage_b_layout_delta_bytes(before_section)
            after_delta = _stage_b_layout_delta_bytes(section_delta)
            summary["change"] = {
                "before_delta_bytes": before_delta,
                "after_delta_bytes": after_delta,
                "absolute_delta_improvement_bytes": abs(before_delta) - abs(after_delta),
            }
    return summary


def _stage_b_count_delta(before: dict[str, int], after: dict[str, int]) -> dict[str, int]:
    return {
        key: int(after.get(key, 0)) - int(before.get(key, 0))
        for key in sorted(set(before) | set(after))
        if int(after.get(key, 0)) - int(before.get(key, 0)) != 0
    }


def _stage_b_layout_section_deltas_from_items(items: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    for item in items:
        evidence = item.get("evidence") if isinstance(item.get("evidence"), dict) else {}
        section_delta = evidence.get("section_delta") if isinstance(evidence.get("section_delta"), dict) else None
        if section_delta is None:
            continue
        name = str(section_delta.get("name") or "")
        if name and name not in result:
            result[name] = section_delta
    return result


def _stage_b_layout_synthesis(
    layout: dict[str, dict[str, Any]],
    *,
    before_layout: dict[str, dict[str, Any]] | None = None,
) -> dict[str, Any]:
    before_layout = before_layout or {}
    sections = [
        _stage_b_layout_suggestion(name, section, before_layout.get(name))
        for name, section in sorted(layout.items(), key=lambda pair: _stage_b_layout_section_rank(pair[0]))
    ]
    return {
        "format": "stage-b-layout-synthesis-v1",
        "status": "satisfied" if not sections else "incomplete",
        "counts": {
            "sections": len(sections),
            "needs_growth": sum(1 for item in sections if item["action"] == "grow"),
            "needs_shrink": sum(1 for item in sections if item["action"] == "shrink"),
            "matched": sum(1 for item in sections if item["action"] == "none"),
        },
        "sections": sections,
    }


def _stage_b_layout_suggestion(
    name: str,
    section_delta: dict[str, Any],
    before_section_delta: dict[str, Any] | None,
) -> dict[str, Any]:
    delta = _stage_b_layout_delta_bytes(section_delta)
    before_delta = _stage_b_layout_delta_bytes(before_section_delta) if before_section_delta is not None else None
    expected = section_delta.get("expected") if isinstance(section_delta.get("expected"), dict) else {}
    candidate = section_delta.get("candidate") if isinstance(section_delta.get("candidate"), dict) else {}
    action = "none" if delta == 0 else ("grow" if delta < 0 else "shrink")
    anchor_bytes = abs(delta)
    candidate_step = None
    if before_section_delta is not None:
        before_candidate = before_section_delta.get("candidate") if isinstance(before_section_delta.get("candidate"), dict) else {}
        before_end = _stage_b_int_value(before_candidate.get("rva_end"))
        after_end = _stage_b_int_value(candidate.get("rva_end"))
        if before_end is not None and after_end is not None:
            candidate_step = after_end - before_end
    suggestion = _stage_b_layout_source_suggestion(name, delta)
    return {
        "section": name,
        "action": action,
        "expected": _stage_b_section_span_for_synthesis(expected),
        "candidate": _stage_b_section_span_for_synthesis(candidate),
        "delta_bytes": delta,
        "anchor_bytes": anchor_bytes,
        "before_delta_bytes": before_delta,
        "absolute_delta_improvement_bytes": None if before_delta is None else abs(before_delta) - abs(delta),
        "observed_candidate_step_bytes": candidate_step,
        "alignment": {
            "status": _stage_b_layout_alignment_status(delta, before_delta, candidate_step),
            "note": "linker input-section alignment and PE section rounding can move spans in larger steps than the requested anchor byte count",
        },
        "linker_gc": {
            "risk": "unreferenced anchors can be discarded when --gc-sections is active",
            "required_keepalive": "mark anchors used and reference them from a retained function or constructor",
        },
        "linker": {
            "section_start_flag": _stage_b_layout_section_start_flag(name, expected),
            "note": "preserve section start first; size anchors only help after section RVAs already match",
        },
        "source": suggestion,
    }


def _stage_b_layout_delta_bytes(section_delta: dict[str, Any] | None) -> int:
    if not isinstance(section_delta, dict):
        return 0
    delta = section_delta.get("delta") if isinstance(section_delta.get("delta"), dict) else {}
    size = delta.get("size") if isinstance(delta.get("size"), dict) else {}
    value = _stage_b_int_value(size.get("delta"))
    if value is not None:
        return value
    expected = section_delta.get("expected") if isinstance(section_delta.get("expected"), dict) else {}
    candidate = section_delta.get("candidate") if isinstance(section_delta.get("candidate"), dict) else {}
    expected_size = _stage_b_section_size(expected)
    candidate_size = _stage_b_section_size(candidate)
    if expected_size is None or candidate_size is None:
        return 0
    return candidate_size - expected_size


def _stage_b_section_span_for_synthesis(section: dict[str, Any]) -> dict[str, Any]:
    return {
        "rva_start": section.get("rva_start"),
        "rva_end": section.get("rva_end"),
        "size": _stage_b_section_size(section),
        "executable": section.get("executable"),
        "readable": section.get("readable"),
        "writable": section.get("writable"),
    }


def _stage_b_layout_section_summary(section_delta: dict[str, Any]) -> dict[str, Any]:
    return {
        "name": section_delta.get("name"),
        "delta_bytes": _stage_b_layout_delta_bytes(section_delta),
        "expected": _stage_b_section_span_for_synthesis(
            section_delta.get("expected") if isinstance(section_delta.get("expected"), dict) else {}
        ),
        "candidate": _stage_b_section_span_for_synthesis(
            section_delta.get("candidate") if isinstance(section_delta.get("candidate"), dict) else {}
        ),
    }


def _stage_b_layout_alignment_status(delta: int, before_delta: int | None, candidate_step: int | None) -> str:
    if delta == 0:
        return "matched"
    if before_delta is not None and before_delta != 0 and (before_delta > 0) != (delta > 0):
        return "crossed_target_alignment_boundary"
    if candidate_step not in {None, 0} and abs(delta) <= abs(candidate_step):
        return "near_alignment_boundary"
    return "needs_iteration"


def _stage_b_layout_section_start_flag(name: str, expected: dict[str, Any]) -> str | None:
    start = _stage_b_int_value(expected.get("rva_start"))
    if start is None or not name.startswith("."):
        return None
    return f"-Wl,--section-start,{name}=0x{0x400000 + start:x}"


def _stage_b_layout_source_suggestion(name: str, delta: int) -> dict[str, Any]:
    bytes_needed = abs(delta)
    if delta == 0:
        return {"kind": "none", "next_action": "section span matches the reference contract"}
    verb = "add" if delta < 0 else "remove_or_reduce"
    if name == ".bss":
        declaration = f'__attribute__((used, section(".bss"))) volatile unsigned char stage_b_layout_bss_pad[{bytes_needed}];'
    elif name == ".rdata":
        declaration = f'__attribute__((used, section(".rdata$stage_b_layout_pad"))) static const unsigned char stage_b_layout_rdata_pad[{bytes_needed}] = {{0}};'
    elif name == ".data":
        declaration = f'__attribute__((used, section(".data$stage_b_layout_pad"))) volatile unsigned char stage_b_layout_data_pad[{bytes_needed}] = {{0}};'
    elif name == ".tls":
        declaration = f'__attribute__((used, section(".tls"))) volatile unsigned char stage_b_layout_tls_pad[{bytes_needed}] = {{0}};'
    elif name == ".text":
        declaration = f'__asm__(".section .text$stage_b_layout_pad,\\"x\\"\\n.fill {bytes_needed},1,0x90\\n.text\\n");'
    else:
        declaration = ""
    if name in {".edata", ".reloc"}:
        return {
            "kind": "linker_generated_section",
            "operation": verb,
            "bytes": bytes_needed,
            "next_action": f"adjust exports/relocations that feed {name}; raw C padding is unlikely to control this linker-generated section exactly",
        }
    return {
        "kind": "source_anchor",
        "operation": verb,
        "bytes": bytes_needed,
        "declaration": declaration,
        "next_action": f"{verb} {bytes_needed} byte(s) of retained input-section content for {name}, then rerun stage-b-diff-delta",
    }


def _stage_b_layout_section_rank(name: str) -> tuple[int, str]:
    order = {".text": 0, ".rdata": 1, ".data": 2, ".bss": 3, ".tls": 4, ".edata": 5, ".reloc": 6}
    return (order.get(name, 100), name)


def _stage_b_candidate_module_contexts(candidate_modules: list[dict[str, Any]] | None) -> list[dict[str, Any]]:
    contexts: list[dict[str, Any]] = []
    for index, module in enumerate(candidate_modules or []):
        if not isinstance(module, dict):
            raise StageAInputError("Stage B candidate module entries must be objects")
        candidate_path = module.get("candidate") or module.get("binary") or module.get("path")
        linker_map = module.get("linker_map") or module.get("linker_map_candidate") or module.get("map")
        skeleton_manifest = module.get("skeleton_manifest") or module.get("manifest")
        if candidate_path is None or linker_map is None or skeleton_manifest is None:
            raise StageAInputError(
                "Stage B candidate modules require candidate, linker_map, and skeleton_manifest paths"
            )
        candidate_path = Path(candidate_path)
        linker_map = Path(linker_map)
        skeleton_manifest = Path(skeleton_manifest)
        binary = _parse_stage_a_pe(candidate_path)
        functions = _parse_linker_map_functions(linker_map, binary)
        skeleton = _load_json(skeleton_manifest)
        contexts.append(
            {
                "name": str(module.get("name") or candidate_path.name or f"candidate-module-{index}"),
                "role": str(module.get("role") or "candidate_module"),
                "path": str(candidate_path),
                "sha256": sha256_file(candidate_path),
                "linker_map": {"path": str(linker_map), "sha256": sha256_file(linker_map)},
                "skeleton_manifest": {"path": str(skeleton_manifest), "sha256": sha256_file(skeleton_manifest)},
                "image": _stage_b_candidate_image_range(binary),
                "functions": functions,
                "source_map": _stage_b_source_map_by_function(skeleton),
            }
        )
    return contexts


def _stage_b_candidate_module_artifact(module: dict[str, Any]) -> dict[str, Any]:
    artifact = {
        "name": module.get("name"),
        "role": module.get("role"),
        "path": module.get("path"),
        "sha256": module.get("sha256"),
        "linker_map": module.get("linker_map"),
        "skeleton_manifest": module.get("skeleton_manifest"),
        "image": module.get("image"),
    }
    return {key: value for key, value in artifact.items() if value is not None}


def _stage_b_candidate_crash_report_artifact(path: Path, crash: dict[str, Any] | None) -> dict[str, Any]:
    artifact: dict[str, Any] = {"path": str(path), "sha256": sha256_file(path)}
    if isinstance(crash, dict):
        artifact["status"] = crash.get("status")
        artifact["crash_kind"] = crash.get("crash_kind")
        artifact["case_id"] = crash.get("case_id")
        artifact["has_backtrace"] = bool(crash.get("backtrace"))
        artifact["has_seh_exception"] = isinstance(crash.get("seh_exception"), dict)
        if isinstance(crash.get("diagnostic_functional_report"), dict):
            artifact["diagnostic_functional_report"] = crash.get("diagnostic_functional_report")
    return artifact


def _load_optional_stage_b_json(path: Path) -> dict[str, Any] | None:
    payload = _load_json(path)
    return payload if isinstance(payload, dict) else {"format": "unknown", "payload": payload}


def _stage_b_load_unit_contracts(
    *,
    reference_contract: Path,
    contract: dict[str, Any],
    unit_contract_dir: Path | None,
) -> dict[str, Any]:
    directory = _stage_b_unit_contract_dir(reference_contract, contract, unit_contract_dir)
    paths = {
        "block_contracts": directory / "block-contracts.jsonl",
        "function_contracts": directory / "function-contracts.jsonl",
        "cluster_contracts": directory / "cluster-contracts.jsonl",
        "repair_units": directory / "repair-units.json",
        "source_obligations": directory / "source-obligations.json",
        "semantic_transfer_contracts": directory / "semantic-transfer-contracts.jsonl",
        "semantic_region_contracts": directory / "semantic-region-contracts.jsonl",
        "memory_frame_contracts": directory / "memory-frame-contracts.json",
        "call_summary_contracts": directory / "call-summary-contracts.json",
        "cluster_semantic_contracts": directory / "cluster-semantic-contracts.jsonl",
    }
    block_contracts = _load_stage_b_jsonl(paths["block_contracts"])
    function_contracts = _load_stage_b_jsonl(paths["function_contracts"])
    cluster_contracts = _load_stage_b_jsonl(paths["cluster_contracts"])
    repair_units = _load_stage_b_optional_json(paths["repair_units"])
    source_obligations = _load_stage_b_optional_json(paths["source_obligations"])
    semantic_transfer_contracts = _load_stage_b_jsonl(paths["semantic_transfer_contracts"])
    semantic_region_contracts = _load_stage_b_jsonl(paths["semantic_region_contracts"])
    memory_frame_contracts = _load_stage_b_optional_json(paths["memory_frame_contracts"])
    call_summary_contracts = _load_stage_b_optional_json(paths["call_summary_contracts"])
    cluster_semantic_contracts = _load_stage_b_jsonl(paths["cluster_semantic_contracts"])
    return {
        "artifact": {
            "status": "available" if any(path.is_file() for path in paths.values()) else "derived_or_missing",
            "directory": str(directory),
            "paths": {name: str(path) for name, path in paths.items()},
            "counts": {
                "block_contracts": len(block_contracts),
                "function_contracts": len(function_contracts),
                "cluster_contracts": len(cluster_contracts),
                "work_items": len(repair_units.get("work_items", [])) if isinstance(repair_units.get("work_items"), list) else 0,
                "source_obligations": len(source_obligations.get("obligations", [])) if isinstance(source_obligations.get("obligations"), list) else 0,
                "semantic_transfer_contracts": len(semantic_transfer_contracts),
                "semantic_region_contracts": len(semantic_region_contracts),
                "memory_accesses": len(memory_frame_contracts.get("accesses", [])) if isinstance(memory_frame_contracts.get("accesses"), list) else 0,
                "call_summaries": len(call_summary_contracts.get("calls", [])) if isinstance(call_summary_contracts.get("calls"), list) else 0,
                "cluster_semantic_contracts": len(cluster_semantic_contracts),
            },
        },
        "block_contracts": block_contracts,
        "function_contracts": function_contracts,
        "cluster_contracts": cluster_contracts,
        "repair_units": repair_units,
        "source_obligations": source_obligations,
        "semantic_transfer_contracts": semantic_transfer_contracts,
        "semantic_region_contracts": semantic_region_contracts,
        "memory_frame_contracts": memory_frame_contracts,
        "call_summary_contracts": call_summary_contracts,
        "cluster_semantic_contracts": cluster_semantic_contracts,
    }


def _stage_b_unit_contract_dir(reference_contract: Path, contract: dict[str, Any], explicit: Path | None) -> Path:
    if explicit is not None:
        return explicit
    sidecars = contract.get("sidecars") if isinstance(contract.get("sidecars"), dict) else {}
    unit = sidecars.get("unit_contracts") if isinstance(sidecars.get("unit_contracts"), dict) else {}
    directory = unit.get("directory")
    if isinstance(directory, str) and directory:
        path = Path(directory)
        return path if path.is_absolute() else reference_contract.parent / path
    return reference_contract.parent


def _load_stage_b_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.is_file():
        return []
    rows: list[dict[str, Any]] = []
    try:
        for line in path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            value = json.loads(line)
            if isinstance(value, dict):
                rows.append(value)
    except (OSError, json.JSONDecodeError):
        return []
    return rows


def _load_stage_b_optional_json(path: Path) -> dict[str, Any]:
    if not path.is_file():
        return {}
    try:
        value = _load_json(path)
    except StageAInputError:
        return {}
    return value if isinstance(value, dict) else {}


def _stage_b_candidate_probe_report_artifact(path: Path, probe: dict[str, Any] | None) -> dict[str, Any]:
    artifact: dict[str, Any] = {"path": str(path), "sha256": sha256_file(path)}
    if isinstance(probe, dict):
        probes = probe.get("probes") if isinstance(probe.get("probes"), list) else []
        artifact["format"] = probe.get("format")
        artifact["status"] = probe.get("status")
        artifact["counts"] = {
            "probes": len(probes),
            "failing": sum(1 for item in probes if isinstance(item, dict) and item.get("status") not in {"pass", "satisfied"}),
        }
    return artifact


def _stage_b_delta_repair_items(
    *,
    contract: dict[str, Any],
    validation: dict[str, Any],
    skeleton: dict[str, Any],
    candidate_functions: list[dict[str, Any]],
    crash: dict[str, Any] | None,
    functional: dict[str, Any] | None,
    candidate_symbols: list[dict[str, Any]] | None = None,
    candidate_binary: Any | None = None,
    candidate_modules: list[dict[str, Any]] | None = None,
    unit_contracts: dict[str, Any] | None = None,
    candidate_probe: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    source_map = _stage_b_source_map_by_function(skeleton)
    contract_functions = _stage_b_contract_functions(contract)
    candidate_by_name = {str(item.get("name") or ""): item for item in candidate_functions}
    validation_items: list[dict[str, Any]] = []
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
                validation_items.append(
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
                validation_items.append(
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
        if family_name == "binary_faithfulness":
            validation_items.extend(
                _stage_b_binary_faithfulness_repair_items(
                    family=family,
                    evidence=evidence,
                    source_map=source_map,
                    contract_functions=contract_functions,
                    candidate_functions=candidate_functions,
                    candidate_symbols=candidate_symbols,
                )
            )
            continue
        if family_name == "abi_callsites":
            validation_items.extend(
                _stage_b_abi_repair_items(
                    family=family,
                    evidence=evidence,
                    source_map=source_map,
                    candidate_symbols=candidate_symbols,
                )
            )
            continue
        validation_items.append(
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
    for item in validation_items:
        _stage_b_set_repair_item_source(item, "stage-a-contract-candidate-validation")
    items: list[dict[str, Any]] = list(validation_items)
    items.extend(_stage_b_functional_repair_items(functional, source_map))
    items.extend(_stage_b_unit_contract_repair_items(unit_contracts, source_map, validation=validation))
    items.extend(_stage_b_candidate_probe_repair_items(candidate_probe, source_map))
    items.extend(
        _stage_b_crash_repair_items(
            crash,
            candidate_functions,
            source_map,
            candidate_binary,
            candidate_modules=candidate_modules,
        )
    )
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


def _stage_b_set_repair_item_source(item: dict[str, Any], source: str) -> None:
    evidence = item.get("evidence")
    if not isinstance(evidence, dict):
        evidence = {}
        item["evidence"] = evidence
    evidence.setdefault("source", source)


def _stage_b_unit_contract_repair_items(
    unit_contracts: dict[str, Any] | None,
    source_map: dict[str, dict[str, Any]],
    *,
    validation: dict[str, Any],
) -> list[dict[str, Any]]:
    if not isinstance(unit_contracts, dict):
        return []
    if validation.get("verdict") == "pass":
        return []
    repair_units = unit_contracts.get("repair_units") if isinstance(unit_contracts.get("repair_units"), dict) else {}
    work_items = repair_units.get("work_items") if isinstance(repair_units.get("work_items"), list) else []
    satisfied_families = _stage_b_validation_satisfied_families(validation)
    items: list[dict[str, Any]] = []
    for work in work_items:
        if not isinstance(work, dict):
            continue
        family = str(work.get("family") or "unit_contract")
        if family in satisfied_families:
            continue
        if _stage_b_work_item_satisfied_by_checked_semantic_region(work, unit_contracts):
            continue
        function = _stage_b_work_item_function(work)
        items.append(
            _stage_b_repair_item(
                family=family,
                function=function,
                block_id=str(work.get("original_block") or "") or None,
                source_map=source_map,
                repair_class=str(work.get("repair_class") or "contract_guided_repair_unit"),
                next_action=str(work.get("next_action") or "repair this unit contract and re-run candidate-only delta explanation"),
                evidence={
                    "source": "stage-a-unit-contract",
                    "work_item": work,
                    "unit_contract_artifact": unit_contracts.get("artifact"),
                },
            )
        )
    has_semantic_work_items = any(
        isinstance(work, dict)
        and (
            isinstance(work.get("source_semantic_transfer"), dict)
            or isinstance(work.get("source_semantic_region"), dict)
            or isinstance(work.get("source_semantic_cluster"), dict)
        )
        for work in work_items
    )
    if not has_semantic_work_items:
        items.extend(_stage_b_semantic_contract_repair_items(unit_contracts, source_map))
    return items


def _stage_b_work_item_satisfied_by_checked_semantic_region(work: dict[str, Any], unit_contracts: dict[str, Any]) -> bool:
    if str(work.get("repair_class") or "") != "loop_or_state_machine":
        return False
    cluster = work.get("source_cluster") if isinstance(work.get("source_cluster"), dict) else {}
    if cluster.get("cluster_kind") != "abi_loop_backedge_candidate":
        return False
    evidence = cluster.get("evidence") if isinstance(cluster.get("evidence"), dict) else {}
    loop = evidence.get("loop_hint") if isinstance(evidence.get("loop_hint"), dict) else {}
    target_rva = _stage_b_int_value(loop.get("target_rva"))
    if target_rva is None:
        return False
    block_id = str(work.get("original_block") or cluster.get("block_id") or "")
    if not block_id:
        return False
    regions = unit_contracts.get("semantic_region_contracts") if isinstance(unit_contracts.get("semantic_region_contracts"), list) else []
    for region in regions:
        if not isinstance(region, dict) or region.get("status") != "checked":
            continue
        if str(region.get("block_id") or region.get("function") or "") != block_id:
            continue
        ir = region.get("ir") if isinstance(region.get("ir"), dict) else {}
        for operation in ir.get("operations", []) if isinstance(ir.get("operations"), list) else []:
            if not isinstance(operation, dict) or operation.get("op") != "direct_jump":
                continue
            if _stage_b_int_value(operation.get("target_rva")) == target_rva:
                return True
    return False


def _stage_b_validation_satisfied_families(validation: dict[str, Any]) -> set[str]:
    families = validation.get("families") if isinstance(validation.get("families"), list) else []
    result: set[str] = set()
    for family in families:
        if not isinstance(family, dict):
            continue
        name = family.get("family")
        if isinstance(name, str) and family.get("status") in {"satisfied", "not_applicable"}:
            result.add(name)
    return result


def _stage_b_semantic_contract_repair_items(
    unit_contracts: dict[str, Any],
    source_map: dict[str, dict[str, Any]],
    *,
    limit: int = 20,
) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    seen: set[str] = set()
    transfers = unit_contracts.get("semantic_transfer_contracts") if isinstance(unit_contracts.get("semantic_transfer_contracts"), list) else []
    for transfer in transfers:
        if not isinstance(transfer, dict) or transfer.get("status") in {"reimplementable", "complete"}:
            continue
        item_id = str(transfer.get("id") or "")
        if item_id in seen:
            continue
        seen.add(item_id)
        items.append(
            _stage_b_repair_item(
                family="semantic_transfer",
                function=str(transfer.get("function") or "") or None,
                block_id=str(transfer.get("block_id") or "") or None,
                source_map=source_map,
                repair_class=_stage_b_semantic_repair_class(transfer),
                next_action=str(
                    transfer.get("next_action")
                    or "complete this semantic transfer contract before expecting guided reimplementation"
                ),
                evidence={"source": "stage-a-semantic-transfer-contract", "semantic_transfer": transfer},
            )
        )
        if len(items) >= limit:
            return items
    regions = unit_contracts.get("semantic_region_contracts") if isinstance(unit_contracts.get("semantic_region_contracts"), list) else []
    for region in regions:
        if not isinstance(region, dict) or region.get("status") in {"checked", "complete"}:
            continue
        item_id = str(region.get("id") or "")
        if item_id in seen:
            continue
        seen.add(item_id)
        items.append(
            _stage_b_repair_item(
                family="semantic_region",
                function=str(region.get("function") or "") or None,
                block_id=str(region.get("block_id") or "") or None,
                source_map=source_map,
                repair_class="verified_decompiler_region_contract",
                next_action=str(region.get("next_action") or "close this selected region contract before lowering it into Stage B C"),
                evidence={"source": "stage-a-semantic-region-contract", "semantic_region": region},
            )
        )
        if len(items) >= limit:
            return items
    clusters = unit_contracts.get("cluster_semantic_contracts") if isinstance(unit_contracts.get("cluster_semantic_contracts"), list) else []
    for cluster in clusters:
        if not isinstance(cluster, dict) or cluster.get("status") in {"reimplementable", "complete"}:
            continue
        item_id = str(cluster.get("id") or "")
        if item_id in seen:
            continue
        seen.add(item_id)
        items.append(
            _stage_b_repair_item(
                family="semantic_cluster",
                function=str(cluster.get("function") or "") or None,
                block_id=str(cluster.get("block_id") or "") or None,
                source_map=source_map,
                repair_class=str(cluster.get("repair_class") or _stage_b_semantic_repair_class(cluster)),
                next_action=str(cluster.get("next_action") or "recover the missing facts for this semantic cluster"),
                evidence={"source": "stage-a-cluster-semantic-contract", "semantic_cluster": cluster},
            )
        )
        if len(items) >= limit:
            return items
    return items


def _stage_b_semantic_repair_class(row: dict[str, Any]) -> str:
    text = json.dumps(row, sort_keys=True, default=str).lower()
    if "varargs" in text or "printf" in text or "stdio" in text:
        return "varargs_or_stdio_bridge"
    if "sret" in text or "out_param" in text:
        return "hidden_sret_or_out_param"
    if "switch" in text or "jump_table" in text or "indirect_jump" in text:
        return "switch_or_jump_table_dispatch"
    if "loop" in text or "backedge" in text or "state_machine" in text:
        return "loop_or_state_machine"
    if "function_pointer" in text or "unknown_target" in text:
        return "function_pointer_target"
    if "memory" in text or "frame" in text or "alias" in text:
        return "memory_effect_mismatch"
    return "semantic_transfer_contract"


def _stage_b_candidate_probe_repair_items(
    candidate_probe: dict[str, Any] | None,
    source_map: dict[str, dict[str, Any]],
) -> list[dict[str, Any]]:
    if not isinstance(candidate_probe, dict):
        return []
    probes = candidate_probe.get("probes") if isinstance(candidate_probe.get("probes"), list) else []
    items: list[dict[str, Any]] = []
    for probe in probes:
        if not isinstance(probe, dict) or probe.get("status") in {"pass", "satisfied"}:
            continue
        function = probe.get("function") or probe.get("original_function")
        items.append(
            _stage_b_repair_item(
                family=str(probe.get("family") or "candidate_probe"),
                function=str(function) if function else None,
                block_id=str(probe.get("block_id") or probe.get("original_block") or "") or None,
                source_map=source_map,
                repair_class=str(probe.get("repair_class") or probe.get("category") or "candidate_runtime_probe"),
                next_action=str(probe.get("next_action") or "repair the candidate-only runtime probe failure; do not trace the original binary"),
                evidence={"source": "candidate-only-probe-report", "probe": probe},
            )
        )
    return items


def _stage_b_work_item_function(work: dict[str, Any]) -> str | None:
    for key in ("original_function", "function"):
        value = work.get(key)
        if isinstance(value, str) and value:
            return value
    for key in ("source_cluster", "source_gap"):
        value = work.get(key)
        if isinstance(value, dict):
            nested = value.get("function") or value.get("original_function")
            if isinstance(nested, str) and nested:
                return nested
    return None


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
        if "switch" in text or "jump_table" in text:
            return "switch_or_jump_table_dispatch"
        if "loop" in text or "state_machine" in text:
            return "loop_or_state_machine"
        if "function_pointer" in text:
            return "function_pointer_target"
        if "memory" in text or "field_access" in text:
            return "memory_effect_mismatch"
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


def _stage_b_binary_faithfulness_repair_items(
    *,
    family: dict[str, Any],
    evidence: dict[str, Any],
    source_map: dict[str, dict[str, Any]],
    contract_functions: dict[str, dict[str, Any]] | None = None,
    candidate_functions: list[dict[str, Any]] | None = None,
    candidate_symbols: list[dict[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    expected = evidence.get("expected") if isinstance(evidence.get("expected"), dict) else {}
    candidate = evidence.get("candidate") if isinstance(evidence.get("candidate"), dict) else {}
    contract_functions = contract_functions or {}
    candidate_functions = candidate_functions or []
    items: list[dict[str, Any]] = []

    header_delta = _stage_b_pe_header_delta(expected, candidate)
    if header_delta:
        items.append(
            _stage_b_repair_item(
                family="binary_faithfulness",
                function="pe-header",
                block_id=None,
                source_map=source_map,
                repair_class="pe_header_layout",
                next_action=(
                    "rebuild the candidate with matching PE header fields "
                    f"({', '.join(sorted(header_delta))}) before rerunning Stage A"
                ),
                evidence={"family": _stage_b_contract_family_summary(family), "header_delta": header_delta},
            )
        )

    expected_entry = expected.get("entrypoint_rva")
    candidate_entry = candidate.get("entrypoint_rva")
    if expected_entry != candidate_entry:
        entrypoint_delta = _stage_b_entrypoint_layout_delta(
            expected_entry=expected_entry,
            candidate_entry=candidate_entry,
            contract_functions=contract_functions,
            candidate_functions=candidate_functions,
            source_map=source_map,
        )
        items.append(
            _stage_b_repair_item(
                family="binary_faithfulness",
                function=str(entrypoint_delta.get("repair_function") or "entrypoint"),
                block_id=None,
                source_map=source_map,
                repair_class=str(entrypoint_delta.get("repair_class") or "pe_entrypoint_layout"),
                next_action=_stage_b_entrypoint_layout_next_action(entrypoint_delta),
                evidence={
                    "family": _stage_b_contract_family_summary(family),
                    "entrypoint_delta": entrypoint_delta,
                },
            )
        )

    items.extend(
        _stage_b_section_layout_repair_items(
            family,
            expected,
            candidate,
            source_map,
            candidate_symbols=candidate_symbols,
        )
    )
    import_delta = _stage_b_import_layout_delta(expected.get("imports"), candidate.get("imports"))
    if import_delta["missing"] or import_delta["extra"]:
        items.append(
            _stage_b_repair_item(
                family="binary_faithfulness",
                function="import-table",
                block_id=None,
                source_map=source_map,
                repair_class="pe_import_table_layout",
                next_action=(
                    "rebuild/link the candidate with the same imported DLL and symbol surface "
                    f"({len(import_delta['missing'])} missing, {len(import_delta['extra'])} extra)"
                ),
                evidence={"family": _stage_b_contract_family_summary(family), "import_delta": import_delta},
            )
        )

    if items:
        return items
    return [
        _stage_b_repair_item(
            family="binary_faithfulness",
            function=None,
            block_id=None,
            source_map=source_map,
            repair_class="layout_or_padding",
            next_action=str(family.get("next_action") or "inspect PE layout evidence and repair the candidate"),
            evidence={"family": family},
        )
    ]


def _stage_b_pe_header_delta(expected: dict[str, Any], candidate: dict[str, Any]) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    for key in ("machine", "bitness", "subsystem", "image_base"):
        if expected.get(key) != candidate.get(key):
            result[key] = {"expected": expected.get(key), "candidate": candidate.get(key)}
    return result


def _stage_b_entrypoint_layout_delta(
    *,
    expected_entry: Any,
    candidate_entry: Any,
    contract_functions: dict[str, dict[str, Any]],
    candidate_functions: list[dict[str, Any]],
    source_map: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    expected_rva = _stage_b_int_value(expected_entry)
    candidate_rva = _stage_b_int_value(candidate_entry)
    expected_function = _stage_b_contract_function_for_rva(contract_functions, expected_rva) or _stage_b_source_function_for_rva(source_map, expected_rva)
    candidate_function = _stage_b_candidate_function_for_rva(candidate_functions, candidate_rva)
    expected_name = _stage_b_entrypoint_function_name(expected_function)
    candidate_name = _stage_b_entrypoint_function_name(candidate_function)
    repair_function = candidate_name or expected_name or "entrypoint"
    source_location = _stage_b_source_location(source_map, repair_function)
    source_kind = source_location.get("source_kind") if isinstance(source_location, dict) else None
    repair_class = "runtime_crt_entrypoint_layout" if _stage_b_entrypoint_is_runtime_crt(repair_function, source_kind) else "pe_entrypoint_layout"
    return {
        "expected_rva": expected_entry,
        "candidate_rva": candidate_entry,
        "expected_function": expected_function,
        "candidate_function": candidate_function,
        "expected_function_name": expected_name,
        "candidate_function_name": candidate_name,
        "repair_function": repair_function,
        "repair_class": repair_class,
        "source_kind": source_kind,
    }


def _stage_b_contract_function_for_rva(
    functions: dict[str, dict[str, Any]],
    rva: int | None,
) -> dict[str, Any] | None:
    if rva is None:
        return None
    for name, function in sorted(functions.items()):
        if _stage_b_function_range_contains(function, rva):
            result = dict(function)
            result.setdefault("name", name)
            return result
    return None


def _stage_b_candidate_function_for_rva(functions: list[dict[str, Any]], rva: int | None) -> dict[str, Any] | None:
    if rva is None:
        return None
    for function in functions:
        if isinstance(function, dict) and _stage_b_function_range_contains(function, rva):
            return dict(function)
    return None


def _stage_b_source_function_for_rva(source_map: dict[str, dict[str, Any]], rva: int | None) -> dict[str, Any] | None:
    if rva is None:
        return None
    for name, location in sorted(source_map.items()):
        if not isinstance(location, dict) or not _stage_b_function_range_contains(location, rva):
            continue
        return {
            "name": name,
            "rva_start": location.get("rva_start"),
            "rva_end": location.get("rva_end"),
            "source_kind": location.get("source_kind"),
            "file": location.get("file"),
            "line_start": location.get("line_start"),
            "line_end": location.get("line_end"),
        }
    return None


def _stage_b_function_range_contains(function: dict[str, Any], rva: int) -> bool:
    start = _stage_b_int_value(function.get("rva_start"))
    end = _stage_b_int_value(function.get("rva_end"))
    if start is None or end is None:
        return False
    return start <= rva < end


def _stage_b_entrypoint_function_name(function: dict[str, Any] | None) -> str | None:
    if not isinstance(function, dict):
        return None
    name = function.get("name")
    return str(name) if isinstance(name, str) and name else None


def _stage_b_entrypoint_is_runtime_crt(function_name: str, source_kind: Any) -> bool:
    if source_kind in {"generated_runtime_bridge", "omitted_runtime_entry"}:
        return True
    return _stage_b_is_runtime_crt_bridge_function(function_name) or _stage_b_is_runtime_crt_support_function(function_name)


def _stage_b_entrypoint_layout_next_action(delta: dict[str, Any]) -> str:
    expected_rva = _stage_b_hex(delta.get("expected_rva"))
    candidate_rva = _stage_b_hex(delta.get("candidate_rva"))
    expected_name = str(delta.get("expected_function_name") or "the reference entrypoint")
    candidate_name = str(delta.get("candidate_function_name") or "the candidate entrypoint")
    if delta.get("repair_class") == "runtime_crt_entrypoint_layout":
        return (
            f"align generated runtime/CRT entrypoint {candidate_name} with reference {expected_name} at {expected_rva}; "
            f"candidate PE header currently points at {candidate_rva}; preserve the reference startup thunk/link policy before rerunning Stage A"
        )
    return (
        f"set the candidate PE entrypoint RVA to {expected_rva} or preserve the reference startup thunk layout "
        f"(candidate is {candidate_rva}) before rerunning Stage A"
    )


def _stage_b_section_layout_repair_items(
    family: dict[str, Any],
    expected: dict[str, Any],
    candidate: dict[str, Any],
    source_map: dict[str, dict[str, Any]],
    *,
    candidate_symbols: list[dict[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    expected_sections = _stage_b_sections_by_name(expected.get("sections"))
    candidate_sections = _stage_b_sections_by_name(candidate.get("sections"))
    items: list[dict[str, Any]] = []
    for name in sorted(set(expected_sections) | set(candidate_sections)):
        expected_section = expected_sections.get(name)
        candidate_section = candidate_sections.get(name)
        if expected_section is None or candidate_section is None:
            status = "missing" if expected_section is not None else "extra"
            section = expected_section if expected_section is not None else candidate_section
            items.append(
                _stage_b_repair_item(
                    family="binary_faithfulness",
                    function=f"section:{name}",
                    block_id=None,
                    source_map=source_map,
                    repair_class="pe_section_table_layout",
                    next_action=f"make candidate PE section table match the reference; section {name!r} is {status}",
                    evidence={
                        "family": _stage_b_contract_family_summary(family),
                        "section_delta": {"name": name, "status": status, "section": section},
                    },
                )
            )
            continue
        delta = _stage_b_section_span_delta(expected_section, candidate_section)
        if not delta:
            continue
        expected_span = _stage_b_section_span_text(expected_section)
        candidate_span = _stage_b_section_span_text(candidate_section)
        overflow_symbols = _stage_b_section_overflow_symbols(
            expected_section,
            candidate_section,
            candidate_symbols or [],
        )
        overflow_hint = _stage_b_section_overflow_symbol_hint(overflow_symbols)
        next_action = (
            f"adjust candidate section {name!r} to match reference span {expected_span} "
            f"and permissions (candidate is {candidate_span})"
        )
        if overflow_hint:
            next_action = f"{next_action}; {overflow_hint}"
        section_delta = {
            "name": name,
            "expected": expected_section,
            "candidate": candidate_section,
            "delta": delta,
        }
        if overflow_symbols:
            section_delta["candidate_overflow_symbols"] = overflow_symbols
        items.append(
            _stage_b_repair_item(
                family="binary_faithfulness",
                function=f"section:{name}",
                block_id=None,
                source_map=source_map,
                repair_class="pe_section_span_layout",
                next_action=next_action,
                evidence={
                    "family": _stage_b_contract_family_summary(family),
                    "section_delta": section_delta,
                },
            )
        )
    return items


def _stage_b_sections_by_name(sections: Any) -> dict[str, dict[str, Any]]:
    if not isinstance(sections, list):
        return {}
    result: dict[str, dict[str, Any]] = {}
    for section in sections:
        if not isinstance(section, dict):
            continue
        name = section.get("name")
        if isinstance(name, str) and name:
            result.setdefault(name, section)
    return result


def _stage_b_section_span_delta(expected: dict[str, Any], candidate: dict[str, Any]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key in ("rva_start", "rva_end", "executable", "readable", "writable"):
        if expected.get(key) != candidate.get(key):
            result[key] = {"expected": expected.get(key), "candidate": candidate.get(key)}
    expected_size = _stage_b_section_size(expected)
    candidate_size = _stage_b_section_size(candidate)
    if expected_size != candidate_size:
        result["size"] = {
            "expected": expected_size,
            "candidate": candidate_size,
            "delta": None if expected_size is None or candidate_size is None else candidate_size - expected_size,
        }
    return result


def _stage_b_section_size(section: dict[str, Any]) -> int | None:
    start = _stage_b_int_value(section.get("rva_start"))
    end = _stage_b_int_value(section.get("rva_end"))
    if start is None or end is None:
        return None
    return max(0, end - start)


def _stage_b_section_overflow_symbols(
    expected_section: dict[str, Any],
    candidate_section: dict[str, Any],
    candidate_symbols: list[dict[str, Any]],
    *,
    limit: int = 12,
) -> list[dict[str, Any]]:
    expected_end = _stage_b_int_value(expected_section.get("rva_end"))
    candidate_end = _stage_b_int_value(candidate_section.get("rva_end"))
    section_name = str(candidate_section.get("name") or "")
    if expected_end is None or candidate_end is None or candidate_end <= expected_end or not section_name:
        return []
    result: list[dict[str, Any]] = []
    for symbol in candidate_symbols:
        if not isinstance(symbol, dict) or str(symbol.get("section") or "") != section_name:
            continue
        rva = _stage_b_int_value(symbol.get("rva"))
        if rva is None or rva < expected_end or rva >= candidate_end:
            continue
        result.append(_stage_b_candidate_symbol_summary(symbol))
        if len(result) >= limit:
            break
    return result


def _stage_b_section_overflow_symbol_hint(symbols: list[dict[str, Any]]) -> str:
    if not symbols:
        return ""
    names = []
    for symbol in symbols[:4]:
        if not isinstance(symbol, dict):
            continue
        name = str(symbol.get("name") or "")
        rva = _stage_b_hex(symbol.get("rva"))
        if name:
            names.append(f"{name} at {rva}")
    if not names:
        return ""
    return "first candidate symbols in the overflowing tail: " + ", ".join(names)


def _stage_b_section_span_text(section: dict[str, Any]) -> str:
    return f"{_stage_b_hex(section.get('rva_start'))}-{_stage_b_hex(section.get('rva_end'))}"


def _stage_b_import_layout_delta(expected: Any, candidate: Any) -> dict[str, list[dict[str, Any]]]:
    expected_by_key = _stage_b_imports_by_key(expected)
    candidate_by_key = _stage_b_imports_by_key(candidate)
    return {
        "missing": [expected_by_key[key] for key in sorted(set(expected_by_key) - set(candidate_by_key))],
        "extra": [candidate_by_key[key] for key in sorted(set(candidate_by_key) - set(expected_by_key))],
    }


def _stage_b_imports_by_key(imports: Any) -> dict[tuple[str, str], dict[str, Any]]:
    if not isinstance(imports, list):
        return {}
    result: dict[tuple[str, str], dict[str, Any]] = {}
    for imported in imports:
        if not isinstance(imported, dict):
            continue
        result.setdefault(_stage_b_import_layout_key(imported), imported)
    return result


def _stage_b_import_layout_key(imported: dict[str, Any]) -> tuple[str, str]:
    dll = str(imported.get("dll") or "").lower()
    symbol = imported.get("symbol")
    if symbol not in {None, ""}:
        return (dll, str(symbol))
    ordinal = imported.get("ordinal")
    return (dll, f"#{ordinal}" if ordinal not in {None, ""} else "")


def _stage_b_int_value(value: Any) -> int | None:
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


def _stage_b_hex(value: Any) -> str:
    numeric = _stage_b_int_value(value)
    if numeric is None:
        return str(value)
    return f"0x{numeric:x}"


def _stage_b_parse_linker_map_symbols(path: Path, binary: StageABinary) -> list[dict[str, Any]]:
    try:
        text = Path(path).read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    symbols: list[dict[str, Any]] = []
    seen: set[tuple[int, str, str]] = set()
    pending_section_fragment: str | None = None
    for line in text.splitlines():
        fragment = _stage_b_linker_map_fragment_symbol_line(line, binary)
        if fragment is not None:
            _stage_b_append_linker_map_symbol(symbols, seen, fragment)
            pending_section_fragment = None
            continue
        continuation = _stage_b_linker_map_fragment_continuation_line(line, binary, pending_section_fragment)
        if continuation is not None:
            _stage_b_append_linker_map_symbol(symbols, seen, continuation)
            pending_section_fragment = None
            continue
        section_fragment = _stage_b_linker_map_section_fragment_name(line)
        if section_fragment is not None:
            pending_section_fragment = section_fragment
            continue
        symbol = _stage_b_linker_map_symbol_line(line, binary)
        if symbol is not None:
            _stage_b_append_linker_map_symbol(symbols, seen, symbol)
            pending_section_fragment = None
            continue
        if line.strip():
            pending_section_fragment = None
    return sorted(symbols, key=lambda item: (int(item.get("rva") or 0), str(item.get("name") or "")))


def _stage_b_append_linker_map_symbol(
    symbols: list[dict[str, Any]],
    seen: set[tuple[int, str, str]],
    symbol: dict[str, Any],
) -> None:
    key = (int(symbol["rva"]), str(symbol["name"]), str(symbol.get("source") or ""))
    if key in seen:
        return
    seen.add(key)
    symbols.append(symbol)


def _stage_b_linker_map_symbol_line(line: str, binary: StageABinary) -> dict[str, Any] | None:
    match = re.match(r"^\s*(0x[0-9a-fA-F]+)\s+([A-Za-z_.$@?][A-Za-z0-9_.$@?~-]*)\s*$", line)
    if match is None:
        return None
    name = match.group(2)
    if name.startswith(".") or name in {"PROVIDE", "CREATE_OBJECT_SYMBOLS"}:
        return None
    rva = _stage_b_linker_map_address_to_rva(int(match.group(1), 16), binary)
    return _stage_b_linker_map_symbol_record(binary=binary, rva=rva, name=name, source="symbol")


def _stage_b_linker_map_fragment_symbol_line(line: str, binary: StageABinary) -> dict[str, Any] | None:
    match = re.match(r"^\s*(\.[A-Za-z0-9_.$@?+-]+)\s+(0x[0-9a-fA-F]+)\s+(0x[0-9a-fA-F]+)\b", line)
    if match is None:
        return None
    name = _stage_b_linker_map_section_fragment_name_from_section(match.group(1))
    if name is None:
        return None
    rva = _stage_b_linker_map_address_to_rva(int(match.group(2), 16), binary)
    return _stage_b_linker_map_symbol_record(
        binary=binary,
        rva=rva,
        name=name,
        source="section_fragment",
        size=int(match.group(3), 16),
    )


def _stage_b_linker_map_fragment_continuation_line(
    line: str,
    binary: StageABinary,
    fragment_name: str | None,
) -> dict[str, Any] | None:
    if fragment_name is None:
        return None
    match = re.match(r"^\s*(0x[0-9a-fA-F]+)\s+(0x[0-9a-fA-F]+)\b", line)
    if match is None:
        return None
    rva = _stage_b_linker_map_address_to_rva(int(match.group(1), 16), binary)
    return _stage_b_linker_map_symbol_record(
        binary=binary,
        rva=rva,
        name=fragment_name,
        source="section_fragment",
        size=int(match.group(2), 16),
    )


def _stage_b_linker_map_section_fragment_name(line: str) -> str | None:
    match = re.match(r"^\s*(\.[A-Za-z0-9_.$@?+-]+)\s*$", line)
    if match is None:
        return None
    return _stage_b_linker_map_section_fragment_name_from_section(match.group(1))


def _stage_b_linker_map_section_fragment_name_from_section(section_name: str) -> str | None:
    if "$" not in section_name:
        return None
    fragment = section_name.split("$", 1)[1].strip()
    if not fragment or fragment.startswith("."):
        return None
    return fragment


def _stage_b_linker_map_address_to_rva(address: int, binary: StageABinary) -> int:
    return address - binary.image_base if address >= binary.image_base else address


def _stage_b_linker_map_symbol_record(
    *,
    binary: StageABinary,
    rva: int,
    name: str,
    source: str,
    size: int | None = None,
) -> dict[str, Any] | None:
    section = _section_for_rva(binary, rva)
    if section is None:
        return None
    record: dict[str, Any] = {
        "name": name,
        "rva": rva,
        "rva_hex": f"0x{rva:x}",
        "section": section.name,
        "section_rva_start": int(section.rva_start),
        "section_rva_end": int(section.rva_end),
        "source": source,
    }
    if size is not None:
        record["size"] = size
        record["rva_end"] = min(int(section.rva_end), rva + max(0, size))
    return record


def _stage_b_abi_repair_items(
    *,
    family: dict[str, Any],
    evidence: dict[str, Any],
    source_map: dict[str, dict[str, Any]],
    candidate_symbols: list[dict[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    reference_counts = evidence.get("reference_counts") if isinstance(evidence.get("reference_counts"), dict) else {}
    candidate_counts = evidence.get("candidate_counts") if isinstance(evidence.get("candidate_counts"), dict) else {}
    missing_functions = max(0, int(reference_counts.get("functions") or 0) - int(candidate_counts.get("functions") or 0))
    missing_callsites = max(0, int(reference_counts.get("callsites") or 0) - int(candidate_counts.get("callsites") or 0))
    coverage_gaps = evidence.get("coverage_gaps") if isinstance(evidence.get("coverage_gaps"), dict) else {}
    coverage_gap_counts = coverage_gaps.get("counts") if isinstance(coverage_gaps.get("counts"), dict) else {}
    items: list[dict[str, Any]] = []
    items.extend(_stage_b_abi_coverage_gap_items(evidence, source_map, candidate_symbols=candidate_symbols))
    if missing_functions or missing_callsites:
        named_missing_functions = coverage_gap_counts.get("missing_functions")
        partial_callsite_functions = coverage_gap_counts.get("incomplete_callsite_functions")
        named_missing_callsites = coverage_gap_counts.get("missing_callsites")
        if int(named_missing_functions or 0) == 0 and int(named_missing_callsites or 0) > 0:
            next_action = (
                f"recover ABI callsite coverage gaps: {named_missing_callsites} missing callsites"
                f" across {partial_callsite_functions if partial_callsite_functions is not None else 'unknown'} partially matched functions"
                f" (raw count deficit: {missing_functions} functions, {missing_callsites} callsites); "
                "start with functions that have missing callsites or mismatched call targets, then rerun Stage A contract validation"
            )
        else:
            next_action = (
                f"recover ABI coverage gaps: {named_missing_functions if named_missing_functions is not None else missing_functions} named missing functions"
                f" and {named_missing_callsites if named_missing_callsites is not None else missing_callsites} missing callsites"
                f" across {partial_callsite_functions if partial_callsite_functions is not None else 'unknown'} partially matched functions"
                f" (raw count deficit: {missing_functions} functions, {missing_callsites} callsites); "
                "start with missing linker-root/function coverage, then rerun Stage A contract validation"
            )
        items.append(
            _stage_b_repair_item(
                family="abi_callsites",
                function=None,
                block_id=None,
                source_map=source_map,
                repair_class="abi_callsite_coverage",
                next_action=next_action,
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
    candidate_symbols: list[dict[str, Any]] | None = None,
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
        for signature_item in _stage_b_missing_callsite_signature_items(sample):
            candidate_context = _stage_b_missing_callsite_signature_candidate_context(
                signature_item,
                candidate_symbols or [],
            )
            item_evidence = {"coverage_gap": sample, "missing_callsite_signature": signature_item}
            if candidate_context is not None:
                item_evidence["candidate_memory_context"] = candidate_context
            items.append(
                _stage_b_repair_item(
                    family="abi_callsites",
                    function=name,
                    block_id=_stage_b_missing_callsite_signature_block_id(signature_item),
                    source_map=source_map,
                    repair_class=_stage_b_missing_callsite_signature_repair_class(signature_item),
                    next_action=_stage_b_missing_callsite_signature_next_action(
                        name,
                        signature_item,
                        candidate_context=candidate_context,
                    ),
                    evidence=item_evidence,
                )
            )
            if len(items) >= limit:
                return items
        items.append(
            _stage_b_repair_item(
                family="abi_callsites",
                function=name,
                block_id=None,
                source_map=source_map,
                repair_class=_stage_b_missing_callsite_repair_class(sample),
                next_action=_stage_b_missing_callsite_next_action(name, sample),
                evidence={"coverage_gap": sample},
            )
        )
        if len(items) >= limit:
            return items

    for key, default_repair_class in (
        ("callsite_mismatches", "abi_callsite_mismatch"),
        ("function_mismatches", "abi_function_contract_mismatch"),
    ):
        samples = coverage_gaps.get(key) if isinstance(coverage_gaps.get(key), list) else []
        for sample in samples:
            if not isinstance(sample, dict):
                continue
            name = sample.get("name")
            if not isinstance(name, str) or not name:
                continue
            items.append(
                _stage_b_repair_item(
                    family="abi_callsites",
                    function=name,
                    block_id=str(sample.get("block_id") or "") or None,
                    source_map=source_map,
                    repair_class=str(sample.get("repair_class") or default_repair_class),
                    next_action=str(sample.get("next_action") or "repair this ABI contract mismatch and rerun Stage A contract validation"),
                    evidence={"coverage_gap": sample},
                )
            )
            if len(items) >= limit:
                return items
    return items


def _stage_b_missing_callsite_signature_items(sample: dict[str, Any]) -> list[dict[str, Any]]:
    signatures = sample.get("missing_callsite_signatures")
    if not isinstance(signatures, list) or not signatures:
        signature_delta = sample.get("callsite_signature_delta") if isinstance(sample.get("callsite_signature_delta"), dict) else {}
        signatures = signature_delta.get("reference_only")
        if not isinstance(signatures, list) or not signatures:
            signatures = signature_delta.get("unmatched_reference_signatures")
    if not isinstance(signatures, list):
        return []
    return [item for item in signatures if isinstance(item, dict)]


def _stage_b_missing_callsite_signature_block_id(signature_item: dict[str, Any]) -> str | None:
    callsite = _stage_b_missing_callsite_signature_example_callsite(signature_item)
    block_id = callsite.get("block_id") if isinstance(callsite, dict) else None
    return str(block_id) if isinstance(block_id, str) and block_id else None


def _stage_b_missing_callsite_signature_repair_class(signature_item: dict[str, Any]) -> str:
    signature = signature_item.get("signature") if isinstance(signature_item.get("signature"), dict) else {}
    target = signature.get("target") if isinstance(signature.get("target"), dict) else {}
    if target.get("kind") == "function_pointer":
        return "function_pointer_callsite_coverage"
    if target.get("kind") == "direct":
        return "call_target_mismatch"
    return "abi_callsite_signature_coverage"


def _stage_b_missing_callsite_signature_next_action(
    name: str,
    signature_item: dict[str, Any],
    *,
    candidate_context: dict[str, Any] | None = None,
) -> str:
    missing = signature_item.get("missing")
    if missing not in {None, ""}:
        signature_text = f"{missing} missing callsite signature{'s' if missing != 1 else ''}"
    else:
        signature_text = "missing callsite signature"
    action = f"recover {signature_text} for {name}; preserve the target and argument shape, then rerun Stage A contract validation"
    hint = _stage_b_missing_callsite_signature_hint({"missing_callsite_signatures": [signature_item]})
    context_hint = _stage_b_candidate_memory_context_hint(candidate_context)
    hints = [item for item in (hint, context_hint) if item]
    return f"{action}; {'; '.join(hints)}" if hints else action


def _stage_b_missing_callsite_signature_candidate_context(
    signature_item: dict[str, Any],
    candidate_symbols: list[dict[str, Any]],
) -> dict[str, Any] | None:
    signature = signature_item.get("signature") if isinstance(signature_item.get("signature"), dict) else {}
    target = signature.get("target") if isinstance(signature.get("target"), dict) else {}
    if target.get("kind") != "function_pointer":
        return None
    memory_rva = _stage_b_int_value(target.get("memory_rva"))
    if memory_rva is None:
        return None
    symbols = [item for item in candidate_symbols if isinstance(item, dict) and _stage_b_int_value(item.get("rva")) is not None]
    exact = [_stage_b_candidate_symbol_summary(item) for item in symbols if _stage_b_int_value(item.get("rva")) == memory_rva]
    covering = [
        _stage_b_candidate_symbol_summary(item)
        for item in symbols
        if _stage_b_symbol_covers_rva(item, memory_rva) and _stage_b_int_value(item.get("rva")) != memory_rva
    ]
    before = [
        item
        for item in symbols
        if (symbol_rva := _stage_b_int_value(item.get("rva"))) is not None and symbol_rva < memory_rva
    ]
    after = [
        item
        for item in symbols
        if (symbol_rva := _stage_b_int_value(item.get("rva"))) is not None and symbol_rva > memory_rva
    ]
    before.sort(key=lambda item: int(_stage_b_int_value(item.get("rva")) or 0), reverse=True)
    after.sort(key=lambda item: int(_stage_b_int_value(item.get("rva")) or 0))
    context: dict[str, Any] = {
        "memory_rva": memory_rva,
        "memory_rva_hex": f"0x{memory_rva:x}",
        "symbols_at_rva": exact[:8],
        "covering_symbols": covering[:8],
        "nearest_before": [_stage_b_candidate_symbol_summary(item) for item in before[:3]],
        "nearest_after": [_stage_b_candidate_symbol_summary(item) for item in after[:3]],
    }
    return context


def _stage_b_candidate_symbol_summary(symbol: dict[str, Any]) -> dict[str, Any]:
    result = {
        "name": str(symbol.get("name") or ""),
        "rva": _stage_b_int_value(symbol.get("rva")),
        "rva_hex": _stage_b_hex(symbol.get("rva")),
        "section": str(symbol.get("section") or ""),
        "source": str(symbol.get("source") or ""),
    }
    if symbol.get("size") is not None:
        result["size"] = _stage_b_int_value(symbol.get("size"))
    if symbol.get("rva_end") is not None:
        result["rva_end"] = _stage_b_int_value(symbol.get("rva_end"))
        result["rva_end_hex"] = _stage_b_hex(symbol.get("rva_end"))
    return result


def _stage_b_symbol_covers_rva(symbol: dict[str, Any], rva: int) -> bool:
    start = _stage_b_int_value(symbol.get("rva"))
    end = _stage_b_int_value(symbol.get("rva_end"))
    return start is not None and end is not None and start <= rva < end


def _stage_b_candidate_memory_context_hint(candidate_context: dict[str, Any] | None) -> str:
    if not isinstance(candidate_context, dict):
        return ""
    rva_hex = str(candidate_context.get("memory_rva_hex") or _stage_b_hex(candidate_context.get("memory_rva")))
    symbols = candidate_context.get("symbols_at_rva") if isinstance(candidate_context.get("symbols_at_rva"), list) else []
    symbol = symbols[0] if symbols and isinstance(symbols[0], dict) else None
    if symbol is None:
        covering = candidate_context.get("covering_symbols") if isinstance(candidate_context.get("covering_symbols"), list) else []
        symbol = covering[0] if covering and isinstance(covering[0], dict) else None
    if symbol is None:
        before = candidate_context.get("nearest_before") if isinstance(candidate_context.get("nearest_before"), list) else []
        after = candidate_context.get("nearest_after") if isinstance(candidate_context.get("nearest_after"), list) else []
        neighbors = [
            str(item.get("name") or "")
            for item in (before[:1] + after[:1])
            if isinstance(item, dict) and item.get("name")
        ]
        if neighbors:
            return f"candidate RVA {rva_hex} has no exact symbol; nearest candidate map symbols are {', '.join(neighbors)}"
        return f"candidate RVA {rva_hex} has no symbol in the candidate linker map"
    section = str(symbol.get("section") or "unknown section")
    name = str(symbol.get("name") or "unnamed symbol")
    return (
        f"candidate RVA {rva_hex} currently maps to {section} symbol {name}; "
        "preserve or relocate the reference global function-pointer slot instead of compiling this call as a direct call"
    )


def _stage_b_missing_callsite_signature_example_callsite(signature_item: dict[str, Any]) -> dict[str, Any]:
    examples = signature_item.get("reference_examples") if isinstance(signature_item.get("reference_examples"), list) else []
    example = examples[0] if examples and isinstance(examples[0], dict) else {}
    callsite = example.get("callsite") if isinstance(example.get("callsite"), dict) else {}
    return callsite if isinstance(callsite, dict) else {}


def _stage_b_missing_callsite_next_action(name: str, sample: dict[str, Any]) -> str:
    action = (
        f"recover {sample.get('missing_callsites')} missing generated callsites for {name}; "
        "preserve call instructions and rerun Stage A contract validation"
    )
    hint = _stage_b_missing_callsite_signature_hint(sample)
    return f"{action}; {hint}" if hint else action


def _stage_b_missing_callsite_repair_class(sample: dict[str, Any]) -> str:
    signature = _stage_b_first_missing_callsite_signature(sample)
    target = signature.get("target") if isinstance(signature.get("target"), dict) else {}
    if target.get("kind") == "function_pointer":
        return "function_pointer_callsite_coverage"
    if target.get("kind") == "direct":
        return "call_target_mismatch"
    return "abi_callsite_function_coverage"


def _stage_b_missing_callsite_signature_hint(sample: dict[str, Any]) -> str:
    signature_item = _stage_b_first_missing_callsite_signature_item(sample)
    first = signature_item if isinstance(signature_item, dict) else {}
    if not first:
        return ""
    signature = first.get("signature") if isinstance(first.get("signature"), dict) else {}
    parts: list[str] = []
    signature_id = first.get("signature_id")
    if isinstance(signature_id, str) and signature_id:
        parts.append(signature_id)
    target_hint = _stage_b_callsite_target_signature_hint(signature.get("target"))
    if target_hint:
        parts.append(f"target {target_hint}")
    inventory = signature.get("argument_inventory") if isinstance(signature.get("argument_inventory"), dict) else {}
    if inventory.get("argument_count") is not None:
        parts.append(f"{inventory.get('argument_count')} args")
    argument_hint = _stage_b_callsite_argument_signature_hint(inventory)
    if argument_hint:
        parts.append(argument_hint)
    preservation_hint = _stage_b_callsite_preservation_signature_hint(signature)
    if preservation_hint:
        parts.append(preservation_hint)
    examples = first.get("reference_examples") if isinstance(first.get("reference_examples"), list) else []
    example = examples[0] if examples and isinstance(examples[0], dict) else {}
    callsite = example.get("callsite") if isinstance(example.get("callsite"), dict) else {}
    if isinstance(callsite.get("id"), str) and callsite.get("id"):
        parts.append(f"example {callsite.get('id')}")
    if not parts:
        return ""
    return "first missing signature: " + ", ".join(parts)


def _stage_b_first_missing_callsite_signature(sample: dict[str, Any]) -> dict[str, Any]:
    item = _stage_b_first_missing_callsite_signature_item(sample)
    return item.get("signature") if isinstance(item.get("signature"), dict) else {}


def _stage_b_first_missing_callsite_signature_item(sample: dict[str, Any]) -> dict[str, Any]:
    signatures = sample.get("missing_callsite_signatures")
    if not isinstance(signatures, list) or not signatures:
        signature_delta = sample.get("callsite_signature_delta") if isinstance(sample.get("callsite_signature_delta"), dict) else {}
        signatures = signature_delta.get("unmatched_reference_signatures")
        if not isinstance(signatures, list) or not signatures:
            signatures = signature_delta.get("reference_only") if isinstance(signature_delta.get("reference_only"), list) else []
    first = signatures[0] if signatures and isinstance(signatures[0], dict) else {}
    return first if isinstance(first, dict) else {}


def _stage_b_callsite_argument_signature_hint(inventory: dict[str, Any]) -> str:
    stack_args = inventory.get("stack_args") if isinstance(inventory.get("stack_args"), list) else []
    hints: list[str] = []
    for argument in stack_args[:4]:
        if not isinstance(argument, dict):
            continue
        index = argument.get("index")
        source = argument.get("source") if isinstance(argument.get("source"), dict) else {}
        if source.get("value") is not None:
            hints.append(f"arg{index}={source.get('value')}")
    return " ".join(hints)


def _stage_b_callsite_preservation_signature_hint(signature: dict[str, Any]) -> str:
    target = signature.get("target") if isinstance(signature.get("target"), dict) else {}
    if target.get("kind") != "function_pointer":
        return ""
    operand = str(target.get("operand") or "")
    memory_role = str(target.get("memory_role") or "")
    if "esp" in operand or memory_role == "stack_pointer_slot":
        slot = operand or memory_role
        return f"preserve indirect stack-slot call {slot}; prevent compiler folding to a direct call"
    if memory_role == "global_writable_pointer_slot":
        return "preserve indirect global-slot call; prevent compiler folding to a direct call"
    return "preserve indirect function-pointer call shape"


def _stage_b_callsite_target_signature_hint(target: Any) -> str:
    if not isinstance(target, dict) or not target:
        return ""
    kind = target.get("kind")
    if kind == "import":
        symbol = str(target.get("symbol") or "")
        ordinal = str(target.get("ordinal") or "")
        name = symbol or (f"ordinal:{ordinal}" if ordinal else "")
        dll = str(target.get("dll") or "")
        return f"import {dll}!{name}" if dll or name else "import"
    if kind == "direct":
        keys = target.get("resolved_match_keys") if isinstance(target.get("resolved_match_keys"), list) else []
        if keys:
            return "direct " + "/".join(str(item) for item in keys[:3])
        if target.get("target_rva") is not None:
            return f"direct rva {target.get('target_rva')}"
        return "direct"
    if kind == "function_pointer":
        role = target.get("operand") or target.get("memory_role") or target.get("register") or ""
        return f"function pointer {role}".strip()
    return str(kind or "")


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
        if _stage_b_is_runtime_crt_support_function(function_name):
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
        "runtime_crt_stack_bridge": "verify generated runtime/CRT support implementation, bridge, and linker policy for this stack out-param helper",
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
    if _stage_b_is_stack_probe_function(function_name):
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


def _stage_b_is_stack_probe_function(function_name: str) -> bool:
    key = _linker_function_match_key(function_name).lower()
    return key in {"chkstk", "chkstk_ms", "alloca_probe", "alloca_probe_8", "alloca_probe_16"} or key.startswith("chkstk_")


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
    entry_function = _stage_b_functional_entry_function(functional, source_map)
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


def _stage_b_functional_entry_function(
    functional: dict[str, Any], source_map: dict[str, dict[str, Any]]
) -> str | None:
    declared = functional.get("entry_function_candidates")
    preferred = (
        [str(item) for item in declared if isinstance(item, str) and item]
        if isinstance(declared, list)
        else ["main", "entrypoint"]
    )
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
    hint = case.get("repair_class_hint")
    if isinstance(hint, str) and hint:
        return hint
    if bool(candidate.get("timed_out")) or fields.intersection({"timed_out", "timeout"}):
        return "candidate_timeout"
    if "stderr" in fields:
        return "stderr_behavior"
    if "stdout" in fields:
        return "stdout_behavior"
    if "returncode" in fields:
        return "cli_exit_status_behavior"
    return "functional_expected_output_failure"


def _stage_b_functional_case_next_action(functional: dict[str, Any], case: dict[str, Any], repair_class: str) -> str:
    case_id = case.get("id")
    target_name = str(functional.get("target_name") or "candidate")
    actions = {
        "candidate_timeout": "repair candidate termination or long-running control flow",
        "stderr_behavior": "recover diagnostic/stderr behavior for this public expected-output case",
        "stdout_behavior": "recover stdout-producing behavior for this public expected-output case",
        "short_option_state_machine": "repair generated short-option parsing and command dispatch for this case",
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
    *,
    candidate_modules: list[dict[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    if not isinstance(crash, dict):
        return []
    if str(crash.get("status") or "").lower() not in {"detected", "crash", "failed"}:
        return []
    modules = _stage_b_crash_candidate_modules(
        candidate_functions=candidate_functions,
        source_map=source_map,
        candidate_binary=candidate_binary,
        candidate_modules=candidate_modules,
    )
    location = _stage_b_candidate_crash_location(crash, modules)
    location_module = _stage_b_crash_location_module(location, modules)
    fault_context = _stage_b_candidate_fault_context_location(crash, modules)
    module_functions = (
        location_module.get("functions")
        if isinstance(location_module, dict) and isinstance(location_module.get("functions"), list)
        else candidate_functions
    )
    module_source_map = (
        location_module.get("source_map")
        if isinstance(location_module, dict) and isinstance(location_module.get("source_map"), dict)
        else source_map
    )
    fault_rva = location.get("rva")
    function = _stage_b_function_for_rva(module_functions, fault_rva) if isinstance(fault_rva, int) else None
    register_context = None
    if function is None:
        register_context = _stage_b_candidate_register_context_location(crash, modules)
        if register_context is not None:
            register_module = _stage_b_crash_location_module(register_context, modules)
            if isinstance(register_module, dict):
                register_functions = register_module.get("functions") if isinstance(register_module.get("functions"), list) else []
                register_rva = register_context.get("rva")
                register_function = _stage_b_function_for_rva(register_functions, register_rva) if isinstance(register_rva, int) else None
                if register_function is not None:
                    function = register_function
                    location["candidate_register_context"] = register_context
                    module_source_map = (
                        register_module.get("source_map")
                        if isinstance(register_module.get("source_map"), dict)
                        else source_map
                    )
        if function is None and fault_context is not None:
            fault_module = _stage_b_crash_location_module(fault_context, modules)
            if isinstance(fault_module, dict):
                fault_functions = fault_module.get("functions") if isinstance(fault_module.get("functions"), list) else []
                fault_rva = fault_context.get("rva")
                fault_function = _stage_b_function_for_rva(fault_functions, fault_rva) if isinstance(fault_rva, int) else None
                if fault_function is not None:
                    function = fault_function
                    location["candidate_fault_context"] = fault_context
                    module_source_map = (
                        fault_module.get("source_map")
                        if isinstance(fault_module.get("source_map"), dict)
                        else source_map
                    )
    if function is not None:
        repair_class = "stack_delta_mismatch"
        module_name = ""
        if isinstance(location.get("module"), dict) and location["module"].get("name"):
            module_name = f" in {location['module']['name']}"
        next_action = f"inspect the candidate-only crash report and repair the mapped generated source span{module_name}"
        text = json.dumps(crash, sort_keys=True, default=str).lower()
        source_location = _stage_b_source_location(module_source_map, function)
        source_kind = source_location.get("source_kind") if isinstance(source_location, dict) else None
        if register_context is not None:
            if source_kind == "omitted_runtime_helper":
                repair_class = "runtime_crt_tls_callback_context"
                next_action = (
                    "candidate-only SEH context has a register pointing into an omitted MinGW runtime helper; "
                    "verify TLS callback/runtime-helper link policy, callback tables, and CRT-owned roots before "
                    "treating this as decompiled application logic"
                )
            else:
                repair_class = "candidate_crash_register_context"
                next_action = (
                    "candidate-only SEH context has a register pointing into this generated function; inspect "
                    "callback, import-thunk, TLS, or ABI state that could hand Wine an invalid runtime pointer"
                )
        elif fault_context is not None and "candidate_fault_context" in location:
            repair_class = "candidate_crash_fault_address_context"
            next_action = (
                "candidate-only crash fault address points into this generated function; inspect ABI, import, "
                "stdio, callback, or out-param state that could hand an external runtime an invalid candidate pointer"
            )
        elif _stage_b_is_stack_probe_function(function):
            repair_class = "stack_probe_or_frame_layout"
            next_action = (
                "repair generated stack-frame size, stack-probe helper linkage, or PE stack/layout before "
                "treating this as a source-level ABI fix"
            )
        elif _stage_b_crash_looks_like_stack_scratch_fault(crash):
            repair_class = "stack_scratch_buffer_or_out_param"
            next_action = (
                "repair the generated local stack scratch/allocation rewrite or recovered out-param for the "
                "source-mapped function"
            )
        elif "realloc" in text:
            repair_class = "hidden_sret_or_out_param"
    elif fault_context is not None:
        repair_class = "candidate_crash_fault_address_context"
        next_action = (
            "candidate crash PC is outside the candidate image, but the fault address points into the candidate image; "
            "inspect ABI/import/stdio pointer recovery and generated read-only data handoff before treating the external "
            "runtime as the cause"
        )
        location["candidate_fault_context"] = fault_context
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
            source_map=module_source_map,
            repair_class=repair_class,
            next_action=next_action,
            evidence={"crash": crash, "candidate_location": location},
        )
    ]


def _stage_b_crash_candidate_modules(
    *,
    candidate_functions: list[dict[str, Any]],
    source_map: dict[str, dict[str, Any]],
    candidate_binary: Any | None,
    candidate_modules: list[dict[str, Any]] | None,
) -> list[dict[str, Any]]:
    modules = [
        {
            "name": "candidate",
            "role": "primary_candidate",
            "image": _stage_b_candidate_image_range(candidate_binary),
            "functions": candidate_functions,
            "source_map": source_map,
        }
    ]
    for index, module in enumerate(candidate_modules or []):
        modules.append(_stage_b_normalize_crash_candidate_module(module, index))
    return modules


def _stage_b_normalize_crash_candidate_module(module: dict[str, Any], index: int) -> dict[str, Any]:
    name = str(module.get("name") or Path(str(module.get("path") or "")).name or f"candidate-module-{index}")
    image = module.get("image")
    if not isinstance(image, dict):
        image = _stage_b_candidate_image_range(module.get("candidate_binary") or module.get("binary"))
    functions = module.get("functions") or module.get("candidate_functions") or []
    if not isinstance(functions, list):
        functions = []
    source_map = _stage_b_normalize_candidate_module_source_map(module.get("source_map") or module.get("skeleton"))
    return {
        "name": name,
        "role": str(module.get("role") or "candidate_module"),
        "path": str(module.get("path") or ""),
        "image": image,
        "functions": functions,
        "source_map": source_map,
    }


def _stage_b_normalize_candidate_module_source_map(value: Any) -> dict[str, dict[str, Any]]:
    if isinstance(value, dict) and isinstance(value.get("source_map"), dict):
        return _stage_b_source_map_by_function(value)
    if isinstance(value, dict):
        normalized: dict[str, dict[str, Any]] = {}
        for key, location in value.items():
            if isinstance(key, str) and isinstance(location, dict):
                normalized[key] = location
                normalized.setdefault(_linker_function_match_key(key), location)
        return normalized
    return {}


def _stage_b_crash_location_module(location: dict[str, Any], modules: list[dict[str, Any]]) -> dict[str, Any] | None:
    index = location.get("module_index")
    if isinstance(index, int) and 0 <= index < len(modules):
        return modules[index]
    return None


def _stage_b_candidate_register_context_location(crash: dict[str, Any], modules: list[dict[str, Any]]) -> dict[str, Any] | None:
    seh = crash.get("seh_exception") if isinstance(crash.get("seh_exception"), dict) else {}
    registers = seh.get("registers") if isinstance(seh.get("registers"), dict) else {}
    for register_name in ("eip", "eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp"):
        value = _optional_crash_address_int(registers.get(register_name))
        if value is None:
            continue
        location = _stage_b_candidate_location_for_pc(value, modules)
        if location is None:
            continue
        location["classification"] = "candidate_seh_register"
        location["register"] = register_name
        location["value"] = _stage_b_prefixed_hex(registers.get(register_name))
        return location
    return None


def _stage_b_candidate_fault_context_location(crash: dict[str, Any], modules: list[dict[str, Any]]) -> dict[str, Any] | None:
    seh = crash.get("seh_exception") if isinstance(crash.get("seh_exception"), dict) else {}
    info = seh.get("info") if isinstance(seh.get("info"), dict) else {}
    for address in (
        crash.get("fault_address"),
        seh.get("fault_address"),
        info.get("1"),
    ):
        value = _optional_crash_address_int(address)
        if value is None:
            continue
        location = _stage_b_candidate_location_for_pc(value, modules)
        if location is None:
            continue
        location["classification"] = "candidate_fault_address"
        location["fault_address"] = _stage_b_prefixed_hex(address)
        return location
    return None


def _stage_b_crash_looks_like_stack_scratch_fault(crash: dict[str, Any]) -> bool:
    access = str(crash.get("access") or "").lower()
    kind = str(crash.get("crash_kind") or "").lower()
    text = json.dumps(crash, sort_keys=True, default=str).lower()
    if "stack" in text or "esp" in text:
        return True
    if access == "write" and kind == "wine_unhandled_page_fault":
        return True
    return False


def _stage_b_candidate_crash_location(crash: dict[str, Any], modules: list[dict[str, Any]]) -> dict[str, Any]:
    explicit_rva = _optional_crash_address_int(crash.get("exception_rva") or crash.get("instruction_rva") or crash.get("fault_rva"))
    if explicit_rva is not None:
        return {
            "classification": "candidate_rva_explicit",
            "rva": explicit_rva,
            "candidate_image": _stage_b_primary_candidate_image(modules),
            "module_index": 0,
            "module": _stage_b_crash_module_summary(modules, 0),
        }
    pc = _optional_crash_address_int(
        crash.get("instruction_address")
        or crash.get("exception_address")
        or crash.get("program_counter")
        or crash.get("pc")
    )
    if pc is not None:
        location = _stage_b_candidate_location_for_pc(pc, modules)
        if location is not None:
            return location
    for frame_index, frame in enumerate(_stage_b_crash_frames(crash)):
        location = _stage_b_candidate_location_for_frame(frame, modules)
        if location is not None:
            location["classification"] = "candidate_backtrace_frame"
            location["frame_index"] = frame_index
            location["frame"] = _stage_b_crash_frame_evidence(frame)
            return location
    image = _stage_b_primary_candidate_image(modules)
    if pc is None:
        return {"classification": "missing_candidate_pc", "rva": None, "candidate_image": image}
    if image is None:
        return {"classification": "candidate_image_unknown", "pc": pc, "rva": None, "candidate_image": None}
    return {
        "classification": "outside_candidate_image",
        "pc": pc,
        "rva": None,
        "candidate_image": image,
    }


def _stage_b_primary_candidate_image(modules: list[dict[str, Any]]) -> dict[str, int] | None:
    if not modules:
        return None
    image = modules[0].get("image")
    return image if isinstance(image, dict) else None


def _stage_b_candidate_location_for_pc(pc: int, modules: list[dict[str, Any]]) -> dict[str, Any] | None:
    for index, module in enumerate(modules):
        image = module.get("image")
        if not isinstance(image, dict):
            continue
        image_base = _optional_int(image.get("image_base"))
        image_end = _optional_int(image.get("image_end"))
        if image_base is None or image_end is None:
            continue
        if image_base <= pc < image_end:
            return {
                "classification": "inside_candidate_image" if index == 0 else "inside_candidate_module_image",
                "pc": pc,
                "rva": pc - image_base,
                "candidate_image": _stage_b_primary_candidate_image(modules),
                "module_index": index,
                "module": _stage_b_crash_module_summary(modules, index),
            }
    return None


def _stage_b_candidate_location_for_frame(frame: dict[str, Any], modules: list[dict[str, Any]]) -> dict[str, Any] | None:
    module_indices = _stage_b_matching_frame_module_indices(frame, modules)
    explicit_rva = _optional_crash_address_int(frame.get("rva") or frame.get("instruction_rva") or frame.get("exception_rva"))
    if explicit_rva is not None and module_indices:
        index = module_indices[0]
        return {
            "pc": _optional_crash_address_int(frame.get("address") or frame.get("instruction_address") or frame.get("pc")),
            "rva": explicit_rva,
            "candidate_image": _stage_b_primary_candidate_image(modules),
            "module_index": index,
            "module": _stage_b_crash_module_summary(modules, index),
        }
    pc = _optional_crash_address_int(
        frame.get("address")
        or frame.get("instruction_address")
        or frame.get("exception_address")
        or frame.get("program_counter")
        or frame.get("pc")
    )
    if pc is None:
        return None
    if module_indices:
        for index in module_indices:
            image = modules[index].get("image")
            if not isinstance(image, dict):
                continue
            image_base = _optional_int(image.get("image_base"))
            image_end = _optional_int(image.get("image_end"))
            if image_base is not None and image_end is not None and image_base <= pc < image_end:
                return {
                    "pc": pc,
                    "rva": pc - image_base,
                    "candidate_image": _stage_b_primary_candidate_image(modules),
                    "module_index": index,
                    "module": _stage_b_crash_module_summary(modules, index),
                }
    return _stage_b_candidate_location_for_pc(pc, modules)


def _stage_b_crash_frames(crash: dict[str, Any]) -> list[dict[str, Any]]:
    for key in ("backtrace", "frames", "stack_frames", "trace"):
        value = crash.get(key)
        if isinstance(value, dict):
            value = value.get("frames")
        if isinstance(value, list):
            return [frame for frame in value if isinstance(frame, dict)]
    return []


def _stage_b_matching_frame_module_indices(frame: dict[str, Any], modules: list[dict[str, Any]]) -> list[int]:
    frame_keys = _stage_b_crash_frame_module_keys(frame)
    if not frame_keys:
        return []
    result: list[int] = []
    for index, module in enumerate(modules):
        if frame_keys & _stage_b_crash_module_keys(module):
            result.append(index)
    return result


def _stage_b_crash_frame_module_keys(frame: dict[str, Any]) -> set[str]:
    keys: set[str] = set()
    for key in ("module", "module_name", "module_path", "image", "binary", "path", "dll"):
        value = frame.get(key)
        if isinstance(value, str):
            keys.update(_stage_b_module_name_keys(value))
    return keys


def _stage_b_crash_module_keys(module: dict[str, Any]) -> set[str]:
    keys: set[str] = set()
    for key in ("name", "path"):
        value = module.get(key)
        if isinstance(value, str):
            keys.update(_stage_b_module_name_keys(value))
    return keys


def _stage_b_module_name_keys(value: str) -> set[str]:
    text = value.strip().replace("\\", "/").lower()
    if not text:
        return set()
    path = Path(text)
    name = path.name
    return {item for item in {text, name, name.removesuffix(".dll"), name.removesuffix(".exe")} if item}


def _stage_b_crash_module_summary(modules: list[dict[str, Any]], index: int) -> dict[str, Any] | None:
    if index < 0 or index >= len(modules):
        return None
    module = modules[index]
    summary = {
        "index": index,
        "name": module.get("name"),
        "role": module.get("role"),
        "path": module.get("path"),
        "image": module.get("image"),
    }
    return {key: value for key, value in summary.items() if value not in (None, "")}


def _stage_b_crash_frame_evidence(frame: dict[str, Any]) -> dict[str, Any]:
    allowed = {
        "index",
        "module",
        "module_name",
        "module_path",
        "image",
        "binary",
        "path",
        "dll",
        "address",
        "instruction_address",
        "exception_address",
        "program_counter",
        "pc",
        "rva",
        "instruction_rva",
        "exception_rva",
        "symbol",
        "function",
    }
    return {key: value for key, value in frame.items() if key in allowed}


def _optional_crash_address_int(value: Any) -> int | None:
    if isinstance(value, str):
        text = value.strip()
        if re.fullmatch(r"[0-9A-Fa-f]{6,16}", text):
            return int(text, 16)
    return _optional_int(value)


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


def _stage_b_repair_rank(item: dict[str, Any]) -> tuple[int, int, int, str]:
    class_rank = {
        "candidate_crash": 0,
        "candidate_crash_fault_address_context": 0,
        "candidate_crash_unmapped": 0,
        "hidden_sret_or_out_param": 1,
        "computed_out_param_or_hidden_sret": 1,
        "runtime_crt_entrypoint_layout": 1,
        "runtime_crt_stack_bridge": 1,
        "stack_probe_or_frame_layout": 1,
        "stack_scratch_buffer_or_out_param": 1,
        "abi_function_coverage": 2,
        "runtime_crt_function_coverage": 2,
        "runtime_crt_tls_callback_context": 2,
        "import_thunk_linkage": 2,
        "missing_decompiler_body": 2,
        "section_gap_or_padding_coverage": 2,
        "abi_callsite_function_coverage": 2,
        "abi_callsite_signature_coverage": 2,
        "function_pointer_callsite_coverage": 2,
        "pe_entrypoint_layout": 2,
        "pe_header_layout": 2,
        "pe_section_table_layout": 3,
        "pe_section_span_layout": 3,
        "abi_callsite_coverage": 3,
        "stage_a_argument_inventory_underconstrained": 3,
        "stack_delta_mismatch": 3,
        "preserved_register_mismatch": 4,
        "varargs_or_stdio_bridge": 5,
        "stderr_behavior": 5,
        "stdout_behavior": 5,
        "semantic_transfer_contract": 5,
        "memory_effect_mismatch": 5,
        "switch_or_jump_table_dispatch": 6,
        "loop_or_state_machine": 6,
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
        "candidate_crash_register_context": 7,
        "global_callback_slot": 7,
        "argument_callback_table": 7,
        "global_callback_table": 7,
        "readonly_callback_table": 7,
        "computed_function_pointer_target": 7,
        "function_pointer_target": 7,
        "candidate_crash_external_module": 8,
        "pe_import_table_layout": 8,
        "stack_out_param_or_scratch_buffer": 8,
        "jump_table_target": 8,
        "function_mapping": 9,
    }
    source_rank = {
        "candidate-crash-report": 1,
        "stage-a-contract-candidate-validation": 1,
        "candidate-only-probe-report": 2,
        "functional-report": 5,
        "stage-a-unit-contract": 6,
        "stage-a-semantic-transfer-contract": 6,
        "stage-a-cluster-semantic-contract": 6,
        "unknown": 4,
    }
    return (
        source_rank.get(_stage_b_repair_item_source(item), 4),
        _stage_b_repair_signal_rank(item),
        class_rank.get(str(item.get("likely_repair_class")), 20),
        str(item.get("original_function") or ""),
    )


def _stage_b_repair_signal_rank(item: dict[str, Any]) -> int:
    source = _stage_b_repair_item_source(item)
    repair_class = str(item.get("likely_repair_class") or "")
    if source == "candidate-crash-report":
        if repair_class == "candidate_crash_external_module":
            return 3
        return 0
    if source != "stage-a-contract-candidate-validation":
        return 0
    evidence = item.get("evidence") if isinstance(item.get("evidence"), dict) else {}
    explicit_contract_keys = {
        "coverage_gap",
        "entrypoint_delta",
        "header_delta",
        "import_delta",
        "missing_function_detail",
        "section_delta",
    }
    if explicit_contract_keys & set(evidence):
        return 0
    if "family" in evidence:
        return 1
    if "callsite" in evidence:
        return 2
    return 1


def _stage_b_repair_item_source(item: dict[str, Any]) -> str:
    evidence = item.get("evidence") if isinstance(item.get("evidence"), dict) else {}
    source = evidence.get("source")
    if isinstance(source, str) and source:
        return source
    family = str(item.get("violated_contract_family") or "")
    repair_class = str(item.get("likely_repair_class") or "")
    if family == "candidate_crash" or repair_class.startswith("candidate_crash"):
        return "candidate-crash-report"
    if family == "functional_expected_output" or repair_class.startswith("functional_"):
        return "functional-report"
    return "unknown"


def _count_by(items: list[dict[str, Any]], key: str) -> dict[str, int]:
    counter: Counter[str] = Counter()
    for item in items:
        counter[str(item.get(key) or "")] += 1
    return dict(sorted(counter.items()))


def _count_by_evidence_source(items: list[dict[str, Any]]) -> dict[str, int]:
    counter: Counter[str] = Counter()
    for item in items:
        counter[_stage_b_repair_item_source(item)] += 1
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


_STAGE_B_STAGE_A_NON_BLOCKING_ISSUES = {
    "functional_binary_binding_contains_original",
    "functional_binary_command_not_bound",
    "functional_binary_hash_mismatch",
    "functional_test_failure",
    "functional_test_report_binary_hash_mismatch",
    "functional_test_report_case_count_mismatch",
    "functional_test_report_case_hash_mismatch",
    "functional_test_report_case_ids_mismatch",
    "functional_test_report_case_manifest_hash_mismatch",
    "functional_test_report_contains_original_runtime_observation",
    "functional_test_report_coverage_case_manifest_hash_mismatch",
    "functional_test_report_coverage_kind_mismatch",
    "functional_test_report_coverage_suite_hash_mismatch",
    "functional_test_report_coverage_suite_mismatch",
    "functional_test_report_empty",
    "functional_test_report_failed",
    "functional_test_report_failed_case_records",
    "functional_test_report_failed_cases",
    "functional_test_report_hash_mismatch",
    "functional_test_report_incomplete_cases",
    "functional_test_report_incomplete_coverage_scope",
    "functional_test_report_missing_case_manifest",
    "functional_test_report_missing_counts",
    "functional_test_report_missing_coverage",
    "functional_test_report_missing_coverage_source",
    "functional_test_report_missing_required_suite_id",
    "functional_test_report_missing_source_hash",
    "functional_test_report_missing_source_revision",
    "functional_test_report_missing_suite_hash",
    "functional_test_report_not_upstream",
    "functional_test_report_original_baseline_failed",
    "functional_test_report_runner_mismatch",
    "functional_test_report_target_mismatch",
    "functional_test_report_wrong_materializer",
    "functional_test_report_wrong_source_kind",
    "functional_test_report_wrong_suite_id",
    "functional_test_report_wrong_suite_kind",
    "functional_test_report_wrong_suite_name",
    "functional_report_not_passing",
    "functional_report_not_upstream",
    "functional_tests_not_passing",
    "invalid_functional_test_report",
    "missing_functional_binary_binding",
    "missing_functional_binary_bindings",
    "missing_functional_report",
    "missing_functional_test_report",
    "missing_functional_test_suites",
    "missing_functional_tests",
    "missing_required_functional_suite",
    "required_functional_suite_not_passing",
}


def _stage_b_stage_a_blocking_preissues(issues: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [
        issue
        for issue in issues
        if str(issue.get("category") or "") not in _STAGE_B_STAGE_A_NON_BLOCKING_ISSUES
    ]


def _stage_b_stage_a_gate(
    *,
    pre_stage_a_issues: list[dict[str, Any]],
    all_issues: list[dict[str, Any]],
    stage_a_result: dict[str, Any] | None,
    map_result: dict[str, Any] | None,
) -> dict[str, Any]:
    pre_stage_a_categories = _issue_categories(pre_stage_a_issues)
    stage_a_blocking_categories = _issue_categories(_stage_b_stage_a_blocking_preissues(pre_stage_a_issues))
    non_blocking_categories = [
        category
        for category in pre_stage_a_categories
        if category not in stage_a_blocking_categories
    ]
    if stage_a_blocking_categories:
        return {
            "eligible": False,
            "ran": False,
            "status": "blocked",
            "reason": "pre_stage_a_requirements_incomplete",
            "blocking_issue_categories": stage_a_blocking_categories,
            "non_blocking_issue_categories": non_blocking_categories,
            "behavioral_mismatch_blocks_stage_a": False,
            "behavioral_blocking_issue_categories": [],
            "iteration_policy": "stage_a_contract_first",
            "runtime_validation_policy": "candidate_only_after_stage_a_pass",
            "next_action": "satisfy Stage B provenance, source, target, and build requirements required to run Stage A",
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
            "non_blocking_issue_categories": non_blocking_categories,
            "behavioral_mismatch_blocks_stage_a": False,
            "behavioral_blocking_issue_categories": [],
            "iteration_policy": "stage_a_contract_first",
            "runtime_validation_policy": "candidate_only_after_stage_a_pass",
            "next_action": "inspect the Stage A input error and provide supported binaries, maps, and model inputs",
        }

    stage_a_verdict = str(stage_a_result.get("verdict") or "")
    map_status = str(map_result.get("status") or "") if isinstance(map_result, dict) else ""
    map_closed = map_result is None or map_status == "pass"
    passed = stage_a_verdict == "pass" and map_closed
    stage_a_categories = [
        category
        for category in _issue_categories(all_issues)
        if category.startswith("stage_a_")
    ]
    return {
        "eligible": True,
        "ran": True,
        "status": "pass" if passed else "incomplete",
        "reason": "stage_a_final_pass" if passed else "stage_a_validation_incomplete",
        "blocking_issue_categories": [] if passed else stage_a_categories,
        "non_blocking_issue_categories": non_blocking_categories,
        "behavioral_mismatch_blocks_stage_a": False,
        "behavioral_blocking_issue_categories": [],
        "iteration_policy": "stage_a_contract_first",
        "runtime_validation_policy": "candidate_only_after_stage_a_pass",
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
        try:
            return int(text, 0)
        except ValueError:
            if re.fullmatch(r"[0-9A-Fa-f]+", text):
                return int(text, 16)
            raise
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
    require_functional_evidence: bool = False,
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
    manual_fixups = provenance_payload.get("manual_behavioral_fixups")
    if not isinstance(manual_fixups, list):
        issues.append(_issue("invalid_manual_behavioral_fixups", "candidate provenance manual_behavioral_fixups must be a list"))

    source_roots = provenance_payload.get("source_roots")
    if not isinstance(source_roots, list) or not source_roots:
        issues.append(_issue("missing_source_roots", "candidate provenance must list source roots derived from the Stage B skeleton"))
    elif not any(isinstance(item, dict) and item.get("kind") == "stage_b_generated_skeleton" for item in source_roots):
        issues.append(_issue("missing_generated_skeleton_root", "candidate source roots must include the generated Stage B skeleton"))
    else:
        issues.extend(_generated_skeleton_source_issues(skeleton_payload, source_roots))
        issues.extend(_generated_state_machine_implementation_issues(skeleton_payload, source_roots))
        issues.extend(_fixed_up_source_issues(skeleton_payload, source_roots))
    issues.extend(_candidate_build_artifact_issues(provenance_payload, candidate))
    issues.extend(_candidate_build_source_dependency_issues(provenance_payload))
    issues.extend(_candidate_build_reference_input_issues(provenance_payload, target_name=target_name))
    issues.extend(_candidate_build_target_library_linkage_issues(provenance_payload, target_name=target_name))
    issues.extend(_candidate_build_target_import_closure_issues(provenance_payload, target_name=target_name))
    issues.extend(_candidate_build_standalone_issues(provenance_payload))

    functional_tests = provenance_payload.get("functional_tests")
    functional_evidence_supplied = functional_report is not None or (
        isinstance(functional_tests, dict) and functional_tests.get("status") == "pass"
    )
    if require_functional_evidence or functional_evidence_supplied:
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
            required_suite_id = (
                str(functional_report_payload.get("suite_id") or "")
                if isinstance(functional_report_payload, dict)
                else ""
            )
            issues.extend(
                _provenance_required_suite_issues(required_suite_id, suites)
            )

        if functional_report is None:
            if isinstance(functional_tests, dict) and functional_tests.get("status") == "pass":
                issues.append(_issue("missing_functional_test_report", "passing functional tests must be backed by a Stage B functional report"))
            elif require_functional_evidence:
                issues.append(_issue("missing_functional_test_report", "final Stage B validation requires a candidate-only functional report"))
    if functional_report is not None and (
        not isinstance(functional_report_payload, dict) or functional_report_payload.get("format") != "stage-b-functional-report-v1"
    ):
        issues.append(_issue("invalid_functional_test_report", "functional report must have format stage-b-functional-report-v1"))
    elif functional_report is not None:
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
        issues.extend(
            _functional_report_required_coverage_issues(functional_report_payload)
        )
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
    state_machine = _skeleton_state_machine_output(skeleton_payload)
    implementation = _skeleton_implementation_output(skeleton_payload)
    if expected is None or state_machine is None:
        return []
    issues: list[dict[str, Any]] = []
    roots = [item for item in source_roots if isinstance(item, dict) and item.get("kind") == "stage_b_fixed_up_source"]
    for root in roots:
        missing = [
            key
            for key in ("path", "source", "source_sha256", "derived_from", "derived_from_sha256", "state_machine", "fixup_policy", "behavioral_fixups")
            if key not in root
        ]
        if implementation is not None and "implementation_manifest" not in root:
            missing.append("implementation_manifest")
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
        if root.get("state_machine") != state_machine:
            issues.append(
                _issue(
                    "fixed_up_source_state_machine_mismatch",
                    "fixed-up source roots must bind the exact Stage A state-machine artifact",
                    details={"expected": state_machine, "actual": root.get("state_machine")},
                )
            )
        if implementation is not None and root.get("implementation_manifest") != implementation:
            issues.append(
                _issue(
                    "fixed_up_source_implementation_mismatch",
                    "fixed-up source roots must bind the exact generated state-machine implementation manifest",
                    details={"expected": implementation, "actual": root.get("implementation_manifest")},
                )
            )
        if root.get("fixup_policy") != "state_machine_contract_guided":
            issues.append(
                _issue(
                    "invalid_fixed_up_source_policy",
                    "fixed-up source roots must declare state_machine_contract_guided repairs",
                    details=root,
                )
            )
        if not isinstance(root.get("behavioral_fixups"), list):
            issues.append(_issue("invalid_fixed_up_source_fixups", "fixed-up source behavioral_fixups must be a list", details=root))
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


def _skeleton_implementation_output(skeleton_payload: dict[str, Any]) -> dict[str, str] | None:
    if skeleton_payload.get("implementation_mode") != "contract-guided-c":
        return None
    outputs = skeleton_payload.get("outputs")
    implementation = outputs.get("implementation") if isinstance(outputs, dict) else None
    manifest = implementation.get("manifest") if isinstance(implementation, dict) else None
    if not isinstance(manifest, dict):
        return None
    path = manifest.get("path")
    digest = manifest.get("sha256")
    if not isinstance(path, str) or not isinstance(digest, str):
        return None
    return {"path": path, "sha256": digest}


def _generated_state_machine_implementation_issues(
    skeleton_payload: dict[str, Any],
    source_roots: list[Any],
) -> list[dict[str, Any]]:
    expected = _skeleton_implementation_output(skeleton_payload)
    if expected is None:
        return []
    roots = [
        item
        for item in source_roots
        if isinstance(item, dict)
        and item.get("kind") in {
            "stage_b_generated_state_machine_implementation",
            "stage_b_generated_skeleton",
        }
    ]
    state_machine = _skeleton_state_machine_output(skeleton_payload)
    for root in roots:
        actual = {
            "path": root.get("implementation_manifest"),
            "sha256": root.get("implementation_manifest_sha256"),
        }
        if actual == expected and root.get("state_machine") == state_machine:
            return []
    return [
        _issue(
            "missing_generated_state_machine_implementation_root",
            "contract-guided candidate provenance must bind the generated semantic-C implementation manifest",
            details={"expected": expected, "actual": roots},
        )
    ]


def _skeleton_state_machine_output(skeleton_payload: dict[str, Any]) -> dict[str, str] | None:
    outputs = skeleton_payload.get("outputs")
    state_machine = outputs.get("state_machine") if isinstance(outputs, dict) else None
    if not isinstance(state_machine, dict):
        return None
    path = state_machine.get("path")
    digest = state_machine.get("sha256")
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


def _provenance_required_suite_issues(
    required_suite_id: str, suites: Any
) -> list[dict[str, Any]]:
    if not required_suite_id or not isinstance(suites, list):
        return []
    for suite in suites:
        if not isinstance(suite, dict):
            continue
        if suite.get("id") != required_suite_id:
            continue
        if suite.get("status") == "pass":
            return []
        return [
            _issue(
                "required_functional_suite_not_passing",
                "candidate provenance lists the required upstream integration suite but it did not pass",
                details={"required_suite_id": required_suite_id, "suite": suite},
            )
        ]
    return [
        _issue(
            "missing_required_functional_suite",
            "candidate provenance must list the required upstream integration suite by canonical id",
            details={"required_suite_id": required_suite_id, "suites": suites},
        )
    ]


def _functional_report_required_coverage_issues(
    report: dict[str, Any],
) -> list[dict[str, Any]]:
    issues: list[dict[str, Any]] = []
    suite_id = str(report.get("suite_id") or "")
    suite_name = str(report.get("suite_name") or "")
    if not suite_id or not suite_name:
        issues.append(
            _issue(
                "functional_test_report_missing_suite_identity",
                "functional report must carry its target-declared suite identity",
                details={"suite_id": suite_id, "suite_name": suite_name},
            )
        )
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

    if coverage.get("suite_id") != suite_id:
        issues.append(
            _issue(
                "functional_test_report_coverage_suite_mismatch",
                "functional report coverage.suite_id does not match the required upstream suite",
                details={"expected": suite_id, "actual": coverage.get("suite_id")},
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
    if suite_id not in required_suite_ids:
        issues.append(
            _issue(
                "functional_test_report_missing_required_suite_id",
                "functional report coverage.required_suite_ids must include the target's required upstream suite id",
                details={"required_suite_id": suite_id, "actual": sorted(required_suite_ids)},
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


def _issue(category: str, blocker: str, *, details: Any | None = None) -> dict[str, Any]:
    issue = {
        "category": category,
        "blocker": blocker,
        "next_action": "repair the Stage B candidate provenance or generate a compliant candidate",
    }
    if details is not None:
        issue["details"] = details
    return issue






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
