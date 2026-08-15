from __future__ import annotations

import base64
import binascii
import json
import os
import re
import signal
import shutil
import stat
import subprocess
from pathlib import Path
from typing import Any

from ..artifacts.formats import (
    CANDIDATE_TEST_CASE_REPORT_FORMAT,
    CANDIDATE_TEST_REPORT_FORMAT,
    CANDIDATE_TEST_SUITE_FORMAT,
)
from ..util import sha256_bytes, sha256_file, utc_now, write_json


class CandidateTestInputError(ValueError):
    pass


def run_candidate_test_suite(
    *,
    suite: Path,
    candidate_command: tuple[str, ...],
    out: Path,
    timeout_seconds: float = 30.0,
    candidate_binary: Path | None = None,
    strip_stderr_line_regexes: tuple[str, ...] | list[str] = (),
) -> dict[str, Any]:
    started_at = utc_now()
    payload = _load_functional_suite(Path(suite))
    cases_payload = payload.get("cases")
    if not isinstance(cases_payload, list) or not cases_payload:
        raise CandidateTestInputError("candidate test suite must contain a non-empty cases list")
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
                    "blocker": "candidate test suite case entry must be an object",
                }
            )
            continue
        cases.append(
            _run_functional_case(
                case=entry,
                index=index,
                candidate_command=candidate_command,
                out=out / "cases",
                default_timeout_seconds=timeout_seconds,
                strip_stderr_line_regexes=strip_stderr_line_regexes,
            )
        )

    result = _build_functional_report(
        payload=payload,
        suite_path=Path(suite),
        cases=cases,
        candidate_command=candidate_command,
        candidate_binary=candidate_binary,
        strip_stderr_line_regexes=strip_stderr_line_regexes,
        started_at=started_at,
        completed_at=utc_now(),
    )
    write_json(out / "candidate-test-report.json", result)
    return result


def run_candidate_test_case(
    *,
    suite: Path,
    case_id: str,
    candidate_command: tuple[str, ...],
    out: Path,
    timeout_seconds: float = 30.0,
    candidate_binary: Path | None = None,
    strip_stderr_line_regexes: tuple[str, ...] | list[str] = (),
) -> dict[str, Any]:
    """Run one expected-output case as an independent cacheable work unit."""

    started_at = utc_now()
    suite_path = Path(suite)
    payload = _load_functional_suite(suite_path)
    normalized = _materialized_suite_cases(payload)
    matches = [
        (index, case)
        for index, case in enumerate(normalized)
        if case["id"] == _artifact_name(case_id)
    ]
    if len(matches) != 1:
        raise CandidateTestInputError(
            f"candidate test suite has {len(matches)} matches for case {case_id!r}"
        )
    index, case = matches[0]
    output = Path(out)
    artifacts = output / "artifacts"
    artifacts.mkdir(parents=True, exist_ok=True)
    result = _run_functional_case(
        case=case,
        index=index,
        candidate_command=candidate_command,
        out=artifacts,
        default_timeout_seconds=timeout_seconds,
        strip_stderr_line_regexes=strip_stderr_line_regexes,
    )
    # CA derivations rewrite self-references from the temporary output path to
    # the final store path.  Keep shard-local artifacts relative so that the
    # report's canonical hash remains stable across that rewrite.
    for stream in ("stdout", "stderr"):
        artifact = result["candidate"][stream]
        artifact["path"] = Path(str(artifact["path"])).relative_to(output).as_posix()
    core = {
        "format": CANDIDATE_TEST_CASE_REPORT_FORMAT,
        "status": result["status"],
        "executes_original_binary": False,
        "started_at": started_at,
        "completed_at": utc_now(),
        "suite_sha256": sha256_file(suite_path),
        "case_index": index,
        "case_id": result["id"],
        "case_definition_sha256": _canonical_sha256(case),
        "runner": {
            "candidate_command": list(candidate_command),
            "strip_stderr_line_regexes": list(strip_stderr_line_regexes),
            "default_timeout_seconds": timeout_seconds,
        },
        "binary_binding": _functional_binary_binding(
            candidate_binary, candidate_command
        ),
        "case": result,
    }
    report = {**core, "report_sha256": _canonical_sha256(core)}
    write_json(output / "candidate-test-case-report.json", report)
    return report


def aggregate_candidate_test_cases(
    *,
    suite: Path,
    case_reports: list[Path] | tuple[Path, ...],
    out: Path,
) -> dict[str, Any]:
    """Validate and deterministically aggregate independently executed cases."""

    suite_path = Path(suite)
    payload = _load_functional_suite(suite_path)
    expected_cases = _materialized_suite_cases(payload)
    suite_sha256 = sha256_file(suite_path)
    reports: list[dict[str, Any]] = []
    roots: list[Path] = []
    for report_value in case_reports:
        report_path = Path(report_value)
        if report_path.is_dir():
            report_path = report_path / "candidate-test-case-report.json"
        report = _load_json(report_path)
        if not isinstance(report, dict) or report.get("format") != CANDIDATE_TEST_CASE_REPORT_FORMAT:
            raise CandidateTestInputError("unsupported candidate test case report")
        core = dict(report)
        expected_hash = core.pop("report_sha256", None)
        if expected_hash != _canonical_sha256(core):
            raise CandidateTestInputError("candidate test case report self-hash is stale")
        if report.get("suite_sha256") != suite_sha256:
            raise CandidateTestInputError("candidate test case report is stale for suite")
        reports.append(report)
        roots.append(report_path.parent)
    reports_with_roots = sorted(
        zip(reports, roots), key=lambda item: int(item[0].get("case_index", -1))
    )
    observed_indexes = [int(report.get("case_index", -1)) for report, _ in reports_with_roots]
    if observed_indexes != list(range(len(expected_cases))):
        raise CandidateTestInputError(
            "candidate test case reports do not exactly cover the suite case inventory"
        )
    commands = {
        tuple(report.get("runner", {}).get("candidate_command", []))
        for report, _ in reports_with_roots
    }
    bindings = {
        _canonical_sha256(report.get("binary_binding", {}))
        for report, _ in reports_with_roots
    }
    strip_policies = {
        tuple(report.get("runner", {}).get("strip_stderr_line_regexes", []))
        for report, _ in reports_with_roots
    }
    if len(commands) != 1 or len(bindings) != 1 or len(strip_policies) != 1:
        raise CandidateTestInputError(
            "candidate test case reports use inconsistent candidate bindings or runner policy"
        )
    output = Path(out)
    output.mkdir(parents=True, exist_ok=True)
    cases: list[dict[str, Any]] = []
    for (report, root), expected in zip(reports_with_roots, expected_cases):
        if report.get("case_id") != expected["id"]:
            raise CandidateTestInputError("candidate test case report order or ID is stale")
        if report.get("case_definition_sha256") != _canonical_sha256(expected):
            raise CandidateTestInputError("candidate test case report definition is stale")
        case = dict(report["case"])
        case["candidate"] = dict(case["candidate"])
        destination = output / "cases" / expected["id"]
        destination.mkdir(parents=True, exist_ok=True)
        for stream in ("stdout", "stderr"):
            artifact = dict(case["candidate"][stream])
            source = Path(str(artifact["path"]))
            if not source.is_absolute():
                source = root / source
            if not source.is_file() or sha256_file(source) != artifact["sha256"]:
                raise CandidateTestInputError(
                    f"candidate test case {expected['id']} {stream} artifact is stale"
                )
            target = destination / f"candidate.{stream}"
            shutil.copyfile(source, target)
            artifact["path"] = str(target)
            case["candidate"][stream] = artifact
        cases.append(case)
    first_report = reports_with_roots[0][0]
    candidate_command = tuple(first_report["runner"]["candidate_command"])
    result = _build_functional_report(
        payload=payload,
        suite_path=suite_path,
        cases=cases,
        candidate_command=candidate_command,
        candidate_binary=None,
        strip_stderr_line_regexes=tuple(
            first_report["runner"]["strip_stderr_line_regexes"]
        ),
        started_at=min(report["started_at"] for report, _ in reports_with_roots),
        completed_at=max(report["completed_at"] for report, _ in reports_with_roots),
        binary_binding=first_report["binary_binding"],
    )
    write_json(output / "candidate-test-report.json", result)
    return result


def _build_functional_report(
    *,
    payload: dict[str, Any],
    suite_path: Path,
    cases: list[dict[str, Any]],
    candidate_command: tuple[str, ...],
    candidate_binary: Path | None,
    strip_stderr_line_regexes: tuple[str, ...] | list[str],
    started_at: str,
    completed_at: str,
    binary_binding: dict[str, Any] | None = None,
) -> dict[str, Any]:
    passed = sum(1 for case in cases if case["status"] == "pass")
    failed = len(cases) - passed
    status = "pass" if cases and failed == 0 else "fail"
    suite_name = str(payload.get("suite_name") or payload.get("name") or suite_path.stem)
    suite_id = str(payload.get("suite_id") or payload.get("id") or _artifact_name(suite_name))
    upstream_suite = bool(payload.get("upstream_suite", False))
    case_manifest = _functional_case_manifest(cases)
    suite_sha256 = sha256_file(suite_path)
    suite_case_manifest_sha256 = _case_manifest_sha256(case_manifest)
    result = {
        "format": CANDIDATE_TEST_REPORT_FORMAT,
        "runner": {
            "name": "candidate-run-test-suite",
            "report_format": CANDIDATE_TEST_REPORT_FORMAT,
            "strip_stderr_line_regexes": list(strip_stderr_line_regexes),
        },
        "status": status,
        "started_at": started_at,
        "completed_at": completed_at,
        "suite": str(suite_path),
        "suite_sha256": suite_sha256,
        "suite_case_manifest_sha256": suite_case_manifest_sha256,
        "target_name": str(payload.get("target_name") or ""),
        "suite_id": suite_id,
        "suite_name": suite_name,
        "suite_kind": str(payload.get("suite_kind") or _coverage_payload(payload).get("suite_kind") or ("upstream_integration" if upstream_suite else "local")),
        "upstream_suite": upstream_suite,
        "oracle": {
            "kind": "expected_output",
            "original_runtime_observations": False,
        },
        "commands": {"candidate": list(candidate_command)},
        "binary_bindings": {
            "candidate": binary_binding
            if binary_binding is not None
            else _functional_binary_binding(candidate_binary, candidate_command),
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
    return result


def _load_functional_suite(path: Path) -> dict[str, Any]:
    payload = _load_json(path)
    if not isinstance(payload, dict):
        raise CandidateTestInputError("candidate test suite must be a JSON object")
    if payload.get("format") != CANDIDATE_TEST_SUITE_FORMAT:
        raise CandidateTestInputError("candidate test suite has an unsupported format")
    cases = payload.get("cases")
    if not isinstance(cases, list) or not cases:
        raise CandidateTestInputError(
            "candidate test suite must contain a non-empty cases list"
        )
    return payload


def _canonical_sha256(value: Any) -> str:
    return sha256_bytes(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    )


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
        raise CandidateTestInputError("candidate test suite cases must be a JSON object or list")
    if not isinstance(entries, list) or not entries:
        raise CandidateTestInputError("candidate test suite cases must contain a non-empty cases list")
    results: list[dict[str, Any]] = []
    for entry in entries:
        if not isinstance(entry, dict):
            raise CandidateTestInputError("candidate test suite case entries must be objects")
        case_id = entry.get("id")
        if not isinstance(case_id, str) or not case_id:
            raise CandidateTestInputError("candidate test suite cases must have non-empty string ids")
        normalized = dict(entry)
        normalized["id"] = _artifact_name(case_id)
        kind = normalized.get("kind")
        if kind not in {"expected-exit", "bounded-liveness"}:
            raise CandidateTestInputError(
                "candidate test case kind must be expected-exit or bounded-liveness"
            )
        _case_args(normalized)
        _case_stdin(normalized)
        _case_env(normalized)
        _case_cwd(normalized)
        _case_stdout_sink(normalized)
        if kind == "expected-exit":
            _case_expected_output(normalized)
        else:
            _case_bounded_liveness(normalized)
        for timeout_key in ("timeout_seconds", "candidate_timeout_seconds"):
            if timeout_key not in normalized:
                continue
            try:
                float(normalized[timeout_key])
            except (TypeError, ValueError) as exc:
                raise CandidateTestInputError(f"candidate test suite case {timeout_key} must be numeric") from exc
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
    candidate_timeout = _case_side_timeout_seconds(case, "candidate_timeout_seconds", timeout)
    env = _case_env(case)
    env_sha256 = _env_sha256(env)
    cwd = _case_cwd(case)
    stdout_sink = _case_stdout_sink(case)
    kind = str(case["kind"])
    if kind == "expected-exit":
        expected = _case_expected_output(case)
        candidate = _run_observed_process(
            command=(*candidate_command, *args),
            stdin_bytes=stdin_bytes,
            env=env,
            cwd=cwd,
            timeout_seconds=candidate_timeout,
            out_prefix=case_out / "candidate",
            strip_stderr_line_regexes=strip_stderr_line_regexes,
            stdout_sink=stdout_sink,
        )
        expectation = _functional_expected_output_result(candidate, expected)
        timeout_failure = bool(candidate.get("timed_out"))
        status = (
            "pass"
            if expectation["status"] == "pass" and not timeout_failure
            else "fail"
        )
    else:
        expected = _case_bounded_liveness(case)
        candidate = _run_bounded_liveness_process(
            command=(*candidate_command, *args),
            stdin_bytes=stdin_bytes,
            env=env,
            cwd=cwd,
            liveness_seconds=float(expected["liveness_seconds"]),
            hard_timeout_seconds=candidate_timeout,
            out_prefix=case_out / "candidate",
            strip_stderr_line_regexes=strip_stderr_line_regexes,
        )
        expectation = {
            "status": "pass" if candidate["liveness_observed"] else "fail",
            "kind": "bounded-liveness",
            "liveness_seconds": expected["liveness_seconds"],
        }
        timeout_failure = False
        status = expectation["status"]
    return {
        "id": case_id,
        "kind": kind,
        "status": status,
        "args": args,
        "timeout_seconds": timeout,
        "candidate_timeout_seconds": candidate_timeout,
        "stdin_sha256": sha256_bytes(stdin_bytes),
        "cwd": cwd,
        "stdout_sink": stdout_sink,
        "env_keys": sorted(env),
        "env_sha256": env_sha256,
        "expected": expected,
        "expectation": expectation,
        "candidate": candidate,
        "mismatch": None
        if status == "pass"
        else (
            _functional_mismatch(
                candidate,
                expected,
                expectation,
                timeout_failure=timeout_failure,
            )
            if kind == "expected-exit"
            else {
                "kind": "candidate-exited-before-liveness-bound",
                "returncode": candidate.get("returncode"),
                "liveness_seconds": expected["liveness_seconds"],
            }
        ),
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
    stdout_sink: str,
) -> dict[str, Any]:
    stdout_path = out_prefix.with_suffix(".stdout")
    stderr_path = out_prefix.with_suffix(".stderr")
    command_list = list(command)
    stdout_file = None
    stdout_target: Any = subprocess.PIPE
    stdout_sink_path: str | None = None
    if stdout_sink == "full_device":
        full_device = Path("/dev/full")
        try:
            mode = full_device.stat().st_mode
        except OSError as exc:
            raise CandidateTestInputError(
                "functional full_device stdout sink requires /dev/full"
            ) from exc
        if not stat.S_ISCHR(mode):
            raise CandidateTestInputError(
                "functional full_device stdout sink requires character device /dev/full"
            )
        stdout_file = full_device.open("wb", buffering=0)
        stdout_target = stdout_file
        stdout_sink_path = str(full_device)
    try:
        proc = subprocess.Popen(
            command_list,
            stdin=subprocess.PIPE,
            stdout=stdout_target,
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
    finally:
        if stdout_file is not None:
            stdout_file.close()
    stdout_path.write_bytes(stdout)
    stderr = _strip_matching_lines(stderr, strip_stderr_line_regexes)
    stderr_path.write_bytes(stderr)
    return {
        "command": list(command),
        "cwd": cwd,
        "returncode": returncode,
        "timed_out": timed_out,
        "stdout_sink": {
            "kind": stdout_sink,
            "path": stdout_sink_path,
        },
        "stdout": _stream_artifact(stdout_path, stdout),
        "stderr": _stream_artifact(stderr_path, stderr),
    }


def _run_bounded_liveness_process(
    *,
    command: tuple[str, ...],
    stdin_bytes: bytes,
    env: dict[str, str],
    cwd: str | None,
    liveness_seconds: float,
    hard_timeout_seconds: float,
    out_prefix: Path,
    strip_stderr_line_regexes: tuple[str, ...] | list[str],
) -> dict[str, Any]:
    if liveness_seconds <= 0 or hard_timeout_seconds <= liveness_seconds:
        raise CandidateTestInputError(
            "bounded-liveness hard timeout must exceed its positive liveness bound"
        )
    stdout_path = out_prefix.with_suffix(".stdout")
    stderr_path = out_prefix.with_suffix(".stderr")
    with stdout_path.open("wb") as stdout_file, stderr_path.open("wb") as stderr_file:
        proc = subprocess.Popen(
            list(command),
            stdin=subprocess.PIPE,
            stdout=stdout_file,
            stderr=stderr_file,
            cwd=cwd,
            env={**os.environ, **env},
            start_new_session=True,
        )
        assert proc.stdin is not None
        try:
            proc.stdin.write(stdin_bytes)
            proc.stdin.close()
            proc.wait(timeout=liveness_seconds)
            liveness_observed = False
            terminated_by_harness = False
        except subprocess.TimeoutExpired:
            liveness_observed = True
            terminated_by_harness = True
            _terminate_process_group(proc, signal.SIGTERM)
            try:
                proc.wait(timeout=max(0.1, hard_timeout_seconds - liveness_seconds))
            except subprocess.TimeoutExpired:
                _terminate_process_group(proc, signal.SIGKILL)
                proc.wait()
        except BaseException:
            if proc.poll() is None:
                _terminate_process_group(proc, signal.SIGKILL)
                proc.wait()
            raise
    stdout = stdout_path.read_bytes()
    stderr = _strip_matching_lines(
        stderr_path.read_bytes(), strip_stderr_line_regexes
    )
    stderr_path.write_bytes(stderr)
    return {
        "command": list(command),
        "cwd": cwd,
        "returncode": proc.returncode,
        "timed_out": False,
        "liveness_observed": liveness_observed,
        "terminated_by_harness": terminated_by_harness,
        "stdout_sink": {"kind": "capture", "path": None},
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
        raise CandidateTestInputError("candidate test suite case args must be a list of strings")
    return tuple(args)


def _case_stdin(case: dict[str, Any]) -> bytes:
    if "stdin" in case and "stdin_text" in case:
        raise CandidateTestInputError("candidate test suite case cannot contain both stdin and stdin_text")
    value = case.get("stdin", case.get("stdin_text", ""))
    if not isinstance(value, str):
        raise CandidateTestInputError("candidate test suite case stdin must be a string")
    return value.encode("utf-8")


def _case_env(case: dict[str, Any]) -> dict[str, str]:
    env = case.get("env", {})
    if not isinstance(env, dict) or not all(isinstance(key, str) and isinstance(value, str) for key, value in env.items()):
        raise CandidateTestInputError("candidate test suite case env must be an object of string values")
    return dict(env)


def _case_cwd(case: dict[str, Any]) -> str | None:
    cwd = case.get("cwd")
    if cwd is None:
        return None
    if not isinstance(cwd, str) or not cwd:
        raise CandidateTestInputError("candidate test suite case cwd must be a non-empty string when present")
    return cwd


def _case_stdout_sink(case: dict[str, Any]) -> str:
    sink = case.get("stdout_sink", "capture")
    if not isinstance(sink, str) or sink not in {"capture", "full_device"}:
        raise CandidateTestInputError(
            "candidate test suite case stdout_sink must be capture or full_device"
        )
    return sink


def _case_expected_output(case: dict[str, Any]) -> dict[str, Any]:
    value = case.get("expected_returncode", case.get("expect_returncode"))
    if value is None:
        raise CandidateTestInputError("candidate test suite case expected_returncode must be present")
    if isinstance(value, bool) or not isinstance(value, int):
        raise CandidateTestInputError("candidate test suite case expected_returncode must be an integer")
    stdout = _case_expected_stream(case, "stdout")
    stderr = _case_expected_stream(case, "stderr")
    return {
        "returncode": value,
        "stdout": stdout["text"],
        "stdout_base64": stdout["base64"],
        "stdout_policy": stdout["policy"],
        "stdout_sha256": stdout["sha256"],
        "stdout_bytes": stdout["bytes"],
        "stderr": stderr["text"],
        "stderr_base64": stderr["base64"],
        "stderr_policy": stderr["policy"],
        "stderr_sha256": stderr["sha256"],
        "stderr_bytes": stderr["bytes"],
    }


def _case_bounded_liveness(case: dict[str, Any]) -> dict[str, Any]:
    if _case_stdout_sink(case) != "capture":
        raise CandidateTestInputError(
            "bounded-liveness cases require captured stdout"
        )
    value = case.get("liveness_seconds")
    try:
        liveness_seconds = float(value)
    except (TypeError, ValueError) as exc:
        raise CandidateTestInputError(
            "bounded-liveness case liveness_seconds must be numeric"
        ) from exc
    hard_timeout = _case_side_timeout_seconds(
        case,
        "candidate_timeout_seconds",
        float(case.get("timeout_seconds", 30.0)),
    )
    if liveness_seconds <= 0 or hard_timeout <= liveness_seconds:
        raise CandidateTestInputError(
            "bounded-liveness hard timeout must exceed its positive liveness bound"
        )
    forbidden = {
        "expected_returncode",
        "expect_returncode",
        "expected_stdout",
        "expected_stdout_text",
        "expected_stdout_base64",
        "expected_stderr",
        "expected_stderr_text",
        "expected_stderr_base64",
    }
    if forbidden & set(case):
        raise CandidateTestInputError(
            "bounded-liveness cases cannot declare exit or output expectations"
        )
    return {
        "liveness_seconds": liveness_seconds,
        "hard_timeout_seconds": hard_timeout,
    }


def _case_expected_stream(case: dict[str, Any], stream: str) -> dict[str, Any]:
    direct_key = f"expected_{stream}"
    text_key = f"expected_{stream}_text"
    base64_key = f"expected_{stream}_base64"
    policy_key = f"expected_{stream}_policy"
    policy = case.get(policy_key, "exact")
    if policy not in {"exact", "any"}:
        raise CandidateTestInputError(f"candidate test suite case {policy_key} must be exact or any")
    supplied = [key for key in (direct_key, text_key, base64_key) if key in case]
    if len(supplied) > 1:
        raise CandidateTestInputError(
            f"candidate test suite case cannot contain multiple {stream} expectations"
        )
    if policy == "any":
        if supplied:
            raise CandidateTestInputError(f"candidate test suite case cannot combine {policy_key}=any with {direct_key}")
        return {
            "text": None,
            "base64": None,
            "policy": "any",
            "sha256": None,
            "bytes": None,
        }
    if not supplied:
        raise CandidateTestInputError(f"candidate test suite case {direct_key} must be present")
    if base64_key in case:
        encoded = case[base64_key]
        if not isinstance(encoded, str):
            raise CandidateTestInputError(
                f"candidate test suite case {base64_key} must be a string"
            )
        try:
            data = base64.b64decode(encoded, validate=True)
        except (binascii.Error, ValueError) as exc:
            raise CandidateTestInputError(
                f"candidate test suite case {base64_key} is invalid"
            ) from exc
        return {
            "text": None,
            "base64": encoded,
            "policy": "exact",
            "sha256": sha256_bytes(data),
            "bytes": len(data),
        }
    value = case.get(direct_key, case.get(text_key))
    if not isinstance(value, str):
        raise CandidateTestInputError(f"candidate test suite case {direct_key} must be a string")
    data = value.encode("utf-8")
    return {
        "text": value,
        "base64": None,
        "policy": "exact",
        "sha256": sha256_bytes(data),
        "bytes": len(data),
    }


def _case_side_timeout_seconds(case: dict[str, Any], key: str, default: float) -> float:
    value = case.get(key, default)
    try:
        return float(value)
    except (TypeError, ValueError) as exc:
        raise CandidateTestInputError(f"candidate test suite case {key} must be numeric") from exc


def _env_sha256(env: dict[str, str]) -> str:
    return sha256_bytes(json.dumps(env, sort_keys=True, separators=(",", ":")).encode("utf-8"))


def _functional_case_manifest(cases: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [
        {
            "id": str(case.get("id") or ""),
            "args": list(case.get("args") or []),
            "stdin_sha256": str(case.get("stdin_sha256") or ""),
            "cwd": case.get("cwd"),
            "stdout_sink": case.get("stdout_sink", "capture"),
            "env_sha256": str(case.get("env_sha256") or ""),
            "timeout_seconds": case.get("timeout_seconds"),
            "candidate_timeout_seconds": case.get("candidate_timeout_seconds"),
            "expected": case.get("expected"),
        }
        for case in cases
    ]


def _case_manifest_sha256(manifest: list[dict[str, Any]]) -> str:
    return sha256_bytes(json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode("utf-8"))


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


def _functional_expected_output_result(candidate: dict[str, Any], expected: dict[str, Any]) -> dict[str, Any]:
    stdout_exact = expected.get("stdout_policy", "exact") == "exact"
    stderr_exact = expected.get("stderr_policy", "exact") == "exact"
    passed = (
        candidate.get("returncode") == expected["returncode"]
        and candidate.get("timed_out") is False
        and (not stdout_exact or _exact_stream_matches(candidate, expected, "stdout"))
        and (not stderr_exact or _exact_stream_matches(candidate, expected, "stderr"))
    )
    return {
        "status": "pass" if passed else "fail",
        "expected_returncode": expected["returncode"],
        "actual_returncode": candidate.get("returncode"),
        "actual_timed_out": candidate.get("timed_out"),
        "expected_stdout_policy": expected.get("stdout_policy", "exact"),
        "expected_stdout_sha256": expected.get("stdout_sha256"),
        "actual_stdout_sha256": candidate.get("stdout", {}).get("sha256"),
        "expected_stderr_policy": expected.get("stderr_policy", "exact"),
        "expected_stderr_sha256": expected.get("stderr_sha256"),
        "actual_stderr_sha256": candidate.get("stderr", {}).get("sha256"),
    }


def _exact_stream_matches(
    candidate: dict[str, Any], expected: dict[str, Any], stream: str
) -> bool:
    artifact = candidate.get(stream, {})
    return (
        artifact.get("sha256") == expected.get(f"{stream}_sha256")
        and artifact.get("bytes") == expected.get(f"{stream}_bytes")
    )


def _functional_mismatch(
    candidate: dict[str, Any],
    expected: dict[str, Any],
    expectation: dict[str, Any],
    *,
    timeout_failure: bool = False,
) -> dict[str, Any]:
    fields = []
    if timeout_failure:
        fields.append("timeout")
    if candidate.get("returncode") != expected["returncode"]:
        fields.append("returncode")
    if expected.get("stdout_policy", "exact") == "exact" and not _exact_stream_matches(candidate, expected, "stdout"):
        fields.append("stdout")
    if expected.get("stderr_policy", "exact") == "exact" and not _exact_stream_matches(candidate, expected, "stderr"):
        fields.append("stderr")
    result: dict[str, Any] = {"fields": fields, "expectation": expectation}
    return result


def _string_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, list):
        return [str(item) for item in value]
    if isinstance(value, tuple):
        return [str(item) for item in value]
    return [str(value)]


def _case_ids_sha256(case_ids: list[str]) -> str:
    return sha256_bytes(json.dumps(case_ids, sort_keys=True, separators=(",", ":")).encode("utf-8"))


def _artifact_name(value: str) -> str:
    return "".join(ch if ch.isalnum() or ch in {"-", "_"} else "-" for ch in value).strip("-") or "artifact"


def _load_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise CandidateTestInputError(f"cannot read {path}: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise CandidateTestInputError(f"invalid JSON in {path}: {exc}") from exc
