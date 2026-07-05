from __future__ import annotations

import json
import os
import re
import signal
import subprocess
from pathlib import Path
from typing import Any

from .util import sha256_bytes, sha256_file, utc_now, write_json


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
STAGE_B_UPSTREAM_SUITE_MATERIALIZER = "stage-b-materialize-upstream-suite"


class StageBFunctionalInputError(ValueError):
    pass


def stage_b_materialize_upstream_suite(
    *,
    target_name: str,
    suite_source: Path,
    source_revision: str,
    cases: Path,
    out: Path,
    suite_scope: str = "full",
) -> dict[str, Any]:
    required = STAGE_B_REQUIRED_FUNCTIONAL_SUITES.get(target_name)
    if required is None:
        raise StageBFunctionalInputError(f"no required Stage B upstream suite is registered for target {target_name!r}")
    if not source_revision:
        raise StageBFunctionalInputError("Stage B upstream suite source revision must be non-empty")
    if suite_scope not in {"full", "subset"}:
        raise StageBFunctionalInputError("Stage B upstream suite scope must be full or subset")
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
        raise StageBFunctionalInputError("Stage B functional suite must be a JSON object")
    cases_payload = payload.get("cases")
    if not isinstance(cases_payload, list) or not cases_payload:
        raise StageBFunctionalInputError("Stage B functional suite must contain a non-empty cases list")
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
        raise StageBFunctionalInputError("Stage B upstream suite cases must be a JSON object or list")
    if not isinstance(entries, list) or not entries:
        raise StageBFunctionalInputError("Stage B upstream suite cases must contain a non-empty cases list")
    results: list[dict[str, Any]] = []
    for entry in entries:
        if not isinstance(entry, dict):
            raise StageBFunctionalInputError("Stage B upstream suite case entries must be objects")
        case_id = entry.get("id")
        if not isinstance(case_id, str) or not case_id:
            raise StageBFunctionalInputError("Stage B upstream suite cases must have non-empty string ids")
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
                raise StageBFunctionalInputError(f"Stage B upstream suite case {timeout_key} must be numeric") from exc
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
        raise StageBFunctionalInputError("functional suite case args must be a list of strings")
    return tuple(args)


def _case_stdin(case: dict[str, Any]) -> bytes:
    if "stdin" in case and "stdin_text" in case:
        raise StageBFunctionalInputError("functional suite case cannot contain both stdin and stdin_text")
    value = case.get("stdin", case.get("stdin_text", ""))
    if not isinstance(value, str):
        raise StageBFunctionalInputError("functional suite case stdin must be a string")
    return value.encode("utf-8")


def _case_env(case: dict[str, Any]) -> dict[str, str]:
    env = case.get("env", {})
    if not isinstance(env, dict) or not all(isinstance(key, str) and isinstance(value, str) for key, value in env.items()):
        raise StageBFunctionalInputError("functional suite case env must be an object of string values")
    return dict(env)


def _case_cwd(case: dict[str, Any]) -> str | None:
    cwd = case.get("cwd")
    if cwd is None:
        return None
    if not isinstance(cwd, str) or not cwd:
        raise StageBFunctionalInputError("functional suite case cwd must be a non-empty string when present")
    return cwd


def _case_expected_original_returncode(case: dict[str, Any]) -> int | None:
    value = case.get("expect_original_returncode")
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int):
        raise StageBFunctionalInputError("functional suite case expect_original_returncode must be an integer")
    return value


def _case_side_timeout_seconds(case: dict[str, Any], key: str, default: float) -> float:
    value = case.get(key, default)
    try:
        return float(value)
    except (TypeError, ValueError) as exc:
        raise StageBFunctionalInputError(f"functional suite case {key} must be numeric") from exc


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
        raise StageBFunctionalInputError(f"cannot read {path}: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise StageBFunctionalInputError(f"invalid JSON in {path}: {exc}") from exc
