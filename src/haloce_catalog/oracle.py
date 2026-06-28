from __future__ import annotations

import os
import shlex
import shutil
import sqlite3
import subprocess
import time
from pathlib import Path
from typing import Any, Mapping, Sequence

from .labels import ensure_label, oracle_test_case_label
from .util import write_json, utc_now


REQUIRED_ORACLE_PROCESS_SUITES = (
    "client-startup",
    "dedicated-server-console",
    "map-discovery-loading",
    "profile-save-config",
    "loopback-networking",
    "logging-errors",
    "representative-client-launch",
)
REQUIRED_ORACLE_PRIVATE_SUITES = ("private-internal-harness",)
ORACLE_CASE_KINDS = ("black_box_process", "private_harness")
ORACLE_TEST_STATUSES = ("planned", "pass", "fail")


def required_oracle_suites(
    case_kind: str,
    *,
    process_suites: tuple[str, ...] = REQUIRED_ORACLE_PROCESS_SUITES,
    private_suites: tuple[str, ...] = REQUIRED_ORACLE_PRIVATE_SUITES,
) -> tuple[str, ...]:
    if case_kind == "black_box_process":
        return process_suites
    if case_kind == "private_harness":
        return private_suites
    raise ValueError(f"unknown oracle case kind: {case_kind}")


def record_oracle_test_case(
    conn: sqlite3.Connection,
    *,
    suite_id: str,
    test_id: str,
    case_kind: str,
    status: str = "pass",
    evidence: str = "",
    command: str | None = None,
    fixture_path: Path | str | None = None,
    trace_log: Path | str | None = None,
    created_at: str | None = None,
    required_process_suites: tuple[str, ...] = REQUIRED_ORACLE_PROCESS_SUITES,
    required_private_suites: tuple[str, ...] = REQUIRED_ORACLE_PRIVATE_SUITES,
) -> dict[str, Any]:
    if case_kind not in ORACLE_CASE_KINDS:
        raise ValueError(f"unknown oracle case kind: {case_kind}")
    if status not in ORACLE_TEST_STATUSES:
        raise ValueError(f"unknown oracle test status: {status}")
    required_suites = required_oracle_suites(
        case_kind,
        process_suites=required_process_suites,
        private_suites=required_private_suites,
    )
    if suite_id not in required_suites:
        raise ValueError(
            f"suite {suite_id!r} is not required for {case_kind!r}; "
            f"expected one of: {', '.join(required_suites)}"
        )

    label = oracle_test_case_label(suite_id, case_kind, test_id)
    created = created_at or utc_now()
    ensure_label(
        conn,
        label,
        "oracle_test_case",
        f"{suite_id}:{case_kind}:{test_id}",
        "original-binary oracle test evidence",
        created_at=created,
    )
    conn.execute(
        """
        INSERT INTO oracle_test_cases(
          label, suite_id, test_id, case_kind, status, evidence, command,
          fixture_path, trace_log, created_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(suite_id, test_id, case_kind) DO UPDATE SET
          status = excluded.status,
          evidence = excluded.evidence,
          command = excluded.command,
          fixture_path = excluded.fixture_path,
          trace_log = excluded.trace_log
        """,
        (
            label,
            suite_id,
            test_id,
            case_kind,
            status,
            evidence,
            command,
            str(fixture_path) if fixture_path is not None else None,
            str(trace_log) if trace_log is not None else None,
            created,
        ),
    )
    return {
        "label": label,
        "suite_id": suite_id,
        "test_id": test_id,
        "case_kind": case_kind,
        "status": status,
    }


def run_oracle_process_test(
    conn: sqlite3.Connection,
    *,
    suite_id: str,
    test_id: str,
    command: Sequence[str],
    artifact_dir: Path,
    timeout_seconds: float = 60.0,
    cwd: Path | str | None = None,
    env: Mapping[str, str] | None = None,
    stdin_text: str | None = None,
    expected_exit_codes: Sequence[int] = (0,),
    stdout_contains: Sequence[str] = (),
    stderr_contains: Sequence[str] = (),
    trace_log: Path | str | None = None,
    offscreen_display: str = "none",
    offscreen_screen: str = "1280x720x24",
    required_process_suites: tuple[str, ...] = REQUIRED_ORACLE_PROCESS_SUITES,
) -> dict[str, Any]:
    if suite_id not in required_process_suites:
        raise ValueError(f"unknown oracle process suite: {suite_id}")
    if not command:
        raise ValueError("oracle process test requires a command")

    started = utc_now()
    started_monotonic = time.monotonic()
    test_artifact_dir = artifact_dir / suite_id / test_id
    test_artifact_dir.mkdir(parents=True, exist_ok=True)
    stdout_path = test_artifact_dir / "stdout.txt"
    stderr_path = test_artifact_dir / "stderr.txt"
    result_path = test_artifact_dir / "result.json"

    run_env = os.environ.copy()
    if env:
        run_env.update({key: str(value) for key, value in env.items()})

    timed_out = False
    returncode: int | None = None
    stdout = ""
    stderr = ""
    offscreen_info: dict[str, Any] = {
        "requested": offscreen_display,
        "screen": offscreen_screen,
        "used": False,
        "backend": None,
        "display": None,
        "reason": "disabled",
    }
    offscreen_process: subprocess.Popen[str] | None = None
    offscreen_failure: str | None = None
    try:
        try:
            offscreen_info, offscreen_process = _start_offscreen_display(
                offscreen_display,
                run_env,
                screen=offscreen_screen,
            )
        except RuntimeError as exc:
            offscreen_failure = str(exc)
            stderr = offscreen_failure
        if offscreen_failure is None:
            completed = subprocess.run(
                list(command),
                cwd=str(cwd) if cwd is not None else None,
                env=run_env,
                input=stdin_text,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=timeout_seconds,
                check=False,
            )
            returncode = int(completed.returncode)
            stdout = completed.stdout or ""
            stderr = completed.stderr or ""
    except subprocess.TimeoutExpired as exc:
        timed_out = True
        stdout = _timeout_stream(exc.stdout)
        stderr = _timeout_stream(exc.stderr)
    finally:
        _stop_offscreen_display(offscreen_process)

    elapsed_seconds = time.monotonic() - started_monotonic
    stdout_path.write_text(stdout, encoding="utf-8", errors="replace")
    stderr_path.write_text(stderr, encoding="utf-8", errors="replace")

    failures: list[str] = []
    expected_exit_set = {int(code) for code in expected_exit_codes}
    if offscreen_failure is not None:
        failures.append(offscreen_failure)
    elif timed_out:
        failures.append(f"timed out after {timeout_seconds:g}s")
    elif returncode not in expected_exit_set:
        failures.append(f"exit code {returncode} not in expected {sorted(expected_exit_set)}")
    for needle in stdout_contains:
        if needle not in stdout:
            failures.append(f"stdout did not contain {needle!r}")
    for needle in stderr_contains:
        if needle not in stderr:
            failures.append(f"stderr did not contain {needle!r}")

    status = "pass" if not failures else "fail"
    command_text = shlex.join(str(part) for part in command)
    evidence = (
        f"process exited {returncode} in {elapsed_seconds:.3f}s; artifacts: {result_path}"
        if status == "pass"
        else f"process oracle failed: {'; '.join(failures)}; artifacts: {result_path}"
    )
    result = {
        "suite_id": suite_id,
        "test_id": test_id,
        "case_kind": "black_box_process",
        "status": status,
        "command": list(command),
        "cwd": str(cwd) if cwd is not None else None,
        "timeout_seconds": timeout_seconds,
        "timed_out": timed_out,
        "returncode": returncode,
        "expected_exit_codes": sorted(expected_exit_set),
        "stdout_contains": list(stdout_contains),
        "stderr_contains": list(stderr_contains),
        "stdout_path": str(stdout_path),
        "stderr_path": str(stderr_path),
        "result_path": str(result_path),
        "trace_log": str(trace_log) if trace_log is not None else None,
        "offscreen_display": offscreen_info,
        "started_at": started,
        "elapsed_seconds": elapsed_seconds,
        "failures": failures,
    }
    write_json(result_path, result)
    with conn:
        record = record_oracle_test_case(
            conn,
            suite_id=suite_id,
            test_id=test_id,
            case_kind="black_box_process",
            status=status,
            evidence=evidence,
            command=command_text,
            fixture_path=result_path,
            trace_log=trace_log,
            created_at=started,
            required_process_suites=required_process_suites,
        )
    result["label"] = record["label"]
    return result


def _start_offscreen_display(
    mode: str,
    run_env: dict[str, str],
    *,
    screen: str,
) -> tuple[dict[str, Any], subprocess.Popen[str] | None]:
    if mode not in {"none", "auto", "x11"}:
        raise ValueError(f"unknown offscreen display mode: {mode}")
    info: dict[str, Any] = {
        "requested": mode,
        "screen": screen,
        "used": False,
        "backend": None,
        "display": None,
        "reason": "disabled",
    }
    if mode == "none":
        return info, None
    existing_display = run_env.get("DISPLAY") or run_env.get("WAYLAND_DISPLAY")
    if mode == "auto" and existing_display:
        info["reason"] = "existing-display"
        info["display"] = existing_display
        return info, None

    xvfb = shutil.which("Xvfb", path=run_env.get("PATH"))
    if xvfb is None:
        raise RuntimeError("offscreen display requested but Xvfb was not found on PATH")

    last_error = ""
    for display_number in range(90, 120):
        display = f":{display_number}"
        process = subprocess.Popen(
            [xvfb, display, "-screen", "0", screen, "-nolisten", "tcp"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        time.sleep(0.1)
        if process.poll() is None:
            run_env["DISPLAY"] = display
            run_env.pop("WAYLAND_DISPLAY", None)
            info.update(
                {
                    "used": True,
                    "backend": "xvfb",
                    "display": display,
                    "reason": "started",
                }
            )
            return info, process
        _, stderr = process.communicate(timeout=1)
        last_error = stderr.strip()
    raise RuntimeError(f"offscreen display requested but Xvfb could not start: {last_error}")


def _stop_offscreen_display(process: subprocess.Popen[str] | None) -> None:
    if process is None or process.poll() is not None:
        return
    process.terminate()
    try:
        process.communicate(timeout=2)
    except subprocess.TimeoutExpired:
        process.kill()
        process.communicate(timeout=2)


def _timeout_stream(value: object) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return str(value)
