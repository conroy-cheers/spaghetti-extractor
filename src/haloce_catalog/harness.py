from __future__ import annotations

import os
import shlex
import sqlite3
import subprocess
import time
from pathlib import Path
from typing import Any, Mapping, Sequence

from .labels import ensure_label, internal_harness_label, internal_harness_run_label
from .oracle import record_oracle_test_case
from .util import write_json, utc_now


INTERNAL_HARNESS_KINDS = ("function", "basic_block", "state_probe", "data_structure", "interface_probe")
INTERNAL_HARNESS_STATUSES = ("planned", "pass", "fail")
ORIGINAL_CODE_HARNESS_KINDS = {"function", "basic_block", "state_probe"}


def upsert_internal_harness(
    conn: sqlite3.Connection,
    *,
    target_label: str,
    harness_id: str,
    harness_kind: str,
    command_template: str = "",
    input_contract: str = "",
    expected_observation: str = "",
    risk: str = "",
    created_at: str | None = None,
) -> dict[str, Any]:
    if harness_kind not in INTERNAL_HARNESS_KINDS:
        raise ValueError(f"unknown internal harness kind: {harness_kind}")
    if conn.execute("SELECT 1 FROM labels WHERE label = ?", (target_label,)).fetchone() is None:
        raise ValueError(f"unknown target label: {target_label}")
    if harness_kind in ORIGINAL_CODE_HARNESS_KINDS and _oracle_mapping(conn, target_label) is None:
        raise ValueError(f"target label has no private oracle mapping: {target_label}")

    label = internal_harness_label(target_label, harness_id)
    created = created_at or utc_now()
    ensure_label(
        conn,
        label,
        "internal_harness",
        f"{target_label}:{harness_id}",
        "private internal-call harness definition",
        created_at=created,
    )
    conn.execute(
        """
        INSERT INTO internal_harnesses(
          label, target_label, harness_id, harness_kind, command_template,
          input_contract, expected_observation, risk, created_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(target_label, harness_id) DO UPDATE SET
          harness_kind = excluded.harness_kind,
          command_template = excluded.command_template,
          input_contract = excluded.input_contract,
          expected_observation = excluded.expected_observation,
          risk = excluded.risk
        """,
        (
            label,
            target_label,
            harness_id,
            harness_kind,
            command_template,
            input_contract,
            expected_observation,
            risk,
            created,
        ),
    )
    return {
        "label": label,
        "target_label": target_label,
        "harness_id": harness_id,
        "harness_kind": harness_kind,
    }


def record_internal_harness_run(
    conn: sqlite3.Connection,
    *,
    harness_label: str,
    test_id: str,
    status: str,
    evidence: str,
    command: str | None = None,
    fixture_path: Path | str | None = None,
    trace_log: Path | str | None = None,
    returncode: int | None = None,
    created_at: str | None = None,
) -> dict[str, Any]:
    if status not in INTERNAL_HARNESS_STATUSES:
        raise ValueError(f"unknown internal harness status: {status}")
    harness = _harness_row(conn, harness_label)
    created = created_at or utc_now()
    label = internal_harness_run_label(harness_label, test_id)
    ensure_label(
        conn,
        label,
        "internal_harness_run",
        f"{harness_label}:{test_id}",
        "private internal-call harness run",
        created_at=created,
    )
    conn.execute(
        """
        INSERT INTO internal_harness_runs(
          label, internal_harness_id, test_id, status, command, evidence,
          fixture_path, trace_log, returncode, created_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(internal_harness_id, test_id) DO UPDATE SET
          status = excluded.status,
          command = excluded.command,
          evidence = excluded.evidence,
          fixture_path = excluded.fixture_path,
          trace_log = excluded.trace_log,
          returncode = excluded.returncode
        """,
        (
            label,
            int(harness["id"]),
            test_id,
            status,
            command,
            evidence,
            str(fixture_path) if fixture_path is not None else None,
            str(trace_log) if trace_log is not None else None,
            returncode,
            created,
        ),
    )
    record_oracle_test_case(
        conn,
        suite_id="private-internal-harness",
        test_id=test_id,
        case_kind="private_harness",
        status=status,
        evidence=evidence,
        command=command,
        fixture_path=fixture_path,
        trace_log=trace_log,
        created_at=created,
    )
    return {
        "label": label,
        "harness_label": harness_label,
        "target_label": str(harness["target_label"]),
        "test_id": test_id,
        "status": status,
    }


def run_internal_harness(
    conn: sqlite3.Connection,
    *,
    harness_label: str,
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
) -> dict[str, Any]:
    if not command:
        raise ValueError("internal harness run requires a command")
    harness = _harness_row(conn, harness_label)
    mapping = _oracle_mapping(conn, str(harness["target_label"]))

    started = utc_now()
    started_monotonic = time.monotonic()
    test_artifact_dir = artifact_dir / str(harness["harness_id"]) / test_id
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
    try:
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

    elapsed_seconds = time.monotonic() - started_monotonic
    stdout_path.write_text(stdout, encoding="utf-8", errors="replace")
    stderr_path.write_text(stderr, encoding="utf-8", errors="replace")

    failures: list[str] = []
    expected_exit_set = {int(code) for code in expected_exit_codes}
    if timed_out:
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
        f"internal harness exited {returncode} in {elapsed_seconds:.3f}s for {harness['target_label']}; artifacts: {result_path}"
        if status == "pass"
        else f"internal harness failed for {harness['target_label']}: {'; '.join(failures)}; artifacts: {result_path}"
    )
    result = {
        "harness_label": harness_label,
        "harness_id": str(harness["harness_id"]),
        "harness_kind": str(harness["harness_kind"]),
        "target_label": str(harness["target_label"]),
        "oracle_mapping": dict(mapping) if mapping is not None else None,
        "test_id": test_id,
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
        "started_at": started,
        "elapsed_seconds": elapsed_seconds,
        "failures": failures,
    }
    write_json(result_path, result)
    with conn:
        record = record_internal_harness_run(
            conn,
            harness_label=harness_label,
            test_id=test_id,
            status=status,
            evidence=evidence,
            command=command_text,
            fixture_path=result_path,
            trace_log=trace_log,
            returncode=returncode,
            created_at=started,
        )
    result["label"] = record["label"]
    return result


def _harness_row(conn: sqlite3.Connection, harness_label: str) -> sqlite3.Row:
    row = conn.execute(
        """
        SELECT *
        FROM internal_harnesses
        WHERE label = ?
        """,
        (harness_label,),
    ).fetchone()
    if row is None:
        raise ValueError(f"unknown internal harness label: {harness_label}")
    return row


def _oracle_mapping(conn: sqlite3.Connection, label: str) -> sqlite3.Row | None:
    return conn.execute(
        """
        SELECT entity_type, binary_id, module_sha256, rva_start, rva_end
        FROM oracle_mappings
        WHERE label = ?
        """,
        (label,),
    ).fetchone()


def _timeout_stream(value: object) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return str(value)
