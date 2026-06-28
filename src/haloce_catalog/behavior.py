from __future__ import annotations

import json
import os
import re
import shlex
import sqlite3
import subprocess
import time
from collections.abc import Mapping as MappingABC
from collections.abc import Sequence as SequenceABC
from pathlib import Path
from typing import Any, Mapping, Sequence

from .labels import (
    behavior_contract_label,
    behavior_observation_label,
    ensure_label,
    process_behavior_observation_label,
)
from .util import json_dumps, sha256_text, write_json, utc_now


BEHAVIOR_OBSERVATION_STATUSES = ("planned", "pass", "fail")
_TEMPLATE_TOKEN = re.compile(r"\{([^{}]+)\}")
_FULL_TEMPLATE_TOKEN = re.compile(r"^\{([^{}]+)\}$")


def upsert_behavior_contract(
    conn: sqlite3.Connection,
    *,
    contract_id: str,
    title: str,
    scope: str,
    version: str,
    contract: Mapping[str, Any],
    evidence: str = "",
    created_at: str | None = None,
) -> dict[str, Any]:
    created = created_at or utc_now()
    label = behavior_contract_label(contract_id, version)
    ensure_label(
        conn,
        label,
        "behavior_contract",
        f"{contract_id}:{version}",
        title,
        private=False,
        created_at=created,
    )
    conn.execute(
        """
        INSERT INTO behavior_contracts(
          label, contract_id, title, scope, version, contract_json, evidence, created_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(contract_id, version) DO UPDATE SET
          title = excluded.title,
          scope = excluded.scope,
          contract_json = excluded.contract_json,
          evidence = excluded.evidence
        """,
        (label, contract_id, title, scope, version, json_dumps(dict(contract)), evidence, created),
    )
    return {
        "label": label,
        "contract_id": contract_id,
        "title": title,
        "scope": scope,
        "version": version,
    }


def record_behavior_observation(
    conn: sqlite3.Connection,
    *,
    behavior_contract_label_value: str,
    test_id: str,
    observed: Mapping[str, Any],
    status: str = "pass",
    command: str | Sequence[str] | None = None,
    input_data: Mapping[str, Any] | None = None,
    evidence: str = "",
    fixture_path: Path | str | None = None,
    created_at: str | None = None,
) -> dict[str, Any]:
    if status not in BEHAVIOR_OBSERVATION_STATUSES:
        raise ValueError(f"unknown behavior observation status: {status}")
    contract = conn.execute(
        """
        SELECT id, label, contract_id, version
        FROM behavior_contracts
        WHERE label = ?
        """,
        (behavior_contract_label_value,),
    ).fetchone()
    if contract is None:
        raise ValueError(f"unknown behavior contract label: {behavior_contract_label_value}")

    observed_json = json_dumps(dict(observed))
    observed_sha = sha256_text(observed_json)
    label = behavior_observation_label(behavior_contract_label_value, test_id)
    created = created_at or utc_now()
    command_text = shlex.join(str(part) for part in command) if isinstance(command, (list, tuple)) else command
    ensure_label(
        conn,
        label,
        "behavior_observation",
        f"{contract['contract_id']}:{test_id}",
        "black-box behavior observation",
        private=False,
        created_at=created,
    )
    conn.execute(
        """
        INSERT INTO behavior_observations(
          label, behavior_contract_id, test_id, status, command, input_json,
          observed_json, observed_sha256, evidence, fixture_path, created_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(behavior_contract_id, test_id) DO UPDATE SET
          status = excluded.status,
          command = excluded.command,
          input_json = excluded.input_json,
          observed_json = excluded.observed_json,
          observed_sha256 = excluded.observed_sha256,
          evidence = excluded.evidence,
          fixture_path = excluded.fixture_path
        """,
        (
            label,
            int(contract["id"]),
            test_id,
            status,
            command_text,
            json_dumps(dict(input_data or {})),
            observed_json,
            observed_sha,
            evidence,
            str(fixture_path) if fixture_path is not None else None,
            created,
        ),
    )
    return {
        "label": label,
        "behavior_contract_label": behavior_contract_label_value,
        "test_id": test_id,
        "status": status,
        "observed_sha256": observed_sha,
    }


def record_process_behavior_observation(
    conn: sqlite3.Connection,
    *,
    behavior_contract_label_value: str,
    test_id: str,
    observed: Mapping[str, Any],
    status: str = "pass",
    command: str | Sequence[str] | None = None,
    input_data: Mapping[str, Any] | None = None,
    evidence: str = "",
    fixture_path: Path | str | None = None,
    created_at: str | None = None,
) -> dict[str, Any]:
    if status not in BEHAVIOR_OBSERVATION_STATUSES:
        raise ValueError(f"unknown process behavior observation status: {status}")
    contract = conn.execute(
        """
        SELECT id, label, contract_id, version
        FROM behavior_contracts
        WHERE label = ?
        """,
        (behavior_contract_label_value,),
    ).fetchone()
    if contract is None:
        raise ValueError(f"unknown behavior contract label: {behavior_contract_label_value}")

    observed_json = json_dumps(dict(observed))
    observed_sha = sha256_text(observed_json)
    label = process_behavior_observation_label(behavior_contract_label_value, test_id)
    created = created_at or utc_now()
    command_text = shlex.join(str(part) for part in command) if isinstance(command, (list, tuple)) else command
    ensure_label(
        conn,
        label,
        "process_behavior_observation",
        f"{contract['contract_id']}:{test_id}",
        "black-box process behavior observation",
        private=False,
        created_at=created,
    )
    conn.execute(
        """
        INSERT INTO process_behavior_observations(
          label, behavior_contract_id, test_id, status, command, input_json,
          observed_json, observed_sha256, evidence, fixture_path, created_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(behavior_contract_id, test_id) DO UPDATE SET
          status = excluded.status,
          command = excluded.command,
          input_json = excluded.input_json,
          observed_json = excluded.observed_json,
          observed_sha256 = excluded.observed_sha256,
          evidence = excluded.evidence,
          fixture_path = excluded.fixture_path
        """,
        (
            label,
            int(contract["id"]),
            test_id,
            status,
            command_text,
            json_dumps(dict(input_data or {})),
            observed_json,
            observed_sha,
            evidence,
            str(fixture_path) if fixture_path is not None else None,
            created,
        ),
    )
    return {
        "label": label,
        "behavior_contract_label": behavior_contract_label_value,
        "test_id": test_id,
        "status": status,
        "observed_sha256": observed_sha,
    }


def run_json_behavior_observation(
    conn: sqlite3.Connection,
    *,
    behavior_contract_label_value: str,
    test_id: str,
    command: Sequence[str],
    artifact_dir: Path,
    timeout_seconds: float = 60.0,
    cwd: Path | str | None = None,
    env: Mapping[str, str] | None = None,
    input_data: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    if not command:
        raise ValueError("behavior observation requires a command")
    started = utc_now()
    start_monotonic = time.monotonic()
    test_artifact_dir = artifact_dir / test_id
    test_artifact_dir.mkdir(parents=True, exist_ok=True)
    stdout_path = test_artifact_dir / "stdout.json"
    stderr_path = test_artifact_dir / "stderr.txt"
    result_path = test_artifact_dir / "result.json"

    run_env = os.environ.copy()
    if env:
        run_env.update(dict(env))

    timed_out = False
    returncode: int | None = None
    stdout = ""
    stderr = ""
    failures: list[str] = []
    observed: dict[str, Any] = {}
    try:
        completed = subprocess.run(
            list(command),
            cwd=str(cwd) if cwd is not None else None,
            env=run_env,
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

    stdout_path.write_text(stdout, encoding="utf-8", errors="replace")
    stderr_path.write_text(stderr, encoding="utf-8", errors="replace")

    if timed_out:
        failures.append(f"timed out after {timeout_seconds:g}s")
    elif returncode != 0:
        failures.append(f"exit code {returncode}")
    if not failures:
        try:
            parsed = json.loads(stdout)
        except json.JSONDecodeError as exc:
            failures.append(f"stdout was not JSON: {exc}")
        else:
            if not isinstance(parsed, dict):
                failures.append("stdout JSON was not an object")
            else:
                observed = parsed

    status = "pass" if not failures else "fail"
    elapsed_seconds = time.monotonic() - start_monotonic
    result = {
        "behavior_contract_label": behavior_contract_label_value,
        "test_id": test_id,
        "status": status,
        "command": list(command),
        "cwd": str(cwd) if cwd is not None else None,
        "timeout_seconds": timeout_seconds,
        "timed_out": timed_out,
        "returncode": returncode,
        "stdout_path": str(stdout_path),
        "stderr_path": str(stderr_path),
        "result_path": str(result_path),
        "elapsed_seconds": elapsed_seconds,
        "failures": failures,
        "started_at": started,
    }
    with conn:
        record = record_behavior_observation(
            conn,
            behavior_contract_label_value=behavior_contract_label_value,
            test_id=test_id,
            observed=observed,
            status=status,
            command=list(command),
            input_data=input_data,
            evidence=(
                f"JSON behavior transcript captured in {elapsed_seconds:.3f}s"
                if status == "pass"
                else f"JSON behavior observation failed: {'; '.join(failures)}"
            ),
            fixture_path=result_path,
            created_at=started,
        )
    result["label"] = record["label"]
    result["observed_sha256"] = record["observed_sha256"]
    write_json(result_path, {**result, "observed": observed})
    return result


def run_process_behavior_observation(
    conn: sqlite3.Connection,
    *,
    behavior_contract_label_value: str,
    test_id: str,
    command: Sequence[str],
    artifact_dir: Path,
    timeout_seconds: float = 60.0,
    cwd: Path | str | None = None,
    env: Mapping[str, str] | None = None,
    input_data: Mapping[str, Any] | None = None,
    stdin_text: str | None = None,
    expected_exit_codes: Sequence[int] | None = None,
    stdout_contains: Sequence[str] = (),
    stderr_contains: Sequence[str] = (),
    strip_stdout_line_regexes: Sequence[str] = (),
    strip_stderr_line_regexes: Sequence[str] = (),
) -> dict[str, Any]:
    if not command:
        raise ValueError("process behavior observation requires a command")
    started = utc_now()
    start_monotonic = time.monotonic()
    test_artifact_dir = artifact_dir / test_id
    test_artifact_dir.mkdir(parents=True, exist_ok=True)
    stdout_path = test_artifact_dir / "stdout.txt"
    stderr_path = test_artifact_dir / "stderr.txt"
    result_path = test_artifact_dir / "result.json"

    run_env = os.environ.copy()
    if env:
        run_env.update(dict(env))

    timed_out = False
    returncode: int | None = None
    stdout = ""
    stderr = ""
    failures: list[str] = []
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

    stdout_path.write_text(stdout, encoding="utf-8", errors="replace")
    stderr_path.write_text(stderr, encoding="utf-8", errors="replace")
    observed_stdout = _strip_matching_lines(stdout, strip_stdout_line_regexes)
    observed_stderr = _strip_matching_lines(stderr, strip_stderr_line_regexes)

    expected_exit_set = {int(code) for code in expected_exit_codes} if expected_exit_codes is not None else None
    if timed_out:
        failures.append(f"timed out after {timeout_seconds:g}s")
    elif expected_exit_set is not None and returncode not in expected_exit_set:
        failures.append(f"exit code {returncode} not in expected {sorted(expected_exit_set)}")
    for needle in stdout_contains:
        if needle not in observed_stdout:
            failures.append(f"stdout did not contain {needle!r}")
    for needle in stderr_contains:
        if needle not in observed_stderr:
            failures.append(f"stderr did not contain {needle!r}")

    observed = {
        "returncode": returncode,
        "timed_out": timed_out,
        "stdout": observed_stdout,
        "stderr": observed_stderr,
    }
    status = "pass" if not failures else "fail"
    elapsed_seconds = time.monotonic() - start_monotonic
    result = {
        "behavior_contract_label": behavior_contract_label_value,
        "test_id": test_id,
        "status": status,
        "command": list(command),
        "cwd": str(cwd) if cwd is not None else None,
        "timeout_seconds": timeout_seconds,
        "timed_out": timed_out,
        "returncode": returncode,
        "expected_exit_codes": sorted(expected_exit_set) if expected_exit_set is not None else None,
        "stdout_contains": list(stdout_contains),
        "stderr_contains": list(stderr_contains),
        "strip_stdout_line_regexes": list(strip_stdout_line_regexes),
        "strip_stderr_line_regexes": list(strip_stderr_line_regexes),
        "stdout_path": str(stdout_path),
        "stderr_path": str(stderr_path),
        "result_path": str(result_path),
        "elapsed_seconds": elapsed_seconds,
        "failures": failures,
        "started_at": started,
    }
    with conn:
        record = record_process_behavior_observation(
            conn,
            behavior_contract_label_value=behavior_contract_label_value,
            test_id=test_id,
            observed=observed,
            status=status,
            command=list(command),
            input_data=input_data,
            evidence=(
                f"process behavior captured in {elapsed_seconds:.3f}s"
                if status == "pass"
                else f"process behavior observation failed: {'; '.join(failures)}"
            ),
            fixture_path=result_path,
            created_at=started,
        )
    result["label"] = record["label"]
    result["observed_sha256"] = record["observed_sha256"]
    write_json(result_path, {**result, "observed": observed})
    return result


def compare_json_behavior(
    *,
    expected: Mapping[str, Any],
    command: Sequence[str],
    artifact_dir: Path,
    test_id: str,
    timeout_seconds: float = 60.0,
    cwd: Path | str | None = None,
    env: Mapping[str, str] | None = None,
    expected_path: Path | str | None = None,
) -> dict[str, Any]:
    if not command:
        raise ValueError("behavior comparison requires a command")
    started = utc_now()
    start_monotonic = time.monotonic()
    test_artifact_dir = artifact_dir / test_id
    test_artifact_dir.mkdir(parents=True, exist_ok=True)
    stdout_path = test_artifact_dir / "stdout.json"
    stderr_path = test_artifact_dir / "stderr.txt"
    result_path = test_artifact_dir / "result.json"

    run_env = os.environ.copy()
    if env:
        run_env.update(dict(env))

    timed_out = False
    returncode: int | None = None
    stdout = ""
    stderr = ""
    failures: list[str] = []
    observed: dict[str, Any] = {}
    try:
        completed = subprocess.run(
            list(command),
            cwd=str(cwd) if cwd is not None else None,
            env=run_env,
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

    stdout_path.write_text(stdout, encoding="utf-8", errors="replace")
    stderr_path.write_text(stderr, encoding="utf-8", errors="replace")

    if timed_out:
        failures.append(f"timed out after {timeout_seconds:g}s")
    elif returncode != 0:
        failures.append(f"exit code {returncode}")
    if not failures:
        try:
            parsed = json.loads(stdout)
        except json.JSONDecodeError as exc:
            failures.append(f"stdout was not JSON: {exc}")
        else:
            if not isinstance(parsed, dict):
                failures.append("stdout JSON was not an object")
            else:
                observed = parsed

    expected_dict = dict(expected)
    if not failures and observed != expected_dict:
        failures.append(_first_json_difference(expected_dict, observed))

    observed_json = json_dumps(observed)
    expected_json = json_dumps(expected_dict)
    result = {
        "test_id": test_id,
        "status": "pass" if not failures else "fail",
        "command": list(command),
        "cwd": str(cwd) if cwd is not None else None,
        "timeout_seconds": timeout_seconds,
        "timed_out": timed_out,
        "returncode": returncode,
        "expected_path": str(expected_path) if expected_path is not None else None,
        "stdout_path": str(stdout_path),
        "stderr_path": str(stderr_path),
        "result_path": str(result_path),
        "elapsed_seconds": time.monotonic() - start_monotonic,
        "failures": failures,
        "started_at": started,
        "expected_sha256": sha256_text(expected_json),
        "observed_sha256": sha256_text(observed_json),
        "observed": observed,
    }
    write_json(result_path, result)
    return result


def compare_process_behavior(
    *,
    expected: Mapping[str, Any],
    command: Sequence[str],
    artifact_dir: Path,
    test_id: str,
    timeout_seconds: float = 60.0,
    cwd: Path | str | None = None,
    env: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    if not command:
        raise ValueError("process behavior comparison requires a command")
    started = utc_now()
    start_monotonic = time.monotonic()
    test_artifact_dir = artifact_dir / test_id
    test_artifact_dir.mkdir(parents=True, exist_ok=True)
    stdout_path = test_artifact_dir / "stdout.txt"
    stderr_path = test_artifact_dir / "stderr.txt"
    result_path = test_artifact_dir / "result.json"

    run_env = os.environ.copy()
    if env:
        run_env.update(dict(env))

    timed_out = False
    returncode: int | None = None
    stdout = ""
    stderr = ""
    failures: list[str] = []
    try:
        completed = subprocess.run(
            list(command),
            cwd=str(cwd) if cwd is not None else None,
            env=run_env,
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

    stdout_path.write_text(stdout, encoding="utf-8", errors="replace")
    stderr_path.write_text(stderr, encoding="utf-8", errors="replace")
    observed = {
        "returncode": returncode,
        "timed_out": timed_out,
        "stdout": stdout,
        "stderr": stderr,
    }
    expected_dict = dict(expected)
    for key in ("returncode", "timed_out", "stdout", "stderr"):
        if key in expected_dict and observed[key] != expected_dict[key]:
            failures.append(_first_json_difference(expected_dict[key], observed[key], f"$.{key}"))
            break
    for stream_key in ("stdout", "stderr"):
        contains_key = f"{stream_key}_contains"
        for needle in expected_dict.get(contains_key, []) or []:
            if needle not in observed[stream_key]:
                failures.append(f"$.{stream_key}: missing substring {needle!r}")
                break
        if failures:
            break

    result = {
        "test_id": test_id,
        "status": "pass" if not failures else "fail",
        "command": list(command),
        "cwd": str(cwd) if cwd is not None else None,
        "timeout_seconds": timeout_seconds,
        "timed_out": timed_out,
        "returncode": returncode,
        "stdout_path": str(stdout_path),
        "stderr_path": str(stderr_path),
        "result_path": str(result_path),
        "elapsed_seconds": time.monotonic() - start_monotonic,
        "failures": failures,
        "started_at": started,
        "expected_sha256": sha256_text(json_dumps(expected_dict)),
        "observed_sha256": sha256_text(json_dumps(observed)),
        "observed": observed,
    }
    write_json(result_path, result)
    return result


def compare_json_spec_observations(
    *,
    spec: Mapping[str, Any],
    command_template: Sequence[str],
    artifact_dir: Path,
    contract_id: str | None = None,
    contract_label: str | None = None,
    timeout_seconds: float = 60.0,
    cwd: Path | str | None = None,
    env: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    """Run a JSON-emitting candidate against observations stored in a public spec.

    Command template items may reference values such as ``{contract_json}``,
    ``{test_id}``, ``{observed.scenario}``, ``{observed.frames}``, or any other
    dotted path from the selected behavior observation context.
    """

    if not command_template:
        raise ValueError("spec observation comparison requires a command template")

    contracts = _selected_behavior_contracts(spec, contract_id=contract_id, contract_label=contract_label)
    artifact_dir.mkdir(parents=True, exist_ok=True)
    contract_dir = artifact_dir / "contracts"
    contract_dir.mkdir(parents=True, exist_ok=True)
    comparisons: list[dict[str, Any]] = []

    for contract in contracts:
        contract_payload = contract.get("contract") or {}
        contract_path = contract_dir / f"{_safe_filename(str(contract.get('contract_id') or contract.get('label') or 'contract'))}-{contract.get('version', '1')}.json"
        write_json(contract_path, contract_payload if isinstance(contract_payload, MappingABC) else {})
        observations = [
            observation
            for observation in contract.get("observations", [])
            if isinstance(observation, MappingABC) and observation.get("status") == "pass"
        ]
        for observation in observations:
            observed = observation.get("observed") or {}
            if not isinstance(observed, MappingABC):
                continue
            context = {
                "contract": contract,
                "contract_id": contract.get("contract_id"),
                "contract_label": contract.get("label"),
                "contract_json": str(contract_path),
                "input": observation.get("input") or {},
                "observed": observed,
                "observed_sha256": observation.get("observed_sha256"),
                "test_id": observation.get("test_id"),
            }
            command = _expand_command_template(command_template, context)
            test_id = f"spec-{_safe_filename(str(contract.get('contract_id') or contract.get('label') or 'contract'))}-{_safe_filename(str(observation.get('test_id') or 'observation'))}"
            comparison = compare_json_behavior(
                expected=observed,
                expected_path=None,
                command=command,
                artifact_dir=artifact_dir,
                test_id=test_id,
                timeout_seconds=timeout_seconds,
                cwd=cwd,
                env=env,
            )
            comparison["contract_id"] = contract.get("contract_id")
            comparison["contract_label"] = contract.get("label")
            comparison["observation_test_id"] = observation.get("test_id")
            comparisons.append(comparison)

    passed = sum(1 for item in comparisons if item["status"] == "pass")
    failed = len(comparisons) - passed
    result = {
        "format": "wincr-json-spec-observation-comparison-v1",
        "status": "pass" if comparisons and failed == 0 else "fail",
        "contracts": len(contracts),
        "observations": len(comparisons),
        "passed": passed,
        "failed": failed,
        "artifact_dir": str(artifact_dir),
        "comparisons": comparisons,
    }
    write_json(artifact_dir / "summary.json", result)
    return result


def compare_process_spec_observations(
    *,
    spec: Mapping[str, Any],
    command_template: Sequence[str],
    artifact_dir: Path,
    contract_id: str | None = None,
    contract_label: str | None = None,
    timeout_seconds: float = 60.0,
    cwd: Path | str | None = None,
    env: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    """Run a candidate against process observations stored in a public spec."""

    if not command_template:
        raise ValueError("process spec observation comparison requires a command template")

    contracts = _selected_behavior_contracts(spec, contract_id=contract_id, contract_label=contract_label)
    artifact_dir.mkdir(parents=True, exist_ok=True)
    contract_dir = artifact_dir / "contracts"
    contract_dir.mkdir(parents=True, exist_ok=True)
    comparisons: list[dict[str, Any]] = []

    for contract in contracts:
        contract_payload = contract.get("contract") or {}
        contract_path = contract_dir / f"{_safe_filename(str(contract.get('contract_id') or contract.get('label') or 'contract'))}-{contract.get('version', '1')}.json"
        write_json(contract_path, contract_payload if isinstance(contract_payload, MappingABC) else {})
        observations = [
            observation
            for observation in contract.get("process_observations", [])
            if isinstance(observation, MappingABC) and observation.get("status") == "pass"
        ]
        for observation in observations:
            observed = observation.get("observed") or {}
            if not isinstance(observed, MappingABC):
                continue
            context = {
                "contract": contract,
                "contract_id": contract.get("contract_id"),
                "contract_label": contract.get("label"),
                "contract_json": str(contract_path),
                "input": observation.get("input") or {},
                "observed": observed,
                "observed_sha256": observation.get("observed_sha256"),
                "test_id": observation.get("test_id"),
            }
            command = _expand_command_template(command_template, context)
            test_id = f"process-spec-{_safe_filename(str(contract.get('contract_id') or contract.get('label') or 'contract'))}-{_safe_filename(str(observation.get('test_id') or 'observation'))}"
            comparison = compare_process_behavior(
                expected=observed,
                command=command,
                artifact_dir=artifact_dir,
                test_id=test_id,
                timeout_seconds=timeout_seconds,
                cwd=cwd,
                env=env,
            )
            comparison["contract_id"] = contract.get("contract_id")
            comparison["contract_label"] = contract.get("label")
            comparison["observation_test_id"] = observation.get("test_id")
            comparisons.append(comparison)

    passed = sum(1 for item in comparisons if item["status"] == "pass")
    failed = len(comparisons) - passed
    result = {
        "format": "wincr-process-spec-observation-comparison-v1",
        "status": "pass" if comparisons and failed == 0 else "fail",
        "contracts": len(contracts),
        "observations": len(comparisons),
        "passed": passed,
        "failed": failed,
        "artifact_dir": str(artifact_dir),
        "comparisons": comparisons,
    }
    write_json(artifact_dir / "summary.json", result)
    return result


def run_clean_spec_suite(
    *,
    spec: Mapping[str, Any],
    artifact_dir: Path,
    json_command_template: Sequence[str] | None = None,
    process_command_template: Sequence[str] | None = None,
    contract_id: str | None = None,
    contract_label: str | None = None,
    timeout_seconds: float = 60.0,
    cwd: Path | str | None = None,
    env: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    """Run all supported public behavior observations from a clean spec.

    This is the generic reimplementation conformance entry point. It consumes
    the same public spec shape accepted by the lower-level comparison commands
    and dispatches each supported observation kind to the corresponding runner.
    """

    contracts = _selected_behavior_contracts(spec, contract_id=contract_id, contract_label=contract_label)
    json_observations = _count_selected_observations(contracts, "observations")
    process_observations = _count_selected_observations(contracts, "process_observations")
    artifact_dir.mkdir(parents=True, exist_ok=True)

    errors: list[str] = []
    checks: list[dict[str, Any]] = []
    total_passed = 0
    total_failed = 0

    if json_observations:
        if not json_command_template:
            errors.append("JSON behavior observations are present but no JSON command template was provided")
            total_failed += json_observations
        else:
            result = compare_json_spec_observations(
                spec=spec,
                command_template=json_command_template,
                artifact_dir=artifact_dir / "json-spec-observations",
                contract_id=contract_id,
                contract_label=contract_label,
                timeout_seconds=timeout_seconds,
                cwd=cwd,
                env=env,
            )
            checks.append(_suite_check("json_spec_observations", result))
            total_passed += int(result.get("passed", 0) or 0)
            total_failed += int(result.get("failed", 0) or 0)
    elif json_command_template:
        checks.append(
            {
                "kind": "json_spec_observations",
                "status": "skipped",
                "reason": "no selected JSON behavior observations",
                "observations": 0,
                "passed": 0,
                "failed": 0,
            }
        )

    if process_observations:
        if not process_command_template:
            errors.append("process behavior observations are present but no process command template was provided")
            total_failed += process_observations
        else:
            result = compare_process_spec_observations(
                spec=spec,
                command_template=process_command_template,
                artifact_dir=artifact_dir / "process-spec-observations",
                contract_id=contract_id,
                contract_label=contract_label,
                timeout_seconds=timeout_seconds,
                cwd=cwd,
                env=env,
            )
            checks.append(_suite_check("process_spec_observations", result))
            total_passed += int(result.get("passed", 0) or 0)
            total_failed += int(result.get("failed", 0) or 0)
    elif process_command_template:
        checks.append(
            {
                "kind": "process_spec_observations",
                "status": "skipped",
                "reason": "no selected process behavior observations",
                "observations": 0,
                "passed": 0,
                "failed": 0,
            }
        )

    total_observations = json_observations + process_observations
    if total_observations == 0:
        errors.append("public spec contains no selected JSON or process behavior observations")

    result = {
        "format": "wincr-clean-spec-suite-run-v1",
        "status": "pass" if not errors and total_observations > 0 and total_failed == 0 else "fail",
        "artifact_dir": str(artifact_dir),
        "contract_filter": {
            "contract_id": contract_id,
            "contract_label": contract_label,
        },
        "summary": {
            "contracts": len(contracts),
            "json_observations": json_observations,
            "process_observations": process_observations,
            "observations": total_observations,
            "passed": total_passed,
            "failed": total_failed,
            "errors": len(errors),
            "checks": len(checks),
        },
        "checks": checks,
        "errors": errors,
    }
    write_json(artifact_dir / "summary.json", result)
    return result


def _suite_check(kind: str, result: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "kind": kind,
        "status": result.get("status"),
        "observations": result.get("observations", 0),
        "passed": result.get("passed", 0),
        "failed": result.get("failed", 0),
        "artifact_dir": result.get("artifact_dir"),
        "summary_json": str(Path(str(result.get("artifact_dir"))) / "summary.json")
        if result.get("artifact_dir")
        else None,
        "failed_samples": [
            {
                "test_id": item.get("test_id"),
                "observation_test_id": item.get("observation_test_id"),
                "failures": item.get("failures", []),
            }
            for item in result.get("comparisons", [])
            if isinstance(item, MappingABC) and item.get("status") != "pass"
        ][:10],
    }


def _count_selected_observations(contracts: Sequence[Mapping[str, Any]], key: str) -> int:
    count = 0
    for contract in contracts:
        observations = contract.get(key, [])
        if not isinstance(observations, SequenceABC) or isinstance(observations, (str, bytes, bytearray)):
            continue
        count += sum(
            1
            for observation in observations
            if isinstance(observation, MappingABC) and observation.get("status") == "pass"
        )
    return count


def _selected_behavior_contracts(
    spec: Mapping[str, Any],
    *,
    contract_id: str | None,
    contract_label: str | None,
) -> list[Mapping[str, Any]]:
    contracts = _behavior_contracts_from_spec(spec)
    if contract_id is not None:
        contracts = [contract for contract in contracts if contract.get("contract_id") == contract_id]
    if contract_label is not None:
        contracts = [contract for contract in contracts if contract.get("label") == contract_label]
    if not contracts:
        target = contract_id or contract_label or "any behavior contract"
        raise ValueError(f"public spec contains no selected behavior observations for {target}")
    return contracts


def _behavior_contracts_from_spec(spec: Mapping[str, Any]) -> list[Mapping[str, Any]]:
    contracts = [contract for contract in spec.get("behavior_contracts", []) if isinstance(contract, MappingABC)]
    if contracts:
        return contracts
    if spec.get("format") != "wincr-clean-specs-v1":
        return []

    spec_records = [record for record in spec.get("spec_records", []) if isinstance(record, MappingABC)]
    test_records = [record for record in spec.get("test_records", []) if isinstance(record, MappingABC)]
    behavior_contracts = [
        record for record in spec_records if record.get("entity_type") == "behavior_contract"
    ]
    if not behavior_contracts:
        return []

    multiple_contracts = len(behavior_contracts) > 1
    normalized: list[Mapping[str, Any]] = []
    for record in behavior_contracts:
        normalized_contract_id = str(record.get("contract_id") or record.get("public_label") or "")
        normalized_label = str(record.get("public_label") or normalized_contract_id)
        observations = [
            _clean_behavior_observation(test)
            for test in test_records
            if test.get("entity_type") == "behavior_observation"
            and _clean_record_matches_contract(test, normalized_contract_id, normalized_label, multiple_contracts)
        ]
        process_observations = [
            _clean_process_observation(test)
            for test in test_records
            if test.get("entity_type") == "process_behavior_observation"
            and _clean_record_matches_contract(test, normalized_contract_id, normalized_label, multiple_contracts)
        ]
        normalized.append(
            {
                "label": normalized_label,
                "contract_id": normalized_contract_id,
                "title": record.get("title") or record.get("sanitized_name") or normalized_contract_id,
                "version": record.get("version") or "1",
                "contract": record.get("contract") if isinstance(record.get("contract"), MappingABC) else dict(record),
                "observations": observations,
                "process_observations": process_observations,
            }
        )
    return normalized


def _clean_record_matches_contract(
    record: Mapping[str, Any],
    contract_id: str,
    contract_label: str,
    multiple_contracts: bool,
) -> bool:
    record_contract_id = str(record.get("contract_id") or "")
    record_contract_label = str(record.get("contract_label") or record.get("contract_public_label") or "")
    if record_contract_id:
        return record_contract_id == contract_id
    if record_contract_label:
        return record_contract_label == contract_label
    return not multiple_contracts


def _clean_behavior_observation(record: Mapping[str, Any]) -> dict[str, Any]:
    vector = _first_mapping(record.get("test_vectors"))
    observed = record.get("outputs")
    if not isinstance(observed, MappingABC):
        observed = vector.get("expected") if vector else {}
    return {
        "label": record.get("public_label"),
        "test_id": record.get("test_id") or vector.get("test_id") or record.get("public_label"),
        "status": record.get("status") or "pass",
        "input": record.get("inputs") if isinstance(record.get("inputs"), MappingABC) else {},
        "observed": observed if isinstance(observed, MappingABC) else {},
        "observed_sha256": record.get("observed_sha256") or vector.get("observed_sha256"),
    }


def _clean_process_observation(record: Mapping[str, Any]) -> dict[str, Any]:
    vector = _first_mapping(record.get("test_vectors"))
    observed = record.get("outputs")
    if not isinstance(observed, MappingABC):
        observed = vector.get("expected_process") if vector else {}
    return {
        "label": record.get("public_label"),
        "test_id": record.get("test_id") or vector.get("test_id") or record.get("public_label"),
        "status": record.get("status") or "pass",
        "input": record.get("inputs") if isinstance(record.get("inputs"), MappingABC) else {},
        "observed": observed if isinstance(observed, MappingABC) else {},
        "observed_sha256": record.get("observed_sha256") or vector.get("observed_sha256"),
    }


def _first_mapping(value: Any) -> Mapping[str, Any]:
    if isinstance(value, SequenceABC) and not isinstance(value, (str, bytes, bytearray)):
        for item in value:
            if isinstance(item, MappingABC):
                return item
    return {}


def _expand_command_template(command_template: Sequence[str], context: Mapping[str, Any]) -> list[str]:
    expanded: list[str] = []
    for item in command_template:
        text = str(item)
        match = _FULL_TEMPLATE_TOKEN.match(text)
        if match is not None:
            value = _lookup_context(match.group(1).strip(), context)
            if isinstance(value, SequenceABC) and not isinstance(value, (str, bytes, bytearray)):
                expanded.extend(str(part) for part in value)
                continue
            expanded.append("" if value is None else str(value))
            continue
        expanded.append(_expand_template_item(text, context))
    return expanded


def _expand_template_item(item: str, context: Mapping[str, Any]) -> str:
    def replace(match: re.Match[str]) -> str:
        token = match.group(1).strip()
        value = _lookup_context(token, context)
        return "" if value is None else str(value)

    return _TEMPLATE_TOKEN.sub(replace, str(item))


def _lookup_context(path: str, context: Mapping[str, Any]) -> Any:
    cursor: Any = context
    for part in path.split("."):
        if isinstance(cursor, MappingABC):
            if part not in cursor:
                raise KeyError(f"unknown command template token: {path}")
            cursor = cursor[part]
        elif isinstance(cursor, SequenceABC) and not isinstance(cursor, (str, bytes, bytearray)):
            cursor = cursor[int(part)]
        else:
            raise KeyError(f"unknown command template token: {path}")
    return cursor


def _safe_filename(value: str) -> str:
    safe = [ch.lower() if ch.isalnum() else "-" for ch in value]
    collapsed = re.sub(r"-+", "-", "".join(safe)).strip("-")
    return collapsed[:80] or "item"


def load_json_file(path: Path) -> dict[str, Any]:
    parsed = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(parsed, dict):
        raise ValueError(f"{path} must contain a JSON object")
    return parsed


def _first_json_difference(expected: Any, observed: Any, path: str = "$") -> str:
    if type(expected) is not type(observed):
        return f"{path}: expected {type(expected).__name__}, observed {type(observed).__name__}"
    if isinstance(expected, dict):
        expected_keys = set(expected)
        observed_keys = set(observed)
        missing = sorted(expected_keys - observed_keys)
        if missing:
            return f"{path}: missing key {missing[0]!r}"
        extra = sorted(observed_keys - expected_keys)
        if extra:
            return f"{path}: unexpected key {extra[0]!r}"
        for key in sorted(expected_keys):
            if expected[key] != observed[key]:
                return _first_json_difference(expected[key], observed[key], f"{path}.{key}")
        return f"{path}: JSON values differ"
    if isinstance(expected, list):
        if len(expected) != len(observed):
            return f"{path}: expected list length {len(expected)}, observed {len(observed)}"
        for index, (expected_item, observed_item) in enumerate(zip(expected, observed, strict=True)):
            if expected_item != observed_item:
                return _first_json_difference(expected_item, observed_item, f"{path}[{index}]")
        return f"{path}: JSON values differ"
    return f"{path}: expected {expected!r}, observed {observed!r}"


def _timeout_stream(value: str | bytes | None) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return value


def _strip_matching_lines(text: str, patterns: Sequence[str]) -> str:
    if not patterns:
        return text
    regexes = [re.compile(pattern) for pattern in patterns]
    kept: list[str] = []
    for line in text.splitlines(keepends=True):
        comparable = line.rstrip("\r\n")
        if any(regex.search(comparable) for regex in regexes):
            continue
        kept.append(line)
    return "".join(kept)
