"""Pinned CBMC process execution with fail-closed property parsing."""

from __future__ import annotations

import hashlib
import json
import os
import re
import signal
import subprocess
from pathlib import Path
from typing import Mapping, Sequence


class CbmcBackendError(RuntimeError):
    """The configured CBMC executable cannot be identified or invoked."""


def validate_smt_solver_binding(value):
    """Validate the optional, explicitly pinned external solver identity."""
    if (not isinstance(value, Mapping)
            or set(value) != {"id", "version", "executable", "sha256"}
            or value["id"] != "z3"
            or not isinstance(value["version"], str) or not value["version"].startswith("Z3 version ")
            or not isinstance(value["executable"], str)
            or re.fullmatch(r"/[A-Za-z0-9_./+\-]+", value["executable"]) is None
            or not isinstance(value["sha256"], str)
            or re.fullmatch(r"[0-9a-f]{64}", value["sha256"]) is None):
        raise CbmcBackendError("external SMT solver binding is malformed")


def bind_smt_solver(path):
    if path is None:
        return None
    executable = Path(path).resolve()
    if not executable.is_file() or not os.access(executable, os.X_OK):
        raise CbmcBackendError("external SMT solver executable is unavailable")
    completed = subprocess.run([str(executable), "--version"], text=True,
                               capture_output=True, check=False, timeout=10)
    binding = {"id": "z3", "version": completed.stdout.strip(),
               "executable": str(executable),
               "sha256": hashlib.sha256(executable.read_bytes()).hexdigest()}
    if completed.returncode != 0:
        raise CbmcBackendError("cannot identify the external SMT solver")
    validate_smt_solver_binding(binding)
    return binding


def solver_arguments(binding=None, *, array_field_sensitive=False):
    if binding is None:
        return ["--sat-solver", "cadical"]
    validate_smt_solver_binding(binding)
    # Splitting bounded arrays into individual fields makes the real caller's
    # memory histories expensive to encode before Z3 even starts. Keep SMT
    # arrays intact; this changes encoding, not bounds, checks or input domains.
    # Readers explicitly select the old encoding for retained legacy commands.
    return ["--smt2", "--z3", "--external-smt2-solver", binding["executable"],
            *([] if array_field_sensitive else ["--no-array-field-sensitivity"])]


def run_cbmc_process(command, *, timeout, cwd=None, **kwargs):
    """Bound external solver children by the same deadline as their CBMC parent."""
    if "--external-smt2-solver" not in command:
        return subprocess.run(command, timeout=timeout, **kwargs,
                              **({"cwd": cwd} if cwd is not None else {}))
    if os.name != "posix":
        raise CbmcBackendError("external SMT process cleanup requires a POSIX host")
    # subprocess.run kills only its immediate child on timeout. CBMC can be
    # waiting for an external solver which otherwise survives that deadline.
    if kwargs != {"text": True, "capture_output": True, "check": False}:
        raise CbmcBackendError("external SMT query process options differ")
    with subprocess.Popen(command, text=True, stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE, cwd=cwd, start_new_session=True) as process:
        try:
            stdout, stderr = process.communicate(timeout=timeout)
        except BaseException as error:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            stdout, stderr = process.communicate()
            if isinstance(error, subprocess.TimeoutExpired):
                error.output, error.stderr = stdout, stderr
            raise
        return subprocess.CompletedProcess(command, process.returncode, stdout, stderr)


def cbmc_version(cbmc: Path) -> str:
    completed = subprocess.run(
        [str(cbmc), "--version"],
        text=True,
        capture_output=True,
        check=False,
    )
    if completed.returncode != 0 or not completed.stdout.strip():
        raise CbmcBackendError("cannot query the pinned CBMC checker")
    return completed.stdout.strip()


def run_cbmc_properties(
    *,
    command: Sequence[str],
    timeout_seconds: int,
    query_evidence=None,
    cwd: Path | None = None,
    output_prefix: Path | None = None,
) -> dict[str, object]:
    """Run one property set and reject malformed or inconclusive output."""

    try:
        completed = (query_evidence.run(command, timeout_seconds=timeout_seconds, cwd=cwd)
                     if query_evidence is not None else run_cbmc_process(
            list(command), text=True, capture_output=True, check=False,
            timeout=timeout_seconds, **({"cwd": str(cwd)} if cwd is not None else {})))
    except subprocess.TimeoutExpired as exc:
        _retain_property_output(output_prefix, exc.stdout or b"", exc.stderr or b"")
        return {
            "status": "incomplete",
            "code": "cbmc_timeout",
            "detail": f"exceeded {timeout_seconds} seconds",
            "output_sha256": _output_sha256(exc.stdout or "", exc.stderr or ""),
        }
    output_sha256 = _output_sha256(completed.stdout, completed.stderr)
    _retain_property_output(output_prefix, completed.stdout, completed.stderr)
    payload = _parse_json(completed.stdout)
    if payload is None:
        return {
            "status": "incomplete",
            "code": "cbmc_output_malformed",
            "detail": (completed.stderr or completed.stdout)[-4000:],
            "output_sha256": output_sha256,
        }
    failures = _failures(payload)
    statuses = _property_statuses(payload)
    if completed.returncode == 0 and statuses and set(statuses.values()) == {"SUCCESS"}:
        return {
            "status": "satisfied",
            "code": "cbmc_properties_satisfied",
            "properties": len(statuses),
            "property_ids": sorted(statuses),
            "output_sha256": output_sha256,
        }
    if failures:
        first = failures[0]
        return {
            "status": "violated",
            "code": "cbmc_counterexample",
            "properties": len(statuses),
            "property_ids": sorted(statuses),
            "source": _failure_source(first),
            "counterexample": _compact_trace(first.get("trace")),
            "detail": first.get("description") or first.get("property"),
            "output_sha256": output_sha256,
        }
    if not statuses:
        object_limits = [row["messageText"] for row in payload if isinstance(row, dict)
                         and row.get("messageType") == "ERROR" and isinstance(row.get("messageText"), str)
                         and row["messageText"].startswith("too many addressed objects:")]
        if object_limits:
            return {"status": "incomplete", "code": "cbmc_object_limit",
                    "detail": object_limits[0], "output_sha256": output_sha256}
        return {
            "status": "incomplete",
            "code": "cbmc_no_properties_checked",
            "detail": (completed.stderr or completed.stdout)[-4000:],
            "output_sha256": output_sha256,
        }
    unsupported = sorted(
        f"{property_id}:{status}"
        for property_id, status in statuses.items()
        if status != "SUCCESS"
    )
    if unsupported:
        return {
            "status": "incomplete",
            "code": "cbmc_property_status_inconclusive",
            "detail": ", ".join(unsupported[:32]),
            "output_sha256": output_sha256,
        }
    return {
        "status": "incomplete",
        "code": "cbmc_checker_error",
        "detail": (completed.stderr or completed.stdout)[-4000:],
        "output_sha256": output_sha256,
    }


def _retain_property_output(prefix: Path | None, stdout: str | bytes, stderr: str | bytes) -> None:
    if prefix is not None:
        for suffix, content in ((".stdout", stdout), (".stderr", stderr)):
            Path(str(prefix) + suffix).write_bytes(content.encode("utf-8") if isinstance(content, str) else content)


def discover_cbmc_assertions(
    *,
    command: Sequence[str],
    timeout_seconds: int,
    query_evidence=None,
) -> dict[str, object]:
    """Inventory every authored assertion in one compiled GOTO model."""

    try:
        completed = (query_evidence.run(command, timeout_seconds=timeout_seconds)
                     if query_evidence is not None else run_cbmc_process(
            list(command), text=True, capture_output=True, check=False,
            timeout=timeout_seconds))
    except subprocess.TimeoutExpired as exc:
        return {
            "status": "incomplete",
            "code": "cbmc_property_inventory_timeout",
            "detail": f"exceeded {timeout_seconds} seconds",
            "output_sha256": _output_sha256(exc.stdout or "", exc.stderr or ""),
        }
    output_sha256 = _output_sha256(completed.stdout, completed.stderr)
    payload = _parse_json(completed.stdout)
    if payload is None or completed.returncode != 0:
        return {
            "status": "incomplete",
            "code": "cbmc_property_inventory_malformed",
            "detail": (completed.stderr or completed.stdout)[-4000:],
            "output_sha256": output_sha256,
        }
    properties = [
        item
        for row in payload
        if isinstance(row, Mapping) and isinstance(row.get("properties"), list)
        for item in row["properties"]
        if isinstance(item, Mapping) and item.get("class") == "assertion"
    ]
    assertions = [
        {
            "property_id": item.get("name"),
            "description": item.get("description"),
            "source_function": (
                item.get("sourceLocation", {}).get("function")
                if isinstance(item.get("sourceLocation"), Mapping)
                else None
            ),
        }
        for item in properties
    ]
    property_ids = [item.get("property_id") for item in assertions]
    if (
        not property_ids
        or any(not isinstance(item, str) or not item for item in property_ids)
        or len(property_ids) != len(set(property_ids))
        or any(
            not isinstance(item.get("description"), str)
            or not item.get("description")
            or not isinstance(item.get("source_function"), str)
            or not item.get("source_function")
            for item in assertions
        )
    ):
        return {
            "status": "incomplete",
            "code": "cbmc_assertion_inventory_empty_or_ambiguous",
            "detail": "compiled proof model has no unique authored assertion inventory",
            "output_sha256": output_sha256,
        }
    return {
        "status": "satisfied",
        "code": "cbmc_assertion_inventory",
        "properties": len(property_ids),
        "property_ids": sorted(property_ids),
        "assertions": sorted(assertions, key=lambda item: str(item["property_id"])),
        "output_sha256": output_sha256,
    }


def discover_cbmc_safety_properties(
    *,
    command: Sequence[str],
    timeout_seconds: int,
    query_evidence=None,
) -> dict[str, object]:
    """Inventory every statically instrumented language-safety property."""

    try:
        completed = (query_evidence.run(command, timeout_seconds=timeout_seconds)
                     if query_evidence is not None else run_cbmc_process(
            list(command), text=True, capture_output=True, check=False,
            timeout=timeout_seconds))
    except subprocess.TimeoutExpired as exc:
        return {
            "status": "incomplete",
            "code": "cbmc_safety_inventory_timeout",
            "detail": f"exceeded {timeout_seconds} seconds",
            "output_sha256": _output_sha256(exc.stdout or "", exc.stderr or ""),
        }
    output_sha256 = _output_sha256(completed.stdout, completed.stderr)
    payload = _parse_json(completed.stdout)
    if payload is None or completed.returncode != 0:
        return {
            "status": "incomplete",
            "code": "cbmc_safety_inventory_malformed",
            "detail": (completed.stderr or completed.stdout)[-4000:],
            "output_sha256": output_sha256,
        }
    containers = [
        row["properties"]
        for row in payload
        if isinstance(row, Mapping) and isinstance(row.get("properties"), list)
    ]
    if not containers:
        return {
            "status": "incomplete",
            "code": "cbmc_safety_inventory_malformed",
            "detail": "CBMC did not return a property inventory",
            "output_sha256": output_sha256,
        }
    properties = [item for rows in containers for item in rows]
    inventory = [
        {
            "property_id": item.get("name"),
            "class": item.get("class"),
            "description": item.get("description"),
            "source_function": (
                item.get("sourceLocation", {}).get("function")
                if isinstance(item.get("sourceLocation"), Mapping)
                else None
            ),
        }
        for item in properties
        if isinstance(item, Mapping)
    ]
    property_ids = [item.get("property_id") for item in inventory]
    if (
        any(
            not all(isinstance(item.get(field), str) and item.get(field)
                    for field in (
                        "property_id",
                        "class",
                        "description",
                        "source_function",
                    ))
            for item in inventory
        )
        or len(inventory) != len(properties)
        or len(property_ids) != len(set(property_ids))
    ):
        return {
            "status": "incomplete",
            "code": "cbmc_safety_inventory_empty_or_ambiguous",
            "detail": "compiled proof model has ambiguous safety properties",
            "output_sha256": output_sha256,
        }
    return {
        "status": "satisfied",
        "code": "cbmc_safety_inventory",
        "properties": len(inventory),
        "property_ids": sorted(str(item) for item in property_ids),
        "safety_properties": sorted(
            inventory, key=lambda item: str(item["property_id"])
        ),
        "output_sha256": output_sha256,
    }


def discover_cbmc_loops(
    *,
    command: Sequence[str],
    timeout_seconds: int,
    query_evidence=None,
) -> dict[str, object]:
    """Inventory reachable loops and their dynamic unwinding properties."""

    try:
        completed = (query_evidence.run(command, timeout_seconds=timeout_seconds)
                     if query_evidence is not None else run_cbmc_process(
            list(command), text=True, capture_output=True, check=False,
            timeout=timeout_seconds))
    except subprocess.TimeoutExpired as exc:
        return {
            "status": "incomplete",
            "code": "cbmc_loop_inventory_timeout",
            "detail": f"exceeded {timeout_seconds} seconds",
            "output_sha256": _output_sha256(exc.stdout or "", exc.stderr or ""),
        }
    output_sha256 = _output_sha256(completed.stdout, completed.stderr)
    payload = _parse_json(completed.stdout)
    if payload is None or completed.returncode != 0:
        return {
            "status": "incomplete",
            "code": "cbmc_loop_inventory_malformed",
            "detail": (completed.stderr or completed.stdout)[-4000:],
            "output_sha256": output_sha256,
        }
    containers = [
        row["loops"]
        for row in payload
        if isinstance(row, Mapping) and isinstance(row.get("loops"), list)
    ]
    if not containers:
        return {
            "status": "incomplete",
            "code": "cbmc_loop_inventory_malformed",
            "detail": "CBMC did not return a loop inventory",
            "output_sha256": output_sha256,
        }
    raw_loops = [item for rows in containers for item in rows]
    loops = [
        {
            "loop_id": item.get("name"),
            "source_function": (
                item.get("sourceLocation", {}).get("function")
                if isinstance(item.get("sourceLocation"), Mapping)
                else None
            ),
        }
        for item in raw_loops
        if isinstance(item, Mapping)
    ]
    if (
        len(loops) != len(raw_loops)
        or any(
            re.fullmatch(r".+\.[0-9]+", str(item.get("loop_id", ""))) is None
            or not isinstance(item.get("source_function"), str)
            or not item.get("source_function")
            for item in loops
        )
        or len({str(item["loop_id"]) for item in loops}) != len(loops)
    ):
        return {
            "status": "incomplete",
            "code": "cbmc_loop_inventory_empty_or_ambiguous",
            "detail": "compiled proof model has ambiguous reachable loops",
            "output_sha256": output_sha256,
        }
    canonical_loops = sorted(loops, key=lambda item: str(item["loop_id"]))
    return {
        "status": "satisfied",
        "code": "cbmc_loop_inventory",
        "loops": canonical_loops,
        "unwinding_property_ids": [
            re.sub(r"\.([0-9]+)$", r".unwind.\1", str(item["loop_id"]))
            for item in canonical_loops
        ],
        "output_sha256": output_sha256,
    }


def run_cbmc_cover(
    *,
    command: Sequence[str],
    expected_functions: Sequence[str],
    timeout_seconds: int,
    query_evidence=None,
) -> dict[str, object]:
    """Require a concrete witness reaching an explicit proof cover point."""

    try:
        completed = (query_evidence.run(command, timeout_seconds=timeout_seconds)
                     if query_evidence is not None else run_cbmc_process(
            list(command), text=True, capture_output=True, check=False,
            timeout=timeout_seconds))
    except subprocess.TimeoutExpired as exc:
        return {
            "status": "incomplete",
            "code": "cbmc_nonvacuity_timeout",
            "detail": f"exceeded {timeout_seconds} seconds",
            "output_sha256": _output_sha256(exc.stdout or "", exc.stderr or ""),
        }
    output_sha256 = _output_sha256(completed.stdout, completed.stderr)
    payload = _parse_json(completed.stdout)
    if payload is None:
        return {
            "status": "incomplete",
            "code": "cbmc_nonvacuity_output_malformed",
            "detail": (completed.stderr or completed.stdout)[-4000:],
            "output_sha256": output_sha256,
        }
    goals = _coverage_goals(payload)
    expected = set(expected_functions)
    if not expected or any(not item for item in expected):
        raise CbmcBackendError("nonvacuity witness function inventory is empty")
    matching = {
        property_id: status
        for property_id, (status, function) in goals.items()
        if function in expected
    }
    observed_functions = {function for _status, function in goals.values()}
    witnessed = {
        goals[property_id][1]
        for property_id, status in matching.items()
        if status == "SATISFIED"
    }
    if (
        completed.returncode == 0
        and matching
        and len(goals) == len(expected)
        and observed_functions == expected
        and all(status == "SATISFIED" for status in matching.values())
        and witnessed == expected
    ):
        return {
            "status": "satisfied",
            "code": "cbmc_nonvacuity_witness",
            "properties": len(matching),
            "property_ids": sorted(
                property_id
                for property_id, status in matching.items()
                if status == "SATISFIED"
            ),
            "expected_functions": sorted(expected),
            "witnessed_functions": sorted(witnessed),
            "output_sha256": output_sha256,
        }
    return {
        "status": "incomplete",
        "code": "cbmc_nonvacuity_unwitnessed",
        "detail": ", ".join(
            f"{property_id}:{status}:{function}"
            for property_id, (status, function) in sorted(goals.items())
        )[:4000]
        or (completed.stderr or completed.stdout)[-4000:],
        "output_sha256": output_sha256,
    }


def _output_sha256(stdout: str | bytes, stderr: str | bytes) -> str:
    stdout_bytes = stdout.encode("utf-8") if isinstance(stdout, str) else stdout
    stderr_bytes = stderr.encode("utf-8") if isinstance(stderr, str) else stderr
    return hashlib.sha256(stdout_bytes + b"\0" + stderr_bytes).hexdigest()


def _parse_json(text: str) -> list[object] | None:
    try:
        value = json.loads(text)
    except json.JSONDecodeError:
        return None
    return value if isinstance(value, list) else [value]


def _failures(payload: list[object]) -> list[Mapping[str, object]]:
    return [
        item
        for item in _property_results(payload)
        if _normalized_property_status(item.get("status")) == "FAILURE"
    ]


def _property_statuses(payload: list[object]) -> dict[str, str]:
    result: dict[str, str] = {}
    for item in _property_results(payload):
        property_id = item.get("property")
        status = _normalized_property_status(item.get("status"))
        if not isinstance(property_id, str) or not property_id:
            continue
        previous = result.get(property_id)
        result[property_id] = (
            "CONTRADICTORY"
            if previous is not None and previous != status
            else status
        )
    return result


def _property_results(payload: list[object]) -> list[Mapping[str, object]]:
    """Accept both ordinary and ``--stop-on-fail`` CBMC JSON layouts."""

    result: list[Mapping[str, object]] = []
    for row in payload:
        if not isinstance(row, Mapping):
            continue
        nested = row.get("result")
        if isinstance(nested, list):
            result.extend(item for item in nested if isinstance(item, Mapping))
        # CBMC's stop-on-fail envelope only places the first failing property
        # directly in the top-level array.  Do not accept an invented direct
        # success envelope as proof-authorizing output.
        if isinstance(row.get("property"), str) and row.get("status") == "failed":
            result.append(row)
    return result


def _normalized_property_status(value: object) -> str:
    if not isinstance(value, str) or not value:
        return "MALFORMED"
    if value == "SUCCESS":
        return "SUCCESS"
    if value in {"FAILURE", "failed"}:
        return "FAILURE"
    return "UNSUPPORTED"


def _failure_source(result: Mapping[str, object]) -> object:
    source = result.get("sourceLocation")
    if isinstance(source, Mapping):
        return source
    trace = result.get("trace")
    if not isinstance(trace, list):
        return None
    for row in reversed(trace):
        if not isinstance(row, Mapping) or row.get("stepType") != "failure":
            continue
        location = row.get("sourceLocation")
        if isinstance(location, Mapping):
            return location
    return None


def _coverage_goals(payload: list[object]) -> dict[str, tuple[str, str]]:
    """Return CBMC cover goal statuses and their source functions."""

    result: dict[str, tuple[str, str]] = {}
    for row in payload:
        if not isinstance(row, Mapping) or not isinstance(row.get("goals"), list):
            continue
        for item in row["goals"]:
            if not isinstance(item, Mapping):
                continue
            property_id = item.get("goal")
            status = item.get("status")
            location = item.get("sourceLocation")
            function = (
                location.get("function") if isinstance(location, Mapping) else None
            )
            if (
                not isinstance(property_id, str)
                or not property_id
                or not isinstance(status, str)
                or not status
                or not isinstance(function, str)
                or not function
            ):
                continue
            normalized = status.upper()
            current = (normalized, function)
            previous = result.get(property_id)
            result[property_id] = (
                ("CONTRADICTORY", function)
                if previous is not None and previous != current
                else current
            )
    return result


def _compact_trace(value: object) -> list[dict[str, object]]:
    if not isinstance(value, list):
        return []
    result: list[dict[str, object]] = []
    for row in value:
        if not isinstance(row, Mapping) or row.get("stepType") not in {
            "assignment",
            "failure",
        }:
            continue
        result.append(
            {
                key: row[key]
                for key in (
                    "stepType",
                    "lhs",
                    "value",
                    "sourceLocation",
                    "comment",
                )
                if key in row
            }
        )
    # Initial nondeterministic assignments explain the witness inputs, while
    # the final assignments explain the violated relation.  Keeping only the
    # first N entries used to discard the failure and every useful derived
    # value on realistic Behavioral-C shards.
    if len(result) <= 128:
        return result
    interesting = re.compile(
        r"(?:spx_proof_exact_result|source_result|spx_(?:exact|source)_world\."
        r"(?:overflow|visible_write_count|call_count|atomic_count))"
    )
    selected = {
        *range(min(16, len(result))),
        *range(max(0, len(result) - 96), len(result)),
        *(
            index
            for index, row in enumerate(result)
            if row.get("stepType") == "failure"
            or interesting.search(str(row.get("lhs", ""))) is not None
        ),
    }
    return [result[index] for index in sorted(selected)]


__all__ = [
    "CbmcBackendError",
    "cbmc_version",
    "discover_cbmc_assertions",
    "discover_cbmc_loops",
    "discover_cbmc_safety_properties",
    "run_cbmc_properties",
    "run_cbmc_cover",
]
