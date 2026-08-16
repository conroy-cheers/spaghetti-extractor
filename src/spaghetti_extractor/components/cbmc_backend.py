"""Pinned CBMC process execution with fail-closed property parsing."""

from __future__ import annotations

import hashlib
import json
import subprocess
from pathlib import Path
from typing import Mapping, Sequence


class CbmcBackendError(RuntimeError):
    """The configured CBMC executable cannot be identified or invoked."""


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
) -> dict[str, object]:
    """Run one property set and reject malformed or inconclusive output."""

    try:
        completed = subprocess.run(
            list(command),
            text=True,
            capture_output=True,
            check=False,
            timeout=timeout_seconds,
        )
    except subprocess.TimeoutExpired as exc:
        return {
            "status": "incomplete",
            "code": "cbmc_timeout",
            "detail": f"exceeded {timeout_seconds} seconds",
            "output_sha256": _output_sha256(exc.stdout or "", exc.stderr or ""),
        }
    output_sha256 = _output_sha256(completed.stdout, completed.stderr)
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
            "source": first.get("sourceLocation"),
            "counterexample": _compact_trace(first.get("trace")),
            "detail": first.get("description") or first.get("property"),
            "output_sha256": output_sha256,
        }
    if not statuses:
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
        for row in payload
        if isinstance(row, Mapping) and isinstance(row.get("result"), list)
        for item in row["result"]
        if isinstance(item, Mapping) and item.get("status") == "FAILURE"
    ]


def _property_statuses(payload: list[object]) -> dict[str, str]:
    result: dict[str, str] = {}
    for row in payload:
        if not isinstance(row, Mapping) or not isinstance(row.get("result"), list):
            continue
        for item in row["result"]:
            if not isinstance(item, Mapping):
                continue
            property_id = item.get("property")
            status = item.get("status")
            if not isinstance(property_id, str) or not property_id:
                continue
            if not isinstance(status, str) or not status:
                status = "MALFORMED"
            previous = result.get(property_id)
            result[property_id] = (
                "CONTRADICTORY"
                if previous is not None and previous != status
                else status
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
                for key in ("stepType", "lhs", "value", "sourceLocation")
                if key in row
            }
        )
        if len(result) >= 32:
            break
    return result


__all__ = [
    "CbmcBackendError",
    "cbmc_version",
    "run_cbmc_properties",
]
