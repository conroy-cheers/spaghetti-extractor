from __future__ import annotations

import shlex
import sqlite3
from pathlib import Path
from typing import Any, Mapping, Sequence

from .behavior import compare_json_behavior
from .labels import ensure_label, mutation_test_case_label
from .util import utc_now


REQUIRED_MUTATION_KINDS = (
    "wrong_implementation",
    "inverted_branch",
    "skipped_external_call",
    "corrupted_serializer",
    "bad_packet_codec",
    "changed_mock_api_behavior",
)
MUTATION_TEST_STATUSES = ("planned", "killed", "survived", "invalid")


def record_mutation_test_case(
    conn: sqlite3.Connection,
    *,
    mutation_kind: str,
    test_id: str,
    status: str = "killed",
    target_label: str | None = None,
    evidence: str = "",
    command: str | None = None,
    fixture_path: Path | str | None = None,
    created_at: str | None = None,
    required_mutation_kinds: tuple[str, ...] = REQUIRED_MUTATION_KINDS,
) -> dict[str, Any]:
    if mutation_kind not in required_mutation_kinds:
        raise ValueError(f"unknown mutation kind: {mutation_kind}")
    if status not in MUTATION_TEST_STATUSES:
        raise ValueError(f"unknown mutation test status: {status}")

    label = mutation_test_case_label(mutation_kind, target_label, test_id)
    created = created_at or utc_now()
    ensure_label(
        conn,
        label,
        "mutation_test_case",
        f"{mutation_kind}:{target_label or 'global'}:{test_id}",
        "mutation-effectiveness evidence",
        created_at=created,
    )
    conn.execute(
        """
        INSERT INTO mutation_test_cases(
          label, mutation_kind, target_label, test_id, status, evidence,
          command, fixture_path, created_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(label) DO UPDATE SET
          mutation_kind = excluded.mutation_kind,
          target_label = excluded.target_label,
          test_id = excluded.test_id,
          status = excluded.status,
          evidence = excluded.evidence,
          command = excluded.command,
          fixture_path = excluded.fixture_path
        """,
        (
            label,
            mutation_kind,
            target_label,
            test_id,
            status,
            evidence,
            command,
            str(fixture_path) if fixture_path is not None else None,
            created,
        ),
    )
    return {
        "label": label,
        "mutation_kind": mutation_kind,
        "target_label": target_label,
        "test_id": test_id,
        "status": status,
    }


def run_json_mutation_test(
    conn: sqlite3.Connection,
    *,
    mutation_kind: str,
    test_id: str,
    expected: Mapping[str, Any],
    command: Sequence[str],
    artifact_dir: Path,
    target_label: str | None = None,
    timeout_seconds: float = 60.0,
    cwd: Path | str | None = None,
    env: Mapping[str, str] | None = None,
    expected_path: Path | str | None = None,
    required_mutation_kinds: tuple[str, ...] = REQUIRED_MUTATION_KINDS,
) -> dict[str, Any]:
    comparison = compare_json_behavior(
        expected=expected,
        expected_path=expected_path,
        command=command,
        artifact_dir=artifact_dir,
        test_id=test_id,
        timeout_seconds=timeout_seconds,
        cwd=cwd,
        env=env,
    )
    status = "survived" if comparison["status"] == "pass" else "killed"
    evidence = (
        "mutant survived JSON behavior comparison"
        if status == "survived"
        else f"mutant killed by JSON behavior comparison: {'; '.join(comparison['failures'])}"
    )
    with conn:
        record = record_mutation_test_case(
            conn,
            mutation_kind=mutation_kind,
            target_label=target_label,
            test_id=test_id,
            status=status,
            evidence=evidence,
            command=shlex.join(str(part) for part in command),
            fixture_path=comparison["result_path"],
            required_mutation_kinds=required_mutation_kinds,
        )
    return {
        **record,
        "comparison": {
            "status": comparison["status"],
            "failures": comparison["failures"],
            "expected_sha256": comparison["expected_sha256"],
            "observed_sha256": comparison["observed_sha256"],
            "result_path": comparison["result_path"],
        },
    }
