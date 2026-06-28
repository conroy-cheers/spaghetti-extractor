from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Any

from .labels import data_state_test_case_label, data_structure_label, ensure_label
from .util import utc_now


DATA_STATE_TEST_STATUSES = ("planned", "pass", "fail")
BASE_DATA_STATE_CASES = ("fixture", "malformed_input")
ROUND_TRIP_KINDS = {"map", "profile", "save", "packet", "config", "codec", "serializer"}
TRANSITION_KINDS = {"state_machine"}


def required_data_state_cases(
    structure_kind: str,
    *,
    round_trip_kinds: set[str] | None = None,
    transition_kinds: set[str] | None = None,
) -> tuple[str, ...]:
    round_trip = ROUND_TRIP_KINDS if round_trip_kinds is None else round_trip_kinds
    transition = TRANSITION_KINDS if transition_kinds is None else transition_kinds
    normalized = structure_kind.strip().lower().replace("-", "_")
    required = list(BASE_DATA_STATE_CASES)
    parts = set(part for part in normalized.split("_") if part)
    if normalized in round_trip or parts & round_trip:
        required.append("round_trip")
    if normalized in transition or normalized.endswith("_state_machine") or "state_machine" in normalized:
        required.append("transition")
    return tuple(dict.fromkeys(required))


def upsert_data_structure(
    conn: sqlite3.Connection,
    *,
    name: str,
    structure_kind: str,
    spec_status: str = "unknown",
    fixture_status: str = "missing",
    description: str = "",
    created_at: str | None = None,
) -> dict[str, Any]:
    label = data_structure_label(name, structure_kind)
    ensure_label(
        conn,
        label,
        "data_structure",
        name,
        description or f"{structure_kind} data structure",
        created_at=created_at or utc_now(),
    )
    conn.execute(
        """
        INSERT INTO data_structures(label, name, structure_kind, spec_status, fixture_status, description)
        VALUES (?, ?, ?, ?, ?, ?)
        ON CONFLICT(label) DO UPDATE SET
          name = excluded.name,
          structure_kind = excluded.structure_kind,
          spec_status = excluded.spec_status,
          fixture_status = excluded.fixture_status,
          description = excluded.description
        """,
        (label, name, structure_kind, spec_status, fixture_status, description),
    )
    return {
        "label": label,
        "name": name,
        "structure_kind": structure_kind,
        "required_case_kinds": list(required_data_state_cases(structure_kind)),
    }


def record_data_state_test_case(
    conn: sqlite3.Connection,
    *,
    data_structure_label_value: str,
    case_kind: str,
    test_id: str,
    status: str = "pass",
    evidence: str = "",
    fixture_path: Path | str | None = None,
    created_at: str | None = None,
    round_trip_kinds: set[str] | None = None,
    transition_kinds: set[str] | None = None,
) -> dict[str, Any]:
    if status not in DATA_STATE_TEST_STATUSES:
        raise ValueError(f"unknown data-state test status: {status}")

    data_structure = conn.execute(
        """
        SELECT id, label, name, structure_kind
        FROM data_structures
        WHERE label = ?
        """,
        (data_structure_label_value,),
    ).fetchone()
    if data_structure is None:
        raise ValueError(f"unknown data structure label: {data_structure_label_value}")

    required_cases = required_data_state_cases(
        str(data_structure["structure_kind"]),
        round_trip_kinds=round_trip_kinds,
        transition_kinds=transition_kinds,
    )
    if case_kind not in required_cases:
        raise ValueError(
            f"case kind {case_kind!r} is not required for {data_structure['structure_kind']!r}; "
            f"expected one of: {', '.join(required_cases)}"
        )

    label = data_state_test_case_label(data_structure_label_value, case_kind, test_id)
    created = created_at or utc_now()
    ensure_label(
        conn,
        label,
        "data_state_test_case",
        f"{data_structure_label_value}:{case_kind}:{test_id}",
        "data/state behavior test case",
        created_at=created,
    )
    conn.execute(
        """
        INSERT INTO data_state_test_cases(
          label, data_structure_id, case_kind, test_id, status, evidence, fixture_path, created_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(data_structure_id, case_kind, test_id) DO UPDATE SET
          status = excluded.status,
          evidence = excluded.evidence,
          fixture_path = excluded.fixture_path
        """,
        (
            label,
            int(data_structure["id"]),
            case_kind,
            test_id,
            status,
            evidence,
            str(fixture_path) if fixture_path is not None else None,
            created,
        ),
    )
    return {
        "label": label,
        "data_structure_label": data_structure_label_value,
        "case_kind": case_kind,
        "test_id": test_id,
        "status": status,
    }
