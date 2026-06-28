from __future__ import annotations

import json
import sqlite3
from typing import Any

from .labels import ensure_label, ensure_oracle_mapping
from .util import json_dumps, utc_now


ROUTINE_CONTRACT_EVIDENCE_SOURCES = {
    "dynamic_observation",
    "strings_imports",
    "callsite_context",
    "disassembly_inferred",
    "human_review",
}
ROUTINE_CONTRACT_CONFIDENCE = {"low", "medium", "high"}
ROUTINE_CONTRACT_TAINT_LEVELS = {
    "behavioral_public",
    "static_inferred_public",
    "private_only",
}
ROUTINE_CONTRACT_REVIEW_STATUSES = {
    "draft",
    "reviewed",
    "rejected_for_publication",
}


def classify_functions(
    conn: sqlite3.Connection,
    *,
    scopes: tuple[str, ...] = ("included", "candidate"),
    subsystem: str,
    purity: str,
    side_effects: str,
    calling_convention: str | None = None,
    signature: str | None = None,
    confidence: str = "medium",
    test_status: str = "specified",
    clean_room_status: str = "ready",
    evidence: str,
    filename: str | None = None,
    function_label: str | None = None,
    name: str | None = None,
    source: str | None = None,
) -> dict[str, Any]:
    if not scopes:
        raise ValueError("at least one binary scope is required")
    if not evidence.strip():
        raise ValueError("function classification evidence is required")

    predicates = [f"b.scope IN ({','.join('?' for _ in scopes)})"]
    params: list[Any] = list(scopes)
    if filename is not None:
        predicates.append("lower(b.filename) = lower(?)")
        params.append(filename)
    if function_label is not None:
        predicates.append("f.label = ?")
        params.append(function_label)
    if name is not None:
        predicates.append("f.name = ?")
        params.append(name)
    if source is not None:
        predicates.append("f.source = ?")
        params.append(source)

    set_clauses = [
        "subsystem = ?",
        "purity = ?",
        "side_effects = ?",
        "confidence = ?",
        "test_status = ?",
        "clean_room_status = ?",
    ]
    set_params: list[Any] = [subsystem, purity, side_effects, confidence, test_status, clean_room_status]
    if calling_convention is not None:
        set_clauses.append("calling_convention = ?")
        set_params.append(calling_convention)
    if signature is not None:
        set_clauses.append("signature = ?")
        set_params.append(signature)

    rows = [
        dict(row)
        for row in conn.execute(
            f"""
            SELECT f.id, f.label, f.name, b.path AS binary_path
            FROM functions f
            JOIN binaries b ON b.id = f.binary_id
            WHERE {' AND '.join(predicates)}
            ORDER BY b.path, f.rva, f.name
            """,
            params,
        )
    ]
    for row in rows:
        conn.execute(
            f"""
            UPDATE functions
            SET {', '.join(set_clauses)}
            WHERE id = ?
            """,
            (*set_params, int(row["id"])),
        )
        conn.execute(
            """
            UPDATE labels
            SET description = ?, private = 0
            WHERE label = ?
            """,
            (evidence, row["label"]),
        )
    return {
        "functions": len(rows),
        "scopes": list(scopes),
        "subsystem": subsystem,
        "purity": purity,
        "side_effects": side_effects,
        "confidence": confidence,
        "test_status": test_status,
        "clean_room_status": clean_room_status,
        "filters": {
            "filename": filename,
            "function_label": function_label,
            "name": name,
            "source": source,
        },
    }


def upsert_internal_routine_contract(
    conn: sqlite3.Connection,
    *,
    label: str,
    function_label: str,
    public_name: str,
    purpose_summary: str,
    calling_convention: str,
    signature: str,
    input_shape: dict[str, Any] | None = None,
    output_shape: dict[str, Any] | None = None,
    preconditions: list[str] | None = None,
    postconditions: list[str] | None = None,
    side_effects: list[str] | None = None,
    state_transitions: list[str] | None = None,
    fixtures: list[str] | None = None,
    evidence_labels: list[str] | None = None,
    evidence_source: str,
    confidence: str,
    taint_level: str,
    review_status: str,
) -> dict[str, Any]:
    _validate_contract_field("evidence_source", evidence_source, ROUTINE_CONTRACT_EVIDENCE_SOURCES)
    _validate_contract_field("confidence", confidence, ROUTINE_CONTRACT_CONFIDENCE)
    _validate_contract_field("taint_level", taint_level, ROUTINE_CONTRACT_TAINT_LEVELS)
    _validate_contract_field("review_status", review_status, ROUTINE_CONTRACT_REVIEW_STATUSES)
    if not label.strip():
        raise ValueError("routine contract label is required")
    if not public_name.strip():
        raise ValueError("routine contract public_name is required")
    if not purpose_summary.strip():
        raise ValueError("routine contract purpose_summary is required")

    row = conn.execute(
        """
        SELECT f.id, f.rva, f.binary_id, b.sha256 AS module_sha256
        FROM functions f
        JOIN binaries b ON b.id = f.binary_id
        WHERE f.label = ?
        """,
        (function_label,),
    ).fetchone()
    if row is None:
        raise ValueError(f"unknown function label: {function_label}")

    created_at = utc_now()
    label_private = 1 if taint_level == "private_only" or review_status == "rejected_for_publication" else 0
    ensure_label(
        conn,
        label,
        "internal_routine_contract",
        public_name,
        purpose_summary,
        private=label_private,
        created_at=created_at,
    )
    ensure_oracle_mapping(
        conn,
        label=label,
        entity_type="internal_routine_contract",
        binary_id=int(row["binary_id"]),
        module_sha256=str(row["module_sha256"]),
        rva_start=int(row["rva"]),
        rva_end=None,
        private={"function_label": function_label},
    )
    conn.execute(
        """
        INSERT INTO internal_routine_contracts(
          label, function_id, public_name, purpose_summary, calling_convention, signature,
          input_shape_json, output_shape_json, preconditions_json, postconditions_json,
          side_effects_json, state_transitions_json, fixtures_json, evidence_labels_json,
          evidence_source, confidence, taint_level, review_status, created_at, updated_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(label) DO UPDATE SET
          function_id = excluded.function_id,
          public_name = excluded.public_name,
          purpose_summary = excluded.purpose_summary,
          calling_convention = excluded.calling_convention,
          signature = excluded.signature,
          input_shape_json = excluded.input_shape_json,
          output_shape_json = excluded.output_shape_json,
          preconditions_json = excluded.preconditions_json,
          postconditions_json = excluded.postconditions_json,
          side_effects_json = excluded.side_effects_json,
          state_transitions_json = excluded.state_transitions_json,
          fixtures_json = excluded.fixtures_json,
          evidence_labels_json = excluded.evidence_labels_json,
          evidence_source = excluded.evidence_source,
          confidence = excluded.confidence,
          taint_level = excluded.taint_level,
          review_status = excluded.review_status,
          updated_at = excluded.updated_at
        """,
        (
            label,
            int(row["id"]),
            public_name,
            purpose_summary,
            calling_convention,
            signature,
            json_dumps(input_shape or {}),
            json_dumps(output_shape or {}),
            json_dumps(preconditions or []),
            json_dumps(postconditions or []),
            json_dumps(side_effects or []),
            json_dumps(state_transitions or []),
            json_dumps(fixtures or []),
            json_dumps(evidence_labels or []),
            evidence_source,
            confidence,
            taint_level,
            review_status,
            created_at,
            created_at,
        ),
    )
    conn.execute(
        """
        UPDATE labels
        SET display_name = ?, description = ?, private = ?
        WHERE label = ?
        """,
        (public_name, purpose_summary, label_private, label),
    )
    return {
        "label": label,
        "function_label": function_label,
        "public_name": public_name,
        "evidence_source": evidence_source,
        "confidence": confidence,
        "taint_level": taint_level,
        "review_status": review_status,
    }


def parse_contract_json(value: str | None, default: Any) -> Any:
    if value is None:
        return default
    parsed = json.loads(value)
    return parsed


def _validate_contract_field(name: str, value: str, allowed: set[str]) -> None:
    if value not in allowed:
        raise ValueError(f"{name} must be one of {sorted(allowed)}")
