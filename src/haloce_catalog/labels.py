from __future__ import annotations

import hashlib
import re
import sqlite3
from pathlib import Path
from typing import Iterable

from .util import json_dumps, utc_now


def stable_label(prefix: str, parts: Iterable[object], *, hint: str | None = None) -> str:
    digest = hashlib.sha1()
    for part in parts:
        digest.update(str(part).encode("utf-8", errors="surrogateescape"))
        digest.update(b"\0")
    suffix = digest.hexdigest()[:12]
    hint_part = f"_{slug(hint)}" if hint else ""
    return f"{prefix}{hint_part}_{suffix}"


def module_label(path: str, sha256: str) -> str:
    stem = slug(Path(path).name)
    return stable_label("mod", [path, sha256], hint=stem)


def function_label(binary_label: str, rva: int, source: str, name: str) -> str:
    hint = slug(name)
    if hint in {"entrypoint", "dll_entrypoint"}:
        return stable_label("fn", [binary_label, rva, source, name], hint=hint)
    return stable_label("fn", [binary_label, rva, source, name])


def executable_range_label(binary_label: str, rva_start: int, rva_end: int, classification: str) -> str:
    return stable_label("range", [binary_label, rva_start, rva_end, classification])


def executable_byte_class_label(
    binary_label: str,
    rva_start: int,
    rva_end: int,
    classification: str,
    source: str,
) -> str:
    return stable_label("ebyte", [binary_label, rva_start, rva_end, classification, source])


def basic_block_label(binary_label: str, rva_start: int, rva_end: int, source: str) -> str:
    return stable_label("bb", [binary_label, rva_start, rva_end, source])


def cfg_edge_label(binary_label: str, from_rva: int, to_rva: int, edge_type: str, source: str) -> str:
    return stable_label("cfg", [binary_label, from_rva, to_rva, edge_type, source])


def call_edge_label(
    binary_label: str,
    caller_rva: int,
    callee_binary_label: str | None,
    callee_rva: int | None,
    callee_symbol: str | None,
    call_type: str,
    source: str,
) -> str:
    return stable_label(
        "call",
        [binary_label, caller_rva, callee_binary_label or "", callee_rva or "", callee_symbol or "", call_type, source],
    )


def data_ref_label(binary_label: str, from_rva: int, to_rva: int, ref_type: str, source: str) -> str:
    return stable_label("dref", [binary_label, from_rva, to_rva, ref_type, source])


def global_label(binary_label: str, rva: int, name: str) -> str:
    return stable_label("glob", [binary_label, rva, name], hint=name)


def static_cross_check_label(binary_label: str, tool: str, checked_at: str, attempt: int | None = None) -> str:
    return stable_label("xcheck", [binary_label, tool, checked_at, attempt or ""], hint=f"{tool}_{binary_label}")


def platform_endpoint_label(dll: str, symbol: str | None, ordinal: int | None) -> str:
    name = symbol if symbol else (f"ord_{ordinal}" if ordinal is not None else "unknown")
    return stable_label("api", [dll.lower(), symbol or "", ordinal or ""], hint=f"{dll}_{name}")


def interface_test_case_label(endpoint_label: str, case_kind: str, test_id: str) -> str:
    return stable_label("ifacetest", [endpoint_label, case_kind, test_id], hint=f"{case_kind}_{test_id}")


def data_structure_label(name: str, structure_kind: str) -> str:
    return stable_label("data", [name, structure_kind], hint=f"{structure_kind}_{name}")


def data_state_test_case_label(data_structure_label_value: str, case_kind: str, test_id: str) -> str:
    return stable_label("datatest", [data_structure_label_value, case_kind, test_id], hint=f"{case_kind}_{test_id}")


def oracle_test_case_label(suite_id: str, case_kind: str, test_id: str) -> str:
    return stable_label("oracletest", [suite_id, case_kind, test_id], hint=f"{case_kind}_{suite_id}_{test_id}")


def internal_harness_label(target_label: str, harness_id: str) -> str:
    return stable_label("harness", [target_label, harness_id], hint=f"{harness_id}_{target_label}")


def internal_harness_run_label(internal_harness_label_value: str, test_id: str) -> str:
    return stable_label("harnessrun", [internal_harness_label_value, test_id], hint=test_id)


def mutation_test_case_label(mutation_kind: str, target_label: str | None, test_id: str) -> str:
    return stable_label("muttest", [mutation_kind, target_label or "", test_id], hint=f"{mutation_kind}_{test_id}")


def behavior_contract_label(contract_id: str, version: str) -> str:
    return stable_label("behavior", [contract_id, version], hint=contract_id)


def behavior_observation_label(behavior_contract_label_value: str, test_id: str) -> str:
    return stable_label("behavobs", [behavior_contract_label_value, test_id], hint=test_id)


def process_behavior_observation_label(behavior_contract_label_value: str, test_id: str) -> str:
    return stable_label("procobs", [behavior_contract_label_value, test_id], hint=test_id)


def test_run_label(test_id: str, suite: str, started_at: str) -> str:
    return stable_label("test", [suite, test_id, started_at], hint=test_id)


def trace_probe_label(probe_id: str, command: str, started_at: str) -> str:
    return stable_label("traceprobe", [probe_id, command, started_at], hint=probe_id)


def value_trace_label(test_id: str, module_sha256: str, routine_label: str | None, block_label: str | None) -> str:
    return stable_label(
        "valtrace",
        [test_id, module_sha256, routine_label or "", block_label or ""],
        hint=f"{test_id}_{routine_label or block_label or module_sha256[:12]}",
    )


def private_artifact_bundle_label(artifact_set_id: str, root_path: str) -> str:
    return stable_label("privbundle", [artifact_set_id, root_path], hint=artifact_set_id)


def private_artifact_label(bundle_label: str, artifact_kind: str, path: str) -> str:
    return stable_label("privart", [bundle_label, artifact_kind, path], hint=artifact_kind)


def waiver_label(binary_label: str, rva_start: int, rva_end: int, category: str, reason: str) -> str:
    return stable_label("waiver", [binary_label, rva_start, rva_end, category, reason])


def coverage_block_label(test_label: str, module_label_value: str | None, rva_start: int, rva_end: int) -> str:
    return stable_label("covbb", [test_label, module_label_value or "", rva_start, rva_end])


def coverage_edge_label(test_label: str, module_label_value: str | None, from_rva: int, to_rva: int) -> str:
    return stable_label("covcfg", [test_label, module_label_value or "", from_rva, to_rva])


def coverage_call_label(
    test_label: str,
    module_label_value: str | None,
    caller_rva: int,
    callee_binary_label: str | None,
    callee_rva: int | None,
    callee_symbol: str | None,
) -> str:
    return stable_label(
        "covcall",
        [test_label, module_label_value or "", caller_rva, callee_binary_label or "", callee_rva or "", callee_symbol or ""],
    )


def ensure_label(
    conn: sqlite3.Connection,
    label: str,
    entity_type: str,
    display_name: str,
    description: str = "",
    *,
    private: bool = True,
    created_at: str | None = None,
) -> str:
    conn.execute(
        """
        INSERT OR IGNORE INTO labels(label, entity_type, display_name, description, private, created_at)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (label, entity_type, display_name, description, 1 if private else 0, created_at or utc_now()),
    )
    return label


def ensure_oracle_mapping(
    conn: sqlite3.Connection,
    *,
    label: str,
    entity_type: str,
    binary_id: int | None,
    module_sha256: str | None,
    rva_start: int | None,
    rva_end: int | None,
    private: dict[str, object] | None = None,
) -> None:
    conn.execute(
        """
        INSERT OR REPLACE INTO oracle_mappings(
          label, entity_type, binary_id, module_sha256, rva_start, rva_end, private_json
        )
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (label, entity_type, binary_id, module_sha256, rva_start, rva_end, json_dumps(private or {})),
    )


def slug(value: str | None) -> str:
    if not value:
        return ""
    cleaned = re.sub(r"[^A-Za-z0-9]+", "_", value).strip("_").lower()
    return cleaned[:48] or "item"
