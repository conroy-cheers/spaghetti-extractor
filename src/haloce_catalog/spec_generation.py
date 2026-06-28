from __future__ import annotations

import json
import sqlite3
from typing import Any

from .util import public_text


def specs_json(conn: sqlite3.Connection) -> dict[str, Any]:
    """Generate label-first clean-room specs from catalog and test evidence.

    This report intentionally avoids raw RVAs, image bases, module hashes, and
    numeric database IDs. Private address mappings stay in oracle_mappings.
    """

    metadata = {row["key"]: row["value"] for row in conn.execute("SELECT key, value FROM metadata ORDER BY key")}
    return {
        "schema_version": 1,
        "catalog": {
            "catalog_version": metadata.get("catalog_version", "unknown"),
            "created_at": metadata.get("created_at", "unknown"),
        },
        "modules": _modules(conn),
        "executable_byte_classes": _executable_byte_classes(conn),
        "functions": _functions(conn),
        "basic_blocks": _basic_blocks(conn),
        "cfg_edges": _cfg_edges(conn),
        "call_edges": _call_edges(conn),
        "coverage_blocks": _coverage_blocks(conn),
        "coverage_edges": _coverage_edges(conn),
        "coverage_call_edges": _coverage_call_edges(conn),
        "data_refs": _data_refs(conn),
        "globals": _globals(conn),
        "waivers": _waivers(conn),
        "platform_endpoints": _platform_endpoints(conn),
        "data_structures": _data_structures(conn),
        "oracle_tests": _oracle_tests(conn),
        "behavior_contracts": _behavior_contracts(conn),
        "internal_routine_contracts": _internal_routine_contracts(conn),
        "internal_harnesses": _internal_harnesses(conn),
        "mutation_tests": _mutation_tests(conn),
        "static_cross_checks": _static_cross_checks(conn),
        "test_runs": _test_runs(conn),
        "trace_probes": _trace_probes(conn),
    }


def specs_markdown(spec: dict[str, Any]) -> str:
    lines = [
        "# Label-First Specifications",
        "",
        "This generated report is derived from catalog labels and observed behavior evidence.",
        "It omits raw RVAs, image bases, module hashes, instruction bytes, and decompiler text.",
        "",
        "## Summary",
        "",
    ]
    for key in [
        "modules",
        "executable_byte_classes",
        "functions",
        "basic_blocks",
        "cfg_edges",
        "call_edges",
        "coverage_blocks",
        "coverage_edges",
        "coverage_call_edges",
        "data_refs",
        "globals",
        "waivers",
        "platform_endpoints",
        "data_structures",
        "oracle_tests",
        "behavior_contracts",
        "internal_routine_contracts",
        "internal_harnesses",
        "mutation_tests",
        "static_cross_checks",
        "test_runs",
        "trace_probes",
    ]:
        lines.append(f"- {key.replace('_', ' ').title()}: {len(spec[key])}")

    lines.extend(["", "## Modules", ""])
    for module in spec["modules"][:100]:
        lines.append(
            f"- `{module['label']}` `{module['path']}` scope={module['scope']} role={module['role']}"
        )

    lines.extend(["", "## Interfaces", ""])
    for endpoint in spec["platform_endpoints"][:100]:
        symbol = endpoint["symbol"] if endpoint["symbol"] is not None else f"#{endpoint['ordinal']}"
        lines.append(
            f"- `{endpoint['label']}` `{endpoint['dll']}!{symbol}` "
            f"mock={endpoint['mock_status']} tests={len(endpoint['test_cases'])}"
        )

    lines.extend(["", "## Data State", ""])
    for structure in spec["data_structures"][:100]:
        lines.append(
            f"- `{structure['label']}` `{structure['name']}` kind={structure['structure_kind']} "
            f"spec={structure['spec_status']} fixtures={structure['fixture_status']}"
        )
        if structure.get("description"):
            lines.append(f"  - Description: {_markdown_inline(structure['description'])}")
        for test_case in structure.get("test_cases", [])[:10]:
            lines.append(
                f"  - `{test_case['test_id']}` case={test_case['case_kind']} status={test_case['status']}: "
                f"{_markdown_inline(test_case.get('evidence') or '')}"
            )

    lines.extend(["", "## Oracle Tests", ""])
    for test in spec["oracle_tests"][:100]:
        lines.append(
            f"- `{test['label']}` suite={test['suite_id']} kind={test['case_kind']} status={test['status']}"
        )

    lines.extend(["", "## Behavior Contracts", ""])
    for contract in spec["behavior_contracts"][:100]:
        lines.append(
            f"- `{contract['label']}` `{contract['contract_id']}` version={contract['version']} "
            f"scope={contract['scope']} observations={len(contract['observations'])} "
            f"process_observations={len(contract.get('process_observations', []))}"
        )
        lines.extend(_behavior_contract_markdown(contract))

    lines.extend(["", "## Internal Routine Contracts", ""])
    for contract in spec["internal_routine_contracts"][:100]:
        lines.append(
            f"- `{contract['label']}` `{contract['public_name']}` function={contract['function_label']} "
            f"confidence={contract['confidence']} taint={contract['taint_level']} review={contract['review_status']}"
        )
        lines.append(f"  - Purpose: {_markdown_inline(contract['purpose_summary'])}")
        lines.append(f"  - Calling convention/signature: `{contract['calling_convention']}` `{contract['signature']}`")
        for key in ["preconditions", "postconditions", "side_effects", "state_transitions"]:
            values = contract.get(key, [])
            if values:
                lines.append(f"  - {key.replace('_', ' ').title()}:")
                for value in values[:20]:
                    lines.append(f"    - {_markdown_inline(value)}")
        if contract.get("input_shape"):
            lines.append("  - Input shape:")
            lines.extend(_indented_json_block(contract["input_shape"], indent="    "))
        if contract.get("output_shape"):
            lines.append("  - Output shape:")
            lines.extend(_indented_json_block(contract["output_shape"], indent="    "))

    lines.extend(["", "## Dynamic Coverage Summary", ""])
    coverage_by_test = _coverage_summary_by_test(spec)
    if coverage_by_test:
        lines.append("| Test ID | Blocks | CFG Edges | Call Edges |")
        lines.append("| --- | ---: | ---: | ---: |")
        for test_id, counts in sorted(coverage_by_test.items())[:100]:
            lines.append(
                f"| `{test_id}` | {counts['blocks']} | {counts['cfg_edges']} | {counts['call_edges']} |"
            )
    else:
        lines.append("- No dynamic coverage has been recorded.")

    lines.extend(["", "## Coverage Evidence Labels", ""])
    for block in spec["coverage_blocks"][:25]:
        lines.append(
            f"- `{block['label']}` block module={block['module_label']} "
            f"test={block['test_id']}"
        )
    for edge in spec["coverage_edges"][:25]:
        lines.append(
            f"- `{edge['label']}` cfg module={edge['module_label']} "
            f"test={edge['test_id']}"
        )
    for edge in spec["coverage_call_edges"][:25]:
        lines.append(
            f"- `{edge['label']}` call module={edge['module_label']} "
            f"callee={edge['callee_module_label'] or edge['callee_symbol']} test={edge['test_id']}"
        )
    hidden_coverage = (
        max(0, len(spec["coverage_blocks"]) - 25)
        + max(0, len(spec["coverage_edges"]) - 25)
        + max(0, len(spec["coverage_call_edges"]) - 25)
    )
    if hidden_coverage:
        lines.append(f"- {hidden_coverage} additional coverage evidence labels are available in `specs.json`.")

    lines.extend(["", "## Waivers", ""])
    for waiver in spec["waivers"][:100]:
        lines.append(
            f"- `{waiver['label']}` module={waiver['module_label']} "
            f"category={waiver['category']} reviewer={waiver['reviewer']}"
        )

    lines.extend(["", "## Trace Probes", ""])
    for probe in spec["trace_probes"][:100]:
        counts = probe["counts"]
        lines.append(
            f"- `{probe['label']}` probe={probe['probe_id']} kind={probe['probe_kind']} "
            f"status={probe['status']} expected_modules={counts['raw_expected_modules']} "
            f"mapped_blocks={counts['mapped_blocks']}"
        )
    lines.append("")
    return "\n".join(lines)


def _behavior_contract_markdown(contract: dict[str, Any]) -> list[str]:
    payload = contract.get("contract", {})
    lines: list[str] = []
    if contract.get("title"):
        lines.append(f"  - Title: {_markdown_inline(contract['title'])}")
    if payload.get("scope"):
        lines.append(f"  - Scope: {_markdown_inline(payload['scope'])}")
    for key in [
        "target",
        "command_line",
        "constants",
        "initial_state",
        "target_generation",
        "scenario_inputs",
        "state_transition",
        "projection",
        "json_transcript",
        "rendering_contract",
    ]:
        if key in payload:
            lines.append(f"  - {key.replace('_', ' ').title()}:")
            lines.extend(_indented_json_block(payload[key], indent="    "))
    observations = contract.get("observations", [])
    if observations:
        lines.append("  - Observations:")
        for observation in observations[:25]:
            observed = observation.get("observed") or {}
            summary = _behavior_observation_summary(observed)
            status = observation.get("status", "unknown")
            digest = str(observation.get("observed_sha256") or "")
            digest_suffix = f" sha256={digest[:12]}" if digest else ""
            lines.append(
                f"    - `{observation['test_id']}` status={status}{digest_suffix}"
                f"{(': ' + summary) if summary else ''}"
            )
        if len(observations) > 25:
            lines.append(f"    - {len(observations) - 25} additional observations are available in `specs.json`.")
    process_observations = contract.get("process_observations", [])
    if process_observations:
        lines.append("  - Process Observations:")
        for observation in process_observations[:25]:
            observed = observation.get("observed") or {}
            summary = _process_observation_summary(observed)
            status = observation.get("status", "unknown")
            digest = str(observation.get("observed_sha256") or "")
            digest_suffix = f" sha256={digest[:12]}" if digest else ""
            lines.append(
                f"    - `{observation['test_id']}` status={status}{digest_suffix}"
                f"{(': ' + summary) if summary else ''}"
            )
        if len(process_observations) > 25:
            lines.append(
                f"    - {len(process_observations) - 25} additional process observations are available in `specs.json`."
            )
    return lines


def _behavior_observation_summary(observed: dict[str, Any]) -> str:
    parts: list[str] = []
    for key in ["scenario", "seed", "frames", "aggregate_hash"]:
        if key in observed:
            parts.append(f"{key}={observed[key]}")
    final = observed.get("final")
    if isinstance(final, dict):
        final_parts = []
        for key in ["frame", "score", "energy", "health", "collected_mask"]:
            if key in final:
                final_parts.append(f"{key}={final[key]}")
        if final_parts:
            parts.append("final(" + ", ".join(final_parts) + ")")
    return ", ".join(parts)


def _process_observation_summary(observed: dict[str, Any]) -> str:
    parts: list[str] = []
    if "returncode" in observed:
        parts.append(f"returncode={observed['returncode']}")
    if observed.get("timed_out"):
        parts.append("timed_out=true")
    stdout = observed.get("stdout")
    if isinstance(stdout, str):
        parts.append(f"stdout_bytes={len(stdout.encode('utf-8', errors='replace'))}")
    stderr = observed.get("stderr")
    if isinstance(stderr, str):
        parts.append(f"stderr_bytes={len(stderr.encode('utf-8', errors='replace'))}")
    return ", ".join(parts)


def _coverage_summary_by_test(spec: dict[str, Any]) -> dict[str, dict[str, int]]:
    summary: dict[str, dict[str, int]] = {}

    def counts_for(test_id: str) -> dict[str, int]:
        return summary.setdefault(test_id, {"blocks": 0, "cfg_edges": 0, "call_edges": 0})

    for block in spec.get("coverage_blocks", []):
        counts_for(block["test_id"])["blocks"] += 1
    for edge in spec.get("coverage_edges", []):
        counts_for(edge["test_id"])["cfg_edges"] += 1
    for edge in spec.get("coverage_call_edges", []):
        counts_for(edge["test_id"])["call_edges"] += 1
    return summary


def _indented_json_block(value: Any, *, indent: str) -> list[str]:
    text = json.dumps(value, indent=2, sort_keys=True)
    return [f"{indent}```json", *[f"{indent}{line}" for line in text.splitlines()], f"{indent}```"]


def _markdown_inline(value: object) -> str:
    text = str(value)
    return text.replace("\n", " ").replace("|", "\\|")


def _modules(conn: sqlite3.Connection) -> list[dict[str, Any]]:
    rows = []
    for row in conn.execute(
        """
        SELECT b.label, b.path, b.filename, b.kind, b.machine, b.subsystem, b.role, b.scope, b.role_reason,
               (SELECT COUNT(*) FROM functions f WHERE f.binary_id = b.id) AS functions,
               (SELECT COUNT(*) FROM basic_blocks bb WHERE bb.binary_id = b.id) AS basic_blocks,
               (SELECT COUNT(*) FROM cfg_edges ce WHERE ce.binary_id = b.id) AS cfg_edges,
               (SELECT COUNT(*) FROM call_edges call WHERE call.binary_id = b.id) AS call_edges,
               (
                 SELECT COUNT(*)
                 FROM executable_byte_classes ebc
                 WHERE ebc.binary_id = b.id
               ) AS executable_byte_classes
        FROM binaries b
        ORDER BY b.scope, b.path
        """
    ):
        rows.append(
            {
                "label": row["label"],
                "path": row["path"],
                "filename": row["filename"],
                "kind": row["kind"],
                "machine": row["machine"],
                "subsystem": row["subsystem"],
                "role": row["role"],
                "scope": row["scope"],
                "role_reason": row["role_reason"],
                "counts": {
                    "functions": row["functions"],
                    "basic_blocks": row["basic_blocks"],
                    "cfg_edges": row["cfg_edges"],
                    "call_edges": row["call_edges"],
                    "executable_byte_classes": row["executable_byte_classes"],
                },
            }
        )
    return rows


def _executable_byte_classes(conn: sqlite3.Connection) -> list[dict[str, Any]]:
    return _dicts(
        conn,
        """
        SELECT ebc.label, b.label AS module_label, ebc.classification, ebc.source,
               ebc.evidence, ebc.confidence
        FROM executable_byte_classes ebc
        JOIN binaries b ON b.id = ebc.binary_id
        ORDER BY b.scope, b.path, ebc.rva_start, ebc.rva_end
        """,
    )


def _functions(conn: sqlite3.Connection) -> list[dict[str, Any]]:
    return _dicts(
        conn,
        """
        SELECT f.label, b.label AS module_label, f.name, f.source, f.calling_convention,
               f.signature, f.subsystem, f.purity, f.side_effects, f.confidence,
               f.test_status, f.clean_room_status
        FROM functions f
        JOIN binaries b ON b.id = f.binary_id
        ORDER BY b.scope, b.path, f.name, f.label
        """,
    )


def _basic_blocks(conn: sqlite3.Connection) -> list[dict[str, Any]]:
    return _dicts(
        conn,
        """
        SELECT bb.label, b.label AS module_label, f.label AS function_label,
               bb.source, bb.classification, bb.confidence
        FROM basic_blocks bb
        JOIN binaries b ON b.id = bb.binary_id
        LEFT JOIN functions f ON f.id = bb.function_id
        ORDER BY b.scope, b.path, bb.rva_start, bb.rva_end
        """,
    )


def _cfg_edges(conn: sqlite3.Connection) -> list[dict[str, Any]]:
    return _dicts(
        conn,
        """
        SELECT ce.label, b.label AS module_label, f.label AS function_label,
               ce.edge_type, ce.source, ce.confidence
        FROM cfg_edges ce
        JOIN binaries b ON b.id = ce.binary_id
        LEFT JOIN functions f ON f.id = ce.function_id
        ORDER BY b.scope, b.path, ce.label
        """,
    )


def _call_edges(conn: sqlite3.Connection) -> list[dict[str, Any]]:
    return _dicts(
        conn,
        """
        SELECT call.label, b.label AS module_label, callee.label AS callee_module_label,
               call.callee_symbol, call.call_type, call.source, call.confidence
        FROM call_edges call
        JOIN binaries b ON b.id = call.binary_id
        LEFT JOIN binaries callee ON callee.id = call.callee_binary_id
        ORDER BY b.scope, b.path, call.label
        """,
    )


def _coverage_blocks(conn: sqlite3.Connection) -> list[dict[str, Any]]:
    return _dicts(
        conn,
        """
        SELECT cb.label, tr.label AS test_label, tr.test_id, tr.suite,
               b.label AS module_label
        FROM coverage_blocks cb
        JOIN test_runs tr ON tr.id = cb.test_run_id
        LEFT JOIN binaries b ON b.id = cb.binary_id
        ORDER BY tr.suite, tr.test_id, b.label, cb.label
        """,
    )


def _coverage_edges(conn: sqlite3.Connection) -> list[dict[str, Any]]:
    return _dicts(
        conn,
        """
        SELECT ce.label, tr.label AS test_label, tr.test_id, tr.suite,
               b.label AS module_label
        FROM coverage_edges ce
        JOIN test_runs tr ON tr.id = ce.test_run_id
        LEFT JOIN binaries b ON b.id = ce.binary_id
        ORDER BY tr.suite, tr.test_id, b.label, ce.label
        """,
    )


def _coverage_call_edges(conn: sqlite3.Connection) -> list[dict[str, Any]]:
    return _dicts(
        conn,
        """
        SELECT cce.label, tr.label AS test_label, tr.test_id, tr.suite,
               b.label AS module_label, callee.label AS callee_module_label,
               cce.callee_symbol
        FROM coverage_call_edges cce
        JOIN test_runs tr ON tr.id = cce.test_run_id
        LEFT JOIN binaries b ON b.id = cce.binary_id
        LEFT JOIN binaries callee ON callee.id = cce.callee_binary_id
        ORDER BY tr.suite, tr.test_id, b.label, cce.label
        """,
    )


def _data_refs(conn: sqlite3.Connection) -> list[dict[str, Any]]:
    return _dicts(
        conn,
        """
        SELECT dr.label, b.label AS module_label, dr.ref_type, dr.source, dr.confidence
        FROM data_refs dr
        JOIN binaries b ON b.id = dr.binary_id
        ORDER BY b.scope, b.path, dr.label
        """,
    )


def _globals(conn: sqlite3.Connection) -> list[dict[str, Any]]:
    return _dicts(
        conn,
        """
        SELECT g.label, b.label AS module_label, g.name, g.data_type, g.subsystem, g.confidence
        FROM globals g
        JOIN binaries b ON b.id = g.binary_id
        ORDER BY b.scope, b.path, g.name, g.label
        """,
    )


def _waivers(conn: sqlite3.Connection) -> list[dict[str, Any]]:
    return _dicts(
        conn,
        """
        SELECT w.label, b.label AS module_label, w.category, w.reason, w.evidence,
               w.reviewer, w.revalidation_trigger, w.created_at
        FROM waivers w
        JOIN binaries b ON b.id = w.binary_id
        ORDER BY b.scope, b.path, w.category, w.label
        """,
    )


def _platform_endpoints(conn: sqlite3.Connection) -> list[dict[str, Any]]:
    endpoints = _dicts(
        conn,
        """
        SELECT pe.label, pe.dll, pe.symbol, pe.ordinal, pe.endpoint_kind,
               pe.subsystem, pe.mock_status, pe.test_status
        FROM platform_endpoints pe
        ORDER BY lower(pe.dll), COALESCE(pe.symbol, ''), COALESCE(pe.ordinal, -1)
        """,
    )
    for endpoint in endpoints:
        endpoint["test_cases"] = _dicts(
            conn,
            """
            SELECT itc.label, itc.case_kind, itc.test_id, itc.status,
                   itc.evidence
            FROM interface_test_cases itc
            JOIN platform_endpoints pe ON pe.id = itc.endpoint_id
            WHERE pe.label = ?
            ORDER BY itc.case_kind, itc.test_id
            """,
            (endpoint["label"],),
        )
        _sanitize_evidence(endpoint["test_cases"])
    return endpoints


def _data_structures(conn: sqlite3.Connection) -> list[dict[str, Any]]:
    structures = _dicts(
        conn,
        """
        SELECT label, name, structure_kind, spec_status, fixture_status, description
        FROM data_structures
        ORDER BY structure_kind, name
        """,
    )
    for structure in structures:
        structure["test_cases"] = _dicts(
            conn,
            """
            SELECT dst.label, dst.case_kind, dst.test_id, dst.status,
                   dst.evidence
            FROM data_state_test_cases dst
            JOIN data_structures ds ON ds.id = dst.data_structure_id
            WHERE ds.label = ?
            ORDER BY dst.case_kind, dst.test_id
            """,
            (structure["label"],),
        )
        _sanitize_evidence(structure["test_cases"])
    return structures


def _oracle_tests(conn: sqlite3.Connection) -> list[dict[str, Any]]:
    tests = _dicts(
        conn,
        """
        SELECT label, suite_id, test_id, case_kind, status, evidence
        FROM oracle_test_cases
        ORDER BY suite_id, case_kind, test_id
        """,
    )
    _sanitize_evidence(tests)
    return tests


def _behavior_contracts(conn: sqlite3.Connection) -> list[dict[str, Any]]:
    contracts = []
    for row in conn.execute(
        """
        SELECT label, contract_id, title, scope, version, contract_json, evidence
        FROM behavior_contracts
        ORDER BY contract_id, version
        """
    ):
        contract = {
            "label": row["label"],
            "contract_id": row["contract_id"],
            "title": row["title"],
            "scope": row["scope"],
            "version": row["version"],
            "contract": _json_dict(row["contract_json"]),
            "evidence": row["evidence"],
            "observations": _dicts(
                conn,
                """
                SELECT bo.label, bo.test_id, bo.status, bo.input_json,
                       bo.observed_json, bo.observed_sha256, bo.evidence
                FROM behavior_observations bo
                JOIN behavior_contracts bc ON bc.id = bo.behavior_contract_id
                WHERE bc.label = ?
                ORDER BY bo.test_id
                """,
                (row["label"],),
            ),
            "process_observations": _dicts(
                conn,
                """
                SELECT pbo.label, pbo.test_id, pbo.status, pbo.input_json,
                       pbo.observed_json, pbo.observed_sha256, pbo.evidence
                FROM process_behavior_observations pbo
                JOIN behavior_contracts bc ON bc.id = pbo.behavior_contract_id
                WHERE bc.label = ?
                ORDER BY pbo.test_id
                """,
                (row["label"],),
            ),
        }
        for observation in contract["observations"]:
            observation["input"] = _json_dict(observation.pop("input_json"))
            observation["observed"] = _json_dict(observation.pop("observed_json"))
            observation["evidence"] = _public_text(observation.get("evidence"))
        for observation in contract["process_observations"]:
            observation["input"] = _json_dict(observation.pop("input_json"))
            observation["observed"] = _json_dict(observation.pop("observed_json"))
            observation["evidence"] = _public_text(observation.get("evidence"))
        contracts.append(contract)
    return contracts


def _internal_routine_contracts(conn: sqlite3.Connection) -> list[dict[str, Any]]:
    contracts = []
    for row in conn.execute(
        """
        SELECT irc.label, f.label AS function_label, irc.public_name, irc.purpose_summary,
               irc.calling_convention, irc.signature, irc.input_shape_json,
               irc.output_shape_json, irc.preconditions_json, irc.postconditions_json,
               irc.side_effects_json, irc.state_transitions_json, irc.fixtures_json,
               irc.evidence_labels_json, irc.evidence_source, irc.confidence,
               irc.taint_level, irc.review_status
        FROM internal_routine_contracts irc
        JOIN functions f ON f.id = irc.function_id
        WHERE irc.taint_level <> 'private_only'
          AND irc.review_status = 'reviewed'
        ORDER BY irc.public_name, irc.label
        """
    ):
        contracts.append(
            {
                "label": row["label"],
                "function_label": row["function_label"],
                "public_name": row["public_name"],
                "purpose_summary": row["purpose_summary"],
                "calling_convention": row["calling_convention"],
                "signature": row["signature"],
                "input_shape": _json_dict(row["input_shape_json"]),
                "output_shape": _json_dict(row["output_shape_json"]),
                "preconditions": _json_list(row["preconditions_json"]),
                "postconditions": _json_list(row["postconditions_json"]),
                "side_effects": _json_list(row["side_effects_json"]),
                "state_transitions": _json_list(row["state_transitions_json"]),
                "fixtures": _json_list(row["fixtures_json"]),
                "evidence_labels": _json_list(row["evidence_labels_json"]),
                "evidence_source": row["evidence_source"],
                "confidence": row["confidence"],
                "taint_level": row["taint_level"],
                "review_status": row["review_status"],
            }
        )
    return contracts


def _internal_harnesses(conn: sqlite3.Connection) -> list[dict[str, Any]]:
    harnesses = _dicts(
        conn,
        """
        SELECT label, target_label, harness_id, harness_kind,
               input_contract, expected_observation, risk
        FROM internal_harnesses
        ORDER BY target_label, harness_id
        """,
    )
    for harness in harnesses:
        harness["runs"] = _dicts(
            conn,
            """
            SELECT ihr.label, ihr.test_id, ihr.status, ihr.evidence, ihr.returncode
            FROM internal_harness_runs ihr
            JOIN internal_harnesses ih ON ih.id = ihr.internal_harness_id
            WHERE ih.label = ?
            ORDER BY ihr.test_id
            """,
            (harness["label"],),
        )
        _sanitize_evidence(harness["runs"])
    return harnesses


def _mutation_tests(conn: sqlite3.Connection) -> list[dict[str, Any]]:
    tests = _dicts(
        conn,
        """
        SELECT label, mutation_kind, target_label, test_id, status,
               evidence
        FROM mutation_test_cases
        ORDER BY mutation_kind, COALESCE(target_label, ''), test_id
        """,
    )
    _sanitize_evidence(tests)
    return tests


def _static_cross_checks(conn: sqlite3.Connection) -> list[dict[str, Any]]:
    return _dicts(
        conn,
        """
        SELECT s.label, b.label AS module_label, s.tool, s.status, s.checked_at,
               s.section_count, s.executable_section_count
        FROM static_cross_checks s
        JOIN binaries b ON b.id = s.binary_id
        ORDER BY b.scope, b.path, s.tool, s.checked_at
        """,
    )


def _test_runs(conn: sqlite3.Connection) -> list[dict[str, Any]]:
    return _dicts(
        conn,
        """
        SELECT label, test_id, suite, status, started_at, finished_at
        FROM test_runs
        ORDER BY suite, test_id, started_at
        """,
    )


def _trace_probes(conn: sqlite3.Connection) -> list[dict[str, Any]]:
    rows = []
    for row in conn.execute(
        """
        SELECT label, probe_id, probe_kind, command, status, started_at, finished_at,
               trace_log, expected_filename, returncode, timed_out, raw_trace_json,
               mapped_json, failures_json
        FROM trace_probe_results
        ORDER BY probe_kind, probe_id, started_at
        """
    ):
        raw_trace = _json_dict(row["raw_trace_json"])
        mapped = _json_dict(row["mapped_json"])
        rows.append(
            {
                "label": row["label"],
                "probe_id": row["probe_id"],
                "probe_kind": row["probe_kind"],
                "status": row["status"],
                "started_at": row["started_at"],
                "finished_at": row["finished_at"],
                "expected_filename": row["expected_filename"],
                "returncode": row["returncode"],
                "timed_out": bool(row["timed_out"]),
                "counts": {
                    "raw_modules": int(raw_trace.get("modules") or 0),
                    "raw_blocks": int(raw_trace.get("blocks") or 0),
                    "raw_cfg_edges": int(raw_trace.get("cfg_edges") or 0),
                    "raw_call_edges": int(raw_trace.get("call_edges") or 0),
                    "raw_expected_modules": int(raw_trace.get("expected_modules") or 0),
                    "raw_expected_blocks": int(raw_trace.get("expected_blocks") or 0),
                    "raw_expected_cfg_edges": int(raw_trace.get("expected_cfg_edges") or 0),
                    "raw_expected_call_edges": int(raw_trace.get("expected_call_edges") or 0),
                    "mapped_blocks": int(mapped.get("blocks") or 0),
                    "mapped_cfg_edges": int(mapped.get("cfg_edges") or 0),
                    "mapped_call_edges": int(mapped.get("call_edges") or 0),
                },
                "failures": _json_list(row["failures_json"]),
            }
        )
    return rows


def _dicts(conn: sqlite3.Connection, query: str, params: tuple[Any, ...] = ()) -> list[dict[str, Any]]:
    return [dict(row) for row in conn.execute(query, params)]


def _sanitize_evidence(records: list[dict[str, Any]]) -> None:
    for record in records:
        if "evidence" in record:
            record["evidence"] = _public_text(record.get("evidence"))


def _public_text(value: object) -> str:
    return public_text(value)


def _json_dict(value: object) -> dict[str, Any]:
    try:
        parsed = json.loads(str(value or "{}"))
    except json.JSONDecodeError:
        return {}
    return parsed if isinstance(parsed, dict) else {}


def _json_list(value: object) -> list[Any]:
    try:
        parsed = json.loads(str(value or "[]"))
    except json.JSONDecodeError:
        return []
    return parsed if isinstance(parsed, list) else []
