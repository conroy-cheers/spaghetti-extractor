"""Explicit, checked exact-prefix call-completion lemmas.

Hints are additional proof obligations, not contracts or input assumptions. The
assertion precedes its assumption in the same model; every accepting proof must
check it. Omitting a hint emits neither the assertion nor the assumption.
"""
from __future__ import annotations

import re
from collections.abc import Mapping

POLICY = "checked-exact-prefix-scalar-call-completion-v1"
FIELD = "call_completion_policy"
PREFIX = "spx-bisimulation-call-completion:"


def parse_lemmas(value, sync_ids):
    if not isinstance(value, list):
        raise ValueError("call completion lemmas must be an explicit list")
    fields = {"id", "start_sync", "target_sync", "component_id", "operation_id", "completed_calls"}
    result = []
    for row in value:
        if not isinstance(row, Mapping) or set(row) != fields:
            raise ValueError("call completion lemma fields differ")
        if any(not isinstance(row[k], str) or re.fullmatch(r"[A-Za-z][A-Za-z0-9_.:-]{0,255}", row[k]) is None
               for k in fields - {"completed_calls"}):
            raise ValueError("call completion lemma identifier is malformed")
        if re.fullmatch(r"[A-Za-z][A-Za-z0-9_]*", row["id"]) is None:
            raise ValueError("call completion lemma id must be a C identifier")
        if row["start_sync"] not in sync_ids or row["target_sync"] not in sync_ids:
            raise ValueError("call completion lemma names an unknown cut")
        if type(row["completed_calls"]) is not int or not 1 <= row["completed_calls"] < 2**32:
            raise ValueError("call completion lemma count must be a positive uint32")
        result.append(dict(row))
    identities = [row["id"] for row in result]
    if identities != sorted(set(identities)):
        raise ValueError("call completion lemmas must have ordered unique ids")
    return tuple(result)


def active(lemmas, sync_id):
    return [row for row in lemmas if row["start_sync"] == sync_id]


def description(row):
    return PREFIX + row["id"]


def symbol(row):
    return "spx_proof_call_completion_" + row["id"]


def metadata(authored):
    return {FIELD: POLICY} if authored.call_completion_lemmas else {}


def bind(authored, sync_id, connected, next_sync_ids, unit_rvas):
    result = []
    for row in active(authored.call_completion_lemmas, sync_id):
        suppliers = [c for c in connected if c["component_id"] == row["component_id"]]
        if len(suppliers) != 1:
            raise ValueError("call completion lemma needs a unique checked supplier")
        supplier = suppliers[0]
        if (supplier["summary_strategy"] != "scalar-body-free-v1"
                or supplier["entry_contract"] is not None or "assurance" in supplier):
            raise ValueError("call completion lemma requires unconditional scalar body-free composition")
        if row["operation_id"] not in supplier["summary_ids"]:
            raise ValueError("call completion lemma names an unknown supplier operation")
        if row["completed_calls"] > supplier["summary_capacity"]:
            raise ValueError("call completion lemma exceeds checked summary capacity")
        if row["target_sync"] not in next_sync_ids:
            raise ValueError("call completion lemma target is not an outgoing barrier")
        target = next(s for s in authored.syncs if s.identity == row["target_sync"])
        from .bisimulation_support import unit_rva
        result.append({**row, "summary_id": supplier["summary_ids"][row["operation_id"]],
                       "target_rva": unit_rvas.get(target.exact_unit_id, unit_rva(target.exact_unit_id))})
    return result


def declarations(rows):
    lines = []
    for row in rows:
        prefix = f"spx_proof_connected_{row['summary_id']:04d}"
        count = row["completed_calls"]
        lines.extend([
            f"static void {symbol(row)}(void) {{",
            f"  uint32_t valid = {prefix}_exact_count < UINT32_C({count}) ||",
            f"      {prefix}_finished[{count - 1}] == UINT32_C(0) ||",
            "      (spx_proof_exact_result.kind <= SPX_BRANCH &&",
            f"       spx_proof_exact_result.target_rva == UINT32_C({row['target_rva']}));",
            f'  __CPROVER_assert(valid, "{description(row)}");',
            "  __CPROVER_assume(valid);",
            "}", "",
        ])
    return lines


def sat_arguments(arguments):
    """Change only the backend, retaining property, slicing and unwind policy."""
    args = iter(arguments)
    result = []
    for argument in args:
        if argument == "--external-smt2-solver":
            next(args)
        elif argument not in {"--smt2", "--z3", "--no-array-field-sensitivity"}:
            result.append(argument)
    if "--sat-solver" not in result:
        result.extend(["--sat-solver", "cadical"])
    return result


def validate_model(planned, model, connected):
    source = planned["source"]
    lemmas = parse_lemmas(source.get("call_completion_lemmas", []), {s["id"] for s in source["syncs"]})
    expected = {FIELD: POLICY} if lemmas else {}
    if {k: model[k] for k in (FIELD,) if k in model} != expected:
        raise ValueError("call completion policy differs from the proof plan")
    for row in lemmas:
        suppliers = [c for c in connected if c["component_id"] == row["component_id"]]
        if (len(suppliers) != 1 or suppliers[0]["summary_strategy"] != "scalar-body-free-v1"
                or suppliers[0]["entry_contract"] is not None or "assurance" in suppliers[0]
                or row["operation_id"] not in suppliers[0]["source_summary_certificate"]["operation_symbols"]):
            raise ValueError("call completion supplier contract differs")
    if "obligation_id" in model:
        selected = active(lemmas, model["obligation_id"].removeprefix("sync:")) if model["obligation_id"].startswith("sync:") else []
        actual = {x for x in model["required_assertion_descriptions"] if x.startswith(PREFIX)}
        if actual != {description(row) for row in selected}:
            raise ValueError("call completion lemma omits or adds a required assertion")
    return expected
