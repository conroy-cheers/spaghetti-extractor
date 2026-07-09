from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from .util import sha256_bytes, sha256_file, write_json


DEPRECATED_PROOF_RULE_ALIASES = {
    "reproducible_jq_same_source_optimization_pair_v1": "same_source_layout_preserving_build_v1",
    "reproducible_stage_b_skeleton_reimplementation_v1": "stage_b_skeleton_reimplementation_contract_v1",
}

TRUSTED_BOUNDARIES = [
    "byte_identical_instruction_decode_v1",
    "checked_layout_preserving_mapping_assumption_v1",
    "local_symbolic_equivalence_result_v1",
    "pe_import_thunk_signature_equivalence_v1",
    "z3_unsat_local_equivalence_oracle_v1",
]

SEMANTIC_CLAIM_KINDS = [
    "decoded_instruction_identity",
    "pe_import_thunk_equivalence",
    "checked_generated_mapping_assumption",
    "symbolic_observable_equivalence",
]

SEMANTIC_TRUSTED_BOUNDARY_KINDS = [
    "byte_identical_instruction_decode_v1",
    "pe_import_thunk_signature_equivalence_v1",
    "checked_layout_preserving_mapping_assumption_v1",
    "z3_unsat_local_equivalence_oracle_v1",
    "local_symbolic_equivalence_result_v1",
]


def stage_a_model_description(
    model: str,
    *,
    model_specs: dict[str, dict[str, Any]],
    default_model: str,
    deprecated_aliases: dict[str, str] | None = None,
) -> dict[str, Any]:
    model_spec = model_specs.get(model, model_specs[default_model])
    loader = "pe32plus" if model_spec["bitness"] == 64 else "pe32"
    abi = "win64" if model_spec["bitness"] == 64 else "win32-cdecl-stdcall"
    return {
        "id": model,
        "architecture": model_spec["architecture"],
        "machine": model_spec.get("machine"),
        "bitness": model_spec["bitness"],
        "pe_magic": model_spec.get("magic"),
        "isa": model_spec["architecture"],
        "loader": loader,
        "abi": abi,
        "environment": "uninterpreted-external-env-v1",
        "proof_rules": [
            "byte_identical_x86_pe32_block",
            "byte_identical_x86_64_pe32plus_block",
            "smt_z3_local_equivalence_v1",
            "direct_cfg_edge_mapping_v1",
            "entry_root_reachability_v1",
            "checked_root_reachability_v1",
            "direct_cfg_reachability_v1",
            "verified_padding_bytes_v1",
            "pe_import_thunk_equivalence_v1",
            "same_source_layout_preserving_build_v1",
            "stage_b_skeleton_reimplementation_contract_v1",
        ],
        "trusted_boundaries": TRUSTED_BOUNDARIES,
        "deprecated_proof_rule_aliases": deprecated_aliases or DEPRECATED_PROOF_RULE_ALIASES,
    }


def proof_model_hash(model_description: dict[str, Any]) -> str:
    return _canonical_json_sha256(model_description)


def generic_proof_rule(rule: Any, *, deprecated_aliases: dict[str, str] | None = None) -> str:
    text = str(rule or "")
    return (deprecated_aliases or DEPRECATED_PROOF_RULE_ALIASES).get(text, text)


def write_solver_evidence_inventory(
    out: Path,
    proof_cache: list[dict[str, Any]],
    *,
    deprecated_aliases: dict[str, str] | None = None,
) -> dict[str, Any]:
    entries: list[dict[str, Any]] = []
    for index, cache_entry in enumerate(proof_cache):
        entries.append(_solver_evidence_entry(out, cache_entry, index, deprecated_aliases=deprecated_aliases))
    text = "".join(json.dumps(entry, sort_keys=True, separators=(",", ":")) + "\n" for entry in entries)
    evidence_path = out / "solver-evidence.jsonl"
    evidence_path.write_text(text, encoding="utf-8")
    status = "satisfied" if all(entry.get("status") == "satisfied" for entry in entries) else "incomplete"
    index_payload = {
        "format": "stage-a-solver-evidence-v1",
        "status": status,
        "path": evidence_path.name,
        "sha256": sha256_file(evidence_path),
        "counts": {
            "entries": len(entries),
            "by_kind": _count_by(entries, "evidence_kind"),
            "by_status": _count_by(entries, "status"),
        },
        "entries": [
            {
                "id": entry["id"],
                "obligation_id": entry.get("obligation_id"),
                "proof_rule": entry.get("proof_rule"),
                "generic_proof_rule": entry.get("generic_proof_rule"),
                "evidence_kind": entry.get("evidence_kind"),
                "status": entry.get("status"),
                "proof_cache": entry.get("proof_cache"),
                "solver": entry.get("solver"),
                "smt_status": entry.get("smt_status"),
                "smt_query_sha256": entry.get("smt_query_sha256"),
                "solver_backend": entry.get("solver_backend"),
                "solver_backend_sha256": entry.get("solver_backend_sha256"),
                "trusted_boundary": entry.get("trusted_boundary"),
                "entry_sha256": entry.get("entry_sha256"),
            }
            for entry in entries
        ],
    }
    write_json(out / "solver-evidence-index.json", index_payload)
    return {
        "format": index_payload["format"],
        "status": status,
        "path": "solver-evidence.jsonl",
        "sha256": index_payload["sha256"],
        "index_path": "solver-evidence-index.json",
        "index_sha256": sha256_file(out / "solver-evidence-index.json"),
        "counts": index_payload["counts"],
        "entries": index_payload["entries"],
    }


def write_proof_ir(
    *,
    out: Path,
    original: Path,
    candidate: Path,
    model_description: dict[str, Any],
    model_hash: str,
    loader_facts: dict[str, Any],
    layout: dict[str, Any],
    obligations: list[dict[str, Any]],
    failures: list[dict[str, Any]],
    incomplete: list[dict[str, Any]],
    proof_cache: list[dict[str, Any]],
    proof_cache_index: dict[str, Any],
    solver_evidence: dict[str, Any],
    mapping_payload: Any,
    invariant_payload: Any,
    mapping_contract: dict[str, Any] | None = None,
    abi_contract: dict[str, Any] | None = None,
    deprecated_aliases: dict[str, str] | None = None,
) -> dict[str, Any]:
    proof_cache_index_path = out / "proof-cache" / "index.json"
    proof_cache_index_sha256 = sha256_file(proof_cache_index_path) if proof_cache_index_path.is_file() else None
    input_artifacts = {
        "original": _input_artifact(original),
        "candidate": _input_artifact(candidate),
        "layout_payload_sha256": _canonical_json_sha256(layout),
        "mapping_payload_sha256": _canonical_json_sha256(mapping_payload),
        "invariant_payload_sha256": _canonical_json_sha256(invariant_payload),
    }
    schema = _proof_ir_schema(model_description)
    layout_summary = {
        "compatible": layout.get("compatible"),
        "issues": layout.get("issues", []),
    }
    loader_profile = _proof_ir_loader_profile(
        model_description=model_description,
        loader_facts=loader_facts,
        layout=layout_summary,
    )
    loader_frontend_profile = _proof_ir_loader_frontend_profile(
        model_description=model_description,
        schema=schema,
        loader_facts=loader_facts,
        loader_profile=loader_profile,
    )
    coverage_summary = _proof_ir_coverage_summary(obligations)
    coverage_profile = _proof_ir_coverage_profile(
        coverage=coverage_summary,
        obligations=obligations,
    )
    obligation_counts = _obligation_counts(obligations, failures, incomplete)
    obligation_items = [_proof_ir_obligation_summary(item, deprecated_aliases=deprecated_aliases) for item in obligations]
    proof_cache_summary = {
        "path": "proof-cache/index.json",
        "sha256": proof_cache_index_sha256,
        "counts": {"entries": len(proof_cache), "by_status": _count_by(proof_cache, "status")},
        "index": proof_cache_index,
    }
    proof_cache_profile = _proof_ir_proof_cache_profile(
        out=out,
        proof_cache=proof_cache,
        proof_cache_index=proof_cache_index,
        proof_cache_index_sha256=proof_cache_index_sha256,
    )
    block_semantics = _proof_ir_block_semantics_inventory(
        out,
        proof_cache,
        deprecated_aliases=deprecated_aliases,
    )
    instruction_semantics = _proof_ir_instruction_semantics_inventory(block_semantics=block_semantics)
    instruction_profile = _proof_ir_instruction_semantics_profile(
        instruction_semantics=instruction_semantics,
        block_semantics=block_semantics,
    )
    proof_artifact_bindings = _proof_ir_artifact_binding_inventory(
        obligation_items=obligation_items,
        proof_cache=proof_cache,
        solver_evidence=solver_evidence,
        block_semantics=block_semantics,
    )
    proof_rule_profile = _proof_ir_proof_rule_profile(
        model_description=model_description,
        obligation_items=obligation_items,
        block_semantics=block_semantics,
        solver_evidence=solver_evidence,
        proof_artifact_bindings=proof_artifact_bindings,
        deprecated_aliases=deprecated_aliases,
    )
    mapping_profile = _proof_ir_mapping_profile(
        model_description=model_description,
        mapping_contract=mapping_contract,
        deprecated_aliases=deprecated_aliases,
    )
    cfg_profile = _proof_ir_cfg_profile(obligation_items=obligation_items)
    reachability_profile = _proof_ir_reachability_profile(obligation_items=obligation_items)
    abi_profile = _proof_ir_abi_profile(
        model_description=model_description,
        abi_contract=abi_contract,
    )
    semantic_observables = _proof_ir_semantic_observables_inventory(
        block_semantics=block_semantics,
        proof_artifact_bindings=proof_artifact_bindings,
    )
    solver_claims = _proof_ir_solver_claims_inventory(
        semantic_observables=semantic_observables,
        solver_evidence=solver_evidence,
    )
    solver_evidence_profile = _proof_ir_solver_evidence_profile(
        out=out,
        proof_cache=proof_cache,
        solver_evidence=solver_evidence,
        solver_claims=solver_claims,
    )
    solver_backend_profile = _proof_ir_solver_backend_profile(
        solver_evidence=solver_evidence,
        solver_claims=solver_claims,
    )
    trusted_boundaries = _proof_ir_trusted_boundary_inventory(
        model_description=model_description,
        semantic_observables=semantic_observables,
    )
    trusted_boundary_profile = _proof_ir_trusted_boundary_profile(
        model_description=model_description,
        semantic_observables=semantic_observables,
        trusted_boundaries=trusted_boundaries,
    )
    target_profile = _proof_ir_target_profile(
        model_description=model_description,
        schema=schema,
        loader_facts=loader_facts,
        loader_frontend_profile=loader_frontend_profile,
        loader_profile=loader_profile,
        trusted_boundary_profile=trusted_boundary_profile,
    )
    semantic_profile = _proof_ir_semantic_observable_profile(
        semantic_observables=semantic_observables,
        trusted_boundaries=trusted_boundaries,
        solver_claims=solver_claims,
    )
    environment_profile = _proof_ir_environment_profile(
        model_description=model_description,
        loader_facts=loader_facts,
        block_semantics=block_semantics,
        semantic_observables=semantic_observables,
        solver_claims=solver_claims,
        solver_evidence=solver_evidence,
        trusted_boundaries=trusted_boundaries,
    )
    profile_manifest = _proof_ir_profile_manifest(
        schema=schema,
        profiles={
            "target_profile": target_profile,
            "loader_frontend_profile": loader_frontend_profile,
            "loader_profile": loader_profile,
            "coverage_profile": coverage_profile,
            "proof_cache_profile": proof_cache_profile,
            "proof_rule_profile": proof_rule_profile,
            "mapping_profile": mapping_profile,
            "cfg_profile": cfg_profile,
            "reachability_profile": reachability_profile,
            "abi_profile": abi_profile,
            "environment_profile": environment_profile,
            "instruction_profile": instruction_profile,
            "semantic_profile": semantic_profile,
            "solver_evidence_profile": solver_evidence_profile,
            "solver_backend_profile": solver_backend_profile,
            "trusted_boundary_profile": trusted_boundary_profile,
        },
    )
    proof_composition = _proof_ir_composition_inventory(
        obligation_items=obligation_items,
        proof_artifact_bindings=proof_artifact_bindings,
        block_semantics=block_semantics,
        instruction_semantics=instruction_semantics,
        semantic_observables=semantic_observables,
        solver_claims=solver_claims,
        trusted_boundaries=trusted_boundaries,
    )
    closure_certificate = _proof_ir_closure_certificate(
        model_hash=model_hash,
        inputs=input_artifacts,
        loader_facts=loader_facts,
        loader_profile=loader_profile,
        layout=layout_summary,
        coverage=coverage_summary,
        coverage_profile=coverage_profile,
        proof_rule_profile=proof_rule_profile,
        mapping_profile=mapping_profile,
        cfg_profile=cfg_profile,
        reachability_profile=reachability_profile,
        abi_profile=abi_profile,
        environment_profile=environment_profile,
        proof_cache_profile=proof_cache_profile,
        obligation_counts=obligation_counts,
        obligation_items=obligation_items,
        block_semantics=block_semantics,
        instruction_semantics=instruction_semantics,
        proof_artifact_bindings=proof_artifact_bindings,
        semantic_observables=semantic_observables,
        solver_claims=solver_claims,
        solver_backend_profile=solver_backend_profile,
        trusted_boundaries=trusted_boundaries,
        trusted_boundary_profile=trusted_boundary_profile,
        profile_manifest=profile_manifest,
        proof_composition=proof_composition,
        proof_cache=proof_cache,
        proof_cache_index=proof_cache_index,
        proof_cache_index_sha256=proof_cache_index_sha256,
        solver_evidence=solver_evidence,
    )
    closure_certificate_sha256 = _canonical_json_sha256(closure_certificate)
    proof_context = _proof_ir_context_binding(
        model_description=model_description,
        model_hash=model_hash,
        inputs=input_artifacts,
        target_profile=target_profile,
        loader_facts=loader_facts,
        loader_frontend_profile=loader_frontend_profile,
        loader_profile=loader_profile,
        layout=layout_summary,
        coverage=coverage_summary,
        coverage_profile=coverage_profile,
        proof_rule_profile=proof_rule_profile,
        mapping_profile=mapping_profile,
        cfg_profile=cfg_profile,
        reachability_profile=reachability_profile,
        abi_profile=abi_profile,
        environment_profile=environment_profile,
        obligation_items=obligation_items,
        proof_cache_profile=proof_cache_profile,
        proof_cache_index_sha256=proof_cache_index_sha256,
        solver_evidence=solver_evidence,
        block_semantics=block_semantics,
        instruction_semantics=instruction_semantics,
        instruction_profile=instruction_profile,
        proof_artifact_bindings=proof_artifact_bindings,
        semantic_observables=semantic_observables,
        solver_claims=solver_claims,
        solver_evidence_profile=solver_evidence_profile,
        solver_backend_profile=solver_backend_profile,
        trusted_boundaries=trusted_boundaries,
        trusted_boundary_profile=trusted_boundary_profile,
        profile_manifest=profile_manifest,
        semantic_profile=semantic_profile,
        proof_composition=proof_composition,
        closure_certificate=closure_certificate,
        closure_certificate_sha256=closure_certificate_sha256,
    )
    payload = {
        "format": "stage-a-proof-ir-v1",
        "schema": schema,
        "model": model_description,
        "model_hash": model_hash,
        "model_components": {
            "isa": model_description.get("isa"),
            "machine": model_description.get("machine"),
            "bitness": model_description.get("bitness"),
            "pe_magic": model_description.get("pe_magic"),
            "loader": model_description.get("loader"),
            "abi": model_description.get("abi"),
            "environment": model_description.get("environment"),
        },
        "target_profile": target_profile,
        "inputs": input_artifacts,
        "loader_facts": loader_facts,
        "loader_frontend_profile": loader_frontend_profile,
        "loader_profile": loader_profile,
        "layout": layout_summary,
        "coverage": coverage_summary,
        "coverage_profile": coverage_profile,
        "proof_cache_profile": proof_cache_profile,
        "proof_rule_profile": proof_rule_profile,
        "mapping_contract": mapping_contract,
        "mapping_profile": mapping_profile,
        "cfg_profile": cfg_profile,
        "reachability_profile": reachability_profile,
        "abi_contract": abi_contract,
        "abi_profile": abi_profile,
        "environment_profile": environment_profile,
        "obligations": {
            "counts": obligation_counts,
            "by_kind": _count_by(obligations, "kind"),
            "by_status": _count_by(obligations, "status"),
            "items": obligation_items,
        },
        "block_semantics": block_semantics,
        "instruction_semantics": instruction_semantics,
        "instruction_profile": instruction_profile,
        "proof_artifact_bindings": proof_artifact_bindings,
        "semantic_observables": semantic_observables,
        "solver_claims": solver_claims,
        "solver_evidence_profile": solver_evidence_profile,
        "solver_backend_profile": solver_backend_profile,
        "trusted_boundaries": trusted_boundaries,
        "trusted_boundary_profile": trusted_boundary_profile,
        "profile_manifest": profile_manifest,
        "semantic_profile": semantic_profile,
        "proof_composition": proof_composition,
        "proof_cache": proof_cache_summary,
        "solver_evidence": solver_evidence,
        "closure_certificate": closure_certificate,
        "proof_context": proof_context,
        "lean_contract": {
            "required_for_final_pass": True,
            "trusted_local_oracles": ["z3_unsat_local_equivalence_oracle_v1"],
            "checked_by": "StageA/Obligations.lean",
        },
    }
    write_json(out / "proof-ir.json", payload)
    return {
        "format": payload["format"],
        "status": "present",
        "path": "proof-ir.json",
        "sha256": sha256_file(out / "proof-ir.json"),
        "model": model_description,
        "model_hash": model_hash,
        "counts": {
            "obligations": len(obligations),
            "proof_cache_entries": len(proof_cache),
            "solver_evidence_entries": solver_evidence.get("counts", {}).get("entries", 0),
            "block_semantics_records": block_semantics["counts"]["records"],
            "instruction_semantics_records": instruction_semantics["counts"]["records"],
            "proof_artifact_binding_records": proof_artifact_bindings["counts"]["records"],
            "semantic_observable_records": semantic_observables["counts"]["records"],
            "solver_claim_records": solver_claims["counts"]["records"],
            "trusted_boundary_records": trusted_boundaries["counts"]["records"],
            "proof_composition_records": proof_composition["counts"]["records"],
        },
        "target_profile": {
            "format": target_profile["format"],
            "status": target_profile["status"],
            "counts": target_profile["counts"],
            "checks": target_profile["checks"],
        },
        "loader_frontend_profile": {
            "format": loader_frontend_profile["format"],
            "status": loader_frontend_profile["status"],
            "counts": loader_frontend_profile["counts"],
            "checks": loader_frontend_profile["checks"],
        },
        "loader_profile": {
            "format": loader_profile["format"],
            "status": loader_profile["status"],
            "counts": loader_profile["counts"],
            "checks": loader_profile["checks"],
        },
        "coverage_profile": {
            "format": coverage_profile["format"],
            "status": coverage_profile["status"],
            "counts": coverage_profile["counts"],
            "checks": coverage_profile["checks"],
        },
        "proof_cache_profile": {
            "format": proof_cache_profile["format"],
            "status": proof_cache_profile["status"],
            "counts": proof_cache_profile["counts"],
            "checks": proof_cache_profile["checks"],
        },
        "proof_rule_profile": {
            "format": proof_rule_profile["format"],
            "status": proof_rule_profile["status"],
            "counts": proof_rule_profile["counts"],
            "checks": proof_rule_profile["checks"],
        },
        "mapping_profile": {
            "format": mapping_profile["format"],
            "status": mapping_profile["status"],
            "counts": mapping_profile["counts"],
            "checks": mapping_profile["checks"],
        },
        "cfg_profile": {
            "format": cfg_profile["format"],
            "status": cfg_profile["status"],
            "counts": cfg_profile["counts"],
            "checks": cfg_profile["checks"],
        },
        "reachability_profile": {
            "format": reachability_profile["format"],
            "status": reachability_profile["status"],
            "counts": reachability_profile["counts"],
            "checks": reachability_profile["checks"],
        },
        "abi_profile": {
            "format": abi_profile["format"],
            "status": abi_profile["status"],
            "counts": abi_profile["counts"],
            "checks": abi_profile["checks"],
        },
        "environment_profile": {
            "format": environment_profile["format"],
            "status": environment_profile["status"],
            "counts": environment_profile["counts"],
            "checks": environment_profile["checks"],
        },
        "instruction_profile": {
            "format": instruction_profile["format"],
            "status": instruction_profile["status"],
            "counts": instruction_profile["counts"],
            "checks": instruction_profile["checks"],
        },
        "semantic_profile": {
            "format": semantic_profile["format"],
            "status": semantic_profile["status"],
            "counts": semantic_profile["counts"],
            "checks": semantic_profile["checks"],
        },
        "solver_evidence_profile": {
            "format": solver_evidence_profile["format"],
            "status": solver_evidence_profile["status"],
            "counts": solver_evidence_profile["counts"],
            "checks": solver_evidence_profile["checks"],
        },
        "solver_backend_profile": {
            "format": solver_backend_profile["format"],
            "status": solver_backend_profile["status"],
            "counts": solver_backend_profile["counts"],
            "checks": solver_backend_profile["checks"],
        },
        "trusted_boundary_profile": {
            "format": trusted_boundary_profile["format"],
            "status": trusted_boundary_profile["status"],
            "counts": trusted_boundary_profile["counts"],
            "checks": trusted_boundary_profile["checks"],
        },
        "profile_manifest": {
            "format": profile_manifest["format"],
            "status": profile_manifest["status"],
            "counts": profile_manifest["counts"],
            "checks": profile_manifest["checks"],
        },
        "proof_cache_index_path": "proof-cache/index.json",
        "proof_cache_index_sha256": proof_cache_index_sha256,
        "proof_context": {
            "format": proof_context["format"],
            "status": proof_context["status"],
            "model_hash": proof_context["model_hash"],
            "model": proof_context["model"],
            "hashes": proof_context["hashes"],
            "sha256": proof_context["sha256"],
            "checks": proof_context["checks"],
        },
        "closure_certificate": {
            "format": closure_certificate["format"],
            "status": closure_certificate["status"],
            "sha256": closure_certificate_sha256,
            "counts": closure_certificate["counts"],
            "checks": closure_certificate["checks"],
        },
    }


def _solver_evidence_entry(
    out: Path,
    cache_entry: dict[str, Any],
    index: int,
    *,
    deprecated_aliases: dict[str, str] | None,
) -> dict[str, Any]:
    path_text = str(cache_entry.get("path") or "")
    proof_cache_path = out / path_text if path_text else out / "proof-cache" / f"missing-{index}.json"
    expected_sha = cache_entry.get("sha256")
    if not path_text or not proof_cache_path.is_file():
        entry = {
            "format": "stage-a-solver-evidence-entry-v1",
            "id": f"evidence:{index:04d}",
            "status": "incomplete",
            "evidence_kind": "missing_proof_cache",
            "proof_cache": path_text,
            "expected_sha256": expected_sha,
            "actual_sha256": None,
            "obligation_id": None,
            "proof_rule": None,
            "generic_proof_rule": None,
        }
        entry["entry_sha256"] = _canonical_json_sha256(entry)
        return entry
    file_sha = sha256_file(proof_cache_path)
    try:
        payload = json.loads(proof_cache_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        entry = {
            "format": "stage-a-solver-evidence-entry-v1",
            "id": f"evidence:{index:04d}",
            "status": "incomplete",
            "evidence_kind": "unreadable_proof_cache",
            "proof_cache": path_text,
            "expected_sha256": expected_sha,
            "actual_sha256": file_sha,
            "file_sha256": file_sha,
            "error": str(exc),
            "obligation_id": None,
            "proof_rule": None,
            "generic_proof_rule": None,
        }
        entry["entry_sha256"] = _canonical_json_sha256(entry)
        return entry
    actual_sha = _proof_cache_payload_sha256(payload)
    proof_rule = _proof_cache_rule(payload)
    entry = {
        "format": "stage-a-solver-evidence-entry-v1",
        "id": f"evidence:{index:04d}:{_safe_gap_part(str(payload.get('obligation_id') or path_text))}",
        "status": "satisfied" if actual_sha == expected_sha else "incomplete",
        "evidence_kind": _proof_cache_evidence_kind(payload),
        "proof_cache": path_text,
        "expected_sha256": expected_sha,
        "actual_sha256": actual_sha,
        "file_sha256": file_sha,
        "obligation_id": payload.get("obligation_id"),
        "proof_rule": proof_rule,
        "generic_proof_rule": generic_proof_rule(proof_rule, deprecated_aliases=deprecated_aliases),
        "cache_format": payload.get("format"),
        "cache_status": cache_entry.get("status"),
    }
    symbolic = payload.get("symbolic") if isinstance(payload.get("symbolic"), dict) else {}
    smt_query = symbolic.get("smt_query")
    if symbolic:
        entry["solver"] = symbolic.get("solver")
        entry["smt_status"] = symbolic.get("smt_status")
        entry["smt_fragment"] = "stage-a-local-symbolic-x86-observables-v1"
        solver_backend = _solver_backend_summary(symbolic.get("solver_backend"))
        if solver_backend is not None:
            entry["solver_backend"] = solver_backend
            entry["solver_backend_sha256"] = _canonical_json_sha256(solver_backend)
        if symbolic.get("solver") == "z3" and symbolic.get("smt_status") == "unsat":
            entry["trusted_boundary"] = "z3_unsat_local_equivalence_oracle_v1"
    if isinstance(smt_query, str):
        entry["smt_query_sha256"] = sha256_bytes(smt_query.encode("utf-8"))
    entry["entry_sha256"] = _canonical_json_sha256(entry)
    return entry


def _proof_ir_block_semantics_inventory(
    out: Path,
    proof_cache: list[dict[str, Any]],
    *,
    deprecated_aliases: dict[str, str] | None,
) -> dict[str, Any]:
    records = [
        _proof_ir_block_semantics_record(out, cache_entry, index, deprecated_aliases=deprecated_aliases)
        for index, cache_entry in enumerate(proof_cache)
    ]
    return {
        "format": "stage-a-block-semantics-inventory-v1",
        "status": "satisfied" if all(record.get("status") == "present" for record in records) else "incomplete",
        "counts": {
            "records": len(records),
            "by_status": _count_by(records, "status"),
            "by_semantics_kind": _count_by(records, "semantics_kind"),
        },
        "records": records,
    }


def _proof_ir_block_semantics_record(
    out: Path,
    cache_entry: dict[str, Any],
    index: int,
    *,
    deprecated_aliases: dict[str, str] | None,
) -> dict[str, Any]:
    path_text = str(cache_entry.get("path") or "")
    proof_cache_path = out / path_text if path_text else out / "proof-cache" / f"missing-{index}.json"
    expected_sha = cache_entry.get("sha256")
    if not path_text or not proof_cache_path.is_file():
        return {
            "format": "stage-a-block-semantics-record-v1",
            "id": f"block-semantics:{index:04d}",
            "status": "incomplete",
            "semantics_kind": "missing_proof_cache",
            "proof_cache": path_text,
            "expected_sha256": expected_sha,
            "actual_sha256": None,
            "obligation_id": None,
            "proof_rule": None,
            "generic_proof_rule": None,
        }
    try:
        payload = json.loads(proof_cache_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return {
            "format": "stage-a-block-semantics-record-v1",
            "id": f"block-semantics:{index:04d}",
            "status": "incomplete",
            "semantics_kind": "unreadable_proof_cache",
            "proof_cache": path_text,
            "expected_sha256": expected_sha,
            "actual_sha256": sha256_file(proof_cache_path),
            "obligation_id": None,
            "proof_rule": None,
            "generic_proof_rule": None,
            "error": str(exc),
        }
    actual_sha = _proof_cache_payload_sha256(payload)
    proof_rule = _proof_cache_rule(payload)
    record = {
        "format": "stage-a-block-semantics-record-v1",
        "id": f"block-semantics:{index:04d}:{_safe_gap_part(str(payload.get('obligation_id') or path_text))}",
        "status": "present" if actual_sha == expected_sha else "incomplete",
        "semantics_kind": _proof_cache_semantics_kind(payload),
        "proof_cache": path_text,
        "expected_sha256": expected_sha,
        "actual_sha256": actual_sha,
        "obligation_id": payload.get("obligation_id"),
        "proof_rule": proof_rule,
        "generic_proof_rule": generic_proof_rule(proof_rule, deprecated_aliases=deprecated_aliases),
        "cache_format": payload.get("format"),
    }
    record.update(_proof_cache_semantics_summary(payload))
    record["record_sha256"] = _canonical_json_sha256(record)
    return record


def _proof_cache_semantics_kind(payload: dict[str, Any]) -> str:
    fmt = payload.get("format")
    if fmt == "stage-a-symbolic-proof-cache-v1":
        return "symbolic_observables"
    if fmt == "stage-a-proof-cache-v1":
        return "decoded_instruction_identity"
    if fmt == "stage-a-mapping-proof-cache-v1":
        return "checked_generated_mapping_assumption"
    if fmt == "stage-a-import-thunk-proof-cache-v1":
        return "pe_import_thunk_semantics"
    return "unknown"


def _proof_cache_semantics_summary(payload: dict[str, Any]) -> dict[str, Any]:
    fmt = payload.get("format")
    query = payload.get("query") if isinstance(payload.get("query"), dict) else {}
    if fmt in {"stage-a-proof-cache-v1", "stage-a-import-thunk-proof-cache-v1"}:
        return {
            "query": _proof_cache_query_summary(query),
            "original": _analysis_semantics_summary(payload.get("original_analysis")),
            "candidate": _analysis_semantics_summary(payload.get("candidate_analysis")),
        }
    if fmt == "stage-a-mapping-proof-cache-v1":
        proof = query.get("proof") if isinstance(query.get("proof"), dict) else {}
        return {
            "query": _proof_cache_query_summary(query),
            "checked_assumption": {
                "proof_sha256": _canonical_json_sha256(proof),
                "proof_rule": proof.get("rule"),
                "checked": proof.get("checked") is True,
                "source_kind": proof.get("source_kind"),
            },
            "original": {"byte_sha256": query.get("original_sha256")},
            "candidate": {"byte_sha256": query.get("candidate_sha256")},
        }
    if fmt == "stage-a-symbolic-proof-cache-v1":
        symbolic = payload.get("symbolic") if isinstance(payload.get("symbolic"), dict) else {}
        smt_query = symbolic.get("smt_query")
        solver_backend = _solver_backend_summary(symbolic.get("solver_backend"))
        return {
            "symbolic": {
                "status": symbolic.get("status"),
                "solver": symbolic.get("solver"),
                "smt_status": symbolic.get("smt_status"),
                "proof_rule": symbolic.get("proof_rule"),
                "solver_backend": solver_backend,
                "solver_backend_sha256": _canonical_json_sha256(solver_backend) if solver_backend is not None else None,
                "smt_query_sha256": sha256_bytes(smt_query.encode("utf-8")) if isinstance(smt_query, str) else None,
                "invariant_sha256": _canonical_json_sha256(symbolic.get("invariant")),
            },
            "original": {"observables_sha256": _canonical_json_sha256(symbolic.get("original_observables"))},
            "candidate": {"observables_sha256": _canonical_json_sha256(symbolic.get("candidate_observables"))},
        }
    return {"query": _proof_cache_query_summary(query)}


def _proof_cache_query_summary(query: dict[str, Any]) -> dict[str, Any]:
    return {
        "kind": query.get("kind"),
        "original_sha256": query.get("original_sha256"),
        "candidate_sha256": query.get("candidate_sha256"),
        "equal": query.get("equal"),
        "same_import_signature": query.get("same_import_signature"),
    }


def _analysis_semantics_summary(value: Any) -> dict[str, Any]:
    analysis = value if isinstance(value, dict) else {}
    instructions = analysis.get("instructions") if isinstance(analysis.get("instructions"), list) else []
    normalized_instructions = _normalized_instruction_stream(instructions)
    return {
        "analysis_sha256": _canonical_json_sha256(analysis),
        "status": analysis.get("status"),
        "machine": analysis.get("machine"),
        "bitness": analysis.get("bitness"),
        "instruction_count": len(instructions),
        "instruction_bytes_sha256": _canonical_json_sha256([item.get("bytes") for item in instructions if isinstance(item, dict)]),
        "instruction_stream_sha256": _canonical_json_sha256(normalized_instructions),
        "decoded_bytes_sha256": _decoded_instruction_bytes_sha256(normalized_instructions),
        "import_signature": analysis.get("import_signature") if isinstance(analysis.get("import_signature"), dict) else None,
    }


def _normalized_instruction_stream(instructions: list[Any]) -> list[dict[str, Any]]:
    normalized: list[dict[str, Any]] = []
    for item in instructions:
        if not isinstance(item, dict):
            continue
        normalized.append(
            {
                "rva": _int_or_none(item.get("rva")),
                "size": _int_or_none(item.get("size")),
                "mnemonic": str(item.get("mnemonic") or ""),
                "op_str": str(item.get("op_str") or ""),
                "bytes": str(item.get("bytes") or ""),
            }
        )
    return normalized


def _decoded_instruction_bytes_sha256(instructions: list[dict[str, Any]]) -> str | None:
    chunks: list[bytes] = []
    for item in instructions:
        text = item.get("bytes")
        if not isinstance(text, str):
            return None
        try:
            chunks.append(bytes.fromhex(text))
        except ValueError:
            return None
    return sha256_bytes(b"".join(chunks))


def _int_or_none(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    return None


def _proof_ir_schema(model_description: dict[str, Any]) -> dict[str, str]:
    loader = str(model_description.get("loader") or "binary")
    isa = str(model_description.get("isa") or "machine")
    return {
        "target_profile": "stage-a-target-profile-v1",
        "loader_facts": f"stage-a-loader-{loader}-facts-v1",
        "loader_frontend_profile": "stage-a-loader-frontend-profile-v1",
        "loader_profile": "stage-a-loader-profile-v1",
        "coverage_profile": "stage-a-executable-coverage-profile-v1",
        "proof_cache_profile": "stage-a-proof-cache-profile-v1",
        "proof_rule_profile": "stage-a-proof-rule-profile-v1",
        "mapping_profile": "stage-a-mapping-profile-v1",
        "cfg_profile": "stage-a-cfg-profile-v1",
        "reachability_profile": "stage-a-reachability-profile-v1",
        "abi_profile": "stage-a-abi-callsite-profile-v1",
        "environment_profile": "stage-a-environment-profile-v1",
        "block_semantics": f"stage-a-{isa}-block-semantics-v1",
        "instruction_semantics": f"stage-a-{isa}-instruction-semantics-v1",
        "instruction_profile": "stage-a-instruction-semantics-profile-v1",
        "semantic_observables": f"stage-a-{isa}-semantic-observables-v1",
        "semantic_profile": "stage-a-semantic-observable-profile-v1",
        "solver_claims": "stage-a-solver-claims-v1",
        "solver_evidence": "stage-a-solver-evidence-v1",
        "solver_evidence_profile": "stage-a-solver-evidence-profile-v1",
        "solver_backend_profile": "stage-a-solver-backend-profile-v1",
        "trusted_boundary_profile": "stage-a-trusted-boundary-profile-v1",
        "profile_manifest": "stage-a-proof-profile-manifest-v1",
        "proof_composition": "stage-a-proof-composition-v1",
    }


def _proof_ir_proof_cache_profile(
    *,
    out: Path,
    proof_cache: list[dict[str, Any]],
    proof_cache_index: dict[str, Any],
    proof_cache_index_sha256: str | None,
) -> dict[str, Any]:
    index_entries = proof_cache_index.get("entries") if isinstance(proof_cache_index.get("entries"), list) else []
    gaps: list[dict[str, Any]] = []
    path_counts: dict[str, int] = {}
    for entry in proof_cache:
        path = entry.get("path") if isinstance(entry, dict) else None
        if isinstance(path, str) and path:
            path_counts[path] = path_counts.get(path, 0) + 1
    duplicate_paths = sum(count - 1 for count in path_counts.values() if count > 1)
    if duplicate_paths:
        gaps.append(
            {
                "category": "duplicate_proof_cache_path",
                "paths": sorted(path for path, count in path_counts.items() if count > 1)[:50],
            }
        )

    counts = {
        "proof_cache_entries": len(proof_cache),
        "proof_cache_index_entries": len(index_entries),
        "proof_cache_file_missing": 0,
        "proof_cache_file_unreadable": 0,
        "proof_cache_payload_hash_mismatches": 0,
        "proof_cache_index_file_missing": 0,
        "proof_cache_index_file_hash_mismatches": 0,
        "proof_cache_index_payload_mismatches": 0,
        "proof_cache_index_entry_mismatches": 0,
        "duplicate_proof_cache_paths": duplicate_paths,
        "proof_cache_gaps": 0,
    }

    if len(index_entries) != len(proof_cache):
        counts["proof_cache_index_entry_mismatches"] += abs(len(index_entries) - len(proof_cache))
        gaps.append(
            {
                "category": "proof_cache_index_entry_count_mismatch",
                "expected": len(proof_cache),
                "observed": len(index_entries),
            }
        )
    elif _canonical_json_sha256(index_entries) != _canonical_json_sha256(proof_cache):
        counts["proof_cache_index_entry_mismatches"] += 1
        gaps.append({"category": "proof_cache_index_entries_mismatch"})

    index_file_required = bool(proof_cache)
    index_path = out / "proof-cache" / "index.json"
    if index_file_required:
        if not index_path.is_file():
            counts["proof_cache_index_file_missing"] += 1
            gaps.append({"category": "proof_cache_index_file_missing", "path": "proof-cache/index.json"})
        else:
            actual_index_sha = sha256_file(index_path)
            if actual_index_sha != proof_cache_index_sha256:
                counts["proof_cache_index_file_hash_mismatches"] += 1
                gaps.append(
                    {
                        "category": "proof_cache_index_file_hash_mismatch",
                        "path": "proof-cache/index.json",
                        "expected": proof_cache_index_sha256,
                        "observed": actual_index_sha,
                    }
                )
            try:
                parsed_index = json.loads(index_path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError) as exc:
                counts["proof_cache_index_payload_mismatches"] += 1
                gaps.append(
                    {
                        "category": "proof_cache_index_payload_unreadable",
                        "path": "proof-cache/index.json",
                        "error": str(exc),
                    }
                )
            else:
                if _canonical_json_sha256(parsed_index) != _canonical_json_sha256(proof_cache_index):
                    counts["proof_cache_index_payload_mismatches"] += 1
                    gaps.append({"category": "proof_cache_index_payload_mismatch", "path": "proof-cache/index.json"})

    for index, entry in enumerate(proof_cache):
        if not isinstance(entry, dict):
            counts["proof_cache_file_unreadable"] += 1
            gaps.append({"category": "proof_cache_entry_non_object", "index": index})
            continue
        path_text = entry.get("path")
        if not isinstance(path_text, str) or not path_text:
            counts["proof_cache_file_missing"] += 1
            gaps.append({"category": "proof_cache_entry_missing_path", "index": index})
            continue
        proof_cache_path = out / path_text
        if not proof_cache_path.is_file():
            counts["proof_cache_file_missing"] += 1
            gaps.append({"category": "proof_cache_file_missing", "path": path_text, "index": index})
            continue
        try:
            payload = json.loads(proof_cache_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            counts["proof_cache_file_unreadable"] += 1
            gaps.append(
                {
                    "category": "proof_cache_file_unreadable",
                    "path": path_text,
                    "index": index,
                    "error": str(exc),
                }
            )
            continue
        actual_sha = _proof_cache_payload_sha256(payload)
        expected_sha = entry.get("sha256")
        if actual_sha != expected_sha:
            counts["proof_cache_payload_hash_mismatches"] += 1
            gaps.append(
                {
                    "category": "proof_cache_payload_hash_mismatch",
                    "path": path_text,
                    "index": index,
                    "expected": expected_sha,
                    "observed": actual_sha,
                }
            )

    counts["proof_cache_gaps"] = (
        counts["proof_cache_file_missing"]
        + counts["proof_cache_file_unreadable"]
        + counts["proof_cache_payload_hash_mismatches"]
        + counts["proof_cache_index_file_missing"]
        + counts["proof_cache_index_file_hash_mismatches"]
        + counts["proof_cache_index_payload_mismatches"]
        + counts["proof_cache_index_entry_mismatches"]
        + counts["duplicate_proof_cache_paths"]
    )
    checks = {
        "proof_cache_index_entries_match": counts["proof_cache_index_entry_mismatches"] == 0,
        "proof_cache_index_file_present": counts["proof_cache_index_file_missing"] == 0,
        "proof_cache_index_file_hash_matches": counts["proof_cache_index_file_hash_mismatches"] == 0,
        "proof_cache_index_payload_matches": counts["proof_cache_index_payload_mismatches"] == 0,
        "proof_cache_files_present": counts["proof_cache_file_missing"] == 0,
        "proof_cache_files_readable": counts["proof_cache_file_unreadable"] == 0,
        "proof_cache_payload_hashes_match": counts["proof_cache_payload_hash_mismatches"] == 0,
        "proof_cache_paths_unique": counts["duplicate_proof_cache_paths"] == 0,
        "proof_cache_gaps_closed": counts["proof_cache_gaps"] == 0,
    }
    return {
        "format": "stage-a-proof-cache-profile-v1",
        "status": "satisfied" if all(checks.values()) else "incomplete",
        "counts": counts,
        "checks": checks,
        "gaps": gaps[:100],
    }


def _proof_ir_target_profile(
    *,
    model_description: dict[str, Any],
    schema: dict[str, str],
    loader_facts: dict[str, Any],
    loader_frontend_profile: dict[str, Any],
    loader_profile: dict[str, Any],
    trusted_boundary_profile: dict[str, Any],
) -> dict[str, Any]:
    model_id = str(model_description.get("id") or "")
    isa = str(model_description.get("isa") or "")
    loader = str(model_description.get("loader") or "")
    bitness = _int_or_none(model_description.get("bitness"))
    machine = str(model_description.get("machine") or "")
    abi = str(model_description.get("abi") or "")
    environment = str(model_description.get("environment") or "")
    expected_loader_facts_schema = f"stage-a-loader-{loader}-facts-v1" if loader else ""
    expected_block_schema = f"stage-a-{isa}-block-semantics-v1" if isa else ""
    expected_instruction_schema = f"stage-a-{isa}-instruction-semantics-v1" if isa else ""
    expected_semantic_schema = f"stage-a-{isa}-semantic-observables-v1" if isa else ""
    loader_profile_model = loader_profile.get("model") if isinstance(loader_profile.get("model"), dict) else {}
    schema_required = (
        "target_profile",
        "loader_facts",
        "loader_frontend_profile",
        "loader_profile",
        "block_semantics",
        "instruction_semantics",
        "semantic_observables",
        "proof_composition",
        "solver_evidence_profile",
        "solver_backend_profile",
        "trusted_boundary_profile",
        "profile_manifest",
    )
    checks = {
        "model_id_present": bool(model_id),
        "isa_present": bool(isa),
        "loader_present": bool(loader),
        "bitness_present": bitness is not None,
        "machine_present": bool(machine),
        "abi_present": bool(abi),
        "environment_present": bool(environment),
        "proof_rules_present": bool(model_description.get("proof_rules")),
        "trusted_boundaries_present": bool(model_description.get("trusted_boundaries")),
        "schema_entries_present": all(isinstance(schema.get(key), str) and bool(schema.get(key)) for key in schema_required),
        "target_profile_schema_matches": schema.get("target_profile") == "stage-a-target-profile-v1",
        "loader_facts_schema_matches_model": schema.get("loader_facts") == expected_loader_facts_schema,
        "loader_frontend_profile_schema_matches": schema.get("loader_frontend_profile") == "stage-a-loader-frontend-profile-v1",
        "loader_profile_schema_matches": schema.get("loader_profile") == "stage-a-loader-profile-v1",
        "block_semantics_schema_matches_isa": schema.get("block_semantics") == expected_block_schema,
        "instruction_semantics_schema_matches_isa": schema.get("instruction_semantics") == expected_instruction_schema,
        "semantic_observables_schema_matches_isa": schema.get("semantic_observables") == expected_semantic_schema,
        "solver_backend_profile_schema_matches": schema.get("solver_backend_profile") == "stage-a-solver-backend-profile-v1",
        "trusted_boundary_profile_schema_matches": schema.get("trusted_boundary_profile") == "stage-a-trusted-boundary-profile-v1",
        "profile_manifest_schema_matches": schema.get("profile_manifest") == "stage-a-proof-profile-manifest-v1",
        "loader_facts_format_matches_schema": loader_facts.get("format") == schema.get("loader_facts"),
        "loader_facts_loader_matches_model": loader_facts.get("loader") == loader,
        "loader_frontend_profile_status_satisfied": loader_frontend_profile.get("status") == "satisfied",
        "loader_profile_model_matches": (
            loader_profile_model.get("id") == model_id
            and loader_profile_model.get("loader") == loader
            and loader_profile_model.get("machine") == machine
            and _int_or_none(loader_profile_model.get("bitness")) == bitness
            and loader_profile_model.get("abi") == abi
        ),
        "loader_profile_status_satisfied": loader_profile.get("status") == "satisfied",
        "trusted_boundary_profile_status_satisfied": trusted_boundary_profile.get("status") == "satisfied",
    }
    counts = {
        "schema_entries": len(schema_required),
        "present_schema_entries": sum(1 for key in schema_required if isinstance(schema.get(key), str) and bool(schema.get(key))),
        "proof_rules": len(model_description.get("proof_rules") if isinstance(model_description.get("proof_rules"), list) else []),
        "trusted_boundaries": len(
            model_description.get("trusted_boundaries") if isinstance(model_description.get("trusted_boundaries"), list) else []
        ),
        "target_gaps": sum(1 for value in checks.values() if value is not True),
    }
    return {
        "format": "stage-a-target-profile-v1",
        "status": "satisfied" if all(checks.values()) else "incomplete",
        "model": {
            "id": model_id,
            "isa": isa,
            "loader": loader,
            "machine": machine,
            "bitness": bitness,
            "abi": abi,
            "environment": environment,
        },
        "schemas": {
            "expected_loader_facts": expected_loader_facts_schema,
            "expected_block_semantics": expected_block_schema,
            "expected_instruction_semantics": expected_instruction_schema,
            "expected_semantic_observables": expected_semantic_schema,
            "actual": {key: schema.get(key) for key in schema_required},
        },
        "counts": counts,
        "checks": checks,
    }


def _proof_ir_loader_frontend_profile(
    *,
    model_description: dict[str, Any],
    schema: dict[str, str],
    loader_facts: dict[str, Any],
    loader_profile: dict[str, Any],
) -> dict[str, Any]:
    loader = str(model_description.get("loader") or "")
    expected_format = f"stage-a-loader-{loader}-facts-v1" if loader else ""
    original = loader_facts.get("original") if isinstance(loader_facts.get("original"), dict) else {}
    candidate = loader_facts.get("candidate") if isinstance(loader_facts.get("candidate"), dict) else {}
    original_gaps = _loader_frontend_side_gaps("original", original)
    candidate_gaps = _loader_frontend_side_gaps("candidate", candidate)
    original_relocations = original.get("relocations") if isinstance(original.get("relocations"), dict) else {}
    candidate_relocations = candidate.get("relocations") if isinstance(candidate.get("relocations"), dict) else {}
    counts = {
        "original_sections": len(original.get("sections") if isinstance(original.get("sections"), list) else []),
        "candidate_sections": len(candidate.get("sections") if isinstance(candidate.get("sections"), list) else []),
        "original_executable_spans": len(
            original.get("executable_sections") if isinstance(original.get("executable_sections"), list) else []
        ),
        "candidate_executable_spans": len(
            candidate.get("executable_sections") if isinstance(candidate.get("executable_sections"), list) else []
        ),
        "original_imports": len(original.get("imports") if isinstance(original.get("imports"), list) else []),
        "candidate_imports": len(candidate.get("imports") if isinstance(candidate.get("imports"), list) else []),
        "original_relocation_blocks": int(
            (original_relocations.get("counts") if isinstance(original_relocations.get("counts"), dict) else {}).get("blocks") or 0
        ),
        "candidate_relocation_blocks": int(
            (candidate_relocations.get("counts") if isinstance(candidate_relocations.get("counts"), dict) else {}).get("blocks") or 0
        ),
        "frontend_gaps": len(original_gaps) + len(candidate_gaps),
    }
    checks = {
        "loader_frontend_schema_matches": schema.get("loader_frontend_profile") == "stage-a-loader-frontend-profile-v1",
        "loader_facts_schema_matches_model": schema.get("loader_facts") == expected_format,
        "loader_facts_format_matches_schema": loader_facts.get("format") == schema.get("loader_facts"),
        "loader_facts_loader_matches_model": loader_facts.get("loader") == loader,
        "loader_frontend_supported": loader in {"pe32", "pe32plus"},
        "original_side_present": bool(original),
        "candidate_side_present": bool(candidate),
        "original_required_fields_present": not original_gaps,
        "candidate_required_fields_present": not candidate_gaps,
        "original_executable_spans_present": counts["original_executable_spans"] > 0,
        "candidate_executable_spans_present": counts["candidate_executable_spans"] > 0,
        "loader_profile_hashed": _is_sha256_hex(_canonical_json_sha256(loader_profile)),
        "loader_profile_status_satisfied": loader_profile.get("status") == "satisfied",
    }
    return {
        "format": "stage-a-loader-frontend-profile-v1",
        "status": "satisfied" if all(checks.values()) else "incomplete",
        "model": {
            "id": model_description.get("id"),
            "loader": loader,
            "machine": model_description.get("machine"),
            "bitness": model_description.get("bitness"),
        },
        "frontend": {
            "loader": loader,
            "facts_format": loader_facts.get("format"),
            "expected_facts_format": expected_format,
            "profile_schema": schema.get("loader_frontend_profile"),
            "loader_profile_sha256": _canonical_json_sha256(loader_profile),
        },
        "counts": counts,
        "checks": checks,
        "gaps": (original_gaps + candidate_gaps)[:100],
    }


def _loader_frontend_side_gaps(side: str, item: dict[str, Any]) -> list[dict[str, Any]]:
    if not item:
        return [{"category": f"{side}_loader_frontend_facts_missing", "side": side}]
    gaps: list[dict[str, Any]] = []
    scalar_fields = (
        ("sha256", str),
        ("size", int),
        ("machine", str),
        ("bitness", int),
        ("image_base", int),
        ("entrypoint_rva", int),
        ("size_of_image", int),
    )
    for field, expected_type in scalar_fields:
        value = item.get(field)
        if not isinstance(value, expected_type) or (expected_type is str and not value):
            gaps.append({"category": f"{side}_loader_frontend_field_missing", "side": side, "field": field})
    list_fields = ("sections", "executable_sections", "imports")
    for field in list_fields:
        if not isinstance(item.get(field), list):
            gaps.append({"category": f"{side}_loader_frontend_field_missing", "side": side, "field": field})
    if not isinstance(item.get("relocations"), dict):
        gaps.append({"category": f"{side}_loader_frontend_field_missing", "side": side, "field": "relocations"})
    executable_sections = item.get("executable_sections") if isinstance(item.get("executable_sections"), list) else []
    if not executable_sections:
        gaps.append({"category": f"{side}_loader_frontend_executable_spans_missing", "side": side})
    return gaps


def _proof_ir_loader_profile(
    *,
    model_description: dict[str, Any],
    loader_facts: dict[str, Any],
    layout: dict[str, Any],
) -> dict[str, Any]:
    expected_loader = str(model_description.get("loader") or "")
    expected_format = f"stage-a-loader-{expected_loader}-facts-v1" if expected_loader else ""
    expected_bitness = _int_or_none(model_description.get("bitness"))
    expected_machine = str(model_description.get("machine") or "")
    original = loader_facts.get("original") if isinstance(loader_facts.get("original"), dict) else {}
    candidate = loader_facts.get("candidate") if isinstance(loader_facts.get("candidate"), dict) else {}
    original_gaps = _loader_profile_side_gaps("original", original, expected_bitness, expected_machine)
    candidate_gaps = _loader_profile_side_gaps("candidate", candidate, expected_bitness, expected_machine)
    original_relocations = original.get("relocations") if isinstance(original.get("relocations"), dict) else {}
    candidate_relocations = candidate.get("relocations") if isinstance(candidate.get("relocations"), dict) else {}
    layout_issues = layout.get("issues") if isinstance(layout.get("issues"), list) else []
    blocking_layout_issues = [
        item
        for item in layout_issues
        if isinstance(item, dict)
        and (
            item.get("severity") in {"fail", "failed", "incomplete", "violated"}
            or item.get("status") in {"fail", "failed", "incomplete", "violated"}
        )
    ]
    original_import_signature = _loader_profile_import_signature(original)
    candidate_import_signature = _loader_profile_import_signature(candidate)
    binary_signature_mismatches = _loader_profile_binary_signature_mismatches(
        original=original,
        candidate=candidate,
        original_import_signature=original_import_signature,
        candidate_import_signature=candidate_import_signature,
    )
    image_base_mismatches = 0
    if isinstance(original.get("image_base"), int) and isinstance(candidate.get("image_base"), int):
        image_base_mismatches = 0 if original.get("image_base") == candidate.get("image_base") else 1
    counts = {
        "model_bitness": int(expected_bitness or 0),
        "original_bitness": int(original.get("bitness") or 0) if isinstance(original.get("bitness"), int) else 0,
        "candidate_bitness": int(candidate.get("bitness") or 0) if isinstance(candidate.get("bitness"), int) else 0,
        "original_sections": len(original.get("sections") if isinstance(original.get("sections"), list) else []),
        "candidate_sections": len(candidate.get("sections") if isinstance(candidate.get("sections"), list) else []),
        "original_executable_sections": len(
            original.get("executable_sections") if isinstance(original.get("executable_sections"), list) else []
        ),
        "candidate_executable_sections": len(
            candidate.get("executable_sections") if isinstance(candidate.get("executable_sections"), list) else []
        ),
        "original_imports": len(original.get("imports") if isinstance(original.get("imports"), list) else []),
        "candidate_imports": len(candidate.get("imports") if isinstance(candidate.get("imports"), list) else []),
        "original_relocation_blocks": int(
            (original_relocations.get("counts") if isinstance(original_relocations.get("counts"), dict) else {}).get("blocks") or 0
        ),
        "candidate_relocation_blocks": int(
            (candidate_relocations.get("counts") if isinstance(candidate_relocations.get("counts"), dict) else {}).get("blocks") or 0
        ),
        "original_relocation_entries": int(
            (original_relocations.get("counts") if isinstance(original_relocations.get("counts"), dict) else {}).get("entries") or 0
        ),
        "candidate_relocation_entries": int(
            (candidate_relocations.get("counts") if isinstance(candidate_relocations.get("counts"), dict) else {}).get("entries") or 0
        ),
        "layout_issues": len([item for item in layout_issues if isinstance(item, dict)]),
        "layout_blocking_issues": len(blocking_layout_issues),
        "original_header_gaps": sum(1 for item in original_gaps if item.get("family") == "header"),
        "candidate_header_gaps": sum(1 for item in candidate_gaps if item.get("family") == "header"),
        "original_section_gaps": sum(1 for item in original_gaps if item.get("family") == "sections"),
        "candidate_section_gaps": sum(1 for item in candidate_gaps if item.get("family") == "sections"),
        "original_import_gaps": sum(1 for item in original_gaps if item.get("family") == "imports"),
        "candidate_import_gaps": sum(1 for item in candidate_gaps if item.get("family") == "imports"),
        "original_relocation_gaps": sum(1 for item in original_gaps if item.get("family") == "relocations"),
        "candidate_relocation_gaps": sum(1 for item in candidate_gaps if item.get("family") == "relocations"),
        "binary_signature_mismatches": len(binary_signature_mismatches),
        "image_base_mismatches": image_base_mismatches,
    }
    checks = {
        "loader_format_matches_model": loader_facts.get("format") == expected_format,
        "loader_name_matches_model": loader_facts.get("loader") == expected_loader,
        "original_facts_present": bool(original),
        "candidate_facts_present": bool(candidate),
        "original_model_matches": _loader_profile_side_matches_model(original, expected_bitness, expected_machine),
        "candidate_model_matches": _loader_profile_side_matches_model(candidate, expected_bitness, expected_machine),
        "layout_compatible": layout.get("compatible") is True,
        "no_blocking_layout_issues": counts["layout_blocking_issues"] == 0,
        "headers_present": counts["original_header_gaps"] == 0 and counts["candidate_header_gaps"] == 0,
        "sections_present": counts["original_section_gaps"] == 0 and counts["candidate_section_gaps"] == 0,
        "executable_sections_present": counts["original_executable_sections"] > 0 and counts["candidate_executable_sections"] > 0,
        "imports_match": original_import_signature == candidate_import_signature,
        "imports_present": counts["original_import_gaps"] == 0 and counts["candidate_import_gaps"] == 0,
        "relocations_closed": counts["original_relocation_gaps"] == 0 and counts["candidate_relocation_gaps"] == 0,
        "binary_signatures_match": counts["binary_signature_mismatches"] == 0,
    }
    return {
        "format": "stage-a-loader-profile-v1",
        "status": "satisfied" if all(checks.values()) else "incomplete",
        "model": {
            "id": model_description.get("id"),
            "architecture": model_description.get("architecture"),
            "machine": model_description.get("machine"),
            "bitness": model_description.get("bitness"),
            "loader": model_description.get("loader"),
            "abi": model_description.get("abi"),
        },
        "counts": counts,
        "checks": checks,
        "gaps": (original_gaps + candidate_gaps + binary_signature_mismatches + blocking_layout_issues)[:100],
        "signatures": {
            "original_imports_sha256": _canonical_json_sha256(original_import_signature),
            "candidate_imports_sha256": _canonical_json_sha256(candidate_import_signature),
            "original_sections_sha256": _canonical_json_sha256(_loader_profile_section_signature(original)),
            "candidate_sections_sha256": _canonical_json_sha256(_loader_profile_section_signature(candidate)),
        },
    }


def _loader_profile_side_gaps(
    side: str,
    item: dict[str, Any],
    expected_bitness: int | None,
    expected_machine: str,
) -> list[dict[str, Any]]:
    gaps: list[dict[str, Any]] = []
    if not item:
        return [{"category": f"{side}_loader_facts_missing", "side": side, "family": "header"}]
    for field in ("machine", "subsystem"):
        if not isinstance(item.get(field), str) or not item.get(field):
            gaps.append({"category": f"{side}_{field}_missing", "side": side, "family": "header"})
    for field in ("bitness", "image_base", "entrypoint_rva", "size_of_image"):
        if not isinstance(item.get(field), int):
            gaps.append({"category": f"{side}_{field}_missing", "side": side, "family": "header"})
    if expected_bitness is not None and isinstance(item.get("bitness"), int) and item.get("bitness") != expected_bitness:
        gaps.append(
            {
                "category": f"{side}_bitness_model_mismatch",
                "side": side,
                "family": "header",
                "expected": expected_bitness,
                "observed": item.get("bitness"),
            }
        )
    if expected_machine and isinstance(item.get("machine"), str) and item.get("machine") != expected_machine:
        gaps.append(
            {
                "category": f"{side}_machine_model_mismatch",
                "side": side,
                "family": "header",
                "expected": expected_machine,
                "observed": item.get("machine"),
            }
        )
    if not isinstance(item.get("sections"), list):
        gaps.append({"category": f"{side}_sections_missing", "side": side, "family": "sections"})
    if not isinstance(item.get("executable_sections"), list):
        gaps.append({"category": f"{side}_executable_sections_missing", "side": side, "family": "sections"})
    if not isinstance(item.get("imports"), list):
        gaps.append({"category": f"{side}_imports_missing", "side": side, "family": "imports"})
    relocations = item.get("relocations")
    if not isinstance(relocations, dict):
        gaps.append({"category": f"{side}_relocations_missing", "side": side, "family": "relocations"})
    else:
        status = relocations.get("status")
        if status not in {"present", "empty_directory"}:
            gaps.append(
                {
                    "category": f"{side}_relocations_not_closed",
                    "side": side,
                    "family": "relocations",
                    "status": status,
                }
            )
        if not isinstance(relocations.get("directory"), dict):
            gaps.append({"category": f"{side}_relocation_directory_missing", "side": side, "family": "relocations"})
        if not isinstance(relocations.get("counts"), dict):
            gaps.append({"category": f"{side}_relocation_counts_missing", "side": side, "family": "relocations"})
    return gaps


def _loader_profile_side_matches_model(
    item: dict[str, Any],
    expected_bitness: int | None,
    expected_machine: str,
) -> bool:
    return bool(
        item
        and (expected_bitness is None or item.get("bitness") == expected_bitness)
        and (not expected_machine or item.get("machine") == expected_machine)
    )


def _loader_profile_import_signature(item: dict[str, Any]) -> list[dict[str, Any]]:
    imports = item.get("imports") if isinstance(item.get("imports"), list) else []
    return sorted(
        (
            {
                "dll": str(imported.get("dll") or "").lower(),
                "symbol": imported.get("symbol") if isinstance(imported.get("symbol"), str) else None,
                "ordinal": imported.get("ordinal") if isinstance(imported.get("ordinal"), int) else None,
            }
            for imported in imports
            if isinstance(imported, dict)
        ),
        key=lambda imported: (
            str(imported.get("dll") or ""),
            str(imported.get("symbol") or ""),
            -1 if imported.get("ordinal") is None else int(imported.get("ordinal")),
        ),
    )


def _loader_profile_section_signature(item: dict[str, Any]) -> list[dict[str, Any]]:
    sections = item.get("sections") if isinstance(item.get("sections"), list) else []
    result: list[dict[str, Any]] = []
    for section in sections:
        if not isinstance(section, dict):
            continue
        permissions = section.get("permissions") if isinstance(section.get("permissions"), dict) else {}
        result.append(
            {
                "name": str(section.get("name") or ""),
                "executable": permissions.get("execute") is True,
                "readable": permissions.get("read") is True,
                "writable": permissions.get("write") is True,
                "code": permissions.get("code") is True,
            }
        )
    return result


def _loader_profile_binary_signature_mismatches(
    *,
    original: dict[str, Any],
    candidate: dict[str, Any],
    original_import_signature: list[dict[str, Any]],
    candidate_import_signature: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    mismatches: list[dict[str, Any]] = []
    for field in ("machine", "bitness"):
        if original.get(field) != candidate.get(field):
            mismatches.append(
                {
                    "category": f"binary_{field}_mismatch",
                    "family": "header",
                    "expected": original.get(field),
                    "observed": candidate.get(field),
                }
            )
    if _loader_profile_section_signature(original) != _loader_profile_section_signature(candidate):
        mismatches.append(
            {
                "category": "binary_section_signature_mismatch",
                "family": "sections",
                "expected_sha256": _canonical_json_sha256(_loader_profile_section_signature(original)),
                "observed_sha256": _canonical_json_sha256(_loader_profile_section_signature(candidate)),
            }
        )
    if original_import_signature != candidate_import_signature:
        mismatches.append(
            {
                "category": "binary_import_signature_mismatch",
                "family": "imports",
                "expected_sha256": _canonical_json_sha256(original_import_signature),
                "observed_sha256": _canonical_json_sha256(candidate_import_signature),
            }
        )
    return mismatches


def _proof_ir_instruction_semantics_inventory(
    *,
    block_semantics: dict[str, Any],
) -> dict[str, Any]:
    block_records = block_semantics.get("records") if isinstance(block_semantics.get("records"), list) else []
    records = [
        _proof_ir_instruction_semantics_record(item)
        for item in block_records
        if isinstance(item, dict) and _block_semantics_requires_instruction_semantics(item)
    ]
    return {
        "format": "stage-a-instruction-semantics-v1",
        "status": "satisfied" if all(record.get("status") == "satisfied" for record in records) else "incomplete",
        "counts": {
            "records": len(records),
            "by_status": _count_by(records, "status"),
            "by_semantics_kind": _count_by(records, "semantics_kind"),
            "gaps": sum(len(record.get("gaps", [])) for record in records if isinstance(record.get("gaps"), list)),
        },
        "records": records,
    }


def _block_semantics_requires_instruction_semantics(record: dict[str, Any]) -> bool:
    return record.get("semantics_kind") in {
        "decoded_instruction_identity",
        "pe_import_thunk_semantics",
    }


def _proof_ir_instruction_semantics_record(record: dict[str, Any]) -> dict[str, Any]:
    obligation_id = str(record.get("obligation_id") or "")
    proof_cache = str(record.get("proof_cache") or "")
    query = record.get("query") if isinstance(record.get("query"), dict) else {}
    original = _instruction_semantics_side_record(
        "original",
        record.get("original"),
        expected_decoded_bytes_sha256=query.get("original_sha256"),
    )
    candidate = _instruction_semantics_side_record(
        "candidate",
        record.get("candidate"),
        expected_decoded_bytes_sha256=query.get("candidate_sha256"),
    )
    gaps: list[dict[str, Any]] = []
    if record.get("status") != "present":
        gaps.append(
            {
                "category": "block_semantics_record_incomplete",
                "obligation_id": obligation_id,
                "proof_cache": proof_cache,
                "record_status": record.get("status"),
            }
        )
    if not _is_sha256_hex(record.get("record_sha256")):
        gaps.append(
            {
                "category": "missing_block_semantics_record_sha256",
                "obligation_id": obligation_id,
                "proof_cache": proof_cache,
            }
        )
    gaps.extend(original["gaps"])
    gaps.extend(candidate["gaps"])
    result = {
        "format": "stage-a-instruction-semantics-record-v1",
        "id": f"instruction-semantics:{_safe_gap_part(obligation_id)}",
        "status": "satisfied" if not gaps else "incomplete",
        "obligation_id": obligation_id,
        "proof_cache": proof_cache,
        "proof_rule": record.get("proof_rule"),
        "generic_proof_rule": record.get("generic_proof_rule"),
        "semantics_kind": record.get("semantics_kind"),
        "block_semantics_record_sha256": record.get("record_sha256"),
        "original": original["summary"],
        "candidate": candidate["summary"],
        "gaps": gaps,
    }
    result["record_sha256"] = _canonical_json_sha256(result)
    return result


def _proof_ir_instruction_semantics_profile(
    *,
    instruction_semantics: dict[str, Any],
    block_semantics: dict[str, Any],
) -> dict[str, Any]:
    records = instruction_semantics.get("records") if isinstance(instruction_semantics.get("records"), list) else []
    block_records = block_semantics.get("records") if isinstance(block_semantics.get("records"), list) else []
    decoded_block_records = [
        item for item in block_records if isinstance(item, dict) and _block_semantics_requires_instruction_semantics(item)
    ]
    rows = [item for item in records if isinstance(item, dict)]
    status_counts = _count_by(rows, "status")
    semantics_kind_counts = _count_by(rows, "semantics_kind")
    gap_counts = _gap_category_counts(rows)
    original_gap_count = sum(count for category, count in gap_counts.items() if category.startswith("original_"))
    candidate_gap_count = sum(count for category, count in gap_counts.items() if category.startswith("candidate_"))
    original_hash_gap_count = sum(
        count
        for category, count in gap_counts.items()
        if category.startswith("original_") and ("sha256" in category or "hash" in category)
    )
    candidate_hash_gap_count = sum(
        count
        for category, count in gap_counts.items()
        if category.startswith("candidate_") and ("sha256" in category or "hash" in category)
    )
    counts = {
        "instruction_semantics_records": len(rows),
        "decoded_instruction_block_semantics": len(decoded_block_records),
        "satisfied_records": _count_value(status_counts, "satisfied"),
        "incomplete_records": len(rows) - _count_value(status_counts, "satisfied"),
        "decoded_instruction_identity_records": _count_value(semantics_kind_counts, "decoded_instruction_identity"),
        "pe_import_thunk_semantics_records": _count_value(semantics_kind_counts, "pe_import_thunk_semantics"),
        "unknown_semantics_records": sum(
            count
            for semantics_kind, count in semantics_kind_counts.items()
            if semantics_kind not in {"decoded_instruction_identity", "pe_import_thunk_semantics"}
        ),
        "instruction_semantics_gaps": sum(gap_counts.values()),
        "original_decode_status_gaps": gap_counts.get("original_decode_status_not_supported", 0),
        "candidate_decode_status_gaps": gap_counts.get("candidate_decode_status_not_supported", 0),
        "original_hash_gaps": original_hash_gap_count,
        "candidate_hash_gaps": candidate_hash_gap_count,
        "decoded_byte_hash_mismatches": sum(
            count
            for category, count in gap_counts.items()
            if category in {"original_decoded_bytes_sha256_mismatch", "candidate_decoded_bytes_sha256_mismatch"}
        ),
        "block_semantics_record_hash_gaps": gap_counts.get("missing_block_semantics_record_sha256", 0),
        "missing_instruction_semantics_records": max(len(decoded_block_records) - len(rows), 0),
    }
    checks = {
        "instruction_semantics_records_match": counts["instruction_semantics_records"]
        == int((instruction_semantics.get("counts") if isinstance(instruction_semantics.get("counts"), dict) else {}).get("records") or 0),
        "decoded_instruction_blocks_match": counts["decoded_instruction_block_semantics"] == counts["instruction_semantics_records"],
        "records_satisfied": counts["satisfied_records"] == counts["instruction_semantics_records"]
        and counts["incomplete_records"] == 0,
        "semantics_kinds_known": counts["unknown_semantics_records"] == 0,
        "semantics_kinds_accounted": counts["decoded_instruction_identity_records"]
        + counts["pe_import_thunk_semantics_records"]
        + counts["unknown_semantics_records"]
        == counts["instruction_semantics_records"],
        "instruction_semantics_gaps_closed": counts["instruction_semantics_gaps"] == 0,
        "decode_status_gaps_closed": counts["original_decode_status_gaps"] == 0 and counts["candidate_decode_status_gaps"] == 0,
        "hash_gaps_closed": counts["original_hash_gaps"] == 0 and counts["candidate_hash_gaps"] == 0,
        "decoded_byte_hash_mismatches_closed": counts["decoded_byte_hash_mismatches"] == 0,
        "block_semantics_record_hash_gaps_closed": counts["block_semantics_record_hash_gaps"] == 0,
        "missing_instruction_semantics_records_closed": counts["missing_instruction_semantics_records"] == 0,
    }
    return {
        "format": "stage-a-instruction-semantics-profile-v1",
        "status": "satisfied" if all(checks.values()) else "incomplete",
        "counts": counts,
        "checks": checks,
        "status_counts": status_counts,
        "semantics_kind_counts": semantics_kind_counts,
        "gap_counts": gap_counts,
    }


def _instruction_semantics_side_record(
    side: str,
    value: Any,
    *,
    expected_decoded_bytes_sha256: Any,
) -> dict[str, Any]:
    item = value if isinstance(value, dict) else {}
    gaps: list[dict[str, Any]] = []
    status = item.get("status")
    if status not in {"ok", "supported"}:
        gaps.append({"category": f"{side}_decode_status_not_supported", "side": side, "status": status})
    if not isinstance(item.get("machine"), str) or not item.get("machine"):
        gaps.append({"category": f"{side}_machine_missing", "side": side})
    if not isinstance(item.get("bitness"), int):
        gaps.append({"category": f"{side}_bitness_missing", "side": side})
    if not isinstance(item.get("instruction_count"), int):
        gaps.append({"category": f"{side}_instruction_count_missing", "side": side})
    if not _is_sha256_hex(item.get("analysis_sha256")):
        gaps.append({"category": f"{side}_analysis_sha256_missing", "side": side})
    if not _is_sha256_hex(item.get("instruction_stream_sha256")):
        gaps.append({"category": f"{side}_instruction_stream_sha256_missing", "side": side})
    if not _is_sha256_hex(item.get("instruction_bytes_sha256")):
        gaps.append({"category": f"{side}_instruction_bytes_sha256_missing", "side": side})
    if not _is_sha256_hex(item.get("decoded_bytes_sha256")):
        gaps.append({"category": f"{side}_decoded_bytes_sha256_missing", "side": side})
    elif _is_sha256_hex(expected_decoded_bytes_sha256) and item.get("decoded_bytes_sha256") != expected_decoded_bytes_sha256:
        gaps.append(
            {
                "category": f"{side}_decoded_bytes_sha256_mismatch",
                "side": side,
                "expected": expected_decoded_bytes_sha256,
                "observed": item.get("decoded_bytes_sha256"),
            }
        )
    return {
        "summary": {
            "status": status,
            "machine": item.get("machine"),
            "bitness": item.get("bitness"),
            "instruction_count": item.get("instruction_count"),
            "analysis_sha256": item.get("analysis_sha256"),
            "instruction_stream_sha256": item.get("instruction_stream_sha256"),
            "instruction_bytes_sha256": item.get("instruction_bytes_sha256"),
            "decoded_bytes_sha256": item.get("decoded_bytes_sha256"),
        },
        "gaps": gaps,
    }


def _proof_ir_solver_claims_inventory(
    *,
    semantic_observables: dict[str, Any],
    solver_evidence: dict[str, Any],
) -> dict[str, Any]:
    semantic_records = (
        semantic_observables.get("records") if isinstance(semantic_observables.get("records"), list) else []
    )
    solver_entries = solver_evidence.get("entries") if isinstance(solver_evidence.get("entries"), list) else []
    solver_by_proof_cache = {
        str(item.get("proof_cache")): item
        for item in solver_entries
        if isinstance(item, dict) and isinstance(item.get("proof_cache"), str) and item.get("proof_cache")
    }
    records = [
        _proof_ir_solver_claim_record(
            item,
            solver_entry=solver_by_proof_cache.get(str(item.get("proof_cache") or "")),
        )
        for item in semantic_records
        if isinstance(item, dict) and _semantic_record_requires_solver_claim(item)
    ]
    return {
        "format": "stage-a-solver-claims-v1",
        "status": "satisfied" if all(record.get("status") == "satisfied" for record in records) else "incomplete",
        "counts": {
            "records": len(records),
            "by_status": _count_by(records, "status"),
            "by_trusted_boundary": _count_by(records, "trusted_boundary"),
            "by_solver": _count_by(records, "solver"),
            "gaps": sum(len(record.get("gaps", [])) for record in records if isinstance(record.get("gaps"), list)),
        },
        "records": records,
    }


def _proof_ir_semantic_observable_profile(
    *,
    semantic_observables: dict[str, Any],
    trusted_boundaries: dict[str, Any],
    solver_claims: dict[str, Any],
) -> dict[str, Any]:
    semantic_records = (
        semantic_observables.get("records") if isinstance(semantic_observables.get("records"), list) else []
    )
    trusted_records = trusted_boundaries.get("records") if isinstance(trusted_boundaries.get("records"), list) else []
    solver_records = solver_claims.get("records") if isinstance(solver_claims.get("records"), list) else []
    claim_counts = _count_by([item for item in semantic_records if isinstance(item, dict)], "claim_kind")
    boundary_counts = _count_by([item for item in trusted_records if isinstance(item, dict)], "trusted_boundary")
    semantic_gap_counts = _gap_category_counts(semantic_records)
    trusted_gap_counts = _gap_category_counts(trusted_records)
    solver_gap_counts = _gap_category_counts(solver_records)
    known_claims = set(SEMANTIC_CLAIM_KINDS)
    known_boundaries = set(SEMANTIC_TRUSTED_BOUNDARY_KINDS)
    missing_claims = _count_value(claim_counts, "missing") + _count_value(claim_counts, "None") + _count_value(claim_counts, "")
    unknown_claims = sum(
        count
        for claim, count in claim_counts.items()
        if claim not in known_claims and claim not in {"missing", "None", ""}
    )
    missing_boundaries = (
        _count_value(boundary_counts, "")
        + _count_value(boundary_counts, "None")
        + trusted_gap_counts.get("missing_trusted_boundary", 0)
    )
    unknown_boundaries = sum(
        count
        for boundary, count in boundary_counts.items()
        if boundary not in known_boundaries and boundary not in {"", "None"}
    )
    unapproved_boundaries = trusted_gap_counts.get("unapproved_trusted_boundary", 0)
    counts = {
        "semantic_observables": len(semantic_records),
        "trusted_boundaries": len(trusted_records),
        "solver_claims": len(solver_records),
        "decoded_instruction_identity": _count_value(claim_counts, "decoded_instruction_identity"),
        "pe_import_thunk_equivalence": _count_value(claim_counts, "pe_import_thunk_equivalence"),
        "checked_generated_mapping_assumption": _count_value(claim_counts, "checked_generated_mapping_assumption"),
        "symbolic_observable_equivalence": _count_value(claim_counts, "symbolic_observable_equivalence"),
        "missing_claims": missing_claims,
        "unknown_claims": unknown_claims,
        "byte_identical_instruction_decode_boundaries": _count_value(boundary_counts, "byte_identical_instruction_decode_v1"),
        "pe_import_thunk_signature_equivalence_boundaries": _count_value(boundary_counts, "pe_import_thunk_signature_equivalence_v1"),
        "checked_layout_preserving_mapping_boundaries": _count_value(
            boundary_counts,
            "checked_layout_preserving_mapping_assumption_v1",
        ),
        "z3_unsat_local_equivalence_boundaries": _count_value(boundary_counts, "z3_unsat_local_equivalence_oracle_v1"),
        "local_symbolic_equivalence_boundaries": _count_value(boundary_counts, "local_symbolic_equivalence_result_v1"),
        "missing_trusted_boundaries": missing_boundaries,
        "unknown_trusted_boundaries": unknown_boundaries,
        "unapproved_trusted_boundaries": unapproved_boundaries,
        "semantic_observable_gaps": sum(semantic_gap_counts.values()),
        "trusted_boundary_gaps": sum(trusted_gap_counts.values()),
        "solver_claim_gaps": sum(solver_gap_counts.values()),
    }
    checks = {
        "semantic_observable_records_match": counts["semantic_observables"]
        == int((semantic_observables.get("counts") if isinstance(semantic_observables.get("counts"), dict) else {}).get("records") or 0),
        "trusted_boundary_records_match": counts["trusted_boundaries"]
        == int((trusted_boundaries.get("counts") if isinstance(trusted_boundaries.get("counts"), dict) else {}).get("records") or 0),
        "solver_claim_records_match": counts["solver_claims"]
        == int((solver_claims.get("counts") if isinstance(solver_claims.get("counts"), dict) else {}).get("records") or 0),
        "claim_kinds_known": counts["missing_claims"] == 0 and counts["unknown_claims"] == 0,
        "trusted_boundaries_known": counts["missing_trusted_boundaries"] == 0
        and counts["unknown_trusted_boundaries"] == 0
        and counts["unapproved_trusted_boundaries"] == 0,
        "decoded_claims_use_decode_boundary": counts["decoded_instruction_identity"]
        == counts["byte_identical_instruction_decode_boundaries"],
        "import_claims_use_import_boundary": counts["pe_import_thunk_equivalence"]
        == counts["pe_import_thunk_signature_equivalence_boundaries"],
        "mapping_claims_use_mapping_boundary": counts["checked_generated_mapping_assumption"]
        == counts["checked_layout_preserving_mapping_boundaries"],
        "symbolic_claims_use_solver_boundary": counts["symbolic_observable_equivalence"]
        == counts["z3_unsat_local_equivalence_boundaries"] + counts["local_symbolic_equivalence_boundaries"],
        "symbolic_claims_match_solver_claims": counts["symbolic_observable_equivalence"] == counts["solver_claims"],
        "semantic_observable_gaps_closed": counts["semantic_observable_gaps"] == 0,
        "trusted_boundary_gaps_closed": counts["trusted_boundary_gaps"] == 0,
        "solver_claim_gaps_closed": counts["solver_claim_gaps"] == 0,
    }
    return {
        "format": "stage-a-semantic-observable-profile-v1",
        "status": "satisfied" if all(checks.values()) else "incomplete",
        "counts": counts,
        "checks": checks,
        "claim_counts": claim_counts,
        "trusted_boundary_counts": boundary_counts,
        "semantic_gap_counts": semantic_gap_counts,
        "trusted_boundary_gap_counts": trusted_gap_counts,
        "solver_claim_gap_counts": solver_gap_counts,
    }


def _proof_ir_cfg_profile(*, obligation_items: list[dict[str, Any]]) -> dict[str, Any]:
    block_rows = [item for item in obligation_items if item.get("kind") == "block_equivalence"]
    direct_rows = [item for item in obligation_items if item.get("kind") == "cfg_edge"]
    structure_rows = [item for item in obligation_items if item.get("kind") == "block_structure"]
    indirect_rows = [item for item in obligation_items if item.get("kind") == "indirect_cfg_target"]
    block_status_by_id = {
        str(item.get("id")): item.get("status")
        for item in block_rows
        if isinstance(item.get("id"), str) and item.get("id")
    }
    known_direct_edge_kinds = {"taken", "fallthrough", "jump", "call"}
    known_indirect_rules = {
        "same_source_layout_preserving_build_v1",
        "stage_b_skeleton_reimplementation_contract_v1",
    }
    direct_status_counts = _count_by(direct_rows, "status")
    structure_status_counts = _count_by(structure_rows, "status")
    indirect_status_counts = _count_by(indirect_rows, "status")
    direct_kind_counts = _count_by(direct_rows, "edge_kind")
    gaps: list[dict[str, Any]] = []

    for item in structure_rows:
        if item.get("status") not in {"proved", "waived_noncode"}:
            gaps.append(
                {
                    "category": "open_block_structure_obligation",
                    "obligation_id": item.get("id"),
                    "status": item.get("status"),
                }
            )

    for item in direct_rows:
        obligation_id = item.get("id")
        edge_kind = item.get("edge_kind")
        source_block = item.get("source_block")
        target_block = item.get("target_block")
        if item.get("status") != "proved":
            gaps.append(
                {
                    "category": "open_direct_cfg_edge_obligation",
                    "obligation_id": obligation_id,
                    "status": item.get("status"),
                    "source_block": source_block,
                    "target_block": target_block,
                    "edge_kind": edge_kind,
                }
            )
            continue
        if not isinstance(source_block, str) or not source_block:
            gaps.append({"category": "direct_cfg_edge_missing_source_block", "obligation_id": obligation_id})
        elif block_status_by_id.get(f"block:{source_block}") != "proved":
            gaps.append(
                {
                    "category": "direct_cfg_edge_source_block_not_proved",
                    "obligation_id": obligation_id,
                    "source_block": source_block,
                    "source_status": block_status_by_id.get(f"block:{source_block}"),
                }
            )
        if not isinstance(target_block, str) or not target_block:
            gaps.append({"category": "direct_cfg_edge_missing_target_block", "obligation_id": obligation_id})
        elif block_status_by_id.get(f"block:{target_block}") != "proved":
            gaps.append(
                {
                    "category": "direct_cfg_edge_target_block_not_proved",
                    "obligation_id": obligation_id,
                    "target_block": target_block,
                    "target_status": block_status_by_id.get(f"block:{target_block}"),
                }
            )
        if edge_kind not in known_direct_edge_kinds:
            gaps.append(
                {
                    "category": "direct_cfg_edge_unknown_kind",
                    "obligation_id": obligation_id,
                    "edge_kind": edge_kind,
                }
            )
        if not isinstance(item.get("original_edge"), dict):
            gaps.append({"category": "direct_cfg_edge_missing_original_evidence", "obligation_id": obligation_id})
        if not isinstance(item.get("candidate_edge"), dict):
            gaps.append({"category": "direct_cfg_edge_missing_candidate_evidence", "obligation_id": obligation_id})

    for item in indirect_rows:
        obligation_id = item.get("id")
        source_block = item.get("source_block")
        if item.get("status") != "proved":
            gaps.append(
                {
                    "category": "open_indirect_cfg_target_obligation",
                    "obligation_id": obligation_id,
                    "status": item.get("status"),
                    "source_block": source_block,
                }
            )
            continue
        if not isinstance(source_block, str) or not source_block:
            gaps.append({"category": "indirect_cfg_target_missing_source_block", "obligation_id": obligation_id})
        elif block_status_by_id.get(f"block:{source_block}") != "proved":
            gaps.append(
                {
                    "category": "indirect_cfg_target_source_block_not_proved",
                    "obligation_id": obligation_id,
                    "source_block": source_block,
                    "source_status": block_status_by_id.get(f"block:{source_block}"),
                }
            )
        if not isinstance(item.get("signature"), dict):
            gaps.append({"category": "indirect_cfg_target_missing_signature", "obligation_id": obligation_id})
        if not isinstance(item.get("original"), dict):
            gaps.append({"category": "indirect_cfg_target_missing_original_evidence", "obligation_id": obligation_id})
        if not isinstance(item.get("candidate"), dict):
            gaps.append({"category": "indirect_cfg_target_missing_candidate_evidence", "obligation_id": obligation_id})
        if item.get("generic_proof_rule") not in known_indirect_rules:
            gaps.append(
                {
                    "category": "indirect_cfg_target_unknown_proof_rule",
                    "obligation_id": obligation_id,
                    "proof_rule": item.get("proof_rule"),
                    "generic_proof_rule": item.get("generic_proof_rule"),
                }
            )

    direct_unknown_kind_count = sum(
        count
        for edge_kind, count in direct_kind_counts.items()
        if edge_kind not in known_direct_edge_kinds
    )
    direct_proved_rows = [item for item in direct_rows if item.get("status") == "proved"]
    indirect_proved_rows = [item for item in indirect_rows if item.get("status") == "proved"]
    counts = {
        "block_equivalence_obligations": len(block_rows),
        "proved_block_equivalence_obligations": sum(1 for item in block_rows if item.get("status") == "proved"),
        "block_structure_obligations": len(structure_rows),
        "open_block_structure_obligations": len(structure_rows)
        - _count_value(structure_status_counts, "proved")
        - _count_value(structure_status_counts, "waived_noncode"),
        "direct_cfg_edge_obligations": len(direct_rows),
        "proved_direct_cfg_edge_obligations": _count_value(direct_status_counts, "proved"),
        "open_direct_cfg_edge_obligations": len(direct_rows) - _count_value(direct_status_counts, "proved"),
        "direct_cfg_taken_edges": _count_value(direct_kind_counts, "taken"),
        "direct_cfg_fallthrough_edges": _count_value(direct_kind_counts, "fallthrough"),
        "direct_cfg_jump_edges": _count_value(direct_kind_counts, "jump"),
        "direct_cfg_call_edges": _count_value(direct_kind_counts, "call"),
        "direct_cfg_unknown_edge_kinds": direct_unknown_kind_count,
        "proved_direct_cfg_edges_with_source_block": sum(
            1 for item in direct_proved_rows if isinstance(item.get("source_block"), str) and item.get("source_block")
        ),
        "proved_direct_cfg_edges_with_target_block": sum(
            1 for item in direct_proved_rows if isinstance(item.get("target_block"), str) and item.get("target_block")
        ),
        "proved_direct_cfg_edges_with_original_evidence": sum(1 for item in direct_proved_rows if isinstance(item.get("original_edge"), dict)),
        "proved_direct_cfg_edges_with_candidate_evidence": sum(1 for item in direct_proved_rows if isinstance(item.get("candidate_edge"), dict)),
        "indirect_cfg_target_obligations": len(indirect_rows),
        "proved_indirect_cfg_target_obligations": _count_value(indirect_status_counts, "proved"),
        "open_indirect_cfg_target_obligations": len(indirect_rows) - _count_value(indirect_status_counts, "proved"),
        "proved_indirect_cfg_targets_with_source_block": sum(
            1 for item in indirect_proved_rows if isinstance(item.get("source_block"), str) and item.get("source_block")
        ),
        "proved_indirect_cfg_targets_with_signature": sum(1 for item in indirect_proved_rows if isinstance(item.get("signature"), dict)),
        "proved_indirect_cfg_targets_with_original_evidence": sum(1 for item in indirect_proved_rows if isinstance(item.get("original"), dict)),
        "proved_indirect_cfg_targets_with_candidate_evidence": sum(1 for item in indirect_proved_rows if isinstance(item.get("candidate"), dict)),
        "indirect_cfg_targets_with_unknown_proof_rule": sum(
            1 for item in indirect_proved_rows if item.get("generic_proof_rule") not in known_indirect_rules
        ),
        "cfg_gaps": len(gaps),
    }
    checks = {
        "block_structure_obligations_closed": counts["open_block_structure_obligations"] == 0,
        "direct_cfg_edges_closed": counts["open_direct_cfg_edge_obligations"] == 0,
        "direct_cfg_edge_kinds_known": counts["direct_cfg_unknown_edge_kinds"] == 0,
        "direct_cfg_edge_metadata_present": counts["proved_direct_cfg_edges_with_source_block"]
        == counts["proved_direct_cfg_edge_obligations"]
        and counts["proved_direct_cfg_edges_with_target_block"] == counts["proved_direct_cfg_edge_obligations"],
        "direct_cfg_edge_evidence_present": counts["proved_direct_cfg_edges_with_original_evidence"]
        == counts["proved_direct_cfg_edge_obligations"]
        and counts["proved_direct_cfg_edges_with_candidate_evidence"] == counts["proved_direct_cfg_edge_obligations"],
        "direct_cfg_edges_bind_proved_blocks": not any(
            gap["category"] in {"direct_cfg_edge_source_block_not_proved", "direct_cfg_edge_target_block_not_proved"}
            for gap in gaps
        ),
        "indirect_cfg_targets_closed": counts["open_indirect_cfg_target_obligations"] == 0,
        "indirect_cfg_target_metadata_present": counts["proved_indirect_cfg_targets_with_source_block"]
        == counts["proved_indirect_cfg_target_obligations"]
        and counts["proved_indirect_cfg_targets_with_signature"] == counts["proved_indirect_cfg_target_obligations"],
        "indirect_cfg_target_evidence_present": counts["proved_indirect_cfg_targets_with_original_evidence"]
        == counts["proved_indirect_cfg_target_obligations"]
        and counts["proved_indirect_cfg_targets_with_candidate_evidence"] == counts["proved_indirect_cfg_target_obligations"],
        "indirect_cfg_targets_bind_proved_blocks": not any(
            gap["category"] == "indirect_cfg_target_source_block_not_proved" for gap in gaps
        ),
        "indirect_cfg_target_rules_known": counts["indirect_cfg_targets_with_unknown_proof_rule"] == 0,
        "cfg_gaps_closed": counts["cfg_gaps"] == 0,
    }
    return {
        "format": "stage-a-cfg-profile-v1",
        "status": "satisfied" if all(checks.values()) else "incomplete",
        "counts": counts,
        "checks": checks,
        "by_direct_edge_status": direct_status_counts,
        "by_direct_edge_kind": direct_kind_counts,
        "by_block_structure_status": structure_status_counts,
        "by_indirect_target_status": indirect_status_counts,
        "gaps": gaps[:100],
    }


def _proof_ir_abi_profile(
    *,
    model_description: dict[str, Any],
    abi_contract: dict[str, Any] | None,
) -> dict[str, Any]:
    if not isinstance(abi_contract, dict):
        checks = {
            "abi_contract_present": False,
            "abi_model_known": bool(model_description.get("abi")),
            "abi_contract_status_satisfied": True,
            "candidate_evidence_present": True,
            "function_counts_match": True,
            "callsite_counts_match": True,
            "import_prototypes_match": True,
            "no_missing_functions": True,
            "no_ambiguous_functions": True,
            "callsites_complete": True,
            "no_function_mismatches": True,
            "no_callsite_mismatches": True,
            "abi_gaps_closed": True,
        }
        return {
            "format": "stage-a-abi-callsite-profile-v1",
            "status": "not_applicable",
            "model_abi": model_description.get("abi"),
            "contract_sha256": None,
            "contract_status": "not_applicable",
            "evidence_kind": None,
            "scope": "not_applicable",
            "counts": {
                "original_functions": 0,
                "candidate_functions": 0,
                "original_blocks": 0,
                "candidate_blocks": 0,
                "original_callsites": 0,
                "candidate_callsites": 0,
                "original_import_prototypes": 0,
                "candidate_import_prototypes": 0,
                "original_hidden_sret_or_out_param_candidates": 0,
                "candidate_hidden_sret_or_out_param_candidates": 0,
                "original_varargs_candidates": 0,
                "candidate_varargs_candidates": 0,
                "original_function_pointer_targets": 0,
                "candidate_function_pointer_targets": 0,
                "missing_functions": 0,
                "ambiguous_functions": 0,
                "incomplete_callsite_functions": 0,
                "missing_callsites": 0,
                "function_mismatches": 0,
                "callsite_mismatches": 0,
                "abi_gaps": 0,
            },
            "checks": checks,
            "gaps": {},
        }

    original = abi_contract.get("original") if isinstance(abi_contract.get("original"), dict) else {}
    candidate = abi_contract.get("candidate") if isinstance(abi_contract.get("candidate"), dict) else {}
    original_counts = _proof_ir_abi_side_counts(original)
    candidate_counts = _proof_ir_abi_side_counts(candidate)
    gap_payload = (
        abi_contract.get("profile_comparison_gaps")
        if isinstance(abi_contract.get("profile_comparison_gaps"), dict)
        else abi_contract.get("comparison_gaps")
        if isinstance(abi_contract.get("comparison_gaps"), dict)
        else abi_contract.get("gaps")
        if isinstance(abi_contract.get("gaps"), dict)
        else {}
    )
    gap_counts = gap_payload.get("counts") if isinstance(gap_payload.get("counts"), dict) else {}
    missing_functions = _count_value(gap_counts, "missing_functions")
    ambiguous_functions = _count_value(gap_counts, "ambiguous_functions")
    incomplete_callsite_functions = _count_value(gap_counts, "incomplete_callsite_functions")
    missing_callsites = _count_value(gap_counts, "missing_callsites")
    function_mismatches = _count_value(gap_counts, "function_mismatches")
    callsite_mismatches = _count_value(gap_counts, "callsite_mismatches")
    abi_gaps = (
        missing_functions
        + ambiguous_functions
        + incomplete_callsite_functions
        + missing_callsites
        + function_mismatches
        + callsite_mismatches
    )
    contract_status = _proof_ir_abi_contract_status(abi_contract.get("status"))
    checks = {
        "abi_contract_present": True,
        "abi_model_known": bool(model_description.get("abi")),
        "abi_contract_status_satisfied": contract_status == "satisfied",
        "candidate_evidence_present": bool(candidate),
        "function_counts_match": original_counts["functions"] == candidate_counts["functions"],
        "callsite_counts_match": original_counts["callsites"] == candidate_counts["callsites"],
        "import_prototypes_match": original_counts["import_prototypes"] == candidate_counts["import_prototypes"],
        "no_missing_functions": missing_functions == 0,
        "no_ambiguous_functions": ambiguous_functions == 0,
        "callsites_complete": incomplete_callsite_functions == 0 and missing_callsites == 0,
        "no_function_mismatches": function_mismatches == 0,
        "no_callsite_mismatches": callsite_mismatches == 0,
        "abi_gaps_closed": abi_gaps == 0,
    }
    return {
        "format": "stage-a-abi-callsite-profile-v1",
        "status": "satisfied" if all(checks.values()) else "incomplete",
        "model_abi": model_description.get("abi"),
        "contract_sha256": _canonical_json_sha256(abi_contract),
        "contract_status": contract_status,
        "evidence_kind": abi_contract.get("evidence_kind"),
        "scope": abi_contract.get("scope"),
        "counts": {
            "original_functions": original_counts["functions"],
            "candidate_functions": candidate_counts["functions"],
            "original_blocks": original_counts["blocks"],
            "candidate_blocks": candidate_counts["blocks"],
            "original_callsites": original_counts["callsites"],
            "candidate_callsites": candidate_counts["callsites"],
            "original_import_prototypes": original_counts["import_prototypes"],
            "candidate_import_prototypes": candidate_counts["import_prototypes"],
            "original_stack_delta_derived_functions": original_counts["stack_delta_derived_functions"],
            "candidate_stack_delta_derived_functions": candidate_counts["stack_delta_derived_functions"],
            "original_stack_delta_block_local_functions": original_counts["stack_delta_block_local_functions"],
            "candidate_stack_delta_block_local_functions": candidate_counts["stack_delta_block_local_functions"],
            "original_register_preserved_candidates": original_counts["register_preserved_candidates"],
            "candidate_register_preserved_candidates": candidate_counts["register_preserved_candidates"],
            "original_register_clobbered_candidates": original_counts["register_clobbered_candidates"],
            "candidate_register_clobbered_candidates": candidate_counts["register_clobbered_candidates"],
            "original_hidden_sret_or_out_param_candidates": original_counts["hidden_sret_or_out_param_candidates"],
            "candidate_hidden_sret_or_out_param_candidates": candidate_counts["hidden_sret_or_out_param_candidates"],
            "original_varargs_candidates": original_counts["varargs_candidates"],
            "candidate_varargs_candidates": candidate_counts["varargs_candidates"],
            "original_direct_call_targets": original_counts["direct_call_targets"],
            "candidate_direct_call_targets": candidate_counts["direct_call_targets"],
            "original_import_call_targets": original_counts["import_call_targets"],
            "candidate_import_call_targets": candidate_counts["import_call_targets"],
            "original_function_pointer_call_targets": original_counts["function_pointer_call_targets"],
            "candidate_function_pointer_call_targets": candidate_counts["function_pointer_call_targets"],
            "original_function_pointer_targets": original_counts["function_pointer_targets"],
            "candidate_function_pointer_targets": candidate_counts["function_pointer_targets"],
            "missing_functions": missing_functions,
            "ambiguous_functions": ambiguous_functions,
            "incomplete_callsite_functions": incomplete_callsite_functions,
            "missing_callsites": missing_callsites,
            "function_mismatches": function_mismatches,
            "callsite_mismatches": callsite_mismatches,
            "abi_gaps": abi_gaps,
        },
        "checks": checks,
        "gaps": {
            "missing_functions": _proof_ir_abi_gap_sample(gap_payload, "missing_functions"),
            "ambiguous_functions": _proof_ir_abi_gap_sample(gap_payload, "ambiguous_functions"),
            "incomplete_callsites": _proof_ir_abi_gap_sample(gap_payload, "incomplete_callsites"),
            "function_mismatches": _proof_ir_abi_gap_sample(gap_payload, "function_mismatches"),
            "callsite_mismatches": _proof_ir_abi_gap_sample(gap_payload, "callsite_mismatches"),
        },
    }


def _proof_ir_abi_side_counts(side: dict[str, Any]) -> dict[str, int]:
    functions = [item for item in side.get("functions", []) if isinstance(item, dict)]
    import_prototypes = [item for item in side.get("import_prototypes", []) if isinstance(item, dict)]
    blocks = [
        block
        for function in functions
        for block in (function.get("blocks") if isinstance(function.get("blocks"), list) else [])
        if isinstance(block, dict)
    ]
    callsites = [
        callsite
        for function in functions
        for callsite in (function.get("callsites") if isinstance(function.get("callsites"), list) else [])
        if isinstance(callsite, dict)
    ]
    stack_delta_derived = 0
    stack_delta_block_local = 0
    preserved = 0
    clobbered = 0
    for function in functions:
        stack_delta = function.get("stack_delta") if isinstance(function.get("stack_delta"), dict) else {}
        if stack_delta.get("status") == "derived":
            stack_delta_derived += 1
        elif stack_delta.get("status") == "block_local":
            stack_delta_block_local += 1
        registers = function.get("registers") if isinstance(function.get("registers"), dict) else {}
        preserved_values = registers.get("preserved_candidates") if isinstance(registers.get("preserved_candidates"), list) else []
        clobbered_values = registers.get("clobbered_candidates") if isinstance(registers.get("clobbered_candidates"), list) else []
        preserved += len([item for item in preserved_values if isinstance(item, str)])
        clobbered += len([item for item in clobbered_values if isinstance(item, str)])
    hidden_sret = 0
    varargs = 0
    direct_targets = 0
    import_targets = 0
    function_pointer_calls = 0
    function_pointer_targets = 0
    for callsite in callsites:
        hidden = (
            callsite.get("hidden_sret_or_out_param_evidence")
            if isinstance(callsite.get("hidden_sret_or_out_param_evidence"), dict)
            else {}
        )
        if hidden.get("status") == "candidate":
            hidden_sret += 1
        varargs_evidence = callsite.get("varargs_evidence") if isinstance(callsite.get("varargs_evidence"), dict) else {}
        if varargs_evidence.get("status") == "candidate":
            varargs += 1
        target = callsite.get("target") if isinstance(callsite.get("target"), dict) else {}
        kind = target.get("kind")
        if kind == "direct":
            direct_targets += 1
        elif kind == "import":
            import_targets += 1
        elif kind == "function_pointer":
            function_pointer_calls += 1
        targets = callsite.get("function_pointer_targets") if isinstance(callsite.get("function_pointer_targets"), list) else []
        function_pointer_targets += len([item for item in targets if isinstance(item, dict)])
    return {
        "functions": len(functions),
        "blocks": len(blocks),
        "callsites": len(callsites),
        "import_prototypes": len(import_prototypes),
        "stack_delta_derived_functions": stack_delta_derived,
        "stack_delta_block_local_functions": stack_delta_block_local,
        "register_preserved_candidates": preserved,
        "register_clobbered_candidates": clobbered,
        "hidden_sret_or_out_param_candidates": hidden_sret,
        "varargs_candidates": varargs,
        "direct_call_targets": direct_targets,
        "import_call_targets": import_targets,
        "function_pointer_call_targets": function_pointer_calls,
        "function_pointer_targets": function_pointer_targets,
    }


def _proof_ir_abi_gap_sample(gaps: dict[str, Any], key: str) -> list[dict[str, Any]]:
    values = gaps.get(key) if isinstance(gaps.get(key), list) else []
    return [item for item in values[:50] if isinstance(item, dict)]


def _proof_ir_abi_contract_status(value: Any) -> str:
    status = str(value or "incomplete")
    if status in {"satisfied", "derived", "pass"}:
        return "satisfied"
    if status == "not_applicable":
        return "not_applicable"
    if status in {"fail", "failed", "violated"}:
        return "violated"
    return "incomplete"


def _proof_ir_environment_profile(
    *,
    model_description: dict[str, Any],
    loader_facts: dict[str, Any],
    block_semantics: dict[str, Any],
    semantic_observables: dict[str, Any],
    solver_claims: dict[str, Any],
    solver_evidence: dict[str, Any],
    trusted_boundaries: dict[str, Any],
) -> dict[str, Any]:
    environment_model = str(model_description.get("environment") or "")
    original_loader = loader_facts.get("original") if isinstance(loader_facts.get("original"), dict) else {}
    candidate_loader = loader_facts.get("candidate") if isinstance(loader_facts.get("candidate"), dict) else {}
    original_import_signature = _loader_profile_import_signature(original_loader)
    candidate_import_signature = _loader_profile_import_signature(candidate_loader)
    original_import_hashes = {_import_signature_sha256(item) for item in original_import_signature}
    candidate_import_hashes = {_import_signature_sha256(item) for item in candidate_import_signature}
    block_records = block_semantics.get("records") if isinstance(block_semantics.get("records"), list) else []
    semantic_records = (
        semantic_observables.get("records") if isinstance(semantic_observables.get("records"), list) else []
    )
    trusted_records = trusted_boundaries.get("records") if isinstance(trusted_boundaries.get("records"), list) else []
    solver_claim_records = solver_claims.get("records") if isinstance(solver_claims.get("records"), list) else []
    solver_evidence_entries = solver_evidence.get("entries") if isinstance(solver_evidence.get("entries"), list) else []
    import_block_records = [
        item
        for item in block_records
        if isinstance(item, dict) and item.get("semantics_kind") == "pe_import_thunk_semantics"
    ]
    import_semantic_records = [
        item
        for item in semantic_records
        if isinstance(item, dict) and item.get("claim_kind") == "pe_import_thunk_equivalence"
    ]
    import_trusted_records = [
        item
        for item in trusted_records
        if isinstance(item, dict) and item.get("trusted_boundary") == "pe_import_thunk_signature_equivalence_v1"
    ]
    import_solver_evidence = [
        item
        for item in solver_evidence_entries
        if isinstance(item, dict) and item.get("evidence_kind") == "pe_import_thunk"
    ]
    symbolic_claims = [
        item
        for item in semantic_records
        if isinstance(item, dict) and item.get("claim_kind") == "symbolic_observable_equivalence"
    ]
    gaps: list[dict[str, Any]] = []
    if environment_model != "uninterpreted-external-env-v1":
        gaps.append(
            {
                "category": "unsupported_environment_model",
                "expected": "uninterpreted-external-env-v1",
                "observed": environment_model,
            }
        )
    if original_import_signature != candidate_import_signature:
        gaps.append(
            {
                "category": "loader_import_signature_mismatch",
                "expected_sha256": _canonical_json_sha256(original_import_signature),
                "observed_sha256": _canonical_json_sha256(candidate_import_signature),
            }
        )
    import_block_signature_counts = _environment_import_block_signature_counts(
        import_block_records=import_block_records,
        original_import_hashes=original_import_hashes,
        candidate_import_hashes=candidate_import_hashes,
        gaps=gaps,
    )
    import_claim_signature_counts = _environment_import_claim_signature_counts(
        import_semantic_records=import_semantic_records,
        gaps=gaps,
    )
    if len(import_block_records) != len(import_semantic_records):
        gaps.append(
            {
                "category": "import_thunk_block_semantic_claim_count_mismatch",
                "block_semantics_records": len(import_block_records),
                "semantic_observable_records": len(import_semantic_records),
            }
        )
    if len(import_semantic_records) != len(import_trusted_records):
        gaps.append(
            {
                "category": "import_thunk_claim_boundary_count_mismatch",
                "semantic_observable_records": len(import_semantic_records),
                "trusted_boundary_records": len(import_trusted_records),
            }
        )
    if len(import_block_records) != len(import_solver_evidence):
        gaps.append(
            {
                "category": "import_thunk_solver_evidence_count_mismatch",
                "block_semantics_records": len(import_block_records),
                "solver_evidence_entries": len(import_solver_evidence),
            }
        )
    if symbolic_claims and environment_model != "uninterpreted-external-env-v1":
        gaps.append(
            {
                "category": "symbolic_external_claim_without_supported_environment_model",
                "symbolic_claims": len(symbolic_claims),
                "environment": environment_model,
            }
        )
    counts = {
        "original_imports": len(original_import_signature),
        "candidate_imports": len(candidate_import_signature),
        "import_thunk_block_semantics_records": len(import_block_records),
        "import_thunk_semantic_observable_records": len(import_semantic_records),
        "import_thunk_trusted_boundary_records": len(import_trusted_records),
        "import_thunk_solver_evidence_entries": len(import_solver_evidence),
        "import_thunk_semantics_with_original_signature": import_block_signature_counts["original_signatures"],
        "import_thunk_semantics_with_candidate_signature": import_block_signature_counts["candidate_signatures"],
        "import_thunk_semantics_with_matching_signatures": import_block_signature_counts["matching_signatures"],
        "import_thunk_semantics_in_original_loader_imports": import_block_signature_counts["original_loader_imports"],
        "import_thunk_semantics_in_candidate_loader_imports": import_block_signature_counts["candidate_loader_imports"],
        "import_thunk_claims_with_original_signature_hash": import_claim_signature_counts["original_signature_hashes"],
        "import_thunk_claims_with_candidate_signature_hash": import_claim_signature_counts["candidate_signature_hashes"],
        "import_thunk_claims_with_matching_signature_hashes": import_claim_signature_counts["matching_signature_hashes"],
        "symbolic_observable_claims": len(symbolic_claims),
        "solver_claims": len([item for item in solver_claim_records if isinstance(item, dict)]),
        "environment_gaps": len(gaps),
    }
    checks = {
        "environment_model_supported": environment_model == "uninterpreted-external-env-v1",
        "loader_import_signatures_match": original_import_signature == candidate_import_signature,
        "loader_import_counts_match": counts["original_imports"] == counts["candidate_imports"],
        "import_thunk_records_accounted": counts["import_thunk_block_semantics_records"]
        == counts["import_thunk_semantic_observable_records"]
        == counts["import_thunk_trusted_boundary_records"]
        == counts["import_thunk_solver_evidence_entries"],
        "import_thunk_semantics_have_signatures": counts["import_thunk_semantics_with_original_signature"]
        == counts["import_thunk_block_semantics_records"]
        and counts["import_thunk_semantics_with_candidate_signature"] == counts["import_thunk_block_semantics_records"],
        "import_thunk_signatures_match": counts["import_thunk_semantics_with_matching_signatures"]
        == counts["import_thunk_block_semantics_records"],
        "import_thunk_semantics_match_loader_imports": counts["import_thunk_semantics_in_original_loader_imports"]
        == counts["import_thunk_block_semantics_records"]
        and counts["import_thunk_semantics_in_candidate_loader_imports"] == counts["import_thunk_block_semantics_records"],
        "import_thunk_claims_have_signature_hashes": counts["import_thunk_claims_with_original_signature_hash"]
        == counts["import_thunk_semantic_observable_records"]
        and counts["import_thunk_claims_with_candidate_signature_hash"] == counts["import_thunk_semantic_observable_records"],
        "import_thunk_claim_signature_hashes_match": counts["import_thunk_claims_with_matching_signature_hashes"]
        == counts["import_thunk_semantic_observable_records"],
        "symbolic_claims_use_environment_model": not symbolic_claims
        or environment_model == "uninterpreted-external-env-v1",
        "solver_claims_accounted": counts["solver_claims"] == counts["symbolic_observable_claims"],
        "environment_gaps_closed": counts["environment_gaps"] == 0,
    }
    return {
        "format": "stage-a-environment-profile-v1",
        "status": "satisfied" if all(checks.values()) else "incomplete",
        "environment": environment_model,
        "counts": counts,
        "checks": checks,
        "signatures": {
            "original_imports_sha256": _canonical_json_sha256(original_import_signature),
            "candidate_imports_sha256": _canonical_json_sha256(candidate_import_signature),
        },
        "gaps": gaps[:100],
    }


def _environment_import_block_signature_counts(
    *,
    import_block_records: list[dict[str, Any]],
    original_import_hashes: set[str],
    candidate_import_hashes: set[str],
    gaps: list[dict[str, Any]],
) -> dict[str, int]:
    counts = {
        "original_signatures": 0,
        "candidate_signatures": 0,
        "matching_signatures": 0,
        "original_loader_imports": 0,
        "candidate_loader_imports": 0,
    }
    for record in import_block_records:
        obligation_id = str(record.get("obligation_id") or "")
        proof_cache = str(record.get("proof_cache") or "")
        original_signature = _normalized_import_signature(
            (record.get("original") if isinstance(record.get("original"), dict) else {}).get("import_signature")
        )
        candidate_signature = _normalized_import_signature(
            (record.get("candidate") if isinstance(record.get("candidate"), dict) else {}).get("import_signature")
        )
        if original_signature is None:
            gaps.append(
                {
                    "category": "original_import_thunk_semantics_missing_import_signature",
                    "obligation_id": obligation_id,
                    "proof_cache": proof_cache,
                }
            )
        else:
            counts["original_signatures"] += 1
            original_hash = _import_signature_sha256(original_signature)
            if original_hash in original_import_hashes:
                counts["original_loader_imports"] += 1
            else:
                gaps.append(
                    {
                        "category": "original_import_thunk_signature_not_in_loader_imports",
                        "obligation_id": obligation_id,
                        "proof_cache": proof_cache,
                        "signature_sha256": original_hash,
                    }
                )
        if candidate_signature is None:
            gaps.append(
                {
                    "category": "candidate_import_thunk_semantics_missing_import_signature",
                    "obligation_id": obligation_id,
                    "proof_cache": proof_cache,
                }
            )
        else:
            counts["candidate_signatures"] += 1
            candidate_hash = _import_signature_sha256(candidate_signature)
            if candidate_hash in candidate_import_hashes:
                counts["candidate_loader_imports"] += 1
            else:
                gaps.append(
                    {
                        "category": "candidate_import_thunk_signature_not_in_loader_imports",
                        "obligation_id": obligation_id,
                        "proof_cache": proof_cache,
                        "signature_sha256": candidate_hash,
                    }
                )
        if original_signature is not None and candidate_signature is not None:
            if original_signature == candidate_signature:
                counts["matching_signatures"] += 1
            else:
                gaps.append(
                    {
                        "category": "import_thunk_semantics_import_signature_mismatch",
                        "obligation_id": obligation_id,
                        "proof_cache": proof_cache,
                        "expected_sha256": _import_signature_sha256(original_signature),
                        "observed_sha256": _import_signature_sha256(candidate_signature),
                    }
                )
    return counts


def _environment_import_claim_signature_counts(
    *,
    import_semantic_records: list[dict[str, Any]],
    gaps: list[dict[str, Any]],
) -> dict[str, int]:
    counts = {
        "original_signature_hashes": 0,
        "candidate_signature_hashes": 0,
        "matching_signature_hashes": 0,
    }
    for record in import_semantic_records:
        obligation_id = str(record.get("obligation_id") or "")
        proof_cache = str(record.get("proof_cache") or "")
        original = record.get("original") if isinstance(record.get("original"), dict) else {}
        candidate = record.get("candidate") if isinstance(record.get("candidate"), dict) else {}
        original_hash = original.get("import_signature_sha256")
        candidate_hash = candidate.get("import_signature_sha256")
        if _is_sha256_hex(original_hash):
            counts["original_signature_hashes"] += 1
        else:
            gaps.append(
                {
                    "category": "original_import_thunk_claim_missing_import_signature_hash",
                    "obligation_id": obligation_id,
                    "proof_cache": proof_cache,
                }
            )
        if _is_sha256_hex(candidate_hash):
            counts["candidate_signature_hashes"] += 1
        else:
            gaps.append(
                {
                    "category": "candidate_import_thunk_claim_missing_import_signature_hash",
                    "obligation_id": obligation_id,
                    "proof_cache": proof_cache,
                }
            )
        if _is_sha256_hex(original_hash) and _is_sha256_hex(candidate_hash):
            if original_hash == candidate_hash:
                counts["matching_signature_hashes"] += 1
            else:
                gaps.append(
                    {
                        "category": "import_thunk_claim_import_signature_hash_mismatch",
                        "obligation_id": obligation_id,
                        "proof_cache": proof_cache,
                        "expected_sha256": original_hash,
                        "observed_sha256": candidate_hash,
                    }
                )
    return counts


def _normalized_import_signature(value: Any) -> dict[str, Any] | None:
    if not isinstance(value, dict):
        return None
    ordinal = value.get("ordinal")
    normalized = {
        "dll": str(value.get("dll") or "").lower(),
        "symbol": value.get("symbol") if isinstance(value.get("symbol"), str) else None,
        "ordinal": ordinal if isinstance(ordinal, int) and not isinstance(ordinal, bool) else None,
    }
    if not normalized["dll"] and normalized["symbol"] is None and normalized["ordinal"] is None:
        return None
    return normalized


def _import_signature_sha256(value: Any) -> str:
    normalized = _normalized_import_signature(value)
    return _canonical_json_sha256(normalized if normalized is not None else value)


def _proof_ir_reachability_profile(*, obligation_items: list[dict[str, Any]]) -> dict[str, Any]:
    block_rows = [item for item in obligation_items if item.get("kind") == "block_equivalence"]
    cfg_rows = [item for item in obligation_items if item.get("kind") == "cfg_edge"]
    reachability_rows = [item for item in obligation_items if item.get("kind") == "reachability"]
    block_status_by_id = {
        str(item.get("id")): item.get("status")
        for item in block_rows
        if isinstance(item.get("id"), str) and item.get("id")
    }
    cfg_by_id = {
        str(item.get("id")): item
        for item in cfg_rows
        if isinstance(item.get("id"), str) and item.get("id")
    }
    reachability_by_block = {
        str(item.get("block")): item
        for item in reachability_rows
        if isinstance(item.get("block"), str) and item.get("block")
    }
    cfg_status_counts = _count_by(cfg_rows, "status")
    reachability_status_counts = _count_by(reachability_rows, "status")
    reachability_rule_counts = _count_by(
        [item for item in reachability_rows if item.get("status") == "proved"],
        "generic_proof_rule",
    )
    known_reachability_rules = {
        "entry_root_reachability_v1",
        "checked_root_reachability_v1",
        "direct_cfg_reachability_v1",
    }
    unknown_reachability_rows = [
        item
        for item in reachability_rows
        if item.get("status") == "proved" and item.get("generic_proof_rule") not in known_reachability_rules
    ]
    gaps: list[dict[str, Any]] = []
    for item in cfg_rows:
        if item.get("status") != "proved":
            gaps.append(
                {
                    "category": "open_cfg_edge_obligation",
                    "obligation_id": item.get("id"),
                    "status": item.get("status"),
                    "source_block": item.get("source_block"),
                    "target_block": item.get("target_block"),
                }
            )
            continue
        source_block = item.get("source_block")
        target_block = item.get("target_block")
        if block_status_by_id.get(f"block:{source_block}") != "proved":
            gaps.append(
                {
                    "category": "cfg_edge_source_block_not_proved",
                    "obligation_id": item.get("id"),
                    "source_block": source_block,
                    "source_status": block_status_by_id.get(f"block:{source_block}"),
                }
            )
        if block_status_by_id.get(f"block:{target_block}") != "proved":
            gaps.append(
                {
                    "category": "cfg_edge_target_block_not_proved",
                    "obligation_id": item.get("id"),
                    "target_block": target_block,
                    "target_status": block_status_by_id.get(f"block:{target_block}"),
                }
            )
        target_reachability = reachability_by_block.get(str(target_block))
        if not isinstance(target_reachability, dict):
            gaps.append(
                {
                    "category": "cfg_edge_target_missing_reachability_obligation",
                    "obligation_id": item.get("id"),
                    "target_block": target_block,
                }
            )
        elif target_reachability.get("status") != "proved":
            gaps.append(
                {
                    "category": "cfg_edge_target_reachability_not_proved",
                    "obligation_id": item.get("id"),
                    "target_block": target_block,
                    "reachability_status": target_reachability.get("status"),
                }
            )
    for item in reachability_rows:
        if item.get("status") != "proved":
            gaps.append(
                {
                    "category": "open_reachability_obligation",
                    "obligation_id": item.get("id"),
                    "status": item.get("status"),
                    "block": item.get("block"),
                }
            )
            continue
        if item.get("generic_proof_rule") not in known_reachability_rules:
            gaps.append(
                {
                    "category": "unknown_reachability_proof_rule",
                    "obligation_id": item.get("id"),
                    "proof_rule": item.get("proof_rule"),
                    "generic_proof_rule": item.get("generic_proof_rule"),
                }
            )
        block_id = item.get("block")
        if isinstance(block_id, str) and block_status_by_id.get(f"block:{block_id}") != "proved":
            gaps.append(
                {
                    "category": "reachability_block_not_proved",
                    "obligation_id": item.get("id"),
                    "block": block_id,
                    "block_status": block_status_by_id.get(f"block:{block_id}"),
                }
            )
        if item.get("generic_proof_rule") == "direct_cfg_reachability_v1":
            edge_id = item.get("edge_obligation")
            edge = cfg_by_id.get(str(edge_id or ""))
            if edge is None:
                gaps.append(
                    {
                        "category": "direct_cfg_reachability_missing_edge_obligation",
                        "obligation_id": item.get("id"),
                        "block": block_id,
                        "edge_obligation": edge_id,
                    }
                )
            elif edge.get("status") != "proved":
                gaps.append(
                    {
                        "category": "direct_cfg_reachability_edge_not_proved",
                        "obligation_id": item.get("id"),
                        "block": block_id,
                        "edge_obligation": edge_id,
                        "edge_status": edge.get("status"),
                    }
                )
            elif isinstance(block_id, str) and edge.get("target_block") != block_id:
                gaps.append(
                    {
                        "category": "direct_cfg_reachability_edge_target_mismatch",
                        "obligation_id": item.get("id"),
                        "block": block_id,
                        "edge_obligation": edge_id,
                        "edge_target_block": edge.get("target_block"),
                    }
                )
    direct_rows = [
        item
        for item in reachability_rows
        if item.get("status") == "proved" and item.get("generic_proof_rule") == "direct_cfg_reachability_v1"
    ]
    direct_rows_with_edge = sum(1 for item in direct_rows if isinstance(item.get("edge_obligation"), str) and item.get("edge_obligation"))
    direct_rows_with_proved_edge = sum(
        1
        for item in direct_rows
        if isinstance(item.get("edge_obligation"), str)
        and (cfg_by_id.get(str(item.get("edge_obligation"))) or {}).get("status") == "proved"
        and (cfg_by_id.get(str(item.get("edge_obligation"))) or {}).get("target_block") == item.get("block")
    )
    counts = {
        "block_equivalence_obligations": len(block_rows),
        "proved_block_equivalence_obligations": sum(1 for item in block_rows if item.get("status") == "proved"),
        "cfg_edge_obligations": len(cfg_rows),
        "proved_cfg_edge_obligations": _count_value(cfg_status_counts, "proved"),
        "open_cfg_edge_obligations": len(cfg_rows) - _count_value(cfg_status_counts, "proved"),
        "reachability_obligations": len(reachability_rows),
        "proved_reachability_obligations": _count_value(reachability_status_counts, "proved"),
        "open_reachability_obligations": len(reachability_rows) - _count_value(reachability_status_counts, "proved"),
        "entry_root_reachability": _count_value(reachability_rule_counts, "entry_root_reachability_v1"),
        "checked_root_reachability": _count_value(reachability_rule_counts, "checked_root_reachability_v1"),
        "direct_cfg_reachability": _count_value(reachability_rule_counts, "direct_cfg_reachability_v1"),
        "unknown_reachability_rules": len(unknown_reachability_rows),
        "direct_cfg_reachability_with_edge_obligation": direct_rows_with_edge,
        "direct_cfg_reachability_with_proved_edge": direct_rows_with_proved_edge,
        "reachability_gaps": len(gaps),
    }
    checks = {
        "cfg_edge_obligations_closed": counts["open_cfg_edge_obligations"] == 0,
        "reachability_obligations_closed": counts["open_reachability_obligations"] == 0,
        "reachability_rules_known": counts["unknown_reachability_rules"] == 0,
        "reachability_rules_accounted": counts["entry_root_reachability"]
        + counts["checked_root_reachability"]
        + counts["direct_cfg_reachability"]
        + counts["unknown_reachability_rules"]
        == counts["proved_reachability_obligations"],
        "direct_cfg_reachability_edges_present": counts["direct_cfg_reachability_with_edge_obligation"]
        == counts["direct_cfg_reachability"],
        "direct_cfg_reachability_edges_proved": counts["direct_cfg_reachability_with_proved_edge"]
        == counts["direct_cfg_reachability"],
        "proved_cfg_edges_bind_proved_blocks": not any(
            gap["category"] in {"cfg_edge_source_block_not_proved", "cfg_edge_target_block_not_proved"}
            for gap in gaps
        ),
        "proved_cfg_edge_targets_have_reachability": not any(
            gap["category"]
            in {"cfg_edge_target_missing_reachability_obligation", "cfg_edge_target_reachability_not_proved"}
            for gap in gaps
        ),
        "proved_reachability_blocks_proved": not any(gap["category"] == "reachability_block_not_proved" for gap in gaps),
        "reachability_gaps_closed": counts["reachability_gaps"] == 0,
    }
    return {
        "format": "stage-a-reachability-profile-v1",
        "status": "satisfied" if all(checks.values()) else "incomplete",
        "counts": counts,
        "checks": checks,
        "by_cfg_edge_status": cfg_status_counts,
        "by_reachability_status": reachability_status_counts,
        "by_reachability_rule": reachability_rule_counts,
        "gaps": gaps[:100],
    }


def _proof_ir_solver_evidence_profile(
    *,
    out: Path,
    proof_cache: list[dict[str, Any]],
    solver_evidence: dict[str, Any],
    solver_claims: dict[str, Any],
) -> dict[str, Any]:
    evidence_entries = solver_evidence.get("entries") if isinstance(solver_evidence.get("entries"), list) else []
    solver_claim_records = solver_claims.get("records") if isinstance(solver_claims.get("records"), list) else []
    evidence_rows = [item for item in evidence_entries if isinstance(item, dict)]
    claim_rows = [item for item in solver_claim_records if isinstance(item, dict)]
    evidence_kind_counts = _count_by(evidence_rows, "evidence_kind")
    status_counts = _count_by(evidence_rows, "status")
    claim_boundary_counts = _count_by(claim_rows, "trusted_boundary")
    solver_claim_gap_counts = _gap_category_counts(claim_rows)
    trusted_z3_entries = [
        item
        for item in evidence_rows
        if item.get("evidence_kind") == "trusted_z3_unsat"
        or item.get("trusted_boundary") == "z3_unsat_local_equivalence_oracle_v1"
    ]
    local_symbolic_entries = [
        item
        for item in evidence_rows
        if item.get("trusted_boundary") == "local_symbolic_equivalence_result_v1"
    ]
    solver_claims_with_query_hash = sum(1 for item in claim_rows if _is_sha256_hex(item.get("smt_query_sha256")))
    evidence_query_hash_gaps = sum(
        1
        for item in trusted_z3_entries + local_symbolic_entries
        if not _is_sha256_hex(item.get("smt_query_sha256"))
    )
    file_binding = _solver_evidence_file_binding(
        out=out,
        solver_evidence=solver_evidence,
        evidence_rows=evidence_rows,
    )
    incomplete_entries = sum(1 for item in evidence_rows if item.get("status") != "satisfied")
    counts = {
        "proof_cache_entries": len(proof_cache),
        "solver_evidence_entries": len(evidence_rows),
        "solver_evidence_index_entries": int((solver_evidence.get("counts") if isinstance(solver_evidence.get("counts"), dict) else {}).get("entries") or 0),
        "solver_claims": len(claim_rows),
        "satisfied_entries": _count_value(status_counts, "satisfied"),
        "incomplete_entries": incomplete_entries,
        "structural_byte_identity_entries": _count_value(evidence_kind_counts, "structural_byte_identity"),
        "checked_generated_mapping_entries": _count_value(evidence_kind_counts, "checked_generated_mapping"),
        "pe_import_thunk_entries": _count_value(evidence_kind_counts, "pe_import_thunk"),
        "trusted_z3_unsat_entries": len(trusted_z3_entries),
        "z3_counterexample_entries": _count_value(evidence_kind_counts, "z3_counterexample"),
        "z3_symbolic_incomplete_entries": _count_value(evidence_kind_counts, "z3_symbolic_incomplete"),
        "missing_proof_cache_entries": _count_value(evidence_kind_counts, "missing_proof_cache"),
        "unreadable_proof_cache_entries": _count_value(evidence_kind_counts, "unreadable_proof_cache"),
        "unknown_proof_cache_entries": _count_value(evidence_kind_counts, "unknown_proof_cache"),
        "trusted_z3_unsat_claims": _count_value(claim_boundary_counts, "z3_unsat_local_equivalence_oracle_v1"),
        "local_symbolic_claims": _count_value(claim_boundary_counts, "local_symbolic_equivalence_result_v1"),
        "solver_claims_with_query_hash": solver_claims_with_query_hash,
        "solver_evidence_query_hash_gaps": evidence_query_hash_gaps,
        "solver_evidence_query_hash_mismatches": solver_claim_gap_counts.get(
            "solver_evidence_smt_query_sha256_mismatch",
            0,
        ),
        "solver_evidence_file_missing": file_binding["counts"]["solver_evidence_file_missing"],
        "solver_evidence_file_hash_mismatches": file_binding["counts"]["solver_evidence_file_hash_mismatches"],
        "solver_evidence_index_file_missing": file_binding["counts"]["solver_evidence_index_file_missing"],
        "solver_evidence_index_hash_mismatches": file_binding["counts"]["solver_evidence_index_hash_mismatches"],
        "solver_evidence_jsonl_parse_gaps": file_binding["counts"]["solver_evidence_jsonl_parse_gaps"],
        "solver_evidence_entry_hash_mismatches": file_binding["counts"]["solver_evidence_entry_hash_mismatches"],
        "solver_evidence_index_entry_hash_mismatches": file_binding["counts"]["solver_evidence_index_entry_hash_mismatches"],
        "solver_claim_gaps": sum(solver_claim_gap_counts.values()),
        "solver_evidence_entry_gaps": incomplete_entries,
    }
    classified_entries = (
        counts["structural_byte_identity_entries"]
        + counts["checked_generated_mapping_entries"]
        + counts["pe_import_thunk_entries"]
        + counts["trusted_z3_unsat_entries"]
        + counts["z3_counterexample_entries"]
        + counts["z3_symbolic_incomplete_entries"]
        + counts["missing_proof_cache_entries"]
        + counts["unreadable_proof_cache_entries"]
        + counts["unknown_proof_cache_entries"]
    )
    checks = {
        "solver_evidence_records_match": counts["solver_evidence_entries"] == counts["solver_evidence_index_entries"],
        "solver_evidence_matches_proof_cache": counts["solver_evidence_entries"] == counts["proof_cache_entries"],
        "solver_claim_records_match": counts["solver_claims"]
        == int((solver_claims.get("counts") if isinstance(solver_claims.get("counts"), dict) else {}).get("records") or 0),
        "solver_evidence_entries_satisfied": counts["satisfied_entries"] == counts["solver_evidence_entries"]
        and counts["incomplete_entries"] == 0,
        "solver_evidence_entries_classified": classified_entries == counts["solver_evidence_entries"],
        "trusted_z3_evidence_matches_claims": counts["trusted_z3_unsat_entries"] == counts["trusted_z3_unsat_claims"],
        "local_symbolic_evidence_matches_claims": len(local_symbolic_entries) == counts["local_symbolic_claims"],
        "solver_claims_have_query_hashes": counts["solver_claims_with_query_hash"] == counts["solver_claims"],
        "solver_evidence_query_hashes_present": counts["solver_evidence_query_hash_gaps"] == 0,
        "solver_evidence_query_hashes_match": counts["solver_evidence_query_hash_mismatches"] == 0,
        "solver_evidence_files_present": counts["solver_evidence_file_missing"] == 0
        and counts["solver_evidence_index_file_missing"] == 0,
        "solver_evidence_file_hashes_match": counts["solver_evidence_file_hash_mismatches"] == 0
        and counts["solver_evidence_index_hash_mismatches"] == 0,
        "solver_evidence_entry_hashes_match": counts["solver_evidence_jsonl_parse_gaps"] == 0
        and counts["solver_evidence_entry_hash_mismatches"] == 0
        and counts["solver_evidence_index_entry_hash_mismatches"] == 0,
        "no_counterexample_entries": counts["z3_counterexample_entries"] == 0,
        "no_incomplete_symbolic_entries": counts["z3_symbolic_incomplete_entries"] == 0,
        "no_missing_proof_cache_entries": counts["missing_proof_cache_entries"] == 0,
        "no_unreadable_proof_cache_entries": counts["unreadable_proof_cache_entries"] == 0,
        "no_unknown_proof_cache_entries": counts["unknown_proof_cache_entries"] == 0,
        "solver_claim_gaps_closed": counts["solver_claim_gaps"] == 0,
        "solver_evidence_entry_gaps_closed": counts["solver_evidence_entry_gaps"] == 0,
    }
    return {
        "format": "stage-a-solver-evidence-profile-v1",
        "status": "satisfied" if all(checks.values()) else "incomplete",
        "counts": counts,
        "checks": checks,
        "evidence_kind_counts": evidence_kind_counts,
        "status_counts": status_counts,
        "solver_claim_boundary_counts": claim_boundary_counts,
        "solver_claim_gap_counts": solver_claim_gap_counts,
        "file_binding": file_binding,
    }


def _solver_backend_summary(value: Any) -> dict[str, Any] | None:
    if not isinstance(value, dict):
        return None
    return {str(key): value[key] for key in sorted(value, key=str)}


def _solver_backend_sha256(value: Any) -> str | None:
    summary = _solver_backend_summary(value)
    if summary is None:
        return None
    return _canonical_json_sha256(summary)


def _proof_ir_solver_backend_profile(
    *,
    solver_evidence: dict[str, Any],
    solver_claims: dict[str, Any],
) -> dict[str, Any]:
    evidence_entries = solver_evidence.get("entries") if isinstance(solver_evidence.get("entries"), list) else []
    solver_claim_records = solver_claims.get("records") if isinstance(solver_claims.get("records"), list) else []
    evidence_rows = [item for item in evidence_entries if isinstance(item, dict)]
    claim_rows = [item for item in solver_claim_records if isinstance(item, dict)]
    solver_backed_evidence = [item for item in evidence_rows if _solver_evidence_row_requires_backend(item)]
    trusted_z3_evidence = [
        item
        for item in solver_backed_evidence
        if item.get("trusted_boundary") == "z3_unsat_local_equivalence_oracle_v1"
        or item.get("evidence_kind") == "trusted_z3_unsat"
    ]
    trusted_z3_claims = [
        item for item in claim_rows if item.get("trusted_boundary") == "z3_unsat_local_equivalence_oracle_v1"
    ]
    gaps: list[dict[str, Any]] = []

    solver_evidence_with_backend = 0
    trusted_z3_with_z3_backend = 0
    for item in solver_backed_evidence:
        backend = item.get("solver_backend") if isinstance(item.get("solver_backend"), dict) else None
        backend_sha256 = item.get("solver_backend_sha256")
        if backend is None:
            gaps.append(
                {
                    "category": "missing_solver_backend_evidence",
                    "obligation_id": item.get("obligation_id"),
                    "proof_cache": item.get("proof_cache"),
                    "evidence_kind": item.get("evidence_kind"),
                }
            )
            continue
        if not _is_sha256_hex(backend_sha256):
            gaps.append(
                {
                    "category": "missing_solver_backend_evidence_sha256",
                    "obligation_id": item.get("obligation_id"),
                    "proof_cache": item.get("proof_cache"),
                    "observed": backend_sha256,
                }
            )
        elif _canonical_json_sha256(backend) != backend_sha256:
            gaps.append(
                {
                    "category": "solver_backend_evidence_sha256_mismatch",
                    "obligation_id": item.get("obligation_id"),
                    "proof_cache": item.get("proof_cache"),
                    "expected": _canonical_json_sha256(backend),
                    "observed": backend_sha256,
                }
            )
        else:
            solver_evidence_with_backend += 1
        gaps.extend(_solver_backend_identity_gaps(backend, item))
        if (
            item.get("trusted_boundary") == "z3_unsat_local_equivalence_oracle_v1"
            or item.get("evidence_kind") == "trusted_z3_unsat"
        ) and backend.get("solver") == "z3" and backend.get("trust_boundary") == "z3_unsat_local_equivalence_oracle_v1":
            trusted_z3_with_z3_backend += 1

    solver_claims_with_backend = 0
    claim_gap_counts = _gap_category_counts(claim_rows)
    for item in claim_rows:
        backend = item.get("solver_backend") if isinstance(item.get("solver_backend"), dict) else None
        backend_sha256 = item.get("solver_backend_sha256")
        if backend is None:
            gaps.append(
                {
                    "category": "missing_solver_backend_claim",
                    "obligation_id": item.get("obligation_id"),
                    "proof_cache": item.get("proof_cache"),
                }
            )
            continue
        if not _is_sha256_hex(backend_sha256):
            gaps.append(
                {
                    "category": "missing_solver_backend_claim_sha256",
                    "obligation_id": item.get("obligation_id"),
                    "proof_cache": item.get("proof_cache"),
                    "observed": backend_sha256,
                }
            )
        elif _canonical_json_sha256(backend) != backend_sha256:
            gaps.append(
                {
                    "category": "solver_backend_claim_sha256_mismatch",
                    "obligation_id": item.get("obligation_id"),
                    "proof_cache": item.get("proof_cache"),
                    "expected": _canonical_json_sha256(backend),
                    "observed": backend_sha256,
                }
            )
        else:
            solver_claims_with_backend += 1
        gaps.extend(_solver_backend_identity_gaps(backend, item))
        if (
            item.get("trusted_boundary") == "z3_unsat_local_equivalence_oracle_v1"
            and backend.get("solver") == "z3"
            and backend.get("trust_boundary") == "z3_unsat_local_equivalence_oracle_v1"
        ):
            trusted_z3_with_z3_backend += 1
        for gap in item.get("gaps", []):
            if isinstance(gap, dict) and str(gap.get("category") or "").startswith("solver_evidence_solver_backend"):
                gaps.append(
                    {
                        "category": gap.get("category"),
                        "obligation_id": item.get("obligation_id"),
                        "proof_cache": item.get("proof_cache"),
                    }
                )

    backend_gap_counts = _gap_category_counts([{"gaps": gaps}])
    counts = {
        "solver_evidence_entries": len(evidence_rows),
        "solver_backed_evidence_entries": len(solver_backed_evidence),
        "trusted_z3_unsat_entries": len(trusted_z3_evidence),
        "solver_claims": len(claim_rows),
        "trusted_z3_unsat_claims": len(trusted_z3_claims),
        "solver_evidence_with_backend": solver_evidence_with_backend,
        "solver_claims_with_backend": solver_claims_with_backend,
        "trusted_z3_with_z3_backend": trusted_z3_with_z3_backend,
        "missing_backend_entries": backend_gap_counts.get("missing_solver_backend_evidence", 0)
        + backend_gap_counts.get("missing_solver_backend_evidence_sha256", 0),
        "missing_backend_claims": backend_gap_counts.get("missing_solver_backend_claim", 0)
        + backend_gap_counts.get("missing_solver_backend_claim_sha256", 0),
        "backend_hash_mismatches": backend_gap_counts.get("solver_backend_evidence_sha256_mismatch", 0)
        + backend_gap_counts.get("solver_backend_claim_sha256_mismatch", 0)
        + backend_gap_counts.get("solver_evidence_solver_backend_sha256_mismatch", 0)
        + backend_gap_counts.get("solver_evidence_solver_backend_mismatch", 0),
        "unknown_solver_backends": backend_gap_counts.get("solver_backend_format_mismatch", 0)
        + backend_gap_counts.get("solver_backend_solver_missing_or_unknown", 0),
        "backend_gaps": len(gaps),
    }
    checks = {
        "solver_backed_evidence_has_backend": counts["solver_evidence_with_backend"]
        == counts["solver_backed_evidence_entries"],
        "solver_claims_have_backend": counts["solver_claims_with_backend"] == counts["solver_claims"],
        "solver_claim_backend_hashes_match_evidence": counts["backend_hash_mismatches"] == 0,
        "trusted_z3_uses_z3_backend": counts["trusted_z3_with_z3_backend"]
        == counts["trusted_z3_unsat_entries"] + counts["trusted_z3_unsat_claims"],
        "backend_gaps_closed": counts["backend_gaps"] == 0,
    }
    return {
        "format": "stage-a-solver-backend-profile-v1",
        "status": "satisfied" if all(checks.values()) else "incomplete",
        "counts": counts,
        "checks": checks,
        "backend_gap_counts": backend_gap_counts,
        "gaps": gaps[:100],
    }


def _solver_evidence_row_requires_backend(row: dict[str, Any]) -> bool:
    return bool(
        isinstance(row.get("solver"), str)
        or row.get("evidence_kind") in {"trusted_z3_unsat", "z3_counterexample", "z3_symbolic_incomplete"}
        or row.get("trusted_boundary")
        in {"z3_unsat_local_equivalence_oracle_v1", "local_symbolic_equivalence_result_v1"}
    )


def _solver_backend_identity_gaps(backend: dict[str, Any], owner: dict[str, Any]) -> list[dict[str, Any]]:
    gaps: list[dict[str, Any]] = []
    required = ("format", "solver", "version", "engine", "smt_fragment", "trust_boundary")
    missing = [field for field in required if not isinstance(backend.get(field), str) or not backend.get(field)]
    if missing:
        gaps.append(
            {
                "category": "solver_backend_required_fields_missing",
                "obligation_id": owner.get("obligation_id"),
                "proof_cache": owner.get("proof_cache"),
                "missing": missing,
            }
        )
    if backend.get("format") != "stage-a-solver-backend-v1":
        gaps.append(
            {
                "category": "solver_backend_format_mismatch",
                "obligation_id": owner.get("obligation_id"),
                "proof_cache": owner.get("proof_cache"),
                "expected": "stage-a-solver-backend-v1",
                "observed": backend.get("format"),
            }
        )
    if backend.get("solver") != "z3":
        gaps.append(
            {
                "category": "solver_backend_solver_missing_or_unknown",
                "obligation_id": owner.get("obligation_id"),
                "proof_cache": owner.get("proof_cache"),
                "expected": "z3",
                "observed": backend.get("solver"),
            }
        )
    return gaps


def _solver_evidence_file_binding(
    *,
    out: Path,
    solver_evidence: dict[str, Any],
    evidence_rows: list[dict[str, Any]],
) -> dict[str, Any]:
    counts = {
        "solver_evidence_file_missing": 0,
        "solver_evidence_file_hash_mismatches": 0,
        "solver_evidence_index_file_missing": 0,
        "solver_evidence_index_hash_mismatches": 0,
        "solver_evidence_jsonl_parse_gaps": 0,
        "solver_evidence_entry_hash_mismatches": 0,
        "solver_evidence_index_entry_hash_mismatches": 0,
    }
    gaps: list[dict[str, Any]] = []
    jsonl_entries: list[dict[str, Any]] = []

    path_text = solver_evidence.get("path")
    if isinstance(path_text, str) and path_text:
        evidence_path = out / path_text
        if not evidence_path.is_file():
            counts["solver_evidence_file_missing"] += 1
            gaps.append({"category": "solver_evidence_file_missing", "path": path_text})
        else:
            actual_sha = sha256_file(evidence_path)
            expected_sha = solver_evidence.get("sha256")
            if actual_sha != expected_sha:
                counts["solver_evidence_file_hash_mismatches"] += 1
                gaps.append(
                    {
                        "category": "solver_evidence_file_hash_mismatch",
                        "path": path_text,
                        "expected": expected_sha,
                        "observed": actual_sha,
                    }
                )
            for line_number, line in enumerate(evidence_path.read_text(encoding="utf-8").splitlines(), start=1):
                if not line.strip():
                    continue
                try:
                    entry = json.loads(line)
                except json.JSONDecodeError as exc:
                    counts["solver_evidence_jsonl_parse_gaps"] += 1
                    gaps.append(
                        {
                            "category": "solver_evidence_jsonl_parse_error",
                            "path": path_text,
                            "line": line_number,
                            "error": str(exc),
                        }
                    )
                    continue
                if not isinstance(entry, dict):
                    counts["solver_evidence_jsonl_parse_gaps"] += 1
                    gaps.append(
                        {
                            "category": "solver_evidence_jsonl_non_object_entry",
                            "path": path_text,
                            "line": line_number,
                        }
                    )
                    continue
                jsonl_entries.append(entry)
                expected_entry_sha = entry.get("entry_sha256")
                comparable_entry = dict(entry)
                comparable_entry.pop("entry_sha256", None)
                actual_entry_sha = _canonical_json_sha256(comparable_entry)
                if expected_entry_sha != actual_entry_sha:
                    counts["solver_evidence_entry_hash_mismatches"] += 1
                    gaps.append(
                        {
                            "category": "solver_evidence_entry_hash_mismatch",
                            "path": path_text,
                            "line": line_number,
                            "id": entry.get("id"),
                            "expected": expected_entry_sha,
                            "observed": actual_entry_sha,
                        }
                    )
    elif evidence_rows:
        counts["solver_evidence_file_missing"] += 1
        gaps.append({"category": "solver_evidence_file_missing", "path": None})

    index_path_text = solver_evidence.get("index_path")
    if isinstance(index_path_text, str) and index_path_text:
        index_path = out / index_path_text
        if not index_path.is_file():
            counts["solver_evidence_index_file_missing"] += 1
            gaps.append({"category": "solver_evidence_index_file_missing", "path": index_path_text})
        else:
            actual_index_sha = sha256_file(index_path)
            expected_index_sha = solver_evidence.get("index_sha256")
            if actual_index_sha != expected_index_sha:
                counts["solver_evidence_index_hash_mismatches"] += 1
                gaps.append(
                    {
                        "category": "solver_evidence_index_hash_mismatch",
                        "path": index_path_text,
                        "expected": expected_index_sha,
                        "observed": actual_index_sha,
                    }
                )
    elif evidence_rows:
        counts["solver_evidence_index_file_missing"] += 1
        gaps.append({"category": "solver_evidence_index_file_missing", "path": None})

    if jsonl_entries:
        jsonl_by_id = {
            str(entry.get("id")): entry
            for entry in jsonl_entries
            if isinstance(entry.get("id"), str) and entry.get("id")
        }
        for index, row in enumerate(evidence_rows):
            if not isinstance(row, dict):
                continue
            row_id = row.get("id")
            jsonl_entry = jsonl_by_id.get(str(row_id)) if isinstance(row_id, str) else None
            if jsonl_entry is None and index < len(jsonl_entries):
                jsonl_entry = jsonl_entries[index]
            if jsonl_entry is None:
                counts["solver_evidence_index_entry_hash_mismatches"] += 1
                gaps.append(
                    {
                        "category": "solver_evidence_index_entry_missing_jsonl_entry",
                        "id": row_id,
                        "index": index,
                    }
                )
                continue
            expected_entry_sha = row.get("entry_sha256")
            observed_entry_sha = jsonl_entry.get("entry_sha256")
            if expected_entry_sha != observed_entry_sha:
                counts["solver_evidence_index_entry_hash_mismatches"] += 1
                gaps.append(
                    {
                        "category": "solver_evidence_index_entry_hash_mismatch",
                        "id": row_id,
                        "index": index,
                        "expected": expected_entry_sha,
                        "observed": observed_entry_sha,
                    }
                )

    return {"counts": counts, "gaps": gaps[:100]}


def _semantic_record_requires_solver_claim(record: dict[str, Any]) -> bool:
    return record.get("claim_kind") == "symbolic_observable_equivalence" or record.get("trusted_boundary") in {
        "z3_unsat_local_equivalence_oracle_v1",
        "local_symbolic_equivalence_result_v1",
    }


def _proof_ir_solver_claim_record(record: dict[str, Any], *, solver_entry: dict[str, Any] | None) -> dict[str, Any]:
    obligation_id = str(record.get("obligation_id") or "")
    proof_cache = str(record.get("proof_cache") or "")
    query = record.get("query") if isinstance(record.get("query"), dict) else {}
    trusted_boundary = record.get("trusted_boundary")
    solver = query.get("solver")
    smt_status = query.get("smt_status")
    smt_query_sha256 = query.get("smt_query_sha256")
    solver_backend = query.get("solver_backend") if isinstance(query.get("solver_backend"), dict) else None
    solver_backend_sha256 = query.get("solver_backend_sha256")
    proof_rule = query.get("proof_rule") or record.get("proof_rule")
    gaps: list[dict[str, Any]] = []
    if record.get("status") != "satisfied":
        gaps.append(
            {
                "category": "semantic_observable_record_incomplete",
                "obligation_id": obligation_id,
                "proof_cache": proof_cache,
                "semantic_status": record.get("status"),
            }
        )
    if record.get("claim_kind") != "symbolic_observable_equivalence":
        gaps.append(
            {
                "category": "unexpected_solver_claim_kind",
                "obligation_id": obligation_id,
                "proof_cache": proof_cache,
                "claim_kind": record.get("claim_kind"),
            }
        )
    if not isinstance(trusted_boundary, str) or not trusted_boundary:
        gaps.append(
            {
                "category": "missing_trusted_boundary",
                "obligation_id": obligation_id,
                "proof_cache": proof_cache,
                "claim_kind": record.get("claim_kind"),
            }
        )
        boundary_text = ""
    else:
        boundary_text = trusted_boundary
        if boundary_text not in {"z3_unsat_local_equivalence_oracle_v1", "local_symbolic_equivalence_result_v1"}:
            gaps.append(
                {
                    "category": "unexpected_solver_trusted_boundary",
                    "obligation_id": obligation_id,
                    "proof_cache": proof_cache,
                    "trusted_boundary": boundary_text,
                }
            )
    if not isinstance(solver, str) or not solver:
        gaps.append({"category": "missing_solver", "obligation_id": obligation_id, "proof_cache": proof_cache})
    if not isinstance(smt_status, str) or not smt_status:
        gaps.append({"category": "missing_smt_status", "obligation_id": obligation_id, "proof_cache": proof_cache})
    if not _is_sha256_hex(smt_query_sha256):
        gaps.append(
            {
                "category": "missing_smt_query_sha256",
                "obligation_id": obligation_id,
                "proof_cache": proof_cache,
                "observed": smt_query_sha256,
            }
        )
    if solver_backend is None:
        gaps.append(
            {
                "category": "missing_solver_backend",
                "obligation_id": obligation_id,
                "proof_cache": proof_cache,
            }
        )
    elif not _is_sha256_hex(solver_backend_sha256):
        gaps.append(
            {
                "category": "missing_solver_backend_sha256",
                "obligation_id": obligation_id,
                "proof_cache": proof_cache,
                "observed": solver_backend_sha256,
            }
        )
    elif _canonical_json_sha256(solver_backend) != solver_backend_sha256:
        gaps.append(
            {
                "category": "solver_backend_sha256_mismatch",
                "obligation_id": obligation_id,
                "proof_cache": proof_cache,
                "expected": _canonical_json_sha256(solver_backend),
                "observed": solver_backend_sha256,
            }
        )
    if not isinstance(proof_rule, str) or not proof_rule:
        gaps.append({"category": "missing_proof_rule", "obligation_id": obligation_id, "proof_cache": proof_cache})
    if not _is_sha256_hex(record.get("record_sha256")):
        gaps.append(
            {
                "category": "missing_semantic_observable_record_sha256",
                "obligation_id": obligation_id,
                "proof_cache": proof_cache,
            }
        )
    if solver_entry is None:
        gaps.append(
            {
                "category": "missing_solver_evidence_entry",
                "obligation_id": obligation_id,
                "proof_cache": proof_cache,
            }
        )
    else:
        if solver_entry.get("status") != "satisfied":
            gaps.append(
                {
                    "category": "incomplete_solver_evidence_entry",
                    "obligation_id": obligation_id,
                    "proof_cache": proof_cache,
                    "solver_status": solver_entry.get("status"),
                }
            )
        for field, expected in (
            ("solver", solver),
            ("smt_status", smt_status),
            ("smt_query_sha256", smt_query_sha256),
            ("trusted_boundary", boundary_text),
            ("solver_backend_sha256", solver_backend_sha256),
        ):
            observed = solver_entry.get(field)
            if observed != expected:
                gaps.append(
                    {
                        "category": f"solver_evidence_{field}_mismatch",
                        "obligation_id": obligation_id,
                        "proof_cache": proof_cache,
                        "expected": expected,
                        "observed": observed,
                    }
                )
        if solver_backend is not None and isinstance(solver_entry.get("solver_backend"), dict):
            if solver_entry.get("solver_backend") != solver_backend:
                gaps.append(
                    {
                        "category": "solver_evidence_solver_backend_mismatch",
                        "obligation_id": obligation_id,
                        "proof_cache": proof_cache,
                    }
                )
    if boundary_text == "z3_unsat_local_equivalence_oracle_v1":
        if solver != "z3":
            gaps.append(
                {
                    "category": "z3_oracle_solver_mismatch",
                    "obligation_id": obligation_id,
                    "proof_cache": proof_cache,
                    "expected": "z3",
                    "observed": solver,
                }
            )
        if smt_status != "unsat":
            gaps.append(
                {
                    "category": "z3_oracle_status_mismatch",
                    "obligation_id": obligation_id,
                    "proof_cache": proof_cache,
                    "expected": "unsat",
                    "observed": smt_status,
                }
            )
        backend_solver = solver_backend.get("solver") if isinstance(solver_backend, dict) else None
        backend_boundary = solver_backend.get("trust_boundary") if isinstance(solver_backend, dict) else None
        if backend_solver != "z3":
            gaps.append(
                {
                    "category": "z3_oracle_solver_backend_mismatch",
                    "obligation_id": obligation_id,
                    "proof_cache": proof_cache,
                    "expected": "z3",
                    "observed": backend_solver,
                }
            )
        if backend_boundary != "z3_unsat_local_equivalence_oracle_v1":
            gaps.append(
                {
                    "category": "z3_oracle_solver_backend_trust_boundary_mismatch",
                    "obligation_id": obligation_id,
                    "proof_cache": proof_cache,
                    "expected": "z3_unsat_local_equivalence_oracle_v1",
                    "observed": backend_boundary,
                }
            )
    result = {
        "format": "stage-a-solver-claim-v1",
        "id": f"solver-claim:{_safe_gap_part(obligation_id)}",
        "status": "satisfied" if not gaps else "incomplete",
        "obligation_id": obligation_id,
        "proof_cache": proof_cache,
        "claim_kind": record.get("claim_kind"),
        "trusted_boundary": boundary_text,
        "solver": solver,
        "smt_status": smt_status,
        "smt_query_sha256": smt_query_sha256,
        "solver_backend": solver_backend,
        "solver_backend_sha256": solver_backend_sha256,
        "proof_rule": proof_rule,
        "generic_proof_rule": record.get("generic_proof_rule"),
        "semantic_observable_record_sha256": record.get("record_sha256"),
        "semantic_observable_claim_sha256": record.get("claim_sha256"),
        "solver_evidence": _solver_claim_evidence_summary(solver_entry),
        "gaps": gaps,
    }
    result["record_sha256"] = _canonical_json_sha256(result)
    return result


def _solver_claim_evidence_summary(entry: dict[str, Any] | None) -> dict[str, Any]:
    if entry is None:
        return {"status": "missing"}
    return {
        "status": entry.get("status"),
        "id": entry.get("id"),
        "proof_cache": entry.get("proof_cache"),
        "obligation_id": entry.get("obligation_id"),
        "evidence_kind": entry.get("evidence_kind"),
        "solver": entry.get("solver"),
        "smt_status": entry.get("smt_status"),
        "smt_query_sha256": entry.get("smt_query_sha256"),
        "solver_backend": entry.get("solver_backend"),
        "solver_backend_sha256": entry.get("solver_backend_sha256"),
        "trusted_boundary": entry.get("trusted_boundary"),
        "entry_sha256": entry.get("entry_sha256"),
    }


def _proof_ir_context_binding(
    *,
    model_description: dict[str, Any],
    model_hash: str,
    inputs: dict[str, Any],
    target_profile: dict[str, Any],
    loader_facts: dict[str, Any],
    loader_frontend_profile: dict[str, Any],
    loader_profile: dict[str, Any],
    layout: dict[str, Any],
    coverage: dict[str, Any],
    coverage_profile: dict[str, Any],
    proof_cache_profile: dict[str, Any],
    proof_rule_profile: dict[str, Any],
    mapping_profile: dict[str, Any],
    cfg_profile: dict[str, Any],
    reachability_profile: dict[str, Any],
    abi_profile: dict[str, Any],
    environment_profile: dict[str, Any],
    obligation_items: list[dict[str, Any]],
    proof_cache_index_sha256: str | None,
    solver_evidence: dict[str, Any],
    block_semantics: dict[str, Any],
    instruction_semantics: dict[str, Any],
    instruction_profile: dict[str, Any],
    proof_artifact_bindings: dict[str, Any],
    semantic_observables: dict[str, Any],
    solver_claims: dict[str, Any],
    solver_evidence_profile: dict[str, Any],
    solver_backend_profile: dict[str, Any],
    trusted_boundaries: dict[str, Any],
    trusted_boundary_profile: dict[str, Any],
    profile_manifest: dict[str, Any],
    semantic_profile: dict[str, Any],
    proof_composition: dict[str, Any],
    closure_certificate: dict[str, Any],
    closure_certificate_sha256: str,
) -> dict[str, Any]:
    original = inputs.get("original") if isinstance(inputs.get("original"), dict) else {}
    candidate = inputs.get("candidate") if isinstance(inputs.get("candidate"), dict) else {}
    canonical_model_hash = proof_model_hash(model_description)
    hashes = {
        "model_hash": model_hash,
        "model_description_sha256": canonical_model_hash,
        "original_sha256": original.get("sha256"),
        "candidate_sha256": candidate.get("sha256"),
        "mapping_payload_sha256": inputs.get("mapping_payload_sha256"),
        "invariant_payload_sha256": inputs.get("invariant_payload_sha256"),
        "target_profile_sha256": _canonical_json_sha256(target_profile),
        "loader_facts_sha256": _canonical_json_sha256(loader_facts),
        "loader_frontend_profile_sha256": _canonical_json_sha256(loader_frontend_profile),
        "loader_profile_sha256": _canonical_json_sha256(loader_profile),
        "layout_payload_sha256": inputs.get("layout_payload_sha256"),
        "layout_sha256": _canonical_json_sha256(layout),
        "coverage_sha256": _canonical_json_sha256(coverage),
        "coverage_profile_sha256": _canonical_json_sha256(coverage_profile),
        "proof_cache_profile_sha256": _canonical_json_sha256(proof_cache_profile),
        "proof_rule_profile_sha256": _canonical_json_sha256(proof_rule_profile),
        "mapping_profile_sha256": _canonical_json_sha256(mapping_profile),
        "cfg_profile_sha256": _canonical_json_sha256(cfg_profile),
        "reachability_profile_sha256": _canonical_json_sha256(reachability_profile),
        "abi_profile_sha256": _canonical_json_sha256(abi_profile),
        "environment_profile_sha256": _canonical_json_sha256(environment_profile),
        "obligations_sha256": _canonical_json_sha256(obligation_items),
        "proof_cache_index_sha256": proof_cache_index_sha256,
        "solver_evidence_sha256": solver_evidence.get("sha256"),
        "solver_evidence_index_sha256": solver_evidence.get("index_sha256"),
        "block_semantics_sha256": _canonical_json_sha256(block_semantics),
        "instruction_semantics_sha256": _canonical_json_sha256(instruction_semantics),
        "instruction_profile_sha256": _canonical_json_sha256(instruction_profile),
        "proof_artifact_bindings_sha256": _canonical_json_sha256(proof_artifact_bindings),
        "semantic_observables_sha256": _canonical_json_sha256(semantic_observables),
        "solver_claims_sha256": _canonical_json_sha256(solver_claims),
        "solver_evidence_profile_sha256": _canonical_json_sha256(solver_evidence_profile),
        "solver_backend_profile_sha256": _canonical_json_sha256(solver_backend_profile),
        "trusted_boundaries_sha256": _canonical_json_sha256(trusted_boundaries),
        "trusted_boundary_profile_sha256": _canonical_json_sha256(trusted_boundary_profile),
        "profile_manifest_sha256": _canonical_json_sha256(profile_manifest),
        "semantic_profile_sha256": _canonical_json_sha256(semantic_profile),
        "proof_composition_sha256": _canonical_json_sha256(proof_composition),
        "closure_certificate_sha256": closure_certificate_sha256,
    }
    checks = {
        "original_input_exists": original.get("exists") is True,
        "candidate_input_exists": candidate.get("exists") is True,
        "model_hash_present": _is_sha256_hex(model_hash),
        "model_hash_matches_model": model_hash == canonical_model_hash,
        "input_hashes_present": _is_sha256_hex(original.get("sha256")) and _is_sha256_hex(candidate.get("sha256")),
        "layout_payload_hashed": _is_sha256_hex(inputs.get("layout_payload_sha256")),
        "mapping_payload_hashed": _is_sha256_hex(inputs.get("mapping_payload_sha256")),
        "invariant_payload_hashed": _is_sha256_hex(inputs.get("invariant_payload_sha256")),
        "proof_cache_index_hashed": _is_sha256_hex(proof_cache_index_sha256),
        "solver_evidence_hashed": _is_sha256_hex(solver_evidence.get("sha256")),
        "solver_evidence_index_hashed": _is_sha256_hex(solver_evidence.get("index_sha256")),
        "target_profile_hashed": _is_sha256_hex(_canonical_json_sha256(target_profile)),
        "target_profile_satisfied": target_profile.get("status") == "satisfied",
        "loader_frontend_profile_hashed": _is_sha256_hex(_canonical_json_sha256(loader_frontend_profile)),
        "loader_frontend_profile_satisfied": loader_frontend_profile.get("status") == "satisfied",
        "loader_profile_hashed": _is_sha256_hex(_canonical_json_sha256(loader_profile)),
        "loader_profile_satisfied": loader_profile.get("status") == "satisfied",
        "coverage_profile_hashed": _is_sha256_hex(_canonical_json_sha256(coverage_profile)),
        "coverage_profile_satisfied": coverage_profile.get("status") == "satisfied",
        "proof_cache_profile_hashed": _is_sha256_hex(_canonical_json_sha256(proof_cache_profile)),
        "proof_cache_profile_satisfied": proof_cache_profile.get("status") == "satisfied",
        "proof_rule_profile_hashed": _is_sha256_hex(_canonical_json_sha256(proof_rule_profile)),
        "proof_rule_profile_satisfied": proof_rule_profile.get("status") == "satisfied",
        "mapping_profile_hashed": _is_sha256_hex(_canonical_json_sha256(mapping_profile)),
        "mapping_profile_satisfied": mapping_profile.get("status") in {"satisfied", "not_applicable"},
        "cfg_profile_hashed": _is_sha256_hex(_canonical_json_sha256(cfg_profile)),
        "cfg_profile_satisfied": cfg_profile.get("status") == "satisfied",
        "reachability_profile_hashed": _is_sha256_hex(_canonical_json_sha256(reachability_profile)),
        "reachability_profile_satisfied": reachability_profile.get("status") == "satisfied",
        "abi_profile_hashed": _is_sha256_hex(_canonical_json_sha256(abi_profile)),
        "abi_profile_satisfied": abi_profile.get("status") in {"satisfied", "not_applicable"},
        "environment_profile_hashed": _is_sha256_hex(_canonical_json_sha256(environment_profile)),
        "environment_profile_satisfied": environment_profile.get("status") == "satisfied",
        "instruction_semantics_hashed": _is_sha256_hex(_canonical_json_sha256(instruction_semantics)),
        "instruction_profile_hashed": _is_sha256_hex(_canonical_json_sha256(instruction_profile)),
        "instruction_profile_satisfied": instruction_profile.get("status") == "satisfied",
        "solver_claims_hashed": _is_sha256_hex(_canonical_json_sha256(solver_claims)),
        "solver_evidence_profile_hashed": _is_sha256_hex(_canonical_json_sha256(solver_evidence_profile)),
        "solver_evidence_profile_satisfied": solver_evidence_profile.get("status") == "satisfied",
        "solver_backend_profile_hashed": _is_sha256_hex(_canonical_json_sha256(solver_backend_profile)),
        "solver_backend_profile_satisfied": solver_backend_profile.get("status") == "satisfied",
        "trusted_boundary_profile_hashed": _is_sha256_hex(_canonical_json_sha256(trusted_boundary_profile)),
        "trusted_boundary_profile_satisfied": trusted_boundary_profile.get("status") == "satisfied",
        "profile_manifest_hashed": _is_sha256_hex(_canonical_json_sha256(profile_manifest)),
        "profile_manifest_satisfied": profile_manifest.get("status") == "satisfied",
        "semantic_profile_hashed": _is_sha256_hex(_canonical_json_sha256(semantic_profile)),
        "semantic_profile_satisfied": semantic_profile.get("status") == "satisfied",
        "proof_composition_hashed": _is_sha256_hex(_canonical_json_sha256(proof_composition)),
        "closure_certificate_hashed": _is_sha256_hex(closure_certificate_sha256),
        "closure_certificate_satisfied": closure_certificate.get("status") == "satisfied",
    }
    context = {
        "format": "stage-a-proof-context-binding-v1",
        "status": "satisfied" if all(checks.values()) else "incomplete",
        "model_hash": model_hash,
        "model": {
            "id": model_description.get("id"),
            "sha256": canonical_model_hash,
        },
        "inputs": {
            "original": {
                "path": original.get("path"),
                "sha256": original.get("sha256"),
                "exists": original.get("exists"),
            },
            "candidate": {
                "path": candidate.get("path"),
                "sha256": candidate.get("sha256"),
                "exists": candidate.get("exists"),
            },
        },
        "hashes": hashes,
        "checks": checks,
    }
    context["sha256"] = _canonical_json_sha256(context)
    return context


def _proof_ir_artifact_binding_inventory(
    *,
    obligation_items: list[dict[str, Any]],
    proof_cache: list[dict[str, Any]],
    solver_evidence: dict[str, Any],
    block_semantics: dict[str, Any],
) -> dict[str, Any]:
    proof_cache_by_path = {
        str(item.get("path")): item
        for item in proof_cache
        if isinstance(item, dict) and isinstance(item.get("path"), str) and item.get("path")
    }
    solver_entries = solver_evidence.get("entries") if isinstance(solver_evidence.get("entries"), list) else []
    solver_by_proof_cache = {
        str(item.get("proof_cache")): item
        for item in solver_entries
        if isinstance(item, dict) and isinstance(item.get("proof_cache"), str) and item.get("proof_cache")
    }
    block_semantics_records = block_semantics.get("records") if isinstance(block_semantics.get("records"), list) else []
    block_semantics_by_proof_cache = {
        str(item.get("proof_cache")): item
        for item in block_semantics_records
        if isinstance(item, dict) and isinstance(item.get("proof_cache"), str) and item.get("proof_cache")
    }
    proof_backed_obligations = [
        item
        for item in obligation_items
        if item.get("status") == "proved" and item.get("kind") == "block_equivalence"
    ]
    records = [
        _proof_ir_artifact_binding_record(
            obligation=item,
            proof_cache_entry=proof_cache_by_path.get(str(item.get("proof_cache") or "")),
            solver_entry=solver_by_proof_cache.get(str(item.get("proof_cache") or "")),
            block_semantics_record=block_semantics_by_proof_cache.get(str(item.get("proof_cache") or "")),
        )
        for item in proof_backed_obligations
    ]
    return {
        "format": "stage-a-proof-artifact-bindings-v1",
        "status": "satisfied" if all(record.get("status") == "satisfied" for record in records) else "incomplete",
        "counts": {
            "records": len(records),
            "by_status": _count_by(records, "status"),
            "gaps": sum(len(record.get("gaps", [])) for record in records if isinstance(record.get("gaps"), list)),
        },
        "records": records,
    }


def _proof_ir_artifact_binding_record(
    *,
    obligation: dict[str, Any],
    proof_cache_entry: dict[str, Any] | None,
    solver_entry: dict[str, Any] | None,
    block_semantics_record: dict[str, Any] | None,
) -> dict[str, Any]:
    obligation_id = str(obligation.get("id") or "")
    proof_cache_path = str(obligation.get("proof_cache") or "")
    expected_rule = obligation.get("proof_rule")
    expected_generic_rule = obligation.get("generic_proof_rule")
    gaps: list[dict[str, Any]] = []
    if not proof_cache_path:
        gaps.append({"category": "missing_proof_cache_reference", "obligation_id": obligation_id})
    if proof_cache_entry is None:
        gaps.append(
            {
                "category": "missing_proof_cache_entry",
                "obligation_id": obligation_id,
                "proof_cache": proof_cache_path,
            }
        )
    elif proof_cache_entry.get("status") not in {None, "proved", "not_required_for_structural_identity", "satisfied"}:
        gaps.append(
            {
                "category": "proof_cache_entry_status_not_closed",
                "obligation_id": obligation_id,
                "proof_cache": proof_cache_path,
                "status": proof_cache_entry.get("status"),
            }
        )
    if solver_entry is None:
        gaps.append(
            {
                "category": "missing_solver_evidence_entry",
                "obligation_id": obligation_id,
                "proof_cache": proof_cache_path,
            }
        )
    else:
        if solver_entry.get("status") != "satisfied":
            gaps.append(
                {
                    "category": "incomplete_solver_evidence_entry",
                    "obligation_id": obligation_id,
                    "proof_cache": proof_cache_path,
                    "solver_status": solver_entry.get("status"),
                }
            )
        gaps.extend(
            _artifact_binding_field_gaps(
                artifact_kind="solver_evidence",
                artifact=solver_entry,
                obligation_id=obligation_id,
                proof_cache_path=proof_cache_path,
                expected_rule=expected_rule,
                expected_generic_rule=expected_generic_rule,
            )
        )
    if block_semantics_record is None:
        gaps.append(
            {
                "category": "missing_block_semantics_record",
                "obligation_id": obligation_id,
                "proof_cache": proof_cache_path,
            }
        )
    else:
        if block_semantics_record.get("status") != "present":
            gaps.append(
                {
                    "category": "incomplete_block_semantics_record",
                    "obligation_id": obligation_id,
                    "proof_cache": proof_cache_path,
                    "record_status": block_semantics_record.get("status"),
                    "semantics_kind": block_semantics_record.get("semantics_kind"),
                }
            )
        gaps.extend(
            _artifact_binding_field_gaps(
                artifact_kind="block_semantics",
                artifact=block_semantics_record,
                obligation_id=obligation_id,
                proof_cache_path=proof_cache_path,
                expected_rule=expected_rule,
                expected_generic_rule=expected_generic_rule,
            )
        )
    record = {
        "format": "stage-a-proof-artifact-binding-v1",
        "id": f"proof-artifact-binding:{_safe_gap_part(obligation_id)}",
        "status": "satisfied" if not gaps else "incomplete",
        "obligation_id": obligation_id,
        "proof_cache": proof_cache_path,
        "proof_rule": expected_rule,
        "generic_proof_rule": expected_generic_rule,
        "proof_cache_entry": _proof_cache_binding_summary(proof_cache_entry),
        "solver_evidence": _solver_evidence_binding_summary(solver_entry),
        "block_semantics": _block_semantics_binding_summary(block_semantics_record),
        "gaps": gaps,
    }
    record["binding_sha256"] = _canonical_json_sha256(record)
    return record


def _proof_cache_binding_summary(entry: dict[str, Any] | None) -> dict[str, Any]:
    if entry is None:
        return {"status": "missing"}
    return {
        "status": entry.get("status"),
        "path": entry.get("path"),
        "sha256": entry.get("sha256"),
    }


def _solver_evidence_binding_summary(entry: dict[str, Any] | None) -> dict[str, Any]:
    if entry is None:
        return {"status": "missing"}
    return {
        "status": entry.get("status"),
        "id": entry.get("id"),
        "proof_cache": entry.get("proof_cache"),
        "obligation_id": entry.get("obligation_id"),
        "proof_rule": entry.get("proof_rule"),
        "generic_proof_rule": entry.get("generic_proof_rule"),
        "evidence_kind": entry.get("evidence_kind"),
        "entry_sha256": entry.get("entry_sha256"),
    }


def _block_semantics_binding_summary(record: dict[str, Any] | None) -> dict[str, Any]:
    if record is None:
        return {"status": "missing"}
    return {
        "status": record.get("status"),
        "id": record.get("id"),
        "proof_cache": record.get("proof_cache"),
        "obligation_id": record.get("obligation_id"),
        "proof_rule": record.get("proof_rule"),
        "generic_proof_rule": record.get("generic_proof_rule"),
        "semantics_kind": record.get("semantics_kind"),
        "record_sha256": record.get("record_sha256"),
    }


def _proof_ir_semantic_observables_inventory(
    *,
    block_semantics: dict[str, Any],
    proof_artifact_bindings: dict[str, Any],
) -> dict[str, Any]:
    block_records = block_semantics.get("records") if isinstance(block_semantics.get("records"), list) else []
    block_by_proof_cache = {
        str(item.get("proof_cache")): item
        for item in block_records
        if isinstance(item, dict) and isinstance(item.get("proof_cache"), str) and item.get("proof_cache")
    }
    binding_records = (
        proof_artifact_bindings.get("records") if isinstance(proof_artifact_bindings.get("records"), list) else []
    )
    records = [
        _proof_ir_semantic_observables_record(
            binding=item,
            block_semantics_record=block_by_proof_cache.get(str(item.get("proof_cache") or "")) if isinstance(item, dict) else None,
        )
        for item in binding_records
        if isinstance(item, dict)
    ]
    return {
        "format": "stage-a-semantic-observables-v1",
        "status": "satisfied" if all(record.get("status") == "satisfied" for record in records) else "incomplete",
        "counts": {
            "records": len(records),
            "by_status": _count_by(records, "status"),
            "by_semantics_kind": _count_by(records, "semantics_kind"),
            "gaps": sum(len(record.get("gaps", [])) for record in records if isinstance(record.get("gaps"), list)),
        },
        "records": records,
    }


def _proof_ir_semantic_observables_record(
    *,
    binding: dict[str, Any],
    block_semantics_record: dict[str, Any] | None,
) -> dict[str, Any]:
    obligation_id = str(binding.get("obligation_id") or "")
    proof_cache = str(binding.get("proof_cache") or "")
    gaps: list[dict[str, Any]] = []
    if binding.get("status") != "satisfied":
        gaps.append(
            {
                "category": "proof_artifact_binding_incomplete",
                "obligation_id": obligation_id,
                "proof_cache": proof_cache,
                "binding_status": binding.get("status"),
            }
        )
    if block_semantics_record is None:
        gaps.append(
            {
                "category": "missing_block_semantics_record",
                "obligation_id": obligation_id,
                "proof_cache": proof_cache,
            }
        )
        record = {
            "format": "stage-a-semantic-observables-record-v1",
            "id": f"semantic-observables:{_safe_gap_part(obligation_id)}",
            "status": "incomplete",
            "obligation_id": obligation_id,
            "proof_cache": proof_cache,
            "proof_rule": binding.get("proof_rule"),
            "generic_proof_rule": binding.get("generic_proof_rule"),
            "semantics_kind": "missing_block_semantics",
            "claim_kind": "missing",
            "gaps": gaps,
        }
        record["record_sha256"] = _canonical_json_sha256(record)
        return record
    if block_semantics_record.get("status") != "present":
        gaps.append(
            {
                "category": "incomplete_block_semantics_record",
                "obligation_id": obligation_id,
                "proof_cache": proof_cache,
                "record_status": block_semantics_record.get("status"),
            }
        )
    semantics_kind = str(block_semantics_record.get("semantics_kind") or "unknown")
    semantic_payload = _semantic_observables_payload(block_semantics_record)
    if semantic_payload["claim_kind"] == "unknown":
        gaps.append(
            {
                "category": "unknown_semantics_kind",
                "obligation_id": obligation_id,
                "proof_cache": proof_cache,
                "semantics_kind": semantics_kind,
            }
        )
    record = {
        "format": "stage-a-semantic-observables-record-v1",
        "id": f"semantic-observables:{_safe_gap_part(obligation_id)}",
        "status": "satisfied" if not gaps else "incomplete",
        "obligation_id": obligation_id,
        "proof_cache": proof_cache,
        "proof_rule": binding.get("proof_rule"),
        "generic_proof_rule": binding.get("generic_proof_rule"),
        "semantics_kind": semantics_kind,
        "claim_kind": semantic_payload["claim_kind"],
        "trusted_boundary": semantic_payload["trusted_boundary"],
        "query": semantic_payload["query"],
        "original": semantic_payload["original"],
        "candidate": semantic_payload["candidate"],
        "invariant_sha256": semantic_payload.get("invariant_sha256"),
        "gaps": gaps,
    }
    record["claim_sha256"] = _canonical_json_sha256(
        {
            "obligation_id": obligation_id,
            "proof_cache": proof_cache,
            "semantics_kind": semantics_kind,
            "claim_kind": record["claim_kind"],
            "query": record["query"],
            "original": record["original"],
            "candidate": record["candidate"],
            "invariant_sha256": record.get("invariant_sha256"),
        }
    )
    record["record_sha256"] = _canonical_json_sha256(record)
    return record


def _semantic_observables_payload(record: dict[str, Any]) -> dict[str, Any]:
    semantics_kind = record.get("semantics_kind")
    if semantics_kind == "decoded_instruction_identity":
        return {
            "claim_kind": "decoded_instruction_identity",
            "trusted_boundary": "byte_identical_instruction_decode_v1",
            "query": _semantic_query(record),
            "original": _semantic_analysis_claim(record.get("original")),
            "candidate": _semantic_analysis_claim(record.get("candidate")),
        }
    if semantics_kind == "pe_import_thunk_semantics":
        return {
            "claim_kind": "pe_import_thunk_equivalence",
            "trusted_boundary": "pe_import_thunk_signature_equivalence_v1",
            "query": _semantic_query(record),
            "original": _semantic_analysis_claim(record.get("original")),
            "candidate": _semantic_analysis_claim(record.get("candidate")),
        }
    if semantics_kind == "checked_generated_mapping_assumption":
        return {
            "claim_kind": "checked_generated_mapping_assumption",
            "trusted_boundary": "checked_layout_preserving_mapping_assumption_v1",
            "query": _semantic_query(record),
            "original": _semantic_byte_claim(record.get("original")),
            "candidate": _semantic_byte_claim(record.get("candidate")),
        }
    if semantics_kind == "symbolic_observables":
        symbolic = record.get("symbolic") if isinstance(record.get("symbolic"), dict) else {}
        solver_backend = _solver_backend_summary(symbolic.get("solver_backend"))
        return {
            "claim_kind": "symbolic_observable_equivalence",
            "trusted_boundary": "z3_unsat_local_equivalence_oracle_v1"
            if symbolic.get("solver") == "z3" and symbolic.get("smt_status") == "unsat"
            else "local_symbolic_equivalence_result_v1",
            "query": {
                "smt_query_sha256": symbolic.get("smt_query_sha256"),
                "solver": symbolic.get("solver"),
                "smt_status": symbolic.get("smt_status"),
                "proof_rule": symbolic.get("proof_rule"),
                "solver_backend": solver_backend,
                "solver_backend_sha256": _canonical_json_sha256(solver_backend) if solver_backend is not None else None,
            },
            "original": _semantic_observables_claim(record.get("original")),
            "candidate": _semantic_observables_claim(record.get("candidate")),
            "invariant_sha256": symbolic.get("invariant_sha256"),
        }
    return {
        "claim_kind": "unknown",
        "trusted_boundary": None,
        "query": _semantic_query(record),
        "original": {},
        "candidate": {},
    }


def _semantic_query(record: dict[str, Any]) -> dict[str, Any]:
    query = record.get("query") if isinstance(record.get("query"), dict) else {}
    return {
        "kind": query.get("kind"),
        "original_sha256": query.get("original_sha256"),
        "candidate_sha256": query.get("candidate_sha256"),
        "equal": query.get("equal"),
        "same_import_signature": query.get("same_import_signature"),
    }


def _semantic_analysis_claim(value: Any) -> dict[str, Any]:
    item = value if isinstance(value, dict) else {}
    result = {
        "analysis_sha256": item.get("analysis_sha256"),
        "status": item.get("status"),
        "machine": item.get("machine"),
        "bitness": item.get("bitness"),
        "instruction_count": item.get("instruction_count"),
        "instruction_bytes_sha256": item.get("instruction_bytes_sha256"),
    }
    if isinstance(item.get("import_signature"), dict):
        result["import_signature_sha256"] = _canonical_json_sha256(item["import_signature"])
    return result


def _semantic_byte_claim(value: Any) -> dict[str, Any]:
    item = value if isinstance(value, dict) else {}
    return {"byte_sha256": item.get("byte_sha256")}


def _semantic_observables_claim(value: Any) -> dict[str, Any]:
    item = value if isinstance(value, dict) else {}
    return {"observables_sha256": item.get("observables_sha256")}


def _proof_ir_trusted_boundary_inventory(
    *,
    model_description: dict[str, Any],
    semantic_observables: dict[str, Any],
) -> dict[str, Any]:
    allowed = [
        str(item)
        for item in model_description.get("trusted_boundaries", TRUSTED_BOUNDARIES)
        if isinstance(item, str) and item
    ]
    allowed_set = set(allowed)
    semantic_records = (
        semantic_observables.get("records") if isinstance(semantic_observables.get("records"), list) else []
    )
    records = [
        _proof_ir_trusted_boundary_record(item, allowed_set=allowed_set)
        for item in semantic_records
        if isinstance(item, dict)
    ]
    return {
        "format": "stage-a-trusted-boundaries-v1",
        "status": "satisfied" if all(record.get("status") == "satisfied" for record in records) else "incomplete",
        "allowed": allowed,
        "counts": {
            "records": len(records),
            "by_status": _count_by(records, "status"),
            "by_boundary": _count_by(records, "trusted_boundary"),
            "gaps": sum(len(record.get("gaps", [])) for record in records if isinstance(record.get("gaps"), list)),
        },
        "records": records,
    }


def _proof_ir_trusted_boundary_profile(
    *,
    model_description: dict[str, Any],
    semantic_observables: dict[str, Any],
    trusted_boundaries: dict[str, Any],
) -> dict[str, Any]:
    model_boundaries = [
        str(item)
        for item in model_description.get("trusted_boundaries", TRUSTED_BOUNDARIES)
        if isinstance(item, str) and item
    ]
    model_boundary_counts: dict[str, int] = {}
    for boundary in model_boundaries:
        model_boundary_counts[boundary] = model_boundary_counts.get(boundary, 0) + 1
    duplicate_model_boundaries = sum(count - 1 for count in model_boundary_counts.values() if count > 1)
    unknown_model_boundaries = sum(1 for boundary in model_boundaries if boundary not in SEMANTIC_TRUSTED_BOUNDARY_KINDS)
    semantic_records = (
        semantic_observables.get("records") if isinstance(semantic_observables.get("records"), list) else []
    )
    records = trusted_boundaries.get("records") if isinstance(trusted_boundaries.get("records"), list) else []
    trusted_counts = trusted_boundaries.get("counts") if isinstance(trusted_boundaries.get("counts"), dict) else {}
    status_counts = trusted_counts.get("by_status") if isinstance(trusted_counts.get("by_status"), dict) else {}
    status_count_total = sum(int(value or 0) for value in status_counts.values())
    trusted_boundary_gaps = _trusted_boundary_gaps_from_records(records)
    allowed_records = sum(1 for item in records if isinstance(item, dict) and item.get("allowed") is True)
    records_with_hash = sum(
        1 for item in records if isinstance(item, dict) and _is_sha256_hex(item.get("record_sha256"))
    )
    incomplete_records = sum(1 for item in records if isinstance(item, dict) and item.get("status") != "satisfied")
    counts = {
        "semantic_observables": len(semantic_records),
        "records": len(records),
        "allowed_records": allowed_records,
        "records_with_hash": records_with_hash,
        "incomplete_records": incomplete_records,
        "model_allowed_boundaries": len(model_boundaries),
        "unknown_model_boundaries": unknown_model_boundaries,
        "duplicate_model_boundaries": duplicate_model_boundaries,
        "trusted_boundary_gaps": len(trusted_boundary_gaps),
    }
    checks = {
        "trusted_boundary_inventory_format_matches": trusted_boundaries.get("format") == "stage-a-trusted-boundaries-v1",
        "trusted_boundary_inventory_status_satisfied": trusted_boundaries.get("status") == "satisfied",
        "model_boundaries_present": counts["model_allowed_boundaries"] > 0,
        "model_boundaries_known": counts["unknown_model_boundaries"] == 0,
        "model_boundary_names_unique": counts["duplicate_model_boundaries"] == 0,
        "record_counts_match": counts["records"] == counts["semantic_observables"],
        "record_status_counts_match": status_count_total == counts["records"],
        "records_allowed": counts["allowed_records"] == counts["records"],
        "records_hashed": counts["records_with_hash"] == counts["records"],
        "records_gap_free": counts["trusted_boundary_gaps"] == 0 and counts["incomplete_records"] == 0,
    }
    return {
        "format": "stage-a-trusted-boundary-profile-v1",
        "status": "satisfied" if all(checks.values()) else "incomplete",
        "counts": counts,
        "checks": checks,
        "gap_samples": trusted_boundary_gaps[:100],
    }


PROFILE_MANIFEST_REQUIRED_FAMILIES = (
    "target_profile",
    "loader_frontend_profile",
    "loader_profile",
    "coverage_profile",
    "proof_cache_profile",
    "proof_rule_profile",
    "mapping_profile",
    "cfg_profile",
    "reachability_profile",
    "abi_profile",
    "environment_profile",
    "instruction_profile",
    "semantic_profile",
    "solver_evidence_profile",
    "solver_backend_profile",
    "trusted_boundary_profile",
)


PROFILE_MANIFEST_ACCEPTED_STATUSES = {
    "mapping_profile": {"satisfied", "not_applicable"},
    "abi_profile": {"satisfied", "not_applicable"},
}


PROFILE_MANIFEST_NOT_APPLICABLE_FALSE_CHECKS = {
    "mapping_profile": {"mapping_contract_present"},
    "abi_profile": {"abi_contract_present"},
}


def _proof_ir_profile_manifest(*, schema: dict[str, str], profiles: dict[str, dict[str, Any]]) -> dict[str, Any]:
    rows = [
        _proof_ir_profile_manifest_row(family=family, schema=schema, profile=profiles.get(family))
        for family in PROFILE_MANIFEST_REQUIRED_FAMILIES
    ]
    gap_count = sum(len(row.get("gaps", [])) for row in rows if isinstance(row.get("gaps"), list))
    counts = {
        "required_profiles": len(PROFILE_MANIFEST_REQUIRED_FAMILIES),
        "present_profiles": sum(1 for row in rows if row.get("present") is True),
        "satisfied_profiles": sum(1 for row in rows if row.get("status") == "satisfied"),
        "not_applicable_profiles": sum(1 for row in rows if row.get("status") == "not_applicable"),
        "rows_with_schema": sum(1 for row in rows if row.get("schema_matches") is True),
        "rows_with_hash": sum(1 for row in rows if _is_sha256_hex(row.get("profile_sha256"))),
        "rows_with_accepted_status": sum(1 for row in rows if row.get("status_accepted") is True),
        "rows_with_checks": sum(1 for row in rows if row.get("checks_closed") is True),
        "profile_manifest_gaps": gap_count,
    }
    checks = {
        "profile_manifest_schema_matches": schema.get("profile_manifest") == "stage-a-proof-profile-manifest-v1",
        "required_profiles_present": counts["present_profiles"] == counts["required_profiles"],
        "profile_schemas_match": counts["rows_with_schema"] == counts["required_profiles"],
        "profile_hashes_present": counts["rows_with_hash"] == counts["required_profiles"],
        "profile_statuses_accepted": counts["rows_with_accepted_status"] == counts["required_profiles"],
        "profile_checks_closed": counts["rows_with_checks"] == counts["required_profiles"],
        "profile_manifest_gaps_closed": counts["profile_manifest_gaps"] == 0,
    }
    return {
        "format": "stage-a-proof-profile-manifest-v1",
        "status": "satisfied" if all(checks.values()) else "incomplete",
        "required_profiles": list(PROFILE_MANIFEST_REQUIRED_FAMILIES),
        "counts": counts,
        "checks": checks,
        "rows": rows,
        "gap_samples": [gap for row in rows for gap in row.get("gaps", [])[:5]][:100],
    }


def _proof_ir_profile_manifest_row(
    *,
    family: str,
    schema: dict[str, str],
    profile: dict[str, Any] | None,
) -> dict[str, Any]:
    item = profile if isinstance(profile, dict) else {}
    present = bool(item)
    expected_format = schema.get(family)
    actual_format = item.get("format")
    status = item.get("status")
    checks = item.get("checks") if isinstance(item.get("checks"), dict) else {}
    accepted_statuses = PROFILE_MANIFEST_ACCEPTED_STATUSES.get(family, {"satisfied"})
    gaps: list[dict[str, Any]] = []
    if not present:
        gaps.append({"category": "missing_profile_family", "profile_family": family})
    if actual_format != expected_format:
        gaps.append(
            {
                "category": "profile_schema_mismatch",
                "profile_family": family,
                "expected_format": expected_format,
                "actual_format": actual_format,
            }
        )
    if status not in accepted_statuses:
        gaps.append(
            {
                "category": "profile_status_not_accepted",
                "profile_family": family,
                "status": status,
                "accepted_statuses": sorted(accepted_statuses),
            }
        )
    if not checks:
        gaps.append({"category": "profile_checks_missing", "profile_family": family})
        checks_closed = False
    else:
        failing_checks = sorted(str(key) for key, value in checks.items() if value is not True)
        allowed_false_checks = (
            PROFILE_MANIFEST_NOT_APPLICABLE_FALSE_CHECKS.get(family, set()) if status == "not_applicable" else set()
        )
        unexpected_failing_checks = [check for check in failing_checks if check not in allowed_false_checks]
        checks_closed = not unexpected_failing_checks
        for check in unexpected_failing_checks[:20]:
            gaps.append({"category": "profile_check_failed", "profile_family": family, "check": check})
    profile_sha256 = _canonical_json_sha256(item) if present else None
    return {
        "format": "stage-a-proof-profile-manifest-row-v1",
        "profile_family": family,
        "present": present,
        "expected_format": expected_format,
        "actual_format": actual_format,
        "schema_matches": actual_format == expected_format,
        "status": status,
        "accepted_statuses": sorted(accepted_statuses),
        "status_accepted": status in accepted_statuses,
        "checks_closed": checks_closed,
        "profile_sha256": profile_sha256,
        "gaps": gaps,
    }


def _proof_ir_trusted_boundary_record(record: dict[str, Any], *, allowed_set: set[str]) -> dict[str, Any]:
    obligation_id = str(record.get("obligation_id") or "")
    proof_cache = str(record.get("proof_cache") or "")
    trusted_boundary = record.get("trusted_boundary")
    gaps: list[dict[str, Any]] = []
    if record.get("status") != "satisfied":
        gaps.append(
            {
                "category": "semantic_observable_record_incomplete",
                "obligation_id": obligation_id,
                "proof_cache": proof_cache,
                "semantic_status": record.get("status"),
            }
        )
    if not isinstance(trusted_boundary, str) or not trusted_boundary:
        gaps.append(
            {
                "category": "missing_trusted_boundary",
                "obligation_id": obligation_id,
                "proof_cache": proof_cache,
                "claim_kind": record.get("claim_kind"),
            }
        )
        boundary_text = ""
    else:
        boundary_text = trusted_boundary
        if boundary_text not in allowed_set:
            gaps.append(
                {
                    "category": "unapproved_trusted_boundary",
                    "obligation_id": obligation_id,
                    "proof_cache": proof_cache,
                    "trusted_boundary": boundary_text,
                    "claim_kind": record.get("claim_kind"),
                }
            )
    result = {
        "format": "stage-a-trusted-boundary-record-v1",
        "id": f"trusted-boundary:{_safe_gap_part(obligation_id)}",
        "status": "satisfied" if not gaps else "incomplete",
        "obligation_id": obligation_id,
        "proof_cache": proof_cache,
        "claim_kind": record.get("claim_kind"),
        "trusted_boundary": boundary_text,
        "allowed": boundary_text in allowed_set if boundary_text else False,
        "semantic_observable_record_sha256": record.get("record_sha256"),
        "gaps": gaps,
    }
    result["record_sha256"] = _canonical_json_sha256(result)
    return result


def _proof_ir_composition_inventory(
    *,
    obligation_items: list[dict[str, Any]],
    proof_artifact_bindings: dict[str, Any],
    block_semantics: dict[str, Any],
    instruction_semantics: dict[str, Any],
    semantic_observables: dict[str, Any],
    solver_claims: dict[str, Any],
    trusted_boundaries: dict[str, Any],
) -> dict[str, Any]:
    proof_backed_obligations = [
        item
        for item in obligation_items
        if item.get("status") == "proved" and item.get("kind") == "block_equivalence"
    ]
    proof_artifact_by_obligation = _record_by_obligation(proof_artifact_bindings)
    block_semantics_by_obligation = _record_by_obligation(block_semantics)
    instruction_semantics_by_obligation = _record_by_obligation(instruction_semantics)
    semantic_observable_by_obligation = _record_by_obligation(semantic_observables)
    solver_claim_by_obligation = _record_by_obligation(solver_claims)
    trusted_boundary_by_obligation = _record_by_obligation(trusted_boundaries)
    records = [
        _proof_ir_composition_record(
            obligation=item,
            proof_artifact_binding=proof_artifact_by_obligation.get(str(item.get("id") or "")),
            block_semantics_record=block_semantics_by_obligation.get(str(item.get("id") or "")),
            instruction_semantics_record=instruction_semantics_by_obligation.get(str(item.get("id") or "")),
            semantic_observable_record=semantic_observable_by_obligation.get(str(item.get("id") or "")),
            solver_claim_record=solver_claim_by_obligation.get(str(item.get("id") or "")),
            trusted_boundary_record=trusted_boundary_by_obligation.get(str(item.get("id") or "")),
        )
        for item in proof_backed_obligations
    ]
    return {
        "format": "stage-a-proof-composition-v1",
        "status": "satisfied" if all(record.get("status") == "satisfied" for record in records) else "incomplete",
        "counts": {
            "records": len(records),
            "by_status": _count_by(records, "status"),
            "by_claim_kind": _count_by(records, "claim_kind"),
            "by_trusted_boundary": _count_by(records, "trusted_boundary"),
            "gaps": sum(len(record.get("gaps", [])) for record in records if isinstance(record.get("gaps"), list)),
        },
        "records": records,
    }


def _proof_ir_composition_record(
    *,
    obligation: dict[str, Any],
    proof_artifact_binding: dict[str, Any] | None,
    block_semantics_record: dict[str, Any] | None,
    instruction_semantics_record: dict[str, Any] | None,
    semantic_observable_record: dict[str, Any] | None,
    solver_claim_record: dict[str, Any] | None,
    trusted_boundary_record: dict[str, Any] | None,
) -> dict[str, Any]:
    obligation_id = str(obligation.get("id") or "")
    proof_cache = str(obligation.get("proof_cache") or "")
    semantics_kind = block_semantics_record.get("semantics_kind") if isinstance(block_semantics_record, dict) else None
    claim_kind = semantic_observable_record.get("claim_kind") if isinstance(semantic_observable_record, dict) else None
    trusted_boundary = (
        semantic_observable_record.get("trusted_boundary") if isinstance(semantic_observable_record, dict) else None
    )
    dependencies = [
        _composition_dependency(
            family="proof_artifact_binding",
            record=proof_artifact_binding,
            expected_closed_status="satisfied",
        ),
        _composition_dependency(
            family="block_semantics",
            record=block_semantics_record,
            expected_closed_status="present",
        ),
        _composition_dependency(
            family="semantic_observable",
            record=semantic_observable_record,
            expected_closed_status="satisfied",
        ),
        _composition_dependency(
            family="trusted_boundary",
            record=trusted_boundary_record,
            expected_closed_status="satisfied",
        ),
    ]
    if isinstance(block_semantics_record, dict) and _block_semantics_requires_instruction_semantics(block_semantics_record):
        dependencies.append(
            _composition_dependency(
                family="instruction_semantics",
                record=instruction_semantics_record,
                expected_closed_status="satisfied",
            )
        )
    if isinstance(semantic_observable_record, dict) and _semantic_record_requires_solver_claim(semantic_observable_record):
        dependencies.append(
            _composition_dependency(
                family="solver_claim",
                record=solver_claim_record,
                expected_closed_status="satisfied",
            )
        )
    gaps: list[dict[str, Any]] = []
    for dependency in dependencies:
        if dependency["status"] == "missing":
            gaps.append(
                {
                    "category": "missing_composition_dependency",
                    "obligation_id": obligation_id,
                    "proof_cache": proof_cache,
                    "family": dependency["family"],
                }
            )
        elif dependency["status"] != dependency["expected_status"]:
            gaps.append(
                {
                    "category": "incomplete_composition_dependency",
                    "obligation_id": obligation_id,
                    "proof_cache": proof_cache,
                    "family": dependency["family"],
                    "expected": dependency["expected_status"],
                    "observed": dependency["status"],
                }
            )
    result = {
        "format": "stage-a-proof-composition-record-v1",
        "id": f"proof-composition:{_safe_gap_part(obligation_id)}",
        "status": "satisfied" if not gaps else "incomplete",
        "composition_rule": "stage-a-local-block-proof-composition-v1",
        "obligation_id": obligation_id,
        "proof_cache": proof_cache,
        "proof_rule": obligation.get("proof_rule"),
        "generic_proof_rule": obligation.get("generic_proof_rule"),
        "semantics_kind": semantics_kind,
        "claim_kind": claim_kind,
        "trusted_boundary": trusted_boundary,
        "dependencies": dependencies,
        "gaps": gaps,
    }
    result["record_sha256"] = _canonical_json_sha256(result)
    return result


def _composition_dependency(
    *,
    family: str,
    record: dict[str, Any] | None,
    expected_closed_status: str,
) -> dict[str, Any]:
    if record is None:
        return {
            "family": family,
            "required": True,
            "status": "missing",
            "expected_status": expected_closed_status,
            "record_id": None,
            "record_sha256": None,
        }
    return {
        "family": family,
        "required": True,
        "status": record.get("status"),
        "expected_status": expected_closed_status,
        "record_id": record.get("id"),
        "record_sha256": _proof_ir_record_sha256(record),
    }


def _record_by_obligation(inventory: dict[str, Any]) -> dict[str, dict[str, Any]]:
    records = inventory.get("records") if isinstance(inventory.get("records"), list) else []
    return {
        str(item.get("obligation_id")): item
        for item in records
        if isinstance(item, dict) and isinstance(item.get("obligation_id"), str)
    }


def _proof_ir_record_sha256(record: dict[str, Any]) -> Any:
    if "record_sha256" in record:
        return record.get("record_sha256")
    if "binding_sha256" in record:
        return record.get("binding_sha256")
    return None


def _proof_ir_closure_certificate(
    *,
    model_hash: str,
    inputs: dict[str, Any],
    loader_facts: dict[str, Any],
    loader_profile: dict[str, Any],
    layout: dict[str, Any],
    coverage: dict[str, Any],
    coverage_profile: dict[str, Any],
    proof_cache_profile: dict[str, Any],
    proof_rule_profile: dict[str, Any],
    mapping_profile: dict[str, Any],
    cfg_profile: dict[str, Any],
    reachability_profile: dict[str, Any],
    abi_profile: dict[str, Any],
    environment_profile: dict[str, Any],
    obligation_counts: dict[str, Any],
    obligation_items: list[dict[str, Any]],
    block_semantics: dict[str, Any],
    instruction_semantics: dict[str, Any],
    proof_artifact_bindings: dict[str, Any],
    semantic_observables: dict[str, Any],
    solver_claims: dict[str, Any],
    solver_backend_profile: dict[str, Any],
    trusted_boundaries: dict[str, Any],
    trusted_boundary_profile: dict[str, Any],
    profile_manifest: dict[str, Any],
    proof_composition: dict[str, Any],
    proof_cache: list[dict[str, Any]],
    proof_cache_index: dict[str, Any],
    proof_cache_index_sha256: str | None,
    solver_evidence: dict[str, Any],
) -> dict[str, Any]:
    closed_statuses = {"proved", "waived_noncode"}
    proof_cache_by_path = {
        str(item.get("path")): item
        for item in proof_cache
        if isinstance(item, dict) and isinstance(item.get("path"), str) and item.get("path")
    }
    solver_entries = solver_evidence.get("entries") if isinstance(solver_evidence.get("entries"), list) else []
    solver_by_proof_cache = {
        str(item.get("proof_cache")): item
        for item in solver_entries
        if isinstance(item, dict) and isinstance(item.get("proof_cache"), str) and item.get("proof_cache")
    }
    block_semantics_records = block_semantics.get("records") if isinstance(block_semantics.get("records"), list) else []
    block_semantics_by_obligation = {
        str(item.get("obligation_id")): item
        for item in block_semantics_records
        if isinstance(item, dict) and isinstance(item.get("obligation_id"), str)
    }
    open_obligations = [
        {
            "id": item.get("id"),
            "kind": item.get("kind"),
            "status": item.get("status"),
            "proof_rule": item.get("proof_rule"),
            "generic_proof_rule": item.get("generic_proof_rule"),
        }
        for item in obligation_items
        if item.get("status") not in closed_statuses
    ]
    proof_backed_obligations = [
        item
        for item in obligation_items
        if item.get("status") == "proved" and item.get("kind") == "block_equivalence"
    ]
    proof_backing_gaps = _proof_backing_gaps(
        proof_backed_obligations=proof_backed_obligations,
        proof_cache_by_path=proof_cache_by_path,
        solver_by_proof_cache=solver_by_proof_cache,
    )
    block_semantics_gaps = _block_semantics_gaps(
        proof_backed_obligations=proof_backed_obligations,
        block_semantics_by_obligation=block_semantics_by_obligation,
    )
    block_semantics_unknown_obligation_gaps = _block_semantics_unknown_obligation_gaps(
        block_semantics_records=block_semantics_records,
        obligation_items=obligation_items,
    )
    decoded_instruction_block_records = [
        item
        for item in block_semantics_records
        if isinstance(item, dict) and _block_semantics_requires_instruction_semantics(item)
    ]
    instruction_semantics_records = (
        instruction_semantics.get("records") if isinstance(instruction_semantics.get("records"), list) else []
    )
    instruction_semantics_gaps = _instruction_semantics_gaps_from_records(instruction_semantics_records)
    instruction_semantics_missing_gaps = _instruction_semantics_missing_gaps(
        decoded_instruction_block_records=decoded_instruction_block_records,
        instruction_semantics_records=instruction_semantics_records,
    )
    proof_cache_evidence_gaps = _proof_cache_evidence_gaps(proof_cache_by_path, solver_by_proof_cache)
    solver_unknown_obligation_gaps = _solver_unknown_obligation_gaps(
        solver_entries=solver_entries,
        obligation_items=obligation_items,
    )
    proof_artifact_binding_records = (
        proof_artifact_bindings.get("records") if isinstance(proof_artifact_bindings.get("records"), list) else []
    )
    evidence_binding_gaps = _evidence_binding_gaps_from_records(proof_artifact_binding_records)
    semantic_observable_records = (
        semantic_observables.get("records") if isinstance(semantic_observables.get("records"), list) else []
    )
    semantic_observable_gaps = _semantic_observable_gaps_from_records(semantic_observable_records)
    solver_claim_records = solver_claims.get("records") if isinstance(solver_claims.get("records"), list) else []
    solver_claim_gaps = _solver_claim_gaps_from_records(solver_claim_records)
    trusted_boundary_records = (
        trusted_boundaries.get("records") if isinstance(trusted_boundaries.get("records"), list) else []
    )
    trusted_boundary_gaps = _trusted_boundary_gaps_from_records(trusted_boundary_records)
    proof_composition_records = (
        proof_composition.get("records") if isinstance(proof_composition.get("records"), list) else []
    )
    proof_composition_gaps = _proof_composition_gaps_from_records(proof_composition_records)
    proof_composition_missing_gaps = _proof_composition_missing_gaps(
        proof_backed_obligations=proof_backed_obligations,
        proof_composition_records=proof_composition_records,
    )
    solver_counts = solver_evidence.get("counts") if isinstance(solver_evidence.get("counts"), dict) else {}
    proof_cache_count = len(proof_cache)
    solver_evidence_count = int(solver_counts.get("entries") or 0)
    hashes = {
        "model_hash": model_hash,
        "original_sha256": (inputs.get("original") if isinstance(inputs.get("original"), dict) else {}).get("sha256"),
        "candidate_sha256": (inputs.get("candidate") if isinstance(inputs.get("candidate"), dict) else {}).get("sha256"),
        "mapping_payload_sha256": inputs.get("mapping_payload_sha256"),
        "invariant_payload_sha256": inputs.get("invariant_payload_sha256"),
        "loader_facts_sha256": _canonical_json_sha256(loader_facts),
        "loader_profile_sha256": _canonical_json_sha256(loader_profile),
        "layout_sha256": _canonical_json_sha256(layout),
        "coverage_sha256": _canonical_json_sha256(coverage),
        "coverage_profile_sha256": _canonical_json_sha256(coverage_profile),
        "proof_cache_profile_sha256": _canonical_json_sha256(proof_cache_profile),
        "proof_rule_profile_sha256": _canonical_json_sha256(proof_rule_profile),
        "mapping_profile_sha256": _canonical_json_sha256(mapping_profile),
        "cfg_profile_sha256": _canonical_json_sha256(cfg_profile),
        "reachability_profile_sha256": _canonical_json_sha256(reachability_profile),
        "abi_profile_sha256": _canonical_json_sha256(abi_profile),
        "environment_profile_sha256": _canonical_json_sha256(environment_profile),
        "obligations_sha256": _canonical_json_sha256(obligation_items),
        "proof_cache_index_sha256": proof_cache_index_sha256,
        "proof_cache_index_payload_sha256": _canonical_json_sha256(proof_cache_index),
        "solver_evidence_sha256": solver_evidence.get("sha256"),
        "solver_evidence_index_sha256": solver_evidence.get("index_sha256"),
        "block_semantics_sha256": _canonical_json_sha256(block_semantics),
        "instruction_semantics_sha256": _canonical_json_sha256(instruction_semantics),
        "proof_artifact_bindings_sha256": _canonical_json_sha256(proof_artifact_bindings),
        "semantic_observables_sha256": _canonical_json_sha256(semantic_observables),
        "solver_claims_sha256": _canonical_json_sha256(solver_claims),
        "solver_backend_profile_sha256": _canonical_json_sha256(solver_backend_profile),
        "trusted_boundaries_sha256": _canonical_json_sha256(trusted_boundaries),
        "trusted_boundary_profile_sha256": _canonical_json_sha256(trusted_boundary_profile),
        "profile_manifest_sha256": _canonical_json_sha256(profile_manifest),
        "proof_composition_sha256": _canonical_json_sha256(proof_composition),
    }
    checks = {
        "obligations_closed": len(open_obligations) == 0,
        "no_failures": int(obligation_counts.get("failures") or 0) == 0,
        "no_incomplete_records": int(obligation_counts.get("incomplete") or 0) == 0,
        "coverage_satisfied": coverage.get("status") == "satisfied",
        "coverage_profile_satisfied": coverage_profile.get("status") == "satisfied",
        "proof_cache_profile_satisfied": proof_cache_profile.get("status") == "satisfied",
        "proof_rule_profile_satisfied": proof_rule_profile.get("status") == "satisfied",
        "mapping_profile_satisfied": mapping_profile.get("status") in {"satisfied", "not_applicable"},
        "cfg_profile_satisfied": cfg_profile.get("status") == "satisfied",
        "reachability_profile_satisfied": reachability_profile.get("status") == "satisfied",
        "abi_profile_satisfied": abi_profile.get("status") in {"satisfied", "not_applicable"},
        "environment_profile_satisfied": environment_profile.get("status") == "satisfied",
        "solver_evidence_satisfied": solver_evidence.get("status") == "satisfied",
        "proof_cache_index_hashed": _is_sha256_hex(proof_cache_index_sha256),
        "solver_evidence_hashed": _is_sha256_hex(solver_evidence.get("sha256")),
        "solver_evidence_index_hashed": _is_sha256_hex(solver_evidence.get("index_sha256")),
        "proof_cache_evidence_count_matches": proof_cache_count == solver_evidence_count,
        "proved_block_obligations_have_proof_cache": not any(gap["category"] == "missing_proof_cache_reference" for gap in proof_backing_gaps),
        "proved_block_obligations_have_solver_evidence": not proof_backing_gaps,
        "proof_cache_entries_have_solver_evidence": not proof_cache_evidence_gaps,
        "solver_evidence_entries_bind_known_obligations": not solver_unknown_obligation_gaps,
        "proof_artifact_bindings_satisfied": proof_artifact_bindings.get("status") == "satisfied",
        "proof_artifacts_bind_same_obligations": not evidence_binding_gaps,
        "semantic_observables_satisfied": semantic_observables.get("status") == "satisfied",
        "proved_block_obligations_have_semantic_observables": not semantic_observable_gaps,
        "solver_claims_satisfied": solver_claims.get("status") == "satisfied",
        "solver_backend_profile_satisfied": solver_backend_profile.get("status") == "satisfied",
        "trusted_solver_claims_have_queries": not solver_claim_gaps,
        "trusted_boundaries_satisfied": trusted_boundaries.get("status") == "satisfied",
        "trusted_boundary_profile_satisfied": trusted_boundary_profile.get("status") == "satisfied",
        "profile_manifest_satisfied": profile_manifest.get("status") == "satisfied",
        "semantic_claims_use_allowed_trusted_boundaries": not trusted_boundary_gaps,
        "proof_composition_satisfied": proof_composition.get("status") == "satisfied",
        "proved_block_obligations_have_composition_records": not proof_composition_missing_gaps,
        "block_semantics_satisfied": block_semantics.get("status") == "satisfied",
        "proved_block_obligations_have_block_semantics": not block_semantics_gaps,
        "block_semantics_records_bind_known_obligations": not block_semantics_unknown_obligation_gaps,
        "instruction_semantics_satisfied": instruction_semantics.get("status") == "satisfied",
        "decoded_block_semantics_have_instruction_semantics": not instruction_semantics_missing_gaps,
    }
    return {
        "format": "stage-a-proof-ir-closure-certificate-v1",
        "status": "satisfied" if all(checks.values()) else "incomplete",
        "counts": {
            "obligations": len(obligation_items),
            "open_obligations": len(open_obligations),
            "failures": int(obligation_counts.get("failures") or 0),
            "incomplete": int(obligation_counts.get("incomplete") or 0),
            "proof_cache_entries": proof_cache_count,
            "solver_evidence_entries": solver_evidence_count,
            "proof_backed_obligations": len(proof_backed_obligations),
            "proof_backing_gaps": len(proof_backing_gaps),
            "proof_cache_evidence_gaps": len(proof_cache_evidence_gaps),
            "proof_cache_profile_gaps": int(
                (proof_cache_profile.get("counts") if isinstance(proof_cache_profile.get("counts"), dict) else {}).get("proof_cache_gaps")
                or 0
            ),
            "solver_unknown_obligation_gaps": len(solver_unknown_obligation_gaps),
            "proof_artifact_bindings": len(proof_artifact_binding_records),
            "evidence_binding_gaps": len(evidence_binding_gaps),
            "semantic_observables": len(semantic_observable_records),
            "semantic_observable_gaps": len(semantic_observable_gaps),
            "solver_claims": len(solver_claim_records),
            "solver_claim_gaps": len(solver_claim_gaps),
            "solver_backend_profile_gaps": int(
                (solver_backend_profile.get("counts") if isinstance(solver_backend_profile.get("counts"), dict) else {}).get("backend_gaps")
                or 0
            ),
            "trusted_boundaries": len(trusted_boundary_records),
            "trusted_boundary_gaps": len(trusted_boundary_gaps),
            "trusted_boundary_profile_gaps": int(
                (trusted_boundary_profile.get("counts") if isinstance(trusted_boundary_profile.get("counts"), dict) else {}).get(
                    "trusted_boundary_gaps"
                )
                or 0
            ),
            "profile_manifest_gaps": int(
                (profile_manifest.get("counts") if isinstance(profile_manifest.get("counts"), dict) else {}).get(
                    "profile_manifest_gaps"
                )
                or 0
            ),
            "mapping_profile_gaps": int(
                (mapping_profile.get("counts") if isinstance(mapping_profile.get("counts"), dict) else {}).get("mapping_gaps")
                or 0
            ),
            "cfg_profile_gaps": int(
                (cfg_profile.get("counts") if isinstance(cfg_profile.get("counts"), dict) else {}).get("cfg_gaps")
                or 0
            ),
            "reachability_profile_gaps": int(
                (reachability_profile.get("counts") if isinstance(reachability_profile.get("counts"), dict) else {}).get("reachability_gaps")
                or 0
            ),
            "abi_profile_gaps": int(
                (abi_profile.get("counts") if isinstance(abi_profile.get("counts"), dict) else {}).get("abi_gaps")
                or 0
            ),
            "environment_profile_gaps": int(
                (environment_profile.get("counts") if isinstance(environment_profile.get("counts"), dict) else {}).get("environment_gaps")
                or 0
            ),
            "proof_composition_records": len(proof_composition_records),
            "proof_composition_gaps": len(proof_composition_gaps) + len(proof_composition_missing_gaps),
            "block_semantics_records": len(block_semantics_records),
            "block_semantics_gaps": len(block_semantics_gaps),
            "block_semantics_unknown_obligation_gaps": len(block_semantics_unknown_obligation_gaps),
            "decoded_instruction_block_semantics": len(decoded_instruction_block_records),
            "instruction_semantics_records": len(instruction_semantics_records),
            "instruction_semantics_gaps": len(instruction_semantics_gaps) + len(instruction_semantics_missing_gaps),
        },
        "closed_statuses": sorted(closed_statuses),
        "checks": checks,
        "hashes": hashes,
        "open_obligations": open_obligations[:100],
        "proof_backing_gaps": proof_backing_gaps[:100],
        "proof_cache_evidence_gaps": proof_cache_evidence_gaps[:100],
        "solver_unknown_obligation_gaps": solver_unknown_obligation_gaps[:100],
        "evidence_binding_gaps": evidence_binding_gaps[:100],
        "semantic_observable_gaps": semantic_observable_gaps[:100],
        "solver_claim_gaps": solver_claim_gaps[:100],
        "trusted_boundary_gaps": trusted_boundary_gaps[:100],
        "proof_composition_gaps": (proof_composition_gaps + proof_composition_missing_gaps)[:100],
        "block_semantics_gaps": block_semantics_gaps[:100],
        "block_semantics_unknown_obligation_gaps": block_semantics_unknown_obligation_gaps[:100],
        "instruction_semantics_gaps": (instruction_semantics_gaps + instruction_semantics_missing_gaps)[:100],
    }


def _block_semantics_gaps(
    *,
    proof_backed_obligations: list[dict[str, Any]],
    block_semantics_by_obligation: dict[str, dict[str, Any]],
) -> list[dict[str, Any]]:
    gaps: list[dict[str, Any]] = []
    for item in proof_backed_obligations:
        obligation_id = str(item.get("id") or "")
        record = block_semantics_by_obligation.get(obligation_id)
        if record is None:
            gaps.append(
                {
                    "category": "missing_block_semantics_record",
                    "obligation_id": obligation_id,
                    "proof_cache": item.get("proof_cache"),
                    "proof_rule": item.get("proof_rule"),
                    "generic_proof_rule": item.get("generic_proof_rule"),
                }
            )
            continue
        if record.get("status") != "present":
            gaps.append(
                {
                    "category": "incomplete_block_semantics_record",
                    "obligation_id": obligation_id,
                    "proof_cache": item.get("proof_cache"),
                    "record_status": record.get("status"),
                    "semantics_kind": record.get("semantics_kind"),
                }
            )
            continue
        if record.get("proof_cache") != item.get("proof_cache"):
            gaps.append(
                {
                    "category": "block_semantics_proof_cache_mismatch",
                    "obligation_id": obligation_id,
                    "expected_proof_cache": item.get("proof_cache"),
                    "actual_proof_cache": record.get("proof_cache"),
                    "semantics_kind": record.get("semantics_kind"),
                }
            )
    return gaps


def _block_semantics_unknown_obligation_gaps(
    *,
    block_semantics_records: list[Any],
    obligation_items: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    obligation_ids = {item.get("id") for item in obligation_items if isinstance(item.get("id"), str)}
    gaps: list[dict[str, Any]] = []
    for item in block_semantics_records:
        if not isinstance(item, dict):
            continue
        obligation_id = item.get("obligation_id")
        if isinstance(obligation_id, str) and obligation_id not in obligation_ids:
            gaps.append(
                {
                    "category": "unknown_block_semantics_obligation",
                    "obligation_id": obligation_id,
                    "proof_cache": item.get("proof_cache"),
                    "status": item.get("status"),
                    "semantics_kind": item.get("semantics_kind"),
                }
            )
    return gaps


def _instruction_semantics_gaps_from_records(records: list[Any]) -> list[dict[str, Any]]:
    gaps: list[dict[str, Any]] = []
    for record in records:
        if not isinstance(record, dict):
            continue
        for gap in record.get("gaps", []):
            if isinstance(gap, dict):
                item = dict(gap)
                item.setdefault("obligation_id", record.get("obligation_id"))
                item.setdefault("proof_cache", record.get("proof_cache"))
                gaps.append(item)
    return gaps


def _instruction_semantics_missing_gaps(
    *,
    decoded_instruction_block_records: list[dict[str, Any]],
    instruction_semantics_records: list[Any],
) -> list[dict[str, Any]]:
    records_by_obligation = {
        str(item.get("obligation_id")): item
        for item in instruction_semantics_records
        if isinstance(item, dict) and isinstance(item.get("obligation_id"), str)
    }
    gaps: list[dict[str, Any]] = []
    for item in decoded_instruction_block_records:
        obligation_id = str(item.get("obligation_id") or "")
        record = records_by_obligation.get(obligation_id)
        if record is None:
            gaps.append(
                {
                    "category": "missing_instruction_semantics_record",
                    "obligation_id": obligation_id,
                    "proof_cache": item.get("proof_cache"),
                    "semantics_kind": item.get("semantics_kind"),
                }
            )
            continue
        if record.get("status") != "satisfied":
            gaps.append(
                {
                    "category": "incomplete_instruction_semantics_record",
                    "obligation_id": obligation_id,
                    "proof_cache": item.get("proof_cache"),
                    "record_status": record.get("status"),
                    "semantics_kind": item.get("semantics_kind"),
                }
            )
    return gaps


def _proof_backing_gaps(
    *,
    proof_backed_obligations: list[dict[str, Any]],
    proof_cache_by_path: dict[str, dict[str, Any]],
    solver_by_proof_cache: dict[str, dict[str, Any]],
) -> list[dict[str, Any]]:
    gaps: list[dict[str, Any]] = []
    for item in proof_backed_obligations:
        proof_cache_path = str(item.get("proof_cache") or "")
        if not proof_cache_path:
            gaps.append(
                {
                    "category": "missing_proof_cache_reference",
                    "obligation_id": item.get("id"),
                    "proof_rule": item.get("proof_rule"),
                    "generic_proof_rule": item.get("generic_proof_rule"),
                }
            )
            continue
        if proof_cache_path not in proof_cache_by_path:
            gaps.append(
                {
                    "category": "missing_proof_cache_entry",
                    "obligation_id": item.get("id"),
                    "proof_cache": proof_cache_path,
                    "proof_rule": item.get("proof_rule"),
                    "generic_proof_rule": item.get("generic_proof_rule"),
                }
            )
            continue
        solver_entry = solver_by_proof_cache.get(proof_cache_path)
        if solver_entry is None:
            gaps.append(
                {
                    "category": "missing_solver_evidence_entry",
                    "obligation_id": item.get("id"),
                    "proof_cache": proof_cache_path,
                    "proof_rule": item.get("proof_rule"),
                    "generic_proof_rule": item.get("generic_proof_rule"),
                }
            )
            continue
        if solver_entry.get("status") != "satisfied":
            gaps.append(
                {
                    "category": "incomplete_solver_evidence_entry",
                    "obligation_id": item.get("id"),
                    "proof_cache": proof_cache_path,
                    "solver_status": solver_entry.get("status"),
                    "proof_rule": item.get("proof_rule"),
                    "generic_proof_rule": item.get("generic_proof_rule"),
                }
            )
    return gaps


def _proof_cache_evidence_gaps(
    proof_cache_by_path: dict[str, dict[str, Any]],
    solver_by_proof_cache: dict[str, dict[str, Any]],
) -> list[dict[str, Any]]:
    gaps: list[dict[str, Any]] = []
    for path, cache_entry in sorted(proof_cache_by_path.items()):
        solver_entry = solver_by_proof_cache.get(path)
        if solver_entry is None:
            gaps.append({"category": "missing_solver_evidence_entry", "proof_cache": path, "status": cache_entry.get("status")})
        elif solver_entry.get("status") != "satisfied":
            gaps.append(
                {
                    "category": "incomplete_solver_evidence_entry",
                    "proof_cache": path,
                    "status": cache_entry.get("status"),
                    "solver_status": solver_entry.get("status"),
                }
            )
    return gaps


def _solver_unknown_obligation_gaps(
    *,
    solver_entries: list[Any],
    obligation_items: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    obligation_ids = {item.get("id") for item in obligation_items if isinstance(item.get("id"), str)}
    gaps: list[dict[str, Any]] = []
    for item in solver_entries:
        if not isinstance(item, dict):
            continue
        obligation_id = item.get("obligation_id")
        if isinstance(obligation_id, str) and obligation_id not in obligation_ids:
            gaps.append(
                {
                    "category": "unknown_solver_evidence_obligation",
                    "obligation_id": obligation_id,
                    "proof_cache": item.get("proof_cache"),
                    "status": item.get("status"),
                }
            )
    return gaps


def _evidence_binding_gaps_from_records(records: list[Any]) -> list[dict[str, Any]]:
    gaps: list[dict[str, Any]] = []
    for record in records:
        if not isinstance(record, dict):
            continue
        for gap in record.get("gaps", []):
            if isinstance(gap, dict):
                gaps.append(gap)
    return gaps


def _semantic_observable_gaps_from_records(records: list[Any]) -> list[dict[str, Any]]:
    gaps: list[dict[str, Any]] = []
    for record in records:
        if not isinstance(record, dict):
            continue
        for gap in record.get("gaps", []):
            if isinstance(gap, dict):
                gaps.append(gap)
    return gaps


def _trusted_boundary_gaps_from_records(records: list[Any]) -> list[dict[str, Any]]:
    gaps: list[dict[str, Any]] = []
    for record in records:
        if not isinstance(record, dict):
            continue
        for gap in record.get("gaps", []):
            if isinstance(gap, dict):
                gaps.append(gap)
    return gaps


def _proof_composition_gaps_from_records(records: list[Any]) -> list[dict[str, Any]]:
    gaps: list[dict[str, Any]] = []
    for record in records:
        if not isinstance(record, dict):
            continue
        for gap in record.get("gaps", []):
            if isinstance(gap, dict):
                gaps.append(gap)
    return gaps


def _proof_composition_missing_gaps(
    *,
    proof_backed_obligations: list[dict[str, Any]],
    proof_composition_records: list[Any],
) -> list[dict[str, Any]]:
    records_by_obligation = {
        str(item.get("obligation_id")): item
        for item in proof_composition_records
        if isinstance(item, dict) and isinstance(item.get("obligation_id"), str)
    }
    gaps: list[dict[str, Any]] = []
    for item in proof_backed_obligations:
        obligation_id = str(item.get("id") or "")
        record = records_by_obligation.get(obligation_id)
        if record is None:
            gaps.append(
                {
                    "category": "missing_proof_composition_record",
                    "obligation_id": obligation_id,
                    "proof_cache": item.get("proof_cache"),
                    "proof_rule": item.get("proof_rule"),
                    "generic_proof_rule": item.get("generic_proof_rule"),
                }
            )
            continue
        if record.get("status") != "satisfied":
            gaps.append(
                {
                    "category": "incomplete_proof_composition_record",
                    "obligation_id": obligation_id,
                    "proof_cache": item.get("proof_cache"),
                    "record_status": record.get("status"),
                }
            )
    return gaps


def _solver_claim_gaps_from_records(records: list[Any]) -> list[dict[str, Any]]:
    gaps: list[dict[str, Any]] = []
    for record in records:
        if not isinstance(record, dict):
            continue
        for gap in record.get("gaps", []):
            if isinstance(gap, dict):
                gaps.append(gap)
    return gaps


def _artifact_binding_field_gaps(
    *,
    artifact_kind: str,
    artifact: dict[str, Any],
    obligation_id: str,
    proof_cache_path: str,
    expected_rule: Any,
    expected_generic_rule: Any,
) -> list[dict[str, Any]]:
    gaps: list[dict[str, Any]] = []
    observed_obligation = artifact.get("obligation_id")
    if observed_obligation != obligation_id:
        gaps.append(
            {
                "category": f"{artifact_kind}_obligation_id_mismatch",
                "obligation_id": obligation_id,
                "proof_cache": proof_cache_path,
                "expected": obligation_id,
                "observed": observed_obligation,
            }
        )
    observed_proof_cache = artifact.get("proof_cache")
    if observed_proof_cache != proof_cache_path:
        gaps.append(
            {
                "category": f"{artifact_kind}_proof_cache_mismatch",
                "obligation_id": obligation_id,
                "expected": proof_cache_path,
                "observed": observed_proof_cache,
            }
        )
    observed_rule = artifact.get("proof_rule")
    if observed_rule != expected_rule:
        gaps.append(
            {
                "category": f"{artifact_kind}_proof_rule_mismatch",
                "obligation_id": obligation_id,
                "proof_cache": proof_cache_path,
                "expected": expected_rule,
                "observed": observed_rule,
            }
        )
    observed_generic_rule = artifact.get("generic_proof_rule")
    if observed_generic_rule != expected_generic_rule:
        gaps.append(
            {
                "category": f"{artifact_kind}_generic_proof_rule_mismatch",
                "obligation_id": obligation_id,
                "proof_cache": proof_cache_path,
                "expected": expected_generic_rule,
                "observed": observed_generic_rule,
            }
        )
    return gaps


def _proof_cache_rule(payload: dict[str, Any]) -> str | None:
    if isinstance(payload.get("proof_rule"), str):
        return payload["proof_rule"]
    symbolic = payload.get("symbolic") if isinstance(payload.get("symbolic"), dict) else {}
    if isinstance(symbolic.get("proof_rule"), str):
        return symbolic["proof_rule"]
    query = payload.get("query") if isinstance(payload.get("query"), dict) else {}
    if isinstance(query.get("proof"), dict) and isinstance(query["proof"].get("rule"), str):
        return query["proof"]["rule"]
    return None


def _proof_cache_payload_sha256(payload: dict[str, Any]) -> str:
    return sha256_bytes(json.dumps(payload, sort_keys=True).encode("utf-8"))


def _proof_cache_evidence_kind(payload: dict[str, Any]) -> str:
    fmt = payload.get("format")
    if fmt == "stage-a-symbolic-proof-cache-v1":
        symbolic = payload.get("symbolic") if isinstance(payload.get("symbolic"), dict) else {}
        if symbolic.get("solver") == "z3" and symbolic.get("smt_status") == "unsat":
            return "trusted_z3_unsat"
        if symbolic.get("solver") == "z3" and symbolic.get("smt_status") == "sat":
            return "z3_counterexample"
        return "z3_symbolic_incomplete"
    if fmt == "stage-a-proof-cache-v1":
        return "structural_byte_identity"
    if fmt == "stage-a-mapping-proof-cache-v1":
        return "checked_generated_mapping"
    if fmt == "stage-a-import-thunk-proof-cache-v1":
        return "pe_import_thunk"
    return "unknown_proof_cache"


def _proof_ir_coverage_summary(obligations: list[dict[str, Any]]) -> dict[str, Any]:
    rows = [item for item in obligations if item.get("kind") == "executable_byte_class"]
    return {
        "status": "satisfied"
        if not any(item.get("status") in {"failed", "unmapped", "incomplete", "out_of_model"} for item in rows)
        else "incomplete",
        "counts": {"obligations": len(rows), "by_status": _count_by(rows, "status")},
        "unmapped": [
            {
                "id": item.get("id"),
                "binary": item.get("binary"),
                "rva_start": item.get("rva_start"),
                "rva_end": item.get("rva_end"),
            }
            for item in rows
            if item.get("status") in {"unmapped", "incomplete", "out_of_model"}
        ][:100],
    }


def _proof_ir_coverage_profile(
    *,
    coverage: dict[str, Any],
    obligations: list[dict[str, Any]],
) -> dict[str, Any]:
    coverage_rows = [item for item in obligations if item.get("kind") == "executable_byte_class"]
    block_rows = [item for item in obligations if item.get("kind") == "block_equivalence"]
    by_status = _count_by(coverage_rows, "status")
    known_statuses = {"failed", "incomplete", "unmapped", "waived_noncode", "out_of_model"}
    unknown_statuses = sum(count for status, count in by_status.items() if status not in known_statuses)
    open_statuses = {"failed", "incomplete", "unmapped", "out_of_model"}
    open_coverage = sum(_count_value(by_status, status) for status in open_statuses) + unknown_statuses
    unmapped = coverage.get("unmapped") if isinstance(coverage.get("unmapped"), list) else []
    coverage_counts = coverage.get("counts") if isinstance(coverage.get("counts"), dict) else {}
    coverage_by_status = coverage_counts.get("by_status") if isinstance(coverage_counts.get("by_status"), dict) else {}
    original_gaps = [item for item in unmapped if isinstance(item, dict) and item.get("binary") == "original"]
    candidate_gaps = [item for item in unmapped if isinstance(item, dict) and item.get("binary") == "candidate"]
    counts = {
        "coverage_obligations": len(coverage_rows),
        "block_equivalence_obligations": len(block_rows),
        "proved_block_equivalence_obligations": sum(1 for item in block_rows if item.get("status") == "proved"),
        "waived_noncode_obligations": _count_value(by_status, "waived_noncode"),
        "unmapped_coverage_obligations": _count_value(by_status, "unmapped"),
        "failed_coverage_obligations": _count_value(by_status, "failed"),
        "incomplete_coverage_obligations": _count_value(by_status, "incomplete"),
        "out_of_model_coverage_obligations": _count_value(by_status, "out_of_model"),
        "unknown_coverage_obligation_statuses": unknown_statuses,
        "open_coverage_obligations": open_coverage,
        "coverage_gaps": len([item for item in unmapped if isinstance(item, dict)]),
        "original_coverage_gaps": len(original_gaps),
        "candidate_coverage_gaps": len(candidate_gaps),
    }
    checks = {
        "coverage_status_satisfied": coverage.get("status") == "satisfied",
        "coverage_counts_match": counts["coverage_obligations"] == int(coverage_counts.get("obligations") or 0),
        "coverage_status_counts_match": by_status == coverage_by_status,
        "coverage_obligations_classified": counts["open_coverage_obligations"] == 0,
        "coverage_gaps_closed": counts["coverage_gaps"] == 0,
        "unknown_statuses_closed": counts["unknown_coverage_obligation_statuses"] == 0,
        "block_equivalence_present": counts["block_equivalence_obligations"] > 0,
        "proved_block_equivalence_within_total": counts["proved_block_equivalence_obligations"]
        <= counts["block_equivalence_obligations"],
    }
    return {
        "format": "stage-a-executable-coverage-profile-v1",
        "status": "satisfied" if all(checks.values()) else "incomplete",
        "counts": counts,
        "checks": checks,
        "status_counts": by_status,
        "gaps": [
            {
                "category": "unclassified_executable_bytes",
                "id": item.get("id"),
                "binary": item.get("binary"),
                "rva_start": item.get("rva_start"),
                "rva_end": item.get("rva_end"),
            }
            for item in unmapped
            if isinstance(item, dict)
        ][:100],
    }


def _proof_ir_proof_rule_profile(
    *,
    model_description: dict[str, Any],
    obligation_items: list[dict[str, Any]],
    block_semantics: dict[str, Any],
    solver_evidence: dict[str, Any],
    proof_artifact_bindings: dict[str, Any],
    deprecated_aliases: dict[str, str] | None,
) -> dict[str, Any]:
    aliases = deprecated_aliases or DEPRECATED_PROOF_RULE_ALIASES
    allowed_rules = {
        str(item)
        for item in model_description.get("proof_rules", [])
        if isinstance(item, str) and item
    }
    block_records = block_semantics.get("records") if isinstance(block_semantics.get("records"), list) else []
    solver_rows = solver_evidence.get("entries") if isinstance(solver_evidence.get("entries"), list) else []
    binding_rows = proof_artifact_bindings.get("records") if isinstance(proof_artifact_bindings.get("records"), list) else []
    obligation_unknown = _proof_rule_unknown_rows(obligation_items, allowed_rules)
    block_unknown = _proof_rule_unknown_rows(block_records, allowed_rules)
    solver_unknown = _proof_rule_unknown_rows(solver_rows, allowed_rules)
    alias_rows = [
        row
        for row in [*obligation_items, *block_records, *solver_rows]
        if isinstance(row, dict) and _proof_rule_uses_deprecated_alias(row, aliases)
    ]
    unnormalized_alias_rows = [
        row
        for row in alias_rows
        if row.get("generic_proof_rule") != aliases.get(str(row.get("proof_rule") or ""))
        or row.get("generic_proof_rule") not in allowed_rules
    ]
    binding_rule_gaps = [
        gap
        for row in binding_rows
        if isinstance(row, dict)
        for gap in row.get("gaps", [])
        if isinstance(gap, dict)
        and str(gap.get("category") or "").endswith(("proof_rule_mismatch", "generic_proof_rule_mismatch"))
    ]
    counts = {
        "model_rules": len(allowed_rules),
        "obligations": len(obligation_items),
        "obligations_with_rules": _proof_rule_rows_with_rules(obligation_items),
        "unknown_obligation_rules": len(obligation_unknown),
        "block_semantics_records": len(block_records),
        "block_semantics_records_with_rules": _proof_rule_rows_with_rules(block_records),
        "unknown_block_semantics_rules": len(block_unknown),
        "solver_evidence_entries": len(solver_rows),
        "solver_evidence_entries_with_rules": _proof_rule_rows_with_rules(solver_rows),
        "unknown_solver_evidence_rules": len(solver_unknown),
        "deprecated_alias_uses": len(alias_rows),
        "unnormalized_deprecated_alias_uses": len(unnormalized_alias_rows),
        "artifact_rule_binding_gaps": len(binding_rule_gaps),
    }
    checks = {
        "model_rules_present": counts["model_rules"] > 0,
        "obligation_rules_present": counts["obligations_with_rules"] == counts["obligations"],
        "obligation_rules_known": counts["unknown_obligation_rules"] == 0,
        "block_semantics_rules_present": counts["block_semantics_records_with_rules"] == counts["block_semantics_records"],
        "block_semantics_rules_known": counts["unknown_block_semantics_rules"] == 0,
        "solver_evidence_rules_present": counts["solver_evidence_entries_with_rules"] == counts["solver_evidence_entries"],
        "solver_evidence_rules_known": counts["unknown_solver_evidence_rules"] == 0,
        "deprecated_aliases_normalized": counts["unnormalized_deprecated_alias_uses"] == 0,
        "artifact_rule_bindings_closed": counts["artifact_rule_binding_gaps"] == 0,
    }
    return {
        "format": "stage-a-proof-rule-profile-v1",
        "status": "satisfied" if all(checks.values()) else "incomplete",
        "model_rules": sorted(allowed_rules),
        "deprecated_aliases": aliases,
        "counts": counts,
        "checks": checks,
        "by_generic_rule": {
            "obligations": _count_by(obligation_items, "generic_proof_rule"),
            "block_semantics": _count_by([row for row in block_records if isinstance(row, dict)], "generic_proof_rule"),
            "solver_evidence": _count_by([row for row in solver_rows if isinstance(row, dict)], "generic_proof_rule"),
        },
        "gaps": {
            "unknown_obligation_rules": _proof_rule_gap_rows(obligation_unknown),
            "unknown_block_semantics_rules": _proof_rule_gap_rows(block_unknown),
            "unknown_solver_evidence_rules": _proof_rule_gap_rows(solver_unknown),
            "unnormalized_deprecated_alias_uses": _proof_rule_gap_rows(unnormalized_alias_rows),
            "artifact_rule_binding_gaps": binding_rule_gaps[:100],
        },
    }


def _proof_rule_rows_with_rules(rows: list[Any]) -> int:
    return sum(
        1
        for row in rows
        if isinstance(row, dict)
        and isinstance(row.get("proof_rule"), str)
        and bool(row.get("proof_rule"))
        and isinstance(row.get("generic_proof_rule"), str)
        and bool(row.get("generic_proof_rule"))
    )


def _proof_rule_unknown_rows(rows: list[Any], allowed_rules: set[str]) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        generic = row.get("generic_proof_rule")
        if not isinstance(generic, str) or not generic or generic not in allowed_rules:
            result.append(row)
    return result


def _proof_rule_uses_deprecated_alias(row: dict[str, Any], aliases: dict[str, str]) -> bool:
    proof_rule = row.get("proof_rule")
    generic = row.get("generic_proof_rule")
    return isinstance(proof_rule, str) and proof_rule in aliases and proof_rule != generic


def _proof_rule_gap_rows(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [
        {
            "id": row.get("id"),
            "obligation_id": row.get("obligation_id"),
            "proof_cache": row.get("proof_cache"),
            "proof_rule": row.get("proof_rule"),
            "generic_proof_rule": row.get("generic_proof_rule"),
            "status": row.get("status"),
        }
        for row in rows[:100]
    ]


def _proof_ir_mapping_profile(
    *,
    model_description: dict[str, Any],
    mapping_contract: dict[str, Any] | None,
    deprecated_aliases: dict[str, str] | None,
) -> dict[str, Any]:
    if not isinstance(mapping_contract, dict):
        checks = {
            "mapping_contract_present": False,
            "mapping_status_satisfied": True,
            "mapping_entries_present": True,
            "mapping_issues_closed": True,
            "mapping_ranges_well_formed": True,
            "mapping_invariants_checked": True,
            "checked_roots_known": True,
            "mapping_proof_rules_known": True,
            "mapping_proof_aliases_normalized": True,
            "waiver_ranges_well_formed": True,
            "mapping_gaps_closed": True,
        }
        return {
            "format": "stage-a-mapping-profile-v1",
            "status": "not_applicable",
            "contract_sha256": None,
            "counts": {
                "blocks": 0,
                "code_blocks": 0,
                "non_code_blocks": 0,
                "reachable_blocks": 0,
                "unchecked_invariant_blocks": 0,
                "root_entries": 0,
                "checked_root_entries": 0,
                "unknown_checked_root_entries": 0,
                "mapping_proofs": 0,
                "checked_mapping_proofs": 0,
                "unchecked_mapping_proofs": 0,
                "deprecated_mapping_proof_rules": 0,
                "unknown_mapping_proof_rules": 0,
                "waivers": 0,
                "malformed_waivers": 0,
                "issues": 0,
                "failed_issues": 0,
                "incomplete_issues": 0,
                "malformed_blocks": 0,
                "mapping_gaps": 0,
            },
            "checks": checks,
            "gaps": [],
        }

    aliases = deprecated_aliases or DEPRECATED_PROOF_RULE_ALIASES
    allowed_rules = {
        str(item)
        for item in model_description.get("proof_rules", [])
        if isinstance(item, str) and item
    }
    blocks = [item for item in mapping_contract.get("blocks", []) if isinstance(item, dict)]
    waivers = [item for item in mapping_contract.get("waivers", []) if isinstance(item, dict)]
    issues = [item for item in mapping_contract.get("issues", []) if isinstance(item, dict)]
    proof_rules = [str(item.get("proof_rule") or "") for item in blocks if item.get("proof_rule")]
    deprecated_rules = [rule for rule in proof_rules if rule in aliases]
    unknown_rules = [
        rule
        for rule in proof_rules
        if generic_proof_rule(rule, deprecated_aliases=aliases) not in allowed_rules
    ]
    malformed_blocks = [
        item
        for item in blocks
        if _mapping_profile_range_size(item.get("original")) <= 0
        or _mapping_profile_range_size(item.get("candidate")) <= 0
    ]
    malformed_waivers = [item for item in waivers if _mapping_profile_range_size(item) <= 0]
    counts_source = mapping_contract.get("counts") if isinstance(mapping_contract.get("counts"), dict) else {}
    counts = {
        "blocks": len(blocks),
        "code_blocks": _count_value(counts_source, "code_blocks"),
        "non_code_blocks": _count_value(counts_source, "non_code_blocks"),
        "reachable_blocks": _count_value(counts_source, "reachable_blocks"),
        "unchecked_invariant_blocks": _count_value(counts_source, "unchecked_invariant_blocks"),
        "root_entries": _count_value(counts_source, "root_entries"),
        "checked_root_entries": _count_value(counts_source, "checked_root_entries"),
        "unknown_checked_root_entries": _count_value(counts_source, "unknown_checked_root_entries"),
        "mapping_proofs": _count_value(counts_source, "mapping_proofs"),
        "checked_mapping_proofs": _count_value(counts_source, "checked_mapping_proofs"),
        "unchecked_mapping_proofs": _count_value(counts_source, "unchecked_mapping_proofs"),
        "deprecated_mapping_proof_rules": len(deprecated_rules),
        "unknown_mapping_proof_rules": len(unknown_rules),
        "waivers": len(waivers),
        "malformed_waivers": len(malformed_waivers),
        "issues": len(issues),
        "failed_issues": _count_value(counts_source, "failed_issues"),
        "incomplete_issues": _count_value(counts_source, "incomplete_issues"),
        "malformed_blocks": len(malformed_blocks),
    }
    mapping_gaps = (
        counts["failed_issues"]
        + counts["incomplete_issues"]
        + counts["unchecked_invariant_blocks"]
        + counts["unknown_checked_root_entries"]
        + counts["unknown_mapping_proof_rules"]
        + counts["malformed_blocks"]
        + counts["malformed_waivers"]
    )
    counts["mapping_gaps"] = mapping_gaps
    checks = {
        "mapping_contract_present": True,
        "mapping_status_satisfied": str(mapping_contract.get("status") or "") == "satisfied",
        "mapping_entries_present": counts["blocks"] > 0 and counts["code_blocks"] > 0,
        "mapping_issues_closed": counts["failed_issues"] == 0 and counts["incomplete_issues"] == 0,
        "mapping_ranges_well_formed": counts["malformed_blocks"] == 0,
        "mapping_invariants_checked": counts["unchecked_invariant_blocks"] == 0,
        "checked_roots_known": counts["unknown_checked_root_entries"] == 0,
        "mapping_proof_rules_known": counts["unknown_mapping_proof_rules"] == 0,
        "mapping_proof_aliases_normalized": all(generic_proof_rule(rule, deprecated_aliases=aliases) in allowed_rules for rule in deprecated_rules),
        "waiver_ranges_well_formed": counts["malformed_waivers"] == 0,
        "mapping_gaps_closed": mapping_gaps == 0,
    }
    return {
        "format": "stage-a-mapping-profile-v1",
        "status": "satisfied" if all(checks.values()) else "incomplete",
        "contract_sha256": _canonical_json_sha256(mapping_contract),
        "counts": counts,
        "checks": checks,
        "gaps": _mapping_profile_gaps(
            issues=issues,
            malformed_blocks=malformed_blocks,
            malformed_waivers=malformed_waivers,
            unknown_rules=unknown_rules,
            unchecked_blocks=[item for item in blocks if item.get("invariant_checked") is not True],
            unknown_roots=[item for item in blocks if item.get("unknown_checked_root") is True],
        ),
    }


def _mapping_profile_range_size(value: Any) -> int:
    if not isinstance(value, dict):
        return 0
    start = value.get("rva_start")
    end = value.get("rva_end")
    if isinstance(start, int) and isinstance(end, int):
        return end - start
    rva = value.get("rva")
    size = value.get("size")
    if isinstance(rva, int) and isinstance(size, int):
        return size
    return 0


def _mapping_profile_gaps(
    *,
    issues: list[dict[str, Any]],
    malformed_blocks: list[dict[str, Any]],
    malformed_waivers: list[dict[str, Any]],
    unknown_rules: list[str],
    unchecked_blocks: list[dict[str, Any]],
    unknown_roots: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    gaps: list[dict[str, Any]] = []
    gaps.extend({"category": "mapping_issue", **item} for item in issues[:50])
    gaps.extend(
        {
            "category": "malformed_mapping_range",
            "block_id": item.get("id"),
            "original": item.get("original"),
            "candidate": item.get("candidate"),
        }
        for item in malformed_blocks[:50]
    )
    gaps.extend(
        {
            "category": "unchecked_mapping_invariant",
            "block_id": item.get("id"),
            "kind": item.get("kind"),
        }
        for item in unchecked_blocks[:50]
    )
    gaps.extend(
        {
            "category": "unknown_checked_root_kind",
            "block_id": item.get("id"),
        }
        for item in unknown_roots[:50]
    )
    gaps.extend({"category": "unknown_mapping_proof_rule", "proof_rule": rule} for rule in sorted(set(unknown_rules))[:50])
    gaps.extend(
        {
            "category": "malformed_waiver_range",
            "waiver_id": item.get("id"),
            "binary": item.get("binary"),
            "rva_start": item.get("rva_start"),
            "rva_end": item.get("rva_end"),
        }
        for item in malformed_waivers[:50]
    )
    return gaps[:100]


def _proof_ir_obligation_summary(item: dict[str, Any], *, deprecated_aliases: dict[str, str] | None) -> dict[str, Any]:
    proof_rule = item.get("proof_rule")
    row = {
        "id": item.get("id"),
        "kind": item.get("kind"),
        "status": item.get("status"),
        "proof_rule": proof_rule,
        "generic_proof_rule": generic_proof_rule(proof_rule, deprecated_aliases=deprecated_aliases),
        "proof_cache": item.get("proof_cache"),
    }
    for key in (
        "source_block",
        "target_block",
        "edge_kind",
        "block",
        "binary",
        "rva_start",
        "rva_end",
        "original_edge",
        "candidate_edge",
        "signature",
        "original",
        "candidate",
    ):
        if key in item:
            row[key] = item[key]
    proof = item.get("proof") if isinstance(item.get("proof"), dict) else {}
    if proof:
        row["proof_kind"] = proof.get("kind")
        row["edge_obligation"] = proof.get("edge_obligation")
        row["proof_source_block"] = proof.get("source_block")
        row["proof_edge_kind"] = proof.get("edge_kind")
        row["root_kind"] = proof.get("root_kind")
    return row


def _input_artifact(path: Path) -> dict[str, Any]:
    return {
        "path": str(path),
        "sha256": sha256_file(path) if path.is_file() else None,
        "exists": path.exists(),
    }


def _obligation_counts(
    obligations: list[dict[str, Any]],
    failures: list[dict[str, Any]],
    incomplete: list[dict[str, Any]],
) -> dict[str, Any]:
    status_counts: dict[str, int] = {}
    for item in obligations:
        status_counts[str(item.get("status"))] = status_counts.get(str(item.get("status")), 0) + 1
    return {
        "obligations": len(obligations),
        "failures": len(failures),
        "incomplete": len(incomplete),
        "by_status": status_counts,
    }


def _count_by(rows: list[dict[str, Any]], key: str) -> dict[str, int]:
    counts: dict[str, int] = {}
    for row in rows:
        value = str(row.get(key))
        counts[value] = counts.get(value, 0) + 1
    return counts


def _count_value(counts: dict[str, int], key: str) -> int:
    return int(counts.get(key) or 0)


def _gap_category_counts(rows: list[Any]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for row in rows:
        if not isinstance(row, dict):
            continue
        gaps = row.get("gaps") if isinstance(row.get("gaps"), list) else []
        for gap in gaps:
            if not isinstance(gap, dict):
                continue
            category = str(gap.get("category") or "unknown")
            counts[category] = counts.get(category, 0) + 1
    return counts


def _is_sha256_hex(value: Any) -> bool:
    return isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) is not None


def _canonical_json_sha256(value: Any) -> str:
    return sha256_bytes(json.dumps(value, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8"))


def _safe_gap_part(value: str) -> str:
    text = re.sub(r"[^A-Za-z0-9_.:-]+", "-", value).strip("-")
    return text[:96] or "item"
