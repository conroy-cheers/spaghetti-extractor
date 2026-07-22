from __future__ import annotations

import json
import re
import shutil
from pathlib import Path
from typing import Any

from ..stage_binary import StageABinary
from ..util import sha256_file, utc_now, write_json
from .schema import (
    SchemaError,
    STAGE_A_RELATIONAL_MODEL_ID,
    STAGE_A_RELATIONAL_PROFILE_ID,
    selected_relational_acceptance_theorem,
)


def _write_relational_verdict(out: Path, started_at: str, original: StageABinary, candidate: StageABinary, contract: dict[str, Any], proof_ir: dict[str, Any], trusted_base: dict[str, Any], verdict: str, lean: dict[str, Any], *, certificates: list[dict[str, Any]], blocker: str | None) -> dict[str, Any]:
    acceptance: dict[str, Any] = {}
    selected_theorem: str | None = None
    try:
        payload = json.loads(
            (out / "whole-program-acceptance.json").read_text(encoding="utf-8")
        )
        if isinstance(payload, dict):
            acceptance = payload
            selected_theorem = selected_relational_acceptance_theorem(acceptance)
    except (OSError, json.JSONDecodeError, SchemaError):
        pass
    checked_theorem = str(lean.get("theorem") or "")
    whole_program_checked = (
        lean.get("status") == "checked"
        and selected_theorem is not None
        and checked_theorem == selected_theorem
    )
    if verdict == "pass" and not whole_program_checked:
        verdict = "incomplete"
        blocker = (
            "pass requires the Lean-checked whole-program acceptance theorem"
        )
    for entry in certificates:
        index = entry.get("region_index")
        if isinstance(index, int) and 0 <= index < len(contract["regions"]):
            entry["region_id"] = contract["regions"][index]["id"]
    certificate_index = {
        "format": "stage-a-relational-certificates-v1",
        "status": "satisfied" if len(certificates) == len(contract["regions"]) else "incomplete",
        "entries": certificates,
        "counts": {"certificates": len(certificates), "regions": len(contract["regions"])},
    }
    write_json(out / "certificates" / "index.json", certificate_index)
    obligation_status = (
        "proved" if lean.get("status") == "checked"
        else "failed" if verdict == "fail"
        else "incomplete"
    )
    finalized_obligations = []
    for obligation in proof_ir["obligations"]:
        if obligation["kind"] == "relational_region_equivalence":
            finalized_obligations.append({
                **obligation,
                "status": obligation_status,
                "evidence": next(
                    (
                        entry for entry in certificates
                        if entry.get("region_id")
                        == obligation["id"].removeprefix("relational:")
                    ),
                    None,
                ),
            })
        elif (
            lean.get("status") == "checked"
            and obligation["kind"] in {
                "cfg_bound_invariant", "cfg_address_separation_invariant",
            }
            and obligation.get("analysis", {}).get("status")
                == "candidate_requires_lean_replay"
        ):
            finalized_obligations.append({
                **obligation,
                "status": "proved",
                "evidence": {
                    "kind": "lean_checked_inductive_invariant_family",
                    "theorem": checked_theorem,
                },
            })
        elif (
            lean.get("status") == "checked"
            and obligation["kind"] == "mapped_relocation_image_relation"
        ):
            finalized_obligations.append({
                **obligation,
                "status": "proved",
                "evidence": {
                    "kind": "lean_checked_mapped_relocation_image_relation",
                    "theorem": checked_theorem,
                    "lemma": (
                        "StageA.Relational."
                        "allMappedRelocationImageRelations_of_valueRegionsClosed"
                    ),
                },
            })
        elif (
            lean.get("status") == "checked"
            and obligation["kind"] == "static_proof_context"
        ):
            finalized_obligations.append({
                **obligation,
                "status": "proved",
                "evidence": {
                    "kind": "lean_checked_static_proof_context",
                    "theorem": "StageA.GeneratedRelational.staticProofContextChecked",
                },
            })
        elif (
            lean.get("status") == "checked"
            and obligation["kind"] == "memory_transition_preservation"
            and obligation.get("analysis", {}).get("status")
                == "candidate_requires_lean_replay"
        ):
            finalized_obligations.append({
                **obligation,
                "status": "proved",
                "evidence": {
                    "kind": "lean_checked_exact_memory_pullback_transition",
                    "theorem": checked_theorem,
                    "lemma": (
                        "StageA.Relational.InvariantWP."
                        "memoryObservationTransitionClosed_of_exact_pullback_pairs"
                    ),
                },
            })
        elif (
            lean.get("status") == "checked"
            and obligation["kind"] == "iat_memory_relation_override"
        ):
            finalized_obligations.append({
                **obligation,
                "status": "proved",
                "evidence": {
                    "kind": "lean_checked_iat_masked_memory_relation",
                    "theorem": "StageA.GeneratedRelational.candidateRelationalEvidenceBundle",
                    "lemma": "StageA.Relational.StateRel.ordinaryMemoryRelation",
                },
            })
        else:
            finalized_obligations.append(obligation)
    assumption_obligations = [
        obligation for obligation in finalized_obligations
        if obligation["kind"] != "relational_region_equivalence"
        and obligation.get("status") != "proved"
    ]
    finalized_ir = dict(proof_ir)
    finalized_ir["status"] = (
        "violated" if verdict == "fail"
        else "incomplete" if verdict != "pass" or assumption_obligations
        else "satisfied"
    )
    finalized_ir["families"] = [
        {"family": "exact_pe_decode", "status": "satisfied" if lean.get("status") == "checked" else "incomplete"},
        {"family": "x86_semantics", "status": "satisfied" if lean.get("status") == "checked" else "incomplete"},
        {
            "family": "executable_coverage",
            "status": "satisfied" if whole_program_checked else "incomplete",
        },
        {"family": "roots_and_targets", "status": "satisfied"},
        {
            "family": "static_proof_context",
            "status": "satisfied" if lean.get("status") == "checked" else "incomplete",
        },
        {
            "family": "relational_regions",
            "status": "satisfied" if lean.get("status") == "checked"
            else "violated" if verdict == "fail"
            else "incomplete",
        },
        {
            "family": "segment_refinement",
            "status": "incomplete" if any(
                obligation["kind"] == "relational_segment_refinement"
                for obligation in assumption_obligations
            ) else "satisfied",
        },
        {
            "family": "cfg_register_relations",
            "status": "incomplete" if any(
                obligation["kind"] == "cfg_register_relation_preservation"
                for obligation in assumption_obligations
            ) else "satisfied",
        },
        {
            "family": "whole_program_composition",
            "status": "incomplete" if any(
                obligation["kind"] == "product_graph_composition"
                for obligation in assumption_obligations
            ) else "satisfied",
        },
        {
            "family": "whole_program_observational_equivalence",
            "status": "satisfied" if whole_program_checked else "incomplete",
        },
        {
            "family": "cfg_invariants",
            "status": "incomplete" if any(
                obligation["kind"] in {
                    "cfg_bound_invariant",
                    "cfg_address_separation_invariant",
                }
                for obligation in assumption_obligations
            ) else "not_applicable",
        },
        {
            "family": "memory_relation",
            "status": "incomplete" if any(
                obligation["kind"] in {
                    "mapped_relocation_image_relation",
                    "memory_transition_preservation",
                    "iat_memory_relation_override",
                }
                for obligation in assumption_obligations
            ) else "satisfied",
        },
        {
            "family": "paired_external_environment_refinement",
            "status": (
                "incomplete" if any(
                    obligation["kind"] == "external_call_product_edge_refinement"
                    for obligation in assumption_obligations
                ) else
                "satisfied" if any(
                    obligation["kind"] == "external_call_product_edge_refinement"
                    for obligation in finalized_obligations
                ) else
                "not_applicable"
            ),
        },
        {"family": "adversarial_environment", "status": "satisfied"},
    ]
    finalized_ir["obligations"] = finalized_obligations
    write_json(out / "relational-proof-ir.json", finalized_ir)
    diagnostic = _lean_diagnostic(lean)
    write_json(
        out / "diagnostics.json",
        {
            "format": "stage-a-relational-diagnostics-v1",
            "status": "satisfied" if verdict == "pass" else "violated" if verdict == "fail" else "incomplete",
            "blocker": blocker,
            "diagnostic": diagnostic,
        },
    )
    result = {
        "format": "stage-a-relational-verdict-v1",
        "verdict": verdict,
        "acceptance_authority": "whole_program_lean",
        "profile": STAGE_A_RELATIONAL_PROFILE_ID,
        "model": STAGE_A_RELATIONAL_MODEL_ID,
        "expected_final_theorem": selected_theorem,
        "acceptance": acceptance,
        "claim_scope": {
            "kind": (
                "whole_program_observational_equivalence"
                if whole_program_checked else "relational_region_certificate"
            ),
            "whole_program_observational_equivalence": whole_program_checked,
            "acceptance_eligible": whole_program_checked,
        },
        "started_at": started_at,
        "completed_at": utc_now(),
        "original": {"path": str(original.path), "sha256": original.sha256},
        "candidate": {"path": str(candidate.path), "sha256": candidate.sha256},
        "interface_manifest_sha256": (
            sha256_file(out / "stage-a-interface-manifest.json")
            if (out / "stage-a-interface-manifest.json").is_file()
            else None
        ),
        "relation_contract_sha256": sha256_file(out / "relation-contract.json"),
        "proof_ir_sha256": sha256_file(out / "relational-proof-ir.json"),
        "semantic_ir_sha256": (
            sha256_file(out / "relational-semantic-ir.json")
            if (out / "relational-semantic-ir.json").is_file()
            else None
        ),
        "memory_contracts_sha256": (
            sha256_file(out / "relational-memory-contracts.json")
            if (out / "relational-memory-contracts.json").is_file()
            else None
        ),
        "static_word_relations_sha256": (
            sha256_file(out / "relational-static-word-relations.json")
            if (out / "relational-static-word-relations.json").is_file()
            else None
        ),
        "register_relations_sha256": (
            sha256_file(out / "relational-register-relations.json")
            if (out / "relational-register-relations.json").is_file()
            else None
        ),
        "runtime_frame_affine_sha256": (
            sha256_file(
                out / "relational-runtime-frame-affine-viability.json"
            )
            if (
                out / "relational-runtime-frame-affine-viability.json"
            ).is_file()
            else None
        ),
        "product_graph_sha256": (
            sha256_file(out / "relational-product-graph.json")
            if (out / "relational-product-graph.json").is_file()
            else None
        ),
        "isa_requirements_sha256": (
            sha256_file(out / "isa-requirements.json")
            if (out / "isa-requirements.json").is_file()
            else None
        ),
        "whole_program_acceptance_sha256": (
            sha256_file(out / "whole-program-acceptance.json")
            if (out / "whole-program-acceptance.json").is_file()
            else None
        ),
        "composition_progress_sha256": (
            sha256_file(out / "composition-progress.json")
            if (out / "composition-progress.json").is_file()
            else None
        ),
        "module_graph_sha256": (
            sha256_file(out / "module-graph.json")
            if (out / "module-graph.json").is_file()
            else None
        ),
        "invariants_sha256": (
            sha256_file(out / "relational-invariants.json")
            if (out / "relational-invariants.json").is_file()
            else None
        ),
        "trusted_base_sha256": sha256_file(out / "trusted-base.json"),
        "counts": {
            "regions": len(contract["regions"]),
            "certificates": len(certificates),
            "failed": 1 if verdict == "fail" else 0,
            "incomplete": (1 if verdict == "incomplete" else 0) + len(assumption_obligations),
            "incomplete_assumptions": len(assumption_obligations),
        },
        "proof": {
            "theorem": checked_theorem,
            "lean": lean,
            "certificate_index": certificate_index,
        },
        "blocker": blocker,
        "diagnostic": diagnostic,
    }
    write_json(out / "verdict.json", result)
    return result

def _write_incomplete(out: Path, started_at: str, original: Path, candidate: Path, blocker: str, *, issues: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    issue_rows = issues or []
    result = {
        "format": "stage-a-relational-verdict-v1",
        "verdict": "incomplete",
        "acceptance_authority": "whole_program_lean",
        "claim_scope": {
            "kind": "whole_program_observational_equivalence",
            "whole_program_observational_equivalence": False,
            "acceptance_eligible": False,
        },
        "profile": STAGE_A_RELATIONAL_PROFILE_ID,
        "model": STAGE_A_RELATIONAL_MODEL_ID,
        "started_at": started_at,
        "completed_at": utc_now(),
        "original": {"path": str(original)},
        "candidate": {"path": str(candidate)},
        "counts": {"regions": 0, "certificates": 0, "incomplete": 1},
        "issues": issue_rows,
        "blocker": blocker,
    }
    write_json(out / "verdict.json", result)
    write_json(
        out / "coverage_gaps.json",
        {
            "format": "stage-a-relational-coverage-gaps-v1",
            "status": "incomplete",
            "gaps": issue_rows,
        },
    )
    return result

def _lean_diagnostic(lean: dict[str, Any]) -> dict[str, Any] | None:
    if isinstance(lean.get("counterexample"), dict):
        return {
            "category": "checked_relational_counterexample",
            "severity": "hard",
            "region_id": lean.get("region_id"),
            "counterexample": lean["counterexample"],
            "next_action": "repair the candidate semantics or strengthen only a justified entry invariant",
        }
    if lean.get("status") == "checked":
        return None
    if isinstance(lean.get("issues"), list) and lean["issues"]:
        return {
            "category": "semantic_preflight_incomplete",
            "severity": "hard",
            "count": len(lean["issues"]),
            "first_issue": lean["issues"][0],
            "next_action": lean["issues"][0].get("next_action"),
        }
    stderr = str(lean.get("stderr") or "") + "\n" + str(lean.get("stdout") or "")
    if not stderr:
        return None
    extraction_failure = re.search(
        r"\b(original|candidate) region (\d+) did not (decode|normalize)\b",
        stderr,
    )
    if extraction_failure is not None:
        side, region_id, phase = extraction_failure.groups()
        if phase == "normalize":
            return {
                "category": "formal_region_target_normalization_incomplete",
                "severity": "hard",
                "side": side,
                "region_id": int(region_id),
                "summary": (
                    "Lean decoded the exact bytes but could not map a control-flow "
                    "target into the canonical relation contract"
                ),
                "counterexample": None,
                "next_action": (
                    "inspect the region outcome and add a checked paired cutpoint or "
                    "termination witness for the unresolved target"
                ),
            }
        return {
            "category": "formal_region_decode_incomplete",
            "severity": "hard",
            "side": side,
            "region_id": int(region_id),
            "summary": "Lean could not execute the complete exact-byte region",
            "counterexample": None,
            "next_action": (
                "inspect the exact region bytes and either add reviewed instruction "
                "semantics or introduce a checked semantic cutpoint"
            ),
        }
    assignment = _counterexample_assignment(stderr)
    error = next((line.strip() for line in stderr.splitlines() if "error:" in line), None)
    return {
        "category": "relational_proof_not_closed",
        "severity": "hard",
        "summary": error or "Lean did not close a generated relational theorem",
        "counterexample": assignment or None,
        "next_action": "inspect the first incomplete region and repair its output relation or candidate semantics",
    }

def _counterexample_assignment(output: str) -> dict[str, int]:
    counterexample = re.search(r"(?:Consider|consider) the following assignment:\n(.*)", output, re.DOTALL)
    if counterexample is None:
        return {}
    assignment: dict[str, int] = {}
    for register, value in re.findall(r"^([a-z][a-z0-9]*) = (\d+)#32$", counterexample.group(1), re.MULTILINE):
        assignment[register] = int(value)
    return assignment

def _certificate_hashes_match(report: Path, index: dict[str, Any]) -> bool:
    entries = index.get("entries")
    if not isinstance(entries, list):
        return False
    return all(
        isinstance(entry, dict)
        and (
            entry.get("kind") == "lean_normalization"
            or (
                entry.get("kind") == "lrat"
                and isinstance(entry.get("path"), str)
                and (report / "certificates" / entry["path"]).is_file()
                and sha256_file(report / "certificates" / entry["path"]) == entry.get("sha256")
            )
        )
        for entry in entries
    )
