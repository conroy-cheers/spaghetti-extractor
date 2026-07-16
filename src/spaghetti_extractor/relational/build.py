from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any

from ..stage_binary import StageABinary, StageAInputError
from ..util import sha256_bytes, sha256_file, write_json
from .schema import (
    RELATION_CONTRACT_FORMAT,
    RELATIONAL_ACCEPTANCE_THEOREM,
    RELATIONAL_KERNEL_MODULES,
    RELATIONAL_PREPARED_REPORT_FILES,
    STAGE_A_RELATIONAL_MODEL_ID,
    STAGE_A_RELATIONAL_PROFILE_ID,
    ModuleGraph,
    PreparedProofDigests,
    SchemaError,
    StageAInterfaceManifest,
)
from .ir import CompositionProgressIR, RelationalProofIR, WholeProgramAcceptanceIR


_LEAN_SOURCE_ROOT = Path(__file__).resolve().parent.parent / "lean" / "StageA"


def _remove_relational_build_output(path: Path) -> None:
    if not path.exists():
        return
    directories = [
        child for child in path.rglob("*")
        if child.is_dir() and not child.is_symlink()
    ]
    for directory in directories:
        directory.chmod(directory.stat().st_mode | 0o700)
    path.chmod(path.stat().st_mode | 0o700)
    shutil.rmtree(path)


def _relational_nix_build_command(
    expression: str,
    builders_file: Path | None,
) -> list[str]:
    command = [
        "nix", "build", "--no-link", "--json", "--impure", "--expr", expression,
    ]
    if builders_file is not None:
        command[2:2] = [
            "--max-jobs", "0", "--cores", "2",
            "--builders", f"@{builders_file}",
        ]
    return command


def stage_a_build_relational(
    *,
    prepared: Path,
    out: Path,
    executor: str = "nix",
    flake: Path | None = None,
    builders_file: Path | None = None,
    target_node: str | None = None,
    target_nodes: list[str] | None = None,
) -> dict[str, Any]:
    prepared = Path(prepared).resolve()
    out = Path(out).resolve()
    if executor != "nix":
        raise StageAInputError(f"unsupported relational proof executor {executor!r}")
    graph = _validate_prepared_relational(prepared)
    graph_node_ids = {node["id"] for node in graph["nodes"]}
    requested_target_nodes = ([target_node] if target_node is not None else []) + list(
        target_nodes or []
    )
    if len(requested_target_nodes) != len(set(requested_target_nodes)):
        raise StageAInputError("relational target-node inventory contains duplicates")
    missing_target_nodes = sorted(set(requested_target_nodes) - graph_node_ids)
    if missing_target_nodes:
        raise StageAInputError(
            "prepared module graph has no nodes " + repr(missing_target_nodes)
        )
    if out == prepared or prepared in out.parents:
        raise StageAInputError("build output must not be inside the prepared proof directory")
    acceptance = graph["acceptance"]
    if not requested_target_nodes and acceptance["status"] != "ready":
        _remove_relational_build_output(out)
        out.mkdir(parents=True)
        result = {
            "format": "stage-a-relational-nix-build-v1",
            "status": "incomplete",
            "verdict": "incomplete",
            "acceptance": acceptance,
            "checks": {
                "prepared_graph_valid": True,
                "whole_program_acceptance_ready": False,
                "nix_graph_built": False,
            },
            "diagnostic": {
                "category": "whole_program_certificate_missing",
                "severity": "hard",
                "next_action": acceptance["blockers"][0]["next_action"],
            },
            "elapsed_seconds": 0.0,
        }
        write_json(out / "verdict.json", result)
        return result

    evaluator = _relational_nix_evaluator()
    flake_root = _find_relational_flake_root(flake)

    focused_prepared: tempfile.TemporaryDirectory[str] | None = None
    nix_prepared = prepared
    focused_input: dict[str, Any] | None = None
    if requested_target_nodes:
        focused_prepared = tempfile.TemporaryDirectory(
            prefix="stage-a-relational-node-input-"
        )
        nix_prepared = Path(focused_prepared.name)
        (nix_prepared / "lean" / "StageA").mkdir(parents=True)
        shutil.copyfile(
            prepared / "module-graph.json", nix_prepared / "module-graph.json"
        )
        nodes = {node["id"]: node for node in graph["nodes"]}
        closure: set[str] = set()

        def include(node_id: str) -> None:
            if node_id in closure:
                return
            closure.add(node_id)
            for dependency in nodes[node_id]["dependencies"]:
                include(dependency)

        for requested_target_node in requested_target_nodes:
            include(requested_target_node)
        modules = sorted({
            module
            for node_id in closure
            for module in nodes[node_id]["modules"]
        })
        source_bytes = 0
        for module in modules:
            metadata = graph["modules"][module]
            source = prepared / metadata["source"]
            destination = nix_prepared / metadata["source"]
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, destination)
            source_bytes += source.stat().st_size
        focused_input = {
            "nodes": len(closure),
            "modules": len(modules),
            "source_bytes": source_bytes,
        }

    locked_nixpkgs = _locked_flake_input(flake_root / "flake.lock", "nixpkgs")
    expression = "\n".join([
        "let",
        f"  nixpkgs = builtins.fetchTree (builtins.fromJSON {json.dumps(json.dumps(locked_nixpkgs, sort_keys=True))});",
        "  pkgs = import nixpkgs { system = builtins.currentSystem; };",
        f"  prepared = builtins.path {{ path = builtins.toPath {json.dumps(str(nix_prepared))}; name = \"stage-a-prepared-proof\"; }};",
        "  targetNode = " + (
            "null" if target_node is None else json.dumps(target_node)
        ) + ";",
        "  targetNodes = [ "
        + " ".join(json.dumps(node) for node in requested_target_nodes)
        + " ];",
        f"in import (builtins.toPath {json.dumps(str(evaluator))}) {{ inherit pkgs prepared targetNode targetNodes; }}",
    ])
    builders_path: Path | None = None
    if builders_file is not None:
        builders_path = Path(builders_file).resolve()
        if not builders_path.is_file():
            raise StageAInputError(f"Nix builders file does not exist: {builders_path}")
    command = _relational_nix_build_command(expression, builders_path)
    started = time.monotonic()
    process = subprocess.run(
        command,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if focused_prepared is not None:
        focused_prepared.cleanup()
    elapsed = round(time.monotonic() - started, 3)
    if process.returncode != 0:
        _remove_relational_build_output(out)
        out.mkdir(parents=True)
        (out / "nix.stdout").write_text(process.stdout, encoding="utf-8")
        (out / "nix.stderr").write_text(process.stderr, encoding="utf-8")
        failure = {
            "format": "stage-a-relational-nix-build-v1",
            "status": "incomplete",
            "verdict": "incomplete",
            "diagnostic": {
                "category": "nix_graph_build_failed",
                "severity": "hard",
                "next_action": "inspect nix.stderr and the first failed derivation log",
            },
            "returncode": process.returncode,
            "elapsed_seconds": elapsed,
        }
        write_json(out / "verdict.json", failure)
        raise StageAInputError(
            f"Nix relational proof graph failed; complete logs are in {out / 'nix.stderr'}:\n"
            + process.stderr[:4000]
            + ("\n...\n" if len(process.stderr) > 12000 else "")
            + process.stderr[-8000:]
        )
    try:
        build_outputs = json.loads(process.stdout)
        result_paths = [Path(output["outputs"]["out"]) for output in build_outputs]
    except (json.JSONDecodeError, IndexError, KeyError, TypeError) as exc:
        raise StageAInputError("Nix returned a malformed relational graph result") from exc
    if requested_target_nodes:
        node_results = [_read_json(path / "module-result.json") for path in result_paths]
        observed_target_nodes = {node_result.get("id") for node_result in node_results}
        if (
            observed_target_nodes != set(requested_target_nodes)
            or len(node_results) != len(requested_target_nodes)
            or any(
                node_result.get("format") != "stage-a-lean-node-result-v1"
                or not isinstance(node_result.get("outputs"), list)
                for node_result in node_results
            )
        ):
            raise StageAInputError("Nix returned malformed relational node-set provenance")
        _remove_relational_build_output(out)
        out.mkdir(parents=True)
        if len(requested_target_nodes) == 1:
            result_path = result_paths[0]
            node_result = node_results[0]
            shutil.copytree(result_path, out, dirs_exist_ok=True, symlinks=True)
            out.chmod(out.stat().st_mode | 0o700)
            result = {
                "format": "stage-a-relational-nix-node-build-v1",
                "status": "checked",
                "target_node": requested_target_nodes[0],
                "result_path": str(result_path),
                "elapsed_seconds": elapsed,
                "focused_input": focused_input,
                "node": node_result,
            }
            write_json(out / "node-build.json", result)
        else:
            result_by_id = {node_result["id"]: node_result for node_result in node_results}
            path_by_id = {
                node_result["id"]: path
                for node_result, path in zip(node_results, result_paths, strict=True)
            }
            result = {
                "format": "stage-a-relational-nix-node-set-build-v1",
                "status": "checked",
                "target_nodes": requested_target_nodes,
                "result_paths": [str(path_by_id[node]) for node in requested_target_nodes],
                "elapsed_seconds": elapsed,
                "focused_input": focused_input,
                "nodes": [result_by_id[node] for node in requested_target_nodes],
            }
            write_json(out / "node-set-build.json", result)
        for directory in [out, *(
            child for child in out.rglob("*") if child.is_dir() and not child.is_symlink()
        )]:
            directory.chmod(directory.stat().st_mode | 0o700)
        return result
    result_path = result_paths[0]
    audit = _read_json(result_path / "audit.json")
    dependency_pack = _read_json(result_path / "dependency-pack.json")
    if (
        dependency_pack.get("format") != "stage-a-lean-root-dependency-pack-v1"
        or dependency_pack.get("node_count") != len(graph["nodes"]) - 1
        or not isinstance(dependency_pack.get("archive_bytes"), int)
        or dependency_pack["archive_bytes"] <= 0
        or not isinstance(dependency_pack.get("archive_sha256"), str)
        or not re.fullmatch(r"[0-9a-f]{64}", dependency_pack["archive_sha256"])
    ):
        raise StageAInputError("Nix relational graph emitted invalid dependency-pack provenance")
    node_provenance_payload = _read_json(result_path / "node-provenance.json")
    node_provenance = node_provenance_payload.get("nodes")
    if (
        node_provenance_payload.get("format") != "stage-a-lean-node-provenance-v1"
        or not isinstance(node_provenance, list)
        or not all(isinstance(node, dict) for node in node_provenance)
    ):
        raise StageAInputError("Nix relational graph omitted node content provenance")
    expected_nodes = {node["id"]: node for node in graph["nodes"]}
    observed_nodes = {node.get("id"): node for node in node_provenance}
    if set(observed_nodes) != set(expected_nodes) or len(observed_nodes) != len(node_provenance):
        raise StageAInputError("Nix relational node provenance does not match the prepared graph")
    for node_id, expected_node in expected_nodes.items():
        observed_node = observed_nodes[node_id]
        if observed_node.get("source_sha256") != expected_node["source_sha256"]:
            raise StageAInputError(f"Nix node source provenance mismatch for {node_id}")
        outputs = observed_node.get("outputs")
        if not isinstance(outputs, list) or {
            output.get("module") for output in outputs if isinstance(output, dict)
        } != set(expected_node["modules"]):
            raise StageAInputError(f"Nix node output inventory mismatch for {node_id}")
        if not all(
            isinstance(output, dict)
            and isinstance(output.get("olean_bytes"), int)
            and output["olean_bytes"] > 0
            and isinstance(output.get("olean_sha256"), str)
            and re.fullmatch(r"[0-9a-f]{64}", output["olean_sha256"])
            for output in outputs
        ):
            raise StageAInputError(f"Nix node output hash is invalid for {node_id}")
    path_info_process = subprocess.run(
        ["nix", "path-info", "--json", str(result_path)],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if path_info_process.returncode != 0:
        raise StageAInputError(
            "cannot query Nix proof provenance:\n" + path_info_process.stderr[-4000:]
        )
    try:
        path_info = json.loads(path_info_process.stdout)
    except json.JSONDecodeError as exc:
        raise StageAInputError("Nix returned malformed path provenance") from exc

    prepared_proof_ir = _read_json(prepared / "relational-proof-ir.json")
    RelationalProofIR.parse(prepared_proof_ir)
    approved_axioms = set(graph["approved_axioms"])
    observed_axioms = audit.get("observed_axioms")
    theorem_checked = (
        audit.get("status") == "checked"
        and audit.get("lean_trust") == 0
        and audit.get("theorem") == graph["expected_final_theorem"]
        and isinstance(observed_axioms, list)
        and set(observed_axioms).issubset(approved_axioms)
    )
    proof_ir = _finalize_nix_proof_ir(
        prepared_proof_ir,
        theorem_checked=theorem_checked,
        theorem=graph["expected_final_theorem"],
        result_path=result_path,
    )
    RelationalProofIR.parse(proof_ir)
    checks = {
        "prepared_graph_valid": True,
        "nix_graph_built": audit.get("status") == "checked",
        "lean_trust_zero": audit.get("lean_trust") == 0,
        "final_theorem_matches": audit.get("theorem") == graph["expected_final_theorem"],
        "axioms_approved": isinstance(observed_axioms, list)
        and set(observed_axioms).issubset(approved_axioms),
        "proof_ir_satisfied": proof_ir["status"] == "satisfied",
        "contract_families_closed": all(
            family.get("status") in {"satisfied", "not_applicable"}
            for family in proof_ir.get("families", [])
        ),
        "original_artifact_matches": sha256_file(prepared / graph["artifacts"]["original"]["path"])
        == graph["artifacts"]["original"]["sha256"],
        "candidate_artifact_matches": sha256_file(prepared / graph["artifacts"]["candidate"]["path"])
        == graph["artifacts"]["candidate"]["sha256"],
    }
    status = "pass" if all(checks.values()) else "incomplete"
    _remove_relational_build_output(out)
    out.mkdir(parents=True)
    for name in RELATIONAL_PREPARED_REPORT_FILES:
        source = prepared / name
        if source.is_file():
            shutil.copyfile(source, out / name)
    shutil.copytree(prepared / "artifacts", out / "artifacts")
    shutil.copytree(prepared / "lean", out / "lean")
    shutil.copyfile(result_path / "audit.json", out / "lean-audit.json")
    shutil.copyfile(result_path / "lean.stdout", out / "lean.stdout")
    shutil.copyfile(result_path / "lean.stderr", out / "lean.stderr")
    shutil.copyfile(result_path / "dependency-pack.json", out / "dependency-pack.json")
    write_json(out / "relational-proof-ir.json", proof_ir)
    report_manifest = _read_json(out / "prepared-proof.json")
    report_manifest["proof_ir_sha256"] = sha256_file(
        out / "relational-proof-ir.json"
    )
    write_json(out / "prepared-proof.json", report_manifest)
    provenance = {
        "format": "stage-a-relational-nix-provenance-v1",
        "executor": executor,
        "flake": str(flake_root),
        "builders_file": str(Path(builders_file).resolve()) if builders_file is not None else None,
        "local_derivation_builds": builders_file is None,
        "flake_lock_sha256": sha256_file(flake_root / "flake.lock"),
        "evaluator_sha256": sha256_file(evaluator),
        "result_path": str(result_path),
        "nodes": node_provenance,
        "dependency_pack": dependency_pack,
        "nix_path_info": path_info,
        "elapsed_seconds": elapsed,
    }
    write_json(out / "nix-provenance.json", provenance)
    result = {
        "format": "stage-a-relational-nix-build-v1",
        "status": status,
        "verdict": status,
        "profile": STAGE_A_RELATIONAL_PROFILE_ID,
        "model": STAGE_A_RELATIONAL_MODEL_ID,
        "claim_scope": {
            "kind": "whole_program_observational_equivalence",
            "whole_program_observational_equivalence": status == "pass",
            "acceptance_eligible": status == "pass",
        },
        "expected_final_theorem": graph["expected_final_theorem"],
        "acceptance": graph["acceptance"],
        "original": {
            "path": graph["artifacts"]["original"]["path"],
            "sha256": graph["artifacts"]["original"]["sha256"],
        },
        "candidate": {
            "path": graph["artifacts"]["candidate"]["path"],
            "sha256": graph["artifacts"]["candidate"]["sha256"],
        },
        "interface_manifest_sha256": sha256_file(
            out / "stage-a-interface-manifest.json"
        ),
        "relation_contract_sha256": sha256_file(out / "relation-contract.json"),
        "proof_ir_sha256": sha256_file(out / "relational-proof-ir.json"),
        "static_word_relations_sha256": sha256_file(
            out / "relational-static-word-relations.json"
        ),
        "product_graph_sha256": sha256_file(out / "relational-product-graph.json"),
        "whole_program_acceptance_sha256": sha256_file(
            out / "whole-program-acceptance.json"
        ),
        "composition_progress_sha256": sha256_file(
            out / "composition-progress.json"
        ),
        "module_graph_sha256": sha256_file(out / "module-graph.json"),
        "trusted_base_sha256": sha256_file(out / "trusted-base.json"),
        "checks": checks,
        "lean_audit": audit,
        "counts": graph["counts"],
        "elapsed_seconds": elapsed,
        "provenance": {
            "result_path": str(result_path),
            "nix_paths": len(path_info),
            "node_derivations": len(node_provenance),
            "dependency_pack_bytes": dependency_pack["archive_bytes"],
        },
    }
    write_json(out / "verdict.json", result)
    return result


def _finalize_proof_ir(
    proof_ir: dict[str, Any],
    *,
    theorem_checked: bool,
    theorem: str,
    evidence: dict[str, Any],
) -> dict[str, Any]:
    acceptance_theorem_checked = (
        theorem_checked and theorem == RELATIONAL_ACCEPTANCE_THEOREM
    )
    invariant_evidence = {
        **evidence,
        "kind": "lean_checked_inductive_invariant_family",
    }
    finalized_obligations = []
    for obligation in proof_ir["obligations"]:
        if obligation["kind"] == "relational_region_equivalence":
            finalized_obligations.append({
                **obligation,
                "status": "proved" if acceptance_theorem_checked else "incomplete",
                "evidence": evidence if acceptance_theorem_checked else None,
            })
        elif (
            acceptance_theorem_checked
            and obligation["kind"] in {
                "product_graph_composition",
                "whole_program_observational_equivalence",
                "cfg_register_relation_preservation",
                "relational_product_graph_structure",
                "relational_product_graph_declared_edge_refinement",
                "relational_product_graph_decoded_exit_completeness",
                "relational_product_graph_reachable_local_refinement",
            }
        ):
            finalized_obligations.append({
                **obligation,
                "status": "proved",
                "blocker": None,
                "evidence": {
                    **evidence,
                    "kind": "lean_checked_whole_program_composition",
                    "theorem": RELATIONAL_ACCEPTANCE_THEOREM,
                },
            })
        elif (
            acceptance_theorem_checked
            and obligation["kind"] in {
                "cfg_bound_invariant", "cfg_address_separation_invariant",
            }
            and obligation.get("analysis", {}).get("status")
                == "candidate_requires_lean_replay"
        ):
            finalized_obligations.append({
                **obligation,
                "status": "proved",
                "evidence": invariant_evidence,
            })
        elif (
            acceptance_theorem_checked
            and obligation["kind"] == "mapped_relocation_image_relation"
        ):
            finalized_obligations.append({
                **obligation,
                "status": "proved",
                "evidence": {
                    **evidence,
                    "kind": "lean_checked_mapped_relocation_image_relation",
                    "lemma": (
                        "StageA.Relational."
                        "allMappedRelocationImageRelations_of_valueRegionsClosed"
                    ),
                },
            })
        elif acceptance_theorem_checked and obligation["kind"] == "static_proof_context":
            finalized_obligations.append({
                **obligation,
                "status": "proved",
                "evidence": {
                    **evidence,
                    "kind": "lean_checked_static_proof_context",
                    "theorem": "StageA.GeneratedRelational.staticProofContextChecked",
                },
            })
        elif (
            acceptance_theorem_checked
            and obligation["kind"] == "iat_memory_relation_override"
        ):
            finalized_obligations.append({
                **obligation,
                "status": "proved",
                "evidence": {
                    **evidence,
                    "kind": "lean_checked_iat_masked_memory_relation",
                    "lemma": "StageA.Relational.StateRel.ordinaryMemoryRelation",
                },
            })
        elif (
            acceptance_theorem_checked
            and obligation["kind"] == "memory_transition_preservation"
            and obligation.get("analysis", {}).get("status")
                == "candidate_requires_lean_replay"
        ):
            finalized_obligations.append({
                **obligation,
                "status": "proved",
                "evidence": {
                    **evidence,
                    "kind": "lean_checked_exact_memory_pullback_transition",
                    "lemma": (
                        "StageA.Relational.InvariantWP."
                        "memoryObservationTransitionClosed_of_exact_pullback_pairs"
                    ),
                },
            })
        elif (
            acceptance_theorem_checked
            and obligation["kind"] == "external_call_product_edge_refinement"
            and obligation.get("status") == "pending_lean"
        ):
            edge_id = int(obligation["edge_id"])
            finalized_obligations.append({
                **obligation,
                "status": "proved",
                "blocker": None,
                "evidence": {
                    **evidence,
                    "kind": "lean_checked_paired_external_call_refinement",
                    "theorem": (
                        "StageA.GeneratedRelational."
                        f"externalCallEdge{edge_id}ProductRefinementChecked"
                    ),
                },
            })
        else:
            finalized_obligations.append(obligation)
    assumption_obligations = [
        obligation for obligation in finalized_obligations
        if obligation["kind"] != "relational_region_equivalence"
        and obligation.get("status") != "proved"
    ]
    external_obligations = [
        obligation for obligation in finalized_obligations
        if obligation["kind"] == "external_call_product_edge_refinement"
    ]
    external_assumptions = [
        obligation for obligation in assumption_obligations
        if obligation["kind"] == "external_call_product_edge_refinement"
    ]
    finalized = dict(proof_ir)
    finalized["status"] = (
        "satisfied"
        if acceptance_theorem_checked and not assumption_obligations
        else "incomplete"
    )
    finalized["families"] = [
        {"family": "exact_pe_decode", "status": "satisfied" if acceptance_theorem_checked else "incomplete"},
        {"family": "x86_semantics", "status": "satisfied" if acceptance_theorem_checked else "incomplete"},
        {"family": "executable_coverage", "status": "satisfied" if acceptance_theorem_checked else "incomplete"},
        {"family": "roots_and_targets", "status": "satisfied" if acceptance_theorem_checked else "incomplete"},
        {"family": "static_proof_context", "status": "satisfied" if acceptance_theorem_checked else "incomplete"},
        {"family": "relational_regions", "status": "satisfied" if acceptance_theorem_checked else "incomplete"},
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
            "status": "satisfied" if acceptance_theorem_checked else "incomplete",
        },
        {
            "family": "cfg_invariants",
            "status": "incomplete" if any(
                obligation["kind"] in {
                    "cfg_bound_invariant", "cfg_address_separation_invariant",
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
                "incomplete" if external_assumptions else
                "satisfied" if external_obligations else
                "not_applicable"
            ),
        },
        {
            "family": "adversarial_environment",
            "status": "incomplete" if external_assumptions else "satisfied",
        },
    ]
    finalized["obligations"] = finalized_obligations
    return finalized


def _finalize_nix_proof_ir(
    proof_ir: dict[str, Any],
    *,
    theorem_checked: bool,
    theorem: str,
    result_path: Path,
) -> dict[str, Any]:
    return _finalize_proof_ir(
        proof_ir,
        theorem_checked=theorem_checked,
        theorem=theorem,
        evidence={
            "kind": "lean_trust_zero_nix_graph",
            "theorem": theorem,
            "lean_trust": 0,
            "nix_result_path": str(result_path),
        },
    )


def _finalize_local_proof_ir(
    proof_ir: dict[str, Any],
    *,
    theorem_checked: bool,
    theorem: str,
) -> dict[str, Any]:
    return _finalize_proof_ir(
        proof_ir,
        theorem_checked=theorem_checked,
        theorem=theorem,
        evidence={
            "kind": "lean_kernel_checked_local_graph",
            "theorem": theorem,
            "lean_trust": 0,
        },
    )


def _check_nix_relational_report(
    *, report: Path, verdict: dict[str, Any], out: Path | None
) -> dict[str, Any]:
    checks: dict[str, bool] = {
        "report_pass": verdict.get("verdict") == "pass",
        "profile_matches": verdict.get("profile") == STAGE_A_RELATIONAL_PROFILE_ID,
        "model_matches": verdict.get("model") == STAGE_A_RELATIONAL_MODEL_ID,
        "claim_scope_acceptance_eligible": (
            verdict.get("claim_scope", {}).get("acceptance_eligible") is True
            and verdict.get("claim_scope", {}).get(
                "whole_program_observational_equivalence"
            ) is True
        ),
    }
    audit: dict[str, Any] = {}
    if checks["report_pass"]:
        try:
            graph = _validate_prepared_relational(report)
            proof_ir = _read_json(report / "relational-proof-ir.json")
            acceptance = _read_json(report / "whole-program-acceptance.json")
            composition_progress = _read_json(report / "composition-progress.json")
            RelationalProofIR.parse(proof_ir)
            WholeProgramAcceptanceIR.parse(acceptance)
            CompositionProgressIR.parse(composition_progress)
            audit = _read_json(report / "lean-audit.json")
            provenance = _read_json(report / "nix-provenance.json")
            dependency_pack = _read_json(report / "dependency-pack.json")
            trusted_base = _read_json(report / "trusted-base.json")
        except StageAInputError:
            checks["prepared_report_valid"] = False
        else:
            checks["prepared_report_valid"] = True
            checks.update({
                "acceptance_ready": (
                    acceptance.get("status") == "ready"
                    and acceptance.get("theorem") == RELATIONAL_ACCEPTANCE_THEOREM
                    and graph.get("expected_final_theorem")
                        == RELATIONAL_ACCEPTANCE_THEOREM
                    and verdict.get("expected_final_theorem")
                        == RELATIONAL_ACCEPTANCE_THEOREM
                    and verdict.get("acceptance") == acceptance
                ),
                "lean_trust_zero": audit.get("lean_trust") == 0,
                "final_theorem_matches": (
                    audit.get("status") == "checked"
                    and audit.get("theorem") == RELATIONAL_ACCEPTANCE_THEOREM
                ),
                "axioms_approved": (
                    isinstance(audit.get("observed_axioms"), list)
                    and set(audit["observed_axioms"]).issubset(
                        set(graph.get("approved_axioms", []))
                    )
                    and audit.get("unexpected_axioms") == []
                ),
                "proof_ir_satisfied": proof_ir.get("status") == "satisfied",
                "contract_families_closed": all(
                    family.get("status") in {"satisfied", "not_applicable"}
                    for family in proof_ir.get("families", [])
                ),
                "proof_ir_hash_matches": (
                    sha256_file(report / "relational-proof-ir.json")
                    == verdict.get("proof_ir_sha256")
                ),
                "contract_hash_matches": (
                    sha256_file(report / "relation-contract.json")
                    == verdict.get("relation_contract_sha256")
                ),
                "product_graph_hash_matches": (
                    sha256_file(report / "relational-product-graph.json")
                    == verdict.get("product_graph_sha256")
                ),
                "acceptance_hash_matches": (
                    sha256_file(report / "whole-program-acceptance.json")
                    == verdict.get("whole_program_acceptance_sha256")
                ),
                "composition_progress_hash_matches": (
                    sha256_file(report / "composition-progress.json")
                    == verdict.get("composition_progress_sha256")
                ),
                "composition_ready": (
                    composition_progress.get("status") == "ready_for_lean"
                    and composition_progress.get("acceptance", {}).get("theorem")
                        == RELATIONAL_ACCEPTANCE_THEOREM
                ),
                "module_graph_hash_matches": (
                    sha256_file(report / "module-graph.json")
                    == verdict.get("module_graph_sha256")
                ),
                "trusted_base_hash_matches": (
                    sha256_file(report / "trusted-base.json")
                    == verdict.get("trusted_base_sha256")
                ),
                "original_matches": (
                    sha256_file(report / graph["artifacts"]["original"]["path"])
                    == graph["artifacts"]["original"]["sha256"]
                    == proof_ir.get("original", {}).get("sha256")
                ),
                "candidate_matches": (
                    sha256_file(report / graph["artifacts"]["candidate"]["path"])
                    == graph["artifacts"]["candidate"]["sha256"]
                    == proof_ir.get("candidate", {}).get("sha256")
                ),
                "kernel_matches": all(
                    sha256_file(
                        _LEAN_SOURCE_ROOT / f"{module}.lean"
                    ) == sha256_file(report / "lean" / "StageA" / f"{module}.lean")
                    for module in RELATIONAL_KERNEL_MODULES
                ),
            })
            expected_nodes = {node["id"]: node for node in graph["nodes"]}
            observed_rows = provenance.get("nodes")
            observed_nodes = {
                row.get("id"): row
                for row in observed_rows or []
                if isinstance(row, dict)
            }
            checks["nix_node_provenance_matches"] = (
                provenance.get("format") == "stage-a-relational-nix-provenance-v1"
                and isinstance(observed_rows, list)
                and len(observed_rows) == len(observed_nodes)
                and set(observed_nodes) == set(expected_nodes)
                and all(
                    observed_nodes[node_id].get("source_sha256")
                        == expected["source_sha256"]
                    and {
                        output.get("module")
                        for output in observed_nodes[node_id].get("outputs", [])
                        if isinstance(output, dict)
                    } == set(expected["modules"])
                    for node_id, expected in expected_nodes.items()
                )
            )
            checks["dependency_pack_provenance_matches"] = (
                dependency_pack.get("format")
                    == "stage-a-lean-root-dependency-pack-v1"
                and provenance.get("dependency_pack") == dependency_pack
                and dependency_pack.get("node_count") == len(graph["nodes"]) - 1
            )
            checks["declared_build_checks_hold"] = all(
                value is True for value in verdict.get("checks", {}).values()
            )
            checks["trusted_base_matches_graph"] = (
                trusted_base.get("approved_axioms") == graph.get("approved_axioms")
            )
    status = "pass" if checks and all(checks.values()) else "incomplete"
    result = {
        "format": "stage-a-relational-proof-check-v1",
        "status": status,
        "profile": STAGE_A_RELATIONAL_PROFILE_ID,
        "claim_scope": {
            "kind": "whole_program_observational_equivalence",
            "whole_program_observational_equivalence": status == "pass",
        },
        "checks": checks,
        "lean_check": audit,
    }
    if out is not None:
        write_json(Path(out), result)
    return result


def _load_contract(path: Path) -> dict[str, Any]:
    payload = _read_json(path)
    if payload.get("format") != RELATION_CONTRACT_FORMAT:
        raise StageAInputError(f"relation contract format must be {RELATION_CONTRACT_FORMAT}")
    return payload


def _read_json(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise StageAInputError(f"cannot read {path}: {exc}") from exc
    if not isinstance(payload, dict):
        raise StageAInputError(f"{path} must contain a JSON object")
    return payload


def _write_relational_module_graph(
    prepared: Path,
    *,
    original_bin: StageABinary,
    candidate_bin: StageABinary,
    trusted_base: dict[str, Any],
) -> dict[str, Any]:
    stage_a = prepared / "lean" / "StageA"
    sources = {path.stem: path for path in stage_a.glob("*.lean")}
    acceptance_path = prepared / "whole-program-acceptance.json"
    acceptance = _read_json(acceptance_path) if acceptance_path.is_file() else {
        "format": "stage-a-whole-program-acceptance-v1",
        "status": "incomplete",
        "required_theorem": RELATIONAL_ACCEPTANCE_THEOREM,
        "theorem": None,
        "profile": None,
        "blockers": [{
            "code": "whole_program_certificate_missing",
            "message": "no whole-program acceptance analysis was generated",
            "next_action": "regenerate the relational proof graph",
        }],
    }
    if acceptance.get("format") != "stage-a-whole-program-acceptance-v1":
        raise StageAInputError("prepared proof has an invalid whole-program acceptance artifact")
    acceptance_ready = acceptance.get("status") == "ready"
    root = "RelationalAcceptance" if acceptance_ready else "RelationalBundle"
    if root not in sources:
        raise StageAInputError(f"prepared proof is missing StageA.{root}")

    import_pattern = re.compile(r"^import StageA\.([A-Za-z0-9_]+)$", re.MULTILINE)
    imports = {
        module: import_pattern.findall(path.read_text(encoding="utf-8"))
        for module, path in sources.items()
    }
    reachable: set[str] = set()
    visiting: set[str] = set()

    def visit(module: str) -> None:
        if module in reachable:
            return
        if module in visiting:
            raise StageAInputError(f"generated Lean module graph contains a cycle at {module}")
        path = sources.get(module)
        if path is None:
            raise StageAInputError(f"generated Lean import StageA.{module} has no source")
        visiting.add(module)
        for dependency in imports[module]:
            visit(dependency)
        visiting.remove(module)
        reachable.add(module)

    visit(root)
    logical_modules = {
        module: {
            "source": f"lean/StageA/{module}.lean",
            "source_sha256": sha256_file(sources[module]),
            "imports": imports[module],
            "source_bytes": sources[module].stat().st_size,
        }
        for module in sorted(reachable)
    }

    def numbered(prefix: str) -> list[str]:
        return sorted(
            (module for module in reachable if module.startswith(prefix)),
            key=lambda module: int(module.removeprefix(prefix)),
        )

    pack_size = max(
        1, int(os.environ.get("SPAGHETTI_EXTRACTOR_STAGE_A_RELATIONAL_NIX_PACK_MODULES", "16"))
    )
    static_usage_pack_size = max(
        1,
        int(
            os.environ.get(
                "SPAGHETTI_EXTRACTOR_STAGE_A_RELATIONAL_STATIC_USAGE_NIX_PACK_MODULES", "4"
            )
        ),
    )
    packed: set[str] = set()
    raw_nodes: list[dict[str, Any]] = []
    for prefix, label, node_pack_size in (
        ("RelationalDefinitionsShard", "definitions-pack", pack_size),
        ("RelationalProofShard", "local-proof-pack", pack_size),
        (
            "RelationalProofStaticUsageLeaf",
            "static-usage-pack",
            static_usage_pack_size,
        ),
    ):
        modules = numbered(prefix)
        for pack_index, offset in enumerate(
            range(0, len(modules), node_pack_size)
        ):
            members = modules[offset : offset + node_pack_size]
            packed.update(members)
            raw_nodes.append({"id": f"{label}-{pack_index:03d}", "modules": members})
    for module in sorted(reachable - packed):
        node_id = re.sub(r"[^a-z0-9]+", "-", module.lower()).strip("-")
        raw_nodes.append({"id": node_id, "modules": [module]})

    module_node = {
        module: node["id"]
        for node in raw_nodes
        for module in node["modules"]
    }
    if len(module_node) != len(reachable):
        raise StageAInputError("generated build packs do not assign every Lean module exactly once")

    def resource_class(modules: list[str]) -> tuple[str, int]:
        names = " ".join(modules)
        source_bytes = sum(logical_modules[module]["source_bytes"] for module in modules)
        if any(
            module in (
                "RelationalProofOriginalCoverageData",
                "RelationalProofCandidateCoverageData",
            )
            for module in modules
        ):
            return "high-memory", max(12288, source_bytes // 1024 * 3)
        if any(
            module.startswith("RelationalProofStaticUsageLeaf")
            or module in (
                "RelationalProofStaticUsageCertificate",
                "RelationalProofClosureData",
            )
            for module in modules
        ):
            return "high-memory", max(6144, source_bytes // 1024 * 3)
        if any(
            module.startswith("RelationalProofRegionIndexChunk")
            or module.startswith("RelationalProofStaticUsageChunk")
            or module in (
                "RelationalProofRegionIndexData",
                "RelationalProofRegionInventoryData",
                "RelationalProofPaddingData",
                "RelationalProofRequiredInputsData",
            )
            for module in modules
        ):
            return "medium", max(2048, source_bytes // 1024 * 2)
        if "RelationalStaticContext" in modules:
            return "high-memory", max(4096, source_bytes // 1024 * 3)
        if any(module.startswith("RelationalStaticCodeMapChunk") for module in modules):
            # The generated source is small, but reducing indexed lookups through a
            # jq-sized imported map dominates the Lean process's resident set.
            return "high-memory", max(4096, source_bytes // 1024 * 3)
        if any(
            module.startswith(prefix)
            for module in modules
            for prefix in (
                "RelationalAcceptanceChunk",
                "RelationalProductGraphChunk",
                "RelationalDynamicRangeIndirectCallChunk",
                "RelationalDynamicCallFanout",
                "RelationalProductDecodedControlChunk",
                "RelationalProductReachabilityChunk",
                "RelationalProductEdgeRefinementChunk",
                "RelationalProductNodeCoverageChunk",
                "RelationalReachableProduct",
            )
        ):
            # Each checker reduces indexed lookups through the full imported jq
            # graph. Six GiB is conservative for the bounded 16-entry chunks.
            return "high-memory", max(6144, source_bytes // 1024 * 3)
        if "DecodeChunk" in names or "StructuralPadding" in names or "StructuralCoverage" in names:
            return "high-memory", max(4096, source_bytes // 1024 * 3)
        if "RelationalProofOriginal" in names or "RelationalProofCandidate" in names:
            return "high-memory", max(16384, source_bytes // 1024 * 3)
        if "DirectChunk" in names or any(
            module.startswith("RelationalProofShard") for module in modules
        ):
            return "medium", max(1536, source_bytes // 1024 * 2)
        if source_bytes >= 512 * 1024:
            return "medium", max(1536, source_bytes // 1024 * 2)
        return "light", max(512, source_bytes // 1024 + 256)

    nodes: list[dict[str, Any]] = []
    for raw in raw_nodes:
        packed_modules = set(raw["modules"])
        internal_dependencies = sorted({
            (module, dependency)
            for module in raw["modules"]
            for dependency in logical_modules[module]["imports"]
            if dependency in packed_modules
        })
        if internal_dependencies:
            raise StageAInputError(
                f"generated build pack {raw['id']} contains internal imports "
                f"{internal_dependencies!r}"
            )
        dependencies = sorted({
            module_node[dependency]
            for module in raw["modules"]
            for dependency in logical_modules[module]["imports"]
            if module_node[dependency] != raw["id"]
        })
        classification, estimated_memory_mb = resource_class(raw["modules"])
        nodes.append({
            "id": raw["id"],
            "modules": raw["modules"],
            "dependencies": dependencies,
            "resource_class": classification,
            "estimated_memory_mb": estimated_memory_mb,
            "source_sha256": sha256_bytes("".join(
                logical_modules[module]["source_sha256"] for module in raw["modules"]
            ).encode("ascii")),
        })

    lean_version = None
    lean_githash = None
    lean = shutil.which("lean")
    if lean is not None:
        lean_version = subprocess.run(
            [lean, "--version"], text=True, stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT, check=False,
        ).stdout.strip()
        lean_githash = subprocess.run(
            [lean, "--githash"], text=True, stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT, check=False,
        ).stdout.strip()
    graph = {
        "format": "stage-a-lean-module-graph-v1",
        "profile": STAGE_A_RELATIONAL_PROFILE_ID,
        "model": STAGE_A_RELATIONAL_MODEL_ID,
        "root_module": root,
        "final_node": module_node[root],
        "expected_final_theorem": (
            RELATIONAL_ACCEPTANCE_THEOREM if acceptance_ready else None
        ),
        "acceptance": acceptance,
        "approved_axioms": trusted_base["approved_axioms"],
        "lean": {"version": lean_version, "githash": lean_githash, "trust": 0},
        "artifacts": {
            "original": {"path": "artifacts/original.pe", "sha256": original_bin.sha256},
            "candidate": {"path": "artifacts/candidate.pe", "sha256": candidate_bin.sha256},
        },
        "modules": logical_modules,
        "nodes": sorted(nodes, key=lambda node: node["id"]),
        "counts": {
            "logical_modules": len(logical_modules),
            "derivations": len(nodes),
            "definition_modules": len(numbered("RelationalDefinitionsShard")),
            "local_proof_modules": len(numbered("RelationalProofShard")),
            "decode_modules": sum("DecodeChunk" in module for module in logical_modules),
            "direct_modules": sum("DirectChunk" in module for module in logical_modules),
            "structural_modules": sum(module.startswith("RelationalProofStructural") for module in logical_modules),
        },
    }
    write_json(prepared / "module-graph.json", graph)
    _validate_relational_module_graph(prepared, graph)
    return graph


def _validate_relational_module_graph(
    prepared: Path, graph: dict[str, Any] | None = None
) -> dict[str, Any]:
    prepared = Path(prepared)
    graph = graph or _read_json(prepared / "module-graph.json")
    try:
        typed_graph = ModuleGraph.parse(graph)
    except SchemaError as exc:
        raise StageAInputError(f"malformed prepared Lean module graph: {exc}") from exc
    if graph.get("format") != "stage-a-lean-module-graph-v1":
        raise StageAInputError("unsupported prepared Lean module graph format")
    if typed_graph.root_module != graph.get("root_module"):
        raise StageAInputError("prepared Lean module graph has an invalid root module")
    modules = graph.get("modules")
    nodes = graph.get("nodes")
    if not isinstance(modules, dict) or not modules or not isinstance(nodes, list) or not nodes:
        raise StageAInputError("prepared Lean module graph is empty or malformed")
    assigned: dict[str, str] = {}
    node_by_id: dict[str, dict[str, Any]] = {}
    import_pattern = re.compile(r"^import StageA\.([A-Za-z0-9_]+)$", re.MULTILINE)
    for module, metadata in modules.items():
        if not re.fullmatch(r"[A-Za-z0-9_]+", module) or not isinstance(metadata, dict):
            raise StageAInputError(f"invalid generated Lean module name {module!r}")
        relative = metadata.get("source")
        if relative != f"lean/StageA/{module}.lean":
            raise StageAInputError(f"module {module} has a noncanonical source path")
        source = prepared / relative
        if not source.is_file() or sha256_file(source) != metadata.get("source_sha256"):
            raise StageAInputError(f"module {module} source hash does not match")
        observed_imports = import_pattern.findall(source.read_text(encoding="utf-8"))
        if observed_imports != metadata.get("imports"):
            raise StageAInputError(f"module {module} import inventory does not match source")
        if any(dependency not in modules for dependency in observed_imports):
            raise StageAInputError(f"module {module} imports an undeclared StageA module")
    for node in nodes:
        if not isinstance(node, dict) or not isinstance(node.get("id"), str):
            raise StageAInputError("malformed Lean graph node")
        node_id = node["id"]
        if node_id in node_by_id:
            raise StageAInputError(f"duplicate Lean graph node {node_id}")
        node_by_id[node_id] = node
        for module in node.get("modules", []):
            if module not in modules or module in assigned:
                raise StageAInputError(f"module {module} has an invalid or duplicate build assignment")
            assigned[module] = node_id
    if set(assigned) != set(modules):
        raise StageAInputError("not every Lean module is assigned to a build node")
    for node_id, node in node_by_id.items():
        module_positions = {module: index for index, module in enumerate(node["modules"])}
        for module in node["modules"]:
            for dependency in modules[module]["imports"]:
                if assigned[dependency] == node_id and module_positions[dependency] >= module_positions[module]:
                    raise StageAInputError(
                        f"node {node_id} does not order internal import {dependency} before {module}"
                    )
        expected = sorted({
            assigned[dependency]
            for module in node["modules"]
            for dependency in modules[module]["imports"]
            if assigned[dependency] != node_id
        })
        if node.get("dependencies") != expected:
            raise StageAInputError(f"node {node_id} dependency inventory does not match imports")
    visiting: set[str] = set()
    visited: set[str] = set()
    def visit_node(node_id: str) -> None:
        if node_id in visited:
            return
        if node_id in visiting:
            raise StageAInputError(f"Lean build graph contains a cycle at {node_id}")
        if node_id not in node_by_id:
            raise StageAInputError(f"Lean build graph references missing node {node_id}")
        visiting.add(node_id)
        for dependency in node_by_id[node_id]["dependencies"]:
            visit_node(dependency)
        visiting.remove(node_id)
        visited.add(node_id)
    visit_node(str(graph.get("final_node")))
    if visited != set(node_by_id):
        raise StageAInputError("Lean graph contains nodes outside the final theorem closure")
    acceptance = graph.get("acceptance")
    if not isinstance(acceptance, dict):
        raise StageAInputError("prepared Lean graph omits its acceptance state")
    acceptance_status = acceptance.get("status")
    theorem = graph.get("expected_final_theorem")
    if acceptance.get("required_theorem") != RELATIONAL_ACCEPTANCE_THEOREM:
        raise StageAInputError("prepared Lean graph names the wrong acceptance theorem")
    if acceptance_status == "ready":
        if (
            theorem != RELATIONAL_ACCEPTANCE_THEOREM
            or acceptance.get("theorem") != theorem
        ):
            raise StageAInputError(
                "acceptance-ready Lean graph does not name the closed whole-program theorem"
            )
    elif acceptance_status == "incomplete":
        if theorem is not None or acceptance.get("theorem") is not None:
            raise StageAInputError(
                "incomplete Lean graph must not advertise an acceptance theorem"
            )
        blockers = acceptance.get("blockers")
        if not isinstance(blockers, list) or not blockers:
            raise StageAInputError("incomplete Lean graph omits acceptance blockers")
    else:
        raise StageAInputError("prepared Lean graph has an invalid acceptance state")
    approved_axioms = graph.get("approved_axioms")
    if not isinstance(approved_axioms, list) or not all(
        isinstance(axiom, str) and re.fullmatch(r"[A-Za-z0-9_.]+", axiom)
        for axiom in approved_axioms
    ):
        raise StageAInputError("prepared Lean graph has an invalid approved-axiom inventory")
    return graph


def _validate_prepared_relational(prepared: Path) -> dict[str, Any]:
    manifest = _read_json(prepared / "prepared-proof.json")
    try:
        PreparedProofDigests.parse(manifest)
    except SchemaError as exc:
        raise StageAInputError(f"malformed prepared relational proof: {exc}") from exc
    if manifest.get("format") != "stage-a-prepared-relational-v1":
        raise StageAInputError("unsupported prepared relational proof format")
    if manifest.get("status") != "prepared":
        raise StageAInputError("relational proof preparation did not complete")
    try:
        StageAInterfaceManifest.parse(
            _read_json(prepared / "stage-a-interface-manifest.json")
        )
    except SchemaError as exc:
        raise StageAInputError(f"malformed Stage A interface manifest: {exc}") from exc
    graph = _validate_relational_module_graph(prepared)
    expected_hashes = {
        "interface_manifest_sha256": prepared / "stage-a-interface-manifest.json",
        "relation_contract_sha256": prepared / "relation-contract.json",
        "proof_ir_sha256": prepared / "relational-proof-ir.json",
        "semantic_ir_sha256": prepared / "relational-semantic-ir.json",
        "memory_contracts_sha256": prepared / "relational-memory-contracts.json",
        "static_word_relations_sha256": (
            prepared / "relational-static-word-relations.json"
        ),
        "register_relations_sha256": prepared / "relational-register-relations.json",
        "stack_windows_sha256": prepared / "relational-stack-windows.json",
        "segment_diagnostics_sha256": (
            prepared / "relational-segment-diagnostics.json"
        ),
        "product_graph_sha256": prepared / "relational-product-graph.json",
        "invariants_sha256": prepared / "relational-invariants.json",
        "whole_program_acceptance_sha256": (
            prepared / "whole-program-acceptance.json"
        ),
        "composition_progress_sha256": prepared / "composition-progress.json",
        "module_graph_sha256": prepared / "module-graph.json",
    }
    for field, path in expected_hashes.items():
        if not path.is_file() or manifest.get(field) != sha256_file(path):
            raise StageAInputError(f"prepared relational proof hash mismatch for {path.name}")
    if manifest.get("expected_final_theorem") != graph.get("expected_final_theorem"):
        raise StageAInputError("prepared relational theorem inventory does not match its graph")
    if manifest.get("acceptance") != graph.get("acceptance"):
        raise StageAInputError("prepared relational acceptance state does not match its graph")
    composition_progress = _read_json(prepared / "composition-progress.json")
    if (
        composition_progress.get("format") != "stage-a-composition-progress-v1"
        or composition_progress.get("trust", {}).get("acceptance_authority") is not False
    ):
        raise StageAInputError("prepared relational composition progress is malformed")
    if manifest.get("composition_progress") != composition_progress:
        raise StageAInputError(
            "prepared relational composition progress does not match its manifest"
        )
    if manifest.get("approved_axioms") != graph.get("approved_axioms"):
        raise StageAInputError("prepared relational axiom inventory does not match its graph")
    if manifest.get("original_sha256") != graph["artifacts"]["original"]["sha256"]:
        raise StageAInputError("prepared original artifact inventory does not match its graph")
    if manifest.get("candidate_sha256") != graph["artifacts"]["candidate"]["sha256"]:
        raise StageAInputError("prepared candidate artifact inventory does not match its graph")
    for artifact in graph["artifacts"].values():
        path = prepared / artifact["path"]
        if not path.is_file() or sha256_file(path) != artifact["sha256"]:
            raise StageAInputError(f"prepared artifact hash mismatch for {artifact['path']}")
    if any(prepared.rglob("*.olean")):
        raise StageAInputError("prepared relational proof must not contain prebuilt Lean objects")
    return graph


def _relational_nix_evaluator() -> Path:
    candidates = [
        Path(__file__).resolve().parents[3] / "nix" / "stage-a-lean-graph.nix",
        Path(__file__).with_name("nix") / "stage-a-lean-graph.nix",
        *(
            parent / "share" / "spaghetti-extractor" / "nix" / "stage-a-lean-graph.nix"
            for parent in Path(__file__).resolve().parents
        ),
    ]
    for candidate in candidates:
        if candidate.is_file():
            return candidate.resolve()
    raise StageAInputError("cannot locate nix/stage-a-lean-graph.nix")


def _find_relational_flake_root(explicit: Path | None) -> Path:
    if explicit is not None:
        root = Path(explicit).resolve()
        if not (root / "flake.nix").is_file() or not (root / "flake.lock").is_file():
            raise StageAInputError(f"{root} is not a locked Nix flake")
        return root
    starts = [Path.cwd().resolve(), Path(__file__).resolve()]
    for start in starts:
        for parent in (start, *start.parents):
            if (parent / "flake.nix").is_file() and (parent / "flake.lock").is_file():
                return parent
    raise StageAInputError("cannot locate the project flake; pass --flake")


def _locked_flake_input(lock_path: Path, input_name: str) -> dict[str, Any]:
    lock = _read_json(lock_path)
    nodes = lock.get("nodes")
    root_name = lock.get("root")
    if not isinstance(nodes, dict) or root_name not in nodes:
        raise StageAInputError(f"{lock_path} has no valid flake-lock node graph")
    root_inputs = nodes[root_name].get("inputs", {})
    node_name = root_inputs.get(input_name) if isinstance(root_inputs, dict) else None
    if not isinstance(node_name, str) or node_name not in nodes:
        raise StageAInputError(f"{lock_path} does not lock the {input_name} input directly")
    locked = nodes[node_name].get("locked")
    if not isinstance(locked, dict):
        raise StageAInputError(f"{lock_path} has no locked source for {input_name}")
    required = {"type", "narHash"}
    if not required.issubset(locked) or not all(
        isinstance(key, str) and isinstance(value, (str, int, bool))
        for key, value in locked.items()
    ):
        raise StageAInputError(f"{lock_path} contains an unsupported lock record for {input_name}")
    return locked
