from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Any

from ...stage_binary import StageABinary, StageAInputError
from ...util import sha256_bytes, write_json
from ..analyses.external import (
    _external_call_site_candidates,
    _semantic_external_target_identity,
)
from ..analyses.stack import _stack_window_transfer_claims
from ..artifacts import write_text_if_changed as _write_text_if_changed
from ..contract import _raw_base_relocations
from ..model import _semantic_hash
from ..schema import (
    FLAG_BITS,
    RELATIONAL_ACCEPTANCE_THEOREM,
    RELATIONAL_KERNEL_MODULES,
)


_LEAN_SOURCE_ROOT = Path(__file__).resolve().parents[2] / "lean" / "StageA"
from .common import (
    _lean_bool,
)
from .expressions import (
    _lean_dynamic_range_relation,
    _lean_external_target,
    _lean_import_register_seed_claim,
    _lean_register_offset_write,
    _lean_semantic_bool_expr,
    _lean_stack_address_separation_claim,
)
from .definitions import (
    _lean_static_range,
    _static_index_ranges,
)


def _write_reachable_product_local_certificate(
    lean_dir: Path,
    product_graph: dict[str, Any],
    segment_candidates: list[dict[str, Any]],
    external_call_refinement_modules: list[dict[str, Any]],
) -> None:
    evidence = product_graph["evidence"]
    decoded_control_ids = set(evidence["decoded_control_complete_node_ids"])
    decoded_node_ids = [
        int(node_id) for node_id in evidence["declared_reachable_node_ids"]
        if node_id in decoded_control_ids
    ]
    refined_edge_ids = [
        int(edge_id) for edge_id in evidence["reachable_locally_refined_edge_ids"]
    ]
    internal_edge_ids = set(int(edge_id) for edge_id in evidence["proved_edge_ids"])
    external_by_edge = {
        int(item["edge_id"]): item for item in external_call_refinement_modules
    }
    proof_chunk_size = max(
        1, int(os.environ.get("SPAGHETTI_EXTRACTOR_STAGE_A_PRODUCT_PROOF_CHUNK", "16"))
    )
    decoded_by_node: dict[int, tuple[dict[str, Any], str]] = {}
    decoded_candidates = evidence["decoded_control_candidates"]
    for chunk_index, offset in enumerate(
        range(0, len(decoded_candidates), proof_chunk_size)
    ):
        module = f"RelationalProductDecodedControlChunk{chunk_index}"
        for candidate in decoded_candidates[offset : offset + proof_chunk_size]:
            decoded_by_node[int(candidate["node_id"])] = (candidate, module)
    internal_by_edge: dict[int, tuple[dict[str, Any], str]] = {}
    for chunk_index, offset in enumerate(
        range(0, len(segment_candidates), proof_chunk_size)
    ):
        module = f"RelationalProductEdgeRefinementChunk{chunk_index}"
        for candidate in segment_candidates[offset : offset + proof_chunk_size]:
            internal_by_edge[int(candidate["edge_index"])] = (candidate, module)
    missing_external_modules = [
        edge_id for edge_id in refined_edge_ids
        if edge_id not in internal_edge_ids and edge_id not in external_by_edge
    ]
    if missing_external_modules:
        raise StageAInputError(
            "reachable local evidence lacks generated external refinement modules for "
            + ", ".join(str(edge_id) for edge_id in missing_external_modules)
        )

    def listed_proof(witnesses: list[str]) -> str:
        return (
            "".join(f"And.intro ({witness}) (" for witness in witnesses)
            + "True.intro"
            + ")" * len(witnesses)
        )

    complete = bool(evidence["reachable_product_local_complete"])
    decoded_rows = ", ".join(str(node_id) for node_id in decoded_node_ids)
    refined_rows = ", ".join(str(edge_id) for edge_id in refined_edge_ids)
    evidence_source = (
        "import StageA.RelationalEnvironment\n"
        "\n"
        "namespace StageA.GeneratedRelational\n\n"
        "open StageA.Formal StageA.Relational\n\n"
        "set_option maxRecDepth 1000000\nset_option maxHeartbeats 0\n\n"
        "def relationalProductLocalEvidence : RelationalProductLocalEvidence := {\n"
        f"  decodedNodeIds := [{decoded_rows}]\n"
        f"  refinedEdgeIds := [{refined_rows}]\n"
        "}\n\n"
        "theorem relationalProductLocalDecodedNodeIdsIncreasingChecked :\n"
        "    strictlyIncreasingNats\n"
        "      relationalProductLocalEvidence.decodedNodeIds = true := by decide\n\n"
        "theorem relationalProductLocalRefinedEdgeIdsIncreasingChecked :\n"
        "    strictlyIncreasingNats\n"
        "      relationalProductLocalEvidence.refinedEdgeIds = true := by decide\n\n"
        "end StageA.GeneratedRelational\n"
    )
    _write_text_if_changed(
        lean_dir / "StageA" / "RelationalReachableProductLocalEvidence.lean",
        evidence_source,
    )

    local_chunk_size = max(
        1,
        int(os.environ.get("SPAGHETTI_EXTRACTOR_STAGE_A_REACHABLE_PRODUCT_LOCAL_CHUNK", "8")),
    )
    node_chunks: list[dict[str, str]] = []
    for chunk_index, offset in enumerate(
        range(0, len(decoded_node_ids), local_chunk_size)
    ):
        selected_ids = decoded_node_ids[offset : offset + local_chunk_size]
        module = f"RelationalReachableProductNodeChunk{chunk_index}"
        ids_name = f"reachableProductNodeChunk{chunk_index}Ids"
        theorem_name = f"reachableProductNodeChunk{chunk_index}Checked"
        validity_theorem_name = (
            f"reachableProductNodeChunk{chunk_index}ValidityChecked"
        )
        imports: set[str] = set()
        witnesses: list[str] = []
        for node_id in selected_ids:
            candidate, decoded_module = decoded_by_node[node_id]
            imports.add(decoded_module)
            region_index = int(candidate["region_index"])
            witnesses.append(
                f"⟨region{region_index}, originalBehavior{region_index}, "
                f"candidateBehavior{region_index}, "
                f"productNode{node_id}DecodedControlEdgesComplete⟩"
            )
        validity_proof = listed_proof([
            "⟨by decide, by decide⟩" for _ in selected_ids
        ])
        chunk_source = (
            "import StageA.RelationalReachableProductLocalEvidence\n"
            + "".join(f"import StageA.{item}\n" for item in sorted(imports))
            + "\nnamespace StageA.GeneratedRelational\n\n"
            "open StageA.Formal StageA.Relational\n\n"
            "set_option maxRecDepth 1000000\nset_option maxHeartbeats 0\n\n"
            f"def {ids_name} : List Nat := ["
            + ", ".join(str(node_id) for node_id in selected_ids)
            + "]\n\n"
            f"theorem {validity_theorem_name} :\n"
            "    AllListedReachableProductNodes relationalProductGraph\n"
            f"      relationalProductReachabilityEvidence {ids_name} := by\n"
            f"  exact {validity_proof}\n\n"
            f"theorem {theorem_name} :\n"
            "    AllListedDecodedControlNodesComplete relationalProductGraph\n"
            f"      staticProofContext {ids_name} := by\n"
            f"  exact {listed_proof(witnesses)}\n\n"
            "end StageA.GeneratedRelational\n"
        )
        _write_text_if_changed(lean_dir / "StageA" / f"{module}.lean", chunk_source)
        node_chunks.append({
            "module": module,
            "ids": ids_name,
            "theorem": theorem_name,
            "validity_theorem": validity_theorem_name,
        })

    edge_chunks: list[dict[str, str]] = []
    for chunk_index, offset in enumerate(
        range(0, len(refined_edge_ids), local_chunk_size)
    ):
        selected_ids = refined_edge_ids[offset : offset + local_chunk_size]
        module = f"RelationalReachableProductEdgeChunk{chunk_index}"
        ids_name = f"reachableProductEdgeChunk{chunk_index}Ids"
        theorem_name = f"reachableProductEdgeChunk{chunk_index}Checked"
        validity_theorem_name = (
            f"reachableProductEdgeChunk{chunk_index}ValidityChecked"
        )
        imports: set[str] = set()
        witnesses: list[str] = []
        for edge_id in selected_ids:
            if edge_id in internal_edge_ids:
                candidate, internal_module = internal_by_edge[edge_id]
                imports.add(internal_module)
                source_index = int(candidate["source_region_index"])
                target_index = int(candidate["target_region_index"])
                witnesses.append(
                    f"Or.inl ⟨segmentRefinementEdge{edge_id}Spec, "
                    f"region{source_index}.inputInvariant, "
                    f"region{target_index}.inputInvariant, "
                    f"productEdge{edge_id}Refined⟩"
                )
                continue
            item = external_by_edge[edge_id]
            imports.add(str(item["module"]))
            source_index = int(item["source_region_index"])
            witnesses.append(
                f"Or.inr ⟨externalCallSite{edge_id}, "
                f"externalCallEdge{edge_id}Spec, region{source_index}.inputInvariant, "
                f"by decide, {item['theorem']}⟩"
            )
        validity_proof = listed_proof(["by decide" for _ in selected_ids])
        chunk_source = (
            "import StageA.RelationalReachableProductLocalEvidence\n"
            + "".join(f"import StageA.{item}\n" for item in sorted(imports))
            + "\nnamespace StageA.GeneratedRelational\n\n"
            "open StageA.Formal StageA.Relational\n\n"
            "set_option maxRecDepth 1000000\nset_option maxHeartbeats 0\n\n"
            f"def {ids_name} : List Nat := ["
            + ", ".join(str(edge_id) for edge_id in selected_ids)
            + "]\n\n"
            f"theorem {validity_theorem_name} :\n"
            "    AllListedReachableFeasibleProductEdges relationalProductGraph\n"
            f"      relationalProductReachabilityEvidence {ids_name} := by\n"
            f"  exact {validity_proof}\n\n"
            f"theorem {theorem_name} :\n"
            "    AllListedProductEdgesLocallyRefined staticProofContext\n"
            f"      relationalProductGraph {ids_name} := by\n"
            f"  exact {listed_proof(witnesses)}\n\n"
            "end StageA.GeneratedRelational\n"
        )
        _write_text_if_changed(lean_dir / "StageA" / f"{module}.lean", chunk_source)
        edge_chunks.append({
            "module": module,
            "ids": ids_name,
            "theorem": theorem_name,
            "validity_theorem": validity_theorem_name,
        })

    def append_proof(
        chunks: list[dict[str, str]], theorem: str, arguments: str,
        proof_key: str = "theorem",
    ) -> str:
        if not chunks:
            return "True.intro"
        proof = chunks[-1][proof_key]
        ids = chunks[-1]["ids"]
        for chunk in reversed(chunks[:-1]):
            proof = (
                f"{theorem} {arguments} {chunk['ids']} ({ids}) "
                f"{chunk[proof_key]} ({proof})"
            )
            ids = f"{chunk['ids']} ++ ({ids})"
        return proof

    node_simp_arguments = ", ".join([
        "relationalProductLocalEvidence",
        *(item["ids"] for item in node_chunks),
    ])
    node_certificate_source = (
        "import StageA.RelationalReachableProductLocalEvidence\n"
        + "".join(f"import StageA.{item['module']}\n" for item in node_chunks)
        + "\nnamespace StageA.GeneratedRelational\n\n"
        "open StageA.Formal StageA.Relational\n\n"
        "set_option maxRecDepth 1000000\nset_option maxHeartbeats 0\n\n"
        "theorem allReachableListedProductNodesValidChecked :\n"
        "    AllListedReachableProductNodes relationalProductGraph\n"
        "      relationalProductReachabilityEvidence\n"
        "      relationalProductLocalEvidence.decodedNodeIds := by\n"
        f"  simpa [{node_simp_arguments}] using\n    ("
        + append_proof(
            node_chunks,
            "allListedReachableProductNodes_append",
            "relationalProductGraph relationalProductReachabilityEvidence",
            "validity_theorem",
        )
        + ")\n\n"
        "theorem allReachableListedDecodedControlNodesCompleteChecked :\n"
        "    AllListedDecodedControlNodesComplete relationalProductGraph\n"
        "      staticProofContext relationalProductLocalEvidence.decodedNodeIds := by\n"
        f"  simpa [{node_simp_arguments}] using\n    ("
        + append_proof(
            node_chunks,
            "allListedDecodedControlNodesComplete_append",
            "relationalProductGraph staticProofContext",
        )
        + ")\n\nend StageA.GeneratedRelational\n"
    )
    _write_text_if_changed(
        lean_dir / "StageA" / "RelationalReachableProductNodeCertificate.lean",
        node_certificate_source,
    )

    edge_simp_arguments = ", ".join([
        "relationalProductLocalEvidence",
        *(item["ids"] for item in edge_chunks),
    ])
    edge_certificate_source = (
        "import StageA.RelationalReachableProductLocalEvidence\n"
        + "".join(f"import StageA.{item['module']}\n" for item in edge_chunks)
        + "\nnamespace StageA.GeneratedRelational\n\n"
        "open StageA.Formal StageA.Relational\n\n"
        "set_option maxRecDepth 1000000\nset_option maxHeartbeats 0\n\n"
        "theorem allReachableListedProductEdgesValidChecked :\n"
        "    AllListedReachableFeasibleProductEdges relationalProductGraph\n"
        "      relationalProductReachabilityEvidence\n"
        "      relationalProductLocalEvidence.refinedEdgeIds := by\n"
        f"  simpa [{edge_simp_arguments}] using\n    ("
        + append_proof(
            edge_chunks,
            "allListedReachableFeasibleProductEdges_append",
            "relationalProductGraph relationalProductReachabilityEvidence",
            "validity_theorem",
        )
        + ")\n\n"
        "theorem allReachableListedProductEdgesLocallyRefinedChecked :\n"
        "    AllListedProductEdgesLocallyRefined staticProofContext\n"
        "      relationalProductGraph relationalProductLocalEvidence.refinedEdgeIds := by\n"
        f"  simpa [{edge_simp_arguments}] using\n    ("
        + append_proof(
            edge_chunks,
            "allListedProductEdgesLocallyRefined_append",
            "staticProofContext relationalProductGraph",
        )
        + ")\n\nend StageA.GeneratedRelational\n"
    )
    _write_text_if_changed(
        lean_dir / "StageA" / "RelationalReachableProductEdgeCertificate.lean",
        edge_certificate_source,
    )

    complete_certificate = ""
    if complete:
        complete_certificate = (
            "\ntheorem relationalProductLocalEvidenceCompleteChecked :\n"
            "    relationalProductLocalEvidence.complete relationalProductGraph\n"
            "      relationalProductReachabilityEvidence = true := by decide\n\n"
            "def reachableProductLocalCertificate :\n"
            "    ReachableProductLocalCertificate staticProofContext\n"
            "      relationalProductGraph relationalProductReachabilityEvidence := {\n"
            "  staticContextValid := staticProofContextChecked\n"
            "  reachabilitySound := "
            "generatedDeclaredGraphReachabilityCertificateChecked\n"
            "  reachableControlComplete :=\n"
            "    reachableProductNodesDecodedControlComplete_of_complete_evidence\n"
            "      staticProofContext relationalProductGraph\n"
            "      relationalProductReachabilityEvidence relationalProductLocalEvidence\n"
            "      relationalProductLocalEvidenceCompleteChecked\n"
            "      allReachableListedDecodedControlNodesCompleteChecked\n"
            "  reachableEdgesRefined :=\n"
            "    reachableProductEdgesLocallyRefined_of_complete_evidence\n"
            "      staticProofContext relationalProductGraph\n"
            "      relationalProductReachabilityEvidence relationalProductLocalEvidence\n"
            "      relationalProductLocalEvidenceCompleteChecked\n"
            "      allReachableListedProductEdgesLocallyRefinedChecked\n"
            "}\n"
        )

    source = (
        "import StageA.RelationalReachableProductLocalEvidence\n"
        "import StageA.RelationalReachableProductNodeCertificate\n"
        "import StageA.RelationalReachableProductEdgeCertificate\n"
        + (
            "import StageA.RelationalProductReachabilityCertificate\n"
            if complete else ""
        )
        + "\nnamespace StageA.GeneratedRelational\n\n"
        "open StageA.Formal StageA.Relational\n\n"
        "set_option maxRecDepth 1000000\nset_option maxHeartbeats 0\n\n"
        "def GeneratedPartialReachableProductLocalCertificate : Prop :=\n"
        "  PartialReachableProductLocalCertificate staticProofContext\n"
        "    relationalProductGraph relationalProductReachabilityEvidence\n"
        "    relationalProductLocalEvidence\n\n"
        "theorem generatedPartialReachableProductLocalCertificateChecked :\n"
        "    GeneratedPartialReachableProductLocalCertificate := {\n"
        "  decodedNodeIdsIncreasing :=\n"
        "    relationalProductLocalDecodedNodeIdsIncreasingChecked\n"
        "  decodedNodeIdsValid := allReachableListedProductNodesValidChecked\n"
        "  refinedEdgeIdsIncreasing :=\n"
        "    relationalProductLocalRefinedEdgeIdsIncreasingChecked\n"
        "  refinedEdgeIdsValid := allReachableListedProductEdgesValidChecked\n"
        "  decodedControlComplete :=\n"
        "    allReachableListedDecodedControlNodesCompleteChecked\n"
        "  edgesLocallyRefined :=\n"
        "    allReachableListedProductEdgesLocallyRefinedChecked\n"
        "}\n"
        + complete_certificate
        + "\nend StageA.GeneratedRelational\n"
    )
    _write_text_if_changed(
        lean_dir / "StageA" / "RelationalReachableProductLocalCertificate.lean",
        source,
    )

def _write_relational_product_graph_modules(
    lean_dir: Path,
    product_graph: dict[str, Any],
    segment_candidates: list[dict[str, Any]],
    segment_refinement_modules: list[dict[str, Any]],
    decode_chunk_regions: list[list[int]],
) -> list[str]:
    nodes = product_graph["nodes"]
    edges = product_graph["edges"]
    evidence = product_graph["evidence"]
    node_rows = ",\n    ".join(
        "{ "
        f"id := {node['id']}, targetId := {node['target_id']}, "
        f"root := {_lean_bool(bool(node['root']))}, outgoingEdgeIds := ["
        + ", ".join(str(edge_id) for edge_id in node["outgoing_edge_ids"])
        + "] }"
        for node in nodes
    )
    edge_rows = ",\n    ".join(
        "{ "
        f"id := {edge['id']}, sourceNodeId := {edge['source_node_id']}, "
        f"targetNodeId := {edge['target_node_id']}, "
        f"sourceTargetId := {edge['source_target_id']}, "
        f"targetTargetId := {edge['target_target_id']}, kind := .{edge['kind']}, "
        f"originalGuard := {_lean_semantic_bool_expr(edge['original_guard'])}, "
        f"candidateGuard := {_lean_semantic_bool_expr(edge['candidate_guard'])}, "
        f"infeasible := {_lean_bool(bool(edge['infeasible']))} }}"
        for edge in edges
    )
    roots = ", ".join(str(node_id) for node_id in product_graph["root_node_ids"])
    proved = ", ".join(str(edge_id) for edge_id in evidence["proved_edge_ids"])
    covered = ", ".join(str(node_id) for node_id in evidence["covered_node_ids"])
    reachable = ", ".join(
        _lean_bool(bool(value)) for value in evidence["declared_reachable_bits"]
    )
    decoded_control_complete = ", ".join(
        str(node_id) for node_id in evidence["decoded_control_complete_node_ids"]
    )
    context_source = (
        "import StageA.RelationalComposition\n"
        "import StageA.RelationalStaticContext\n\n"
        "namespace StageA.GeneratedRelational\n\n"
        "open StageA.Formal StageA.Relational\n\n"
        "set_option maxRecDepth 1000000\nset_option maxHeartbeats 0\n\n"
        "def relationalProductGraph : RelationalProductGraph := {\n"
        f"  nodes := #[\n    {node_rows}\n  ]\n"
        f"  edges := #[\n    {edge_rows}\n  ]\n"
        f"  rootNodeIds := [{roots}]\n"
        "}\n\n"
        "def relationalProductEvidence : RelationalProductEvidence := {\n"
        f"  provedEdgeIds := [{proved}]\n"
        "}\n\n"
        "def relationalProductCoverageEvidence : RelationalProductCoverageEvidence := {\n"
        f"  coveredNodeIds := [{covered}]\n"
        "}\n\n"
        "def relationalProductReachabilityEvidence : "
        "RelationalProductReachabilityEvidence := {\n"
        f"  reachable := #[{reachable}]\n"
        "}\n\n"
        "def relationalDecodedControlEvidence : RelationalDecodedControlEvidence := {\n"
        f"  completeNodeIds := [{decoded_control_complete}]\n"
        "}\n\n"
        "end StageA.GeneratedRelational\n"
    )
    _write_text_if_changed(
        lean_dir / "StageA" / "RelationalProductGraphContext.lean",
        context_source,
    )

    chunk_size = max(
        1, int(os.environ.get("SPAGHETTI_EXTRACTOR_STAGE_A_PRODUCT_GRAPH_CHUNK", "16"))
    )
    node_ranges = _static_index_ranges(len(nodes), chunk_size)
    edge_ranges = _static_index_ranges(len(edges), chunk_size)
    chunk_count = max(len(node_ranges), len(edge_ranges))
    modules: list[str] = []
    node_claims: list[tuple[str, str]] = []
    edge_claims: list[tuple[str, str]] = []
    for chunk_index in range(chunk_count):
        module = f"RelationalProductGraphChunk{chunk_index}"
        modules.append(module)
        definitions: list[str] = []
        if chunk_index < len(node_ranges):
            start, size = node_ranges[chunk_index]
            range_name = f"productNodeRange{chunk_index}"
            theorem_name = f"productNodeRange{chunk_index}Checked"
            definitions.extend([
                _lean_static_range(range_name, start, size),
                (
                    f"theorem {theorem_name} :\n"
                    "    IndexedBoolRangeHolds "
                    "(relationalProductGraph.nodeAtValid staticProofContext) "
                    f"{range_name} :=\n"
                    "  indexedBoolRangeHolds_of_checked "
                    "(relationalProductGraph.nodeAtValid staticProofContext) "
                    f"{range_name} (by decide)"
                ),
            ])
            node_claims.append((range_name, theorem_name))
        if chunk_index < len(edge_ranges):
            start, size = edge_ranges[chunk_index]
            range_name = f"productEdgeRange{chunk_index}"
            theorem_name = f"productEdgeRange{chunk_index}Checked"
            definitions.extend([
                _lean_static_range(range_name, start, size),
                (
                    f"theorem {theorem_name} :\n"
                    "    IndexedBoolRangeHolds relationalProductGraph.edgeAtValid "
                    f"{range_name} :=\n"
                    "  indexedBoolRangeHolds_of_checked "
                    f"relationalProductGraph.edgeAtValid {range_name} (by decide)"
                ),
            ])
            edge_claims.append((range_name, theorem_name))
        source = (
            "import StageA.RelationalProductGraphContext\n\n"
            "namespace StageA.GeneratedRelational\n\n"
            "open StageA.Formal StageA.Relational\n\n"
            "set_option maxRecDepth 1000000\nset_option maxHeartbeats 0\n\n"
            + "\n\n".join(definitions)
            + "\n\nend StageA.GeneratedRelational\n"
        )
        _write_text_if_changed(lean_dir / "StageA" / f"{module}.lean", source)

    def range_certificate_source(
        family: str,
        claims: list[tuple[str, str]],
        predicate: str,
        size: int,
    ) -> str:
        ranges = ", ".join(name for name, _ in claims)
        proof = (
            "".join(f"And.intro {theorem} (" for _, theorem in claims)
            + "True.intro"
            + ")" * len(claims)
        )
        lower = family[0].lower() + family[1:]
        return (
            f"def product{family}Certificate : IndexedBoolCertificate := "
            f"{{ ranges := [{ranges}] }}\n\n"
            f"theorem product{family}Checked :\n"
            f"    product{family}Certificate.Holds {predicate} {size} :=\n"
            "  IndexedBoolCertificate.holds_of_ranges "
            f"{predicate} {size} product{family}Certificate (by decide)\n"
            f"    ({proof})\n\n"
        )

    aggregate_imports = "\n".join(f"import StageA.{module}" for module in modules)
    complete = bool(evidence["complete"])
    candidate_by_edge = {
        int(candidate["edge_index"]): candidate for candidate in segment_candidates
    }
    certificate_source = (
        aggregate_imports
        + "\n\nnamespace StageA.GeneratedRelational\n\n"
        "open StageA.Formal StageA.Relational\n\n"
        "set_option maxRecDepth 1000000\nset_option maxHeartbeats 0\n\n"
        + range_certificate_source(
            "Nodes", node_claims,
            "(relationalProductGraph.nodeAtValid staticProofContext)", len(nodes),
        )
        + range_certificate_source(
            "Edges", edge_claims, "relationalProductGraph.edgeAtValid", len(edges),
        )
        + "theorem relationalProductGraphRootsChecked :\n"
        "    relationalProductGraph.rootsValid staticProofContext = true := by decide\n\n"
        "theorem relationalProductGraphIndexedValidChecked :\n"
        "    relationalProductGraph.IndexedValid staticProofContext :=\n"
        "  ⟨productNodesChecked, productEdgesChecked, relationalProductGraphRootsChecked⟩\n\n"
        "theorem relationalProductEvidenceValidChecked :\n"
        "    relationalProductEvidence.valid relationalProductGraph = true := by decide\n\n"
        "theorem relationalProductCoverageEvidenceValidChecked :\n"
        "    relationalProductCoverageEvidence.valid relationalProductGraph = true := by decide\n\n"
        f"theorem relationalProductEvidenceCompletenessChecked :\n"
        f"    relationalProductEvidence.complete relationalProductGraph = "
        f"{_lean_bool(complete)} := by decide\n"
        + "\n\nend StageA.GeneratedRelational\n"
    )
    _write_text_if_changed(
        lean_dir / "StageA" / "RelationalProductGraphCertificate.lean",
        certificate_source,
    )

    proof_chunk_size = max(
        1, int(os.environ.get("SPAGHETTI_EXTRACTOR_STAGE_A_PRODUCT_PROOF_CHUNK", "16"))
    )
    decode_chunk_by_region = {
        region_index: chunk_index
        for chunk_index, region_indices in enumerate(decode_chunk_regions)
        for region_index in region_indices
    }
    import_seed_candidates = evidence.get("import_register_seed_candidates", [])
    import_seed_modules: list[dict[str, str]] = []
    seeds_by_decode_chunk: dict[int, list[tuple[int, dict[str, Any]]]] = {}
    for seed_index, candidate in enumerate(import_seed_candidates):
        seeds_by_decode_chunk.setdefault(
            decode_chunk_by_region[int(candidate["region_index"])], []
        ).append((seed_index, candidate))
    for module_index, (decode_chunk_index, selected) in enumerate(
        sorted(seeds_by_decode_chunk.items())
    ):
        module = f"RelationalImportRegisterSeedChunk{module_index}"
        claims_name = f"importRegisterSeedChunk{module_index}Claims"
        checked_name = f"importRegisterSeedChunk{module_index}Checked"
        definitions: list[str] = []
        theorem_names: list[str] = []
        for seed_index, candidate in selected:
            region_index = int(candidate["region_index"])
            original_normalized = f"importSeed{seed_index}OriginalNormalized"
            candidate_normalized = f"importSeed{seed_index}CandidateNormalized"
            claim_name = f"importSeed{seed_index}Claim"
            proposition_name = f"importSeed{seed_index}Proposition"
            theorem_name = f"importSeed{seed_index}Checked"
            theorem_names.append(theorem_name)
            definitions.extend([
                f"def {original_normalized} : NormalizedSymbolicBehavior :=\n"
                f"  (normalizeSymbolicBehavior false region{region_index}.targets "
                f"originalBehavior{region_index}).get (by decide)",
                f"def {candidate_normalized} : NormalizedSymbolicBehavior :=\n"
                f"  (normalizeSymbolicBehavior true region{region_index}.targets "
                f"candidateBehavior{region_index}).get (by decide)",
                f"def {claim_name} : ImportRegisterSeedClaim := "
                + _lean_import_register_seed_claim(candidate),
                f"def {proposition_name} : Prop :=\n"
                f"  ImportRegisterSeedClosed originalPe candidatePe "
                f"originalImports candidateImports "
                f"region{region_index}.inputInvariant {original_normalized} "
                f"{candidate_normalized} {claim_name}",
                f"theorem {theorem_name} : {proposition_name} :=\n"
                f"  importRegisterSeedClosed_of_checked originalPe candidatePe "
                f"originalImports candidateImports "
                f"region{region_index}.inputInvariant {original_normalized} "
                f"{candidate_normalized} {claim_name} (by decide)",
            ])
        proof = (
            "".join(f"And.intro {theorem} (" for theorem in theorem_names)
            + "True.intro"
            + ")" * len(theorem_names)
        )
        definitions.extend([
            f"def {claims_name} : List Prop := ["
            + ", ".join(
                f"importSeed{seed_index}Proposition"
                for seed_index, _candidate in selected
            )
            + "]",
            f"theorem {checked_name} : AllInvariantClaims {claims_name} := by\n"
            f"  exact {proof}",
        ])
        source = (
            "import StageA.RelationalComposition\n"
            f"import StageA.RelationalProofOriginalDecodeChunk{decode_chunk_index}\n"
            f"import StageA.RelationalProofCandidateDecodeChunk{decode_chunk_index}\n"
            + "\nnamespace StageA.GeneratedRelational\n\n"
            "open StageA.Formal StageA.Relational\n\n"
            "set_option maxRecDepth 1000000\nset_option maxHeartbeats 0\n\n"
            + "\n\n".join(definitions)
            + "\n\nend StageA.GeneratedRelational\n"
        )
        _write_text_if_changed(lean_dir / "StageA" / f"{module}.lean", source)
        import_seed_modules.append({
            "module": module, "claims": claims_name, "theorem": checked_name,
        })
    import_seed_certificate_type = " ∧ ".join(
        [f"AllInvariantClaims {item['claims']}" for item in import_seed_modules]
        + ["True"]
    )
    import_seed_certificate_proof = (
        "".join(f"And.intro {item['theorem']} (" for item in import_seed_modules)
        + "True.intro"
        + ")" * len(import_seed_modules)
    )
    import_seed_certificate_source = (
        "".join(f"import StageA.{item['module']}\n" for item in import_seed_modules)
        + "import StageA.RelationalProductGraphContext\n\n"
        "namespace StageA.GeneratedRelational\n\n"
        "open StageA.Formal StageA.Relational\n\n"
        f"def GeneratedImportRegisterSeedCertificate : Prop := "
        f"{import_seed_certificate_type}\n\n"
        "theorem generatedImportRegisterSeedCertificateChecked :\n"
        "    GeneratedImportRegisterSeedCertificate := by\n"
        f"  exact {import_seed_certificate_proof}\n\n"
        "end StageA.GeneratedRelational\n"
    )
    _write_text_if_changed(
        lean_dir / "StageA" / "RelationalImportRegisterSeedCertificate.lean",
        import_seed_certificate_source,
    )
    dynamic_call_candidates = evidence.get(
        "dynamic_range_indirect_call_candidates", []
    )
    dynamic_call_modules: list[dict[str, str]] = []
    dynamic_calls_by_decode_chunk: dict[int, list[tuple[int, dict[str, Any]]]] = {}
    for call_index, candidate in enumerate(dynamic_call_candidates):
        source_region_index = int(candidate["source_region_index"])
        dynamic_calls_by_decode_chunk.setdefault(
            decode_chunk_by_region[source_region_index], []
        ).append((call_index, candidate))
    for module_index, (decode_chunk_index, selected) in enumerate(
        sorted(dynamic_calls_by_decode_chunk.items())
    ):
        module = f"RelationalDynamicRangeIndirectCallChunk{module_index}"
        claims_name = f"dynamicRangeIndirectCallChunk{module_index}Claims"
        checked_name = f"dynamicRangeIndirectCallChunk{module_index}Checked"
        definitions: list[str] = []
        theorem_names: list[str] = []
        proposition_names: list[str] = []
        for call_index, candidate in selected:
            region_index = int(candidate["source_region_index"])
            original_normalized = f"dynamicCall{call_index}OriginalNormalized"
            candidate_normalized = f"dynamicCall{call_index}CandidateNormalized"
            claim_name = f"dynamicCall{call_index}Claim"
            proposition_name = f"dynamicCall{call_index}Proposition"
            theorem_name = f"dynamicCall{call_index}Checked"
            theorem_names.append(theorem_name)
            proposition_names.append(proposition_name)
            definitions.extend([
                f"def {original_normalized} : NormalizedSymbolicBehavior :=\n"
                f"  (normalizeSymbolicBehavior false region{region_index}.targets "
                f"originalBehavior{region_index}).get (by decide)",
                f"def {candidate_normalized} : NormalizedSymbolicBehavior :=\n"
                f"  (normalizeSymbolicBehavior true region{region_index}.targets "
                f"candidateBehavior{region_index}).get (by decide)",
                f"def {claim_name} : DynamicRangeIndirectCallClaim := {{\n"
                f"  rangeRelation := "
                f"{_lean_dynamic_range_relation(candidate['range_relation'])}\n"
                f"  wordOffset := {int(candidate['word_offset'])}\n"
                f"  continuationTargetId := "
                f"{int(candidate['continuation_target_id'])}\n"
                "}",
                f"def {proposition_name} : Prop :=\n"
                f"  DynamicRangeIndirectCallTargetsClosed "
                f"region{region_index}.inputInvariant {original_normalized} "
                f"{candidate_normalized} {claim_name}",
                f"theorem {theorem_name} : {proposition_name} :=\n"
                "  dynamicRangeIndirectCallTargetsClosed_of_checked "
                f"region{region_index}.inputInvariant {original_normalized} "
                f"{candidate_normalized} {claim_name} (by decide)",
            ])
        proof = (
            "".join(f"And.intro {theorem} (" for theorem in theorem_names)
            + "True.intro"
            + ")" * len(theorem_names)
        )
        definitions.extend([
            f"def {claims_name} : List Prop := ["
            + ", ".join(proposition_names)
            + "]",
            f"theorem {checked_name} : AllInvariantClaims {claims_name} := by\n"
            f"  exact {proof}",
        ])
        source = (
            "import StageA.RelationalComposition\n"
            f"import StageA.RelationalProofOriginalDecodeChunk{decode_chunk_index}\n"
            f"import StageA.RelationalProofCandidateDecodeChunk{decode_chunk_index}\n"
            + "\nnamespace StageA.GeneratedRelational\n\n"
            "open StageA.Formal StageA.Relational\n\n"
            "set_option maxRecDepth 1000000\nset_option maxHeartbeats 0\n\n"
            + "\n\n".join(definitions)
            + "\n\nend StageA.GeneratedRelational\n"
        )
        _write_text_if_changed(lean_dir / "StageA" / f"{module}.lean", source)
        dynamic_call_modules.append({
            "module": module,
            "claims": claims_name,
            "theorem": checked_name,
        })
    dynamic_call_certificate_type = " ∧ ".join(
        [f"AllInvariantClaims {item['claims']}" for item in dynamic_call_modules]
        + ["True"]
    )
    dynamic_call_certificate_proof = (
        "".join(
            f"And.intro {item['theorem']} (" for item in dynamic_call_modules
        )
        + "True.intro"
        + ")" * len(dynamic_call_modules)
    )
    dynamic_call_certificate_source = (
        "".join(f"import StageA.{item['module']}\n" for item in dynamic_call_modules)
        + "import StageA.RelationalComposition\n\n"
        "namespace StageA.GeneratedRelational\n\n"
        "open StageA.Formal StageA.Relational\n\n"
        f"def GeneratedDynamicRangeIndirectCallCertificate : Prop := "
        f"{dynamic_call_certificate_type}\n\n"
        "theorem generatedDynamicRangeIndirectCallCertificateChecked :\n"
        "    GeneratedDynamicRangeIndirectCallCertificate := by\n"
        f"  exact {dynamic_call_certificate_proof}\n\n"
        "end StageA.GeneratedRelational\n"
    )
    _write_text_if_changed(
        lean_dir / "StageA" / "RelationalDynamicRangeIndirectCallCertificate.lean",
        dynamic_call_certificate_source,
    )
    dynamic_fanout_by_source: dict[int, dict[str, str]] = {}
    dynamic_fanout_chunk_size = max(
        1, int(os.environ.get("SPAGHETTI_EXTRACTOR_STAGE_A_DYNAMIC_FANOUT_CHUNK", "32"))
    )
    for group in evidence.get("dynamic_range_indirect_call_edge_groups", []):
        source_node_id = int(group["source_node_id"])
        candidate_index = int(group["candidate_index"])
        candidate = dynamic_call_candidates[candidate_index]
        edge_ids = [int(edge_id) for edge_id in group["edge_ids"]]
        if not edge_ids:
            raise StageAInputError(
                f"dynamic indirect-call node {source_node_id} has an empty fanout"
            )
        first_edge_id = edge_ids[0]
        if edge_ids != list(range(first_edge_id, first_edge_id + len(edge_ids))):
            raise StageAInputError(
                f"dynamic indirect-call node {source_node_id} fanout is not contiguous"
            )
        claim_name = f"productDynamicCall{candidate_index}Claim"
        first_edge_name = f"productDynamicCall{candidate_index}FirstEdgeId"
        node_name = f"productDynamicCall{candidate_index}Node"
        node_resolved_name = f"productDynamicCall{candidate_index}NodeResolved"
        predicate = (
            "(dynamicRangeIndirectCallEdgeAtMatches relationalProductGraph "
            f"{source_node_id} staticProofContext {claim_name} {first_edge_name})"
        )
        context_module = f"RelationalDynamicCallFanoutContext{candidate_index}"
        context_source = (
            "import StageA.RelationalProductGraphContext\n\n"
            "namespace StageA.GeneratedRelational\n\n"
            "open StageA.Formal StageA.Relational\n\n"
            "set_option maxRecDepth 1000000\nset_option maxHeartbeats 0\n\n"
            f"def {claim_name} : DynamicRangeIndirectCallClaim := {{\n"
            f"  rangeRelation := "
            f"{_lean_dynamic_range_relation(candidate['range_relation'])}\n"
            f"  wordOffset := {int(candidate['word_offset'])}\n"
            f"  continuationTargetId := "
            f"{int(candidate['continuation_target_id'])}\n"
            "}\n\n"
            f"def {first_edge_name} : Nat := {first_edge_id}\n\n"
            "end StageA.GeneratedRelational\n"
        )
        _write_text_if_changed(
            lean_dir / "StageA" / f"{context_module}.lean", context_source
        )
        range_claims: list[tuple[str, str]] = []
        range_modules: list[str] = []
        for range_index, (start, size) in enumerate(
            _static_index_ranges(len(edge_ids), dynamic_fanout_chunk_size)
        ):
            module = (
                f"RelationalDynamicCallFanout{candidate_index}Range{range_index}"
            )
            range_modules.append(module)
            range_name = f"productDynamicCall{candidate_index}Range{range_index}"
            theorem_name = f"{range_name}Checked"
            range_source = (
                f"import StageA.{context_module}\n\n"
                "namespace StageA.GeneratedRelational\n\n"
                "open StageA.Formal StageA.Relational\n\n"
                "set_option maxRecDepth 1000000\nset_option maxHeartbeats 0\n\n"
                + _lean_static_range(range_name, start, size)
                + "\n\n"
                f"theorem {theorem_name} :\n"
                f"    IndexedBoolRangeHolds {predicate} {range_name} :=\n"
                f"  indexedBoolRangeHolds_of_checked {predicate} {range_name} "
                "(by decide)\n\n"
                "end StageA.GeneratedRelational\n"
            )
            _write_text_if_changed(
                lean_dir / "StageA" / f"{module}.lean", range_source
            )
            range_claims.append((range_name, theorem_name))
        certificate_module = (
            f"RelationalDynamicCallFanoutCertificate{candidate_index}"
        )
        certificate_name = f"productDynamicCall{candidate_index}EdgeCertificate"
        holds_name = f"productDynamicCall{candidate_index}EdgesChecked"
        match_name = f"productDynamicCall{candidate_index}EdgesMatch"
        ranges = ", ".join(name for name, _ in range_claims)
        range_proof = (
            "".join(f"And.intro {theorem} (" for _, theorem in range_claims)
            + "True.intro"
            + ")" * len(range_claims)
        )
        certificate_source = (
            "".join(f"import StageA.{module}\n" for module in range_modules)
            + f"import StageA.{context_module}\n\n"
            "namespace StageA.GeneratedRelational\n\n"
            "open StageA.Formal StageA.Relational\n\n"
            "set_option maxRecDepth 1000000\nset_option maxHeartbeats 0\n\n"
            f"def {node_name} : RelationalProductNode :=\n"
            f"  (relationalProductGraph.getNode? {source_node_id}).get (by decide)\n\n"
            f"theorem {node_resolved_name} :\n"
            f"    relationalProductGraph.getNode? {source_node_id} = some {node_name} :=\n"
            "  (Option.some_get (x := relationalProductGraph.getNode? "
            f"{source_node_id}) (by decide)).symm\n\n"
            f"def {certificate_name} : IndexedBoolCertificate := "
            f"{{ ranges := [{ranges}] }}\n\n"
            f"theorem {holds_name} :\n"
            f"    {certificate_name}.Holds {predicate} {len(edge_ids)} :=\n"
            "  IndexedBoolCertificate.holds_of_ranges "
            f"{predicate} {len(edge_ids)} {certificate_name} (by decide)\n"
            f"    ({range_proof})\n\n"
            f"theorem {match_name} :\n"
            "    DynamicRangeIndirectCallEdgesMatch relationalProductGraph "
            f"{source_node_id} staticProofContext {claim_name} "
            f"{first_edge_name} := by\n"
            "  unfold DynamicRangeIndirectCallEdgesMatch\n"
            f"  rw [{node_resolved_name}]\n"
            f"  exact ⟨by decide, {holds_name}⟩\n\n"
            "end StageA.GeneratedRelational\n"
        )
        _write_text_if_changed(
            lean_dir / "StageA" / f"{certificate_module}.lean",
            certificate_source,
        )
        dynamic_fanout_by_source[source_node_id] = {
            "module": certificate_module,
            "claim": claim_name,
            "first_edge": first_edge_name,
            "match": match_name,
        }
    decoded_control_candidates = evidence["decoded_control_candidates"]
    decoded_control_modules: list[str] = []
    for chunk_index, offset in enumerate(
        range(0, len(decoded_control_candidates), proof_chunk_size)
    ):
        selected = decoded_control_candidates[offset : offset + proof_chunk_size]
        module = f"RelationalProductDecodedControlChunk{chunk_index}"
        decoded_control_modules.append(module)
        definitions: list[str] = []
        extra_imports: set[str] = set()
        imported_decode_chunks = sorted({
            decode_chunk_by_region[int(candidate["region_index"])]
            for candidate in selected
        })
        for candidate in selected:
            node_id = int(candidate["node_id"])
            region_index = int(candidate["region_index"])
            theorem_name = f"productNode{node_id}DecodedControlEdgesComplete"
            if candidate.get("profile") == "immutable_relocated_function_pointer_call_v1":
                original_normalized = f"productNode{node_id}OriginalNormalized"
                candidate_normalized = f"productNode{node_id}CandidateNormalized"
                claim_name = f"productNode{node_id}ImmutableIndirectCallClaim"
                closed_name = f"productNode{node_id}ImmutableIndirectCallClosed"
                original_writes = ", ".join(
                    _lean_register_offset_write(write)
                    for write in candidate["original_writes"]
                )
                candidate_writes = ", ".join(
                    _lean_register_offset_write(write)
                    for write in candidate["candidate_writes"]
                )
                definitions.extend([
                    f"def {original_normalized} : NormalizedSymbolicBehavior :=\n"
                    f"  (normalizeSymbolicBehavior false region{region_index}.targets "
                    f"originalBehavior{region_index}).get (by decide)",
                    f"def {candidate_normalized} : NormalizedSymbolicBehavior :=\n"
                    f"  (normalizeSymbolicBehavior true region{region_index}.targets "
                    f"candidateBehavior{region_index}).get (by decide)",
                    f"def {claim_name} : ImmutableIndirectCallTargetClaim := {{\n"
                    f"  targetId := {int(candidate['target_id'])}\n"
                    f"  continuationTargetId := {int(candidate['continuation_target_id'])}\n"
                    f"  originalAddress := {int(candidate['original_address'])}\n"
                    f"  candidateAddress := {int(candidate['candidate_address'])}\n"
                    f"  originalAssembledRead := "
                    f"{_lean_bool(bool(candidate['original_assembled_read']))}\n"
                    f"  candidateAssembledRead := "
                    f"{_lean_bool(bool(candidate['candidate_assembled_read']))}\n"
                    f"  originalWrites := [{original_writes}]\n"
                    f"  candidateWrites := [{candidate_writes}]\n"
                    "}",
                    f"theorem {closed_name} :\n"
                    f"    ImmutableIndirectCallTargetsClosed staticProofContext "
                    f"region{region_index}.inputInvariant {original_normalized} "
                    f"{candidate_normalized} {claim_name} :=\n"
                    "  immutableIndirectCallTargetsClosed_of_checked staticProofContext "
                    f"region{region_index}.inputInvariant {original_normalized} "
                    f"{candidate_normalized} {claim_name} (by decide)",
                    f"theorem {theorem_name} :\n"
                    "    NodeControlEdgesComplete relationalProductGraph "
                    f"{node_id} staticProofContext region{region_index} "
                    f"originalBehavior{region_index} candidateBehavior{region_index} := by\n"
                    f"  exact Or.inr (Or.inl ⟨{original_normalized}, {candidate_normalized}, "
                    f"{claim_name}, ⟨originalBehavior{region_index}CheckedDecoded, "
                    f"candidateBehavior{region_index}CheckedDecoded, by decide, by decide, "
                    f"by decide, {closed_name}⟩⟩)",
                ])
            elif candidate.get("profile") == "immutable_relocated_function_pointer_jump_v1":
                original_normalized = f"productNode{node_id}OriginalNormalized"
                candidate_normalized = f"productNode{node_id}CandidateNormalized"
                claim_name = f"productNode{node_id}ImmutableIndirectJumpClaim"
                closed_name = f"productNode{node_id}ImmutableIndirectJumpClosed"
                original_writes = ", ".join(
                    _lean_register_offset_write(write)
                    for write in candidate["original_writes"]
                )
                candidate_writes = ", ".join(
                    _lean_register_offset_write(write)
                    for write in candidate["candidate_writes"]
                )
                definitions.extend([
                    f"def {original_normalized} : NormalizedSymbolicBehavior :=\n"
                    f"  (normalizeSymbolicBehavior false region{region_index}.targets "
                    f"originalBehavior{region_index}).get (by decide)",
                    f"def {candidate_normalized} : NormalizedSymbolicBehavior :=\n"
                    f"  (normalizeSymbolicBehavior true region{region_index}.targets "
                    f"candidateBehavior{region_index}).get (by decide)",
                    f"theorem {original_normalized}Checked :\n"
                    f"    normalizeSymbolicBehavior false region{region_index}.targets "
                    f"originalBehavior{region_index} = some {original_normalized} := "
                    "by decide",
                    f"theorem {candidate_normalized}Checked :\n"
                    f"    normalizeSymbolicBehavior true region{region_index}.targets "
                    f"candidateBehavior{region_index} = some {candidate_normalized} := "
                    "by decide",
                    f"theorem {original_normalized}WritesEmpty : "
                    f"{original_normalized}.writes = [] := by decide",
                    f"theorem {candidate_normalized}WritesEmpty : "
                    f"{candidate_normalized}.writes = [] := by decide",
                    f"theorem {original_normalized}X87 : "
                    f"{original_normalized}.x87 = "
                    f"originalBehavior{region_index}.x87 := by decide",
                    f"theorem {candidate_normalized}X87 : "
                    f"{candidate_normalized}.x87 = "
                    f"candidateBehavior{region_index}.x87 := by decide",
                    f"theorem {original_normalized}Esp : "
                    f"{original_normalized}.registers.esp = .inputReg .esp := "
                    "by decide",
                    f"theorem {candidate_normalized}Esp : "
                    f"{candidate_normalized}.registers.esp = .inputReg .esp := "
                    "by decide",
                    f"theorem {original_normalized}EspGet : "
                    f"{original_normalized}.registers.get .esp = .inputReg .esp := "
                    "by decide",
                    f"theorem {candidate_normalized}EspGet : "
                    f"{candidate_normalized}.registers.get .esp = .inputReg .esp := "
                    "by decide",
                    f"theorem {original_normalized}RegistersGet (register : Reg) : "
                    f"{original_normalized}.registers.get register = .inputReg register := by\n"
                    "  cases register <;> decide",
                    f"theorem {candidate_normalized}RegistersGet (register : Reg) : "
                    f"{candidate_normalized}.registers.get register = .inputReg register := by\n"
                    "  cases register <;> decide",
                    f"def {claim_name} : ImmutableIndirectJumpTargetClaim := {{\n"
                    f"  targetId := {int(candidate['target_id'])}\n"
                    f"  originalAddress := {int(candidate['original_address'])}\n"
                    f"  candidateAddress := {int(candidate['candidate_address'])}\n"
                    f"  originalAssembledRead := "
                    f"{_lean_bool(bool(candidate['original_assembled_read']))}\n"
                    f"  candidateAssembledRead := "
                    f"{_lean_bool(bool(candidate['candidate_assembled_read']))}\n"
                    f"  originalWrites := [{original_writes}]\n"
                    f"  candidateWrites := [{candidate_writes}]\n"
                    "}",
                    f"theorem {closed_name} :\n"
                    f"    ImmutableIndirectJumpTargetsClosed staticProofContext "
                    f"region{region_index}.inputInvariant {original_normalized} "
                    f"{candidate_normalized} {claim_name} :=\n"
                    "  immutableIndirectJumpTargetsClosed_of_checked staticProofContext "
                    f"region{region_index}.inputInvariant {original_normalized} "
                    f"{candidate_normalized} {claim_name} (by decide)",
                    f"theorem {theorem_name} :\n"
                    "    NodeControlEdgesComplete relationalProductGraph "
                    f"{node_id} staticProofContext region{region_index} "
                    f"originalBehavior{region_index} candidateBehavior{region_index} := by\n"
                    f"  exact Or.inr (Or.inr (Or.inr (Or.inr "
                    f"⟨{original_normalized}, {candidate_normalized}, {claim_name}, "
                    f"⟨originalBehavior{region_index}CheckedDecoded, "
                    f"candidateBehavior{region_index}CheckedDecoded, by decide, by decide, "
                    f"by decide, {closed_name}⟩⟩)))",
                ])
            elif candidate.get("profile") == "dynamic_range_code_pointer_call_v1":
                original_normalized = f"productNode{node_id}OriginalNormalized"
                candidate_normalized = f"productNode{node_id}CandidateNormalized"
                fanout = dynamic_fanout_by_source[node_id]
                extra_imports.add(fanout["module"])
                claim_name = fanout["claim"]
                first_edge_name = fanout["first_edge"]
                match_name = fanout["match"]
                closed_name = f"productNode{node_id}DynamicIndirectCallFiniteTargetsClosed"
                definitions.extend([
                    f"def {original_normalized} : NormalizedSymbolicBehavior :=\n"
                    f"  (normalizeSymbolicBehavior false region{region_index}.targets "
                    f"originalBehavior{region_index}).get (by decide)",
                    f"def {candidate_normalized} : NormalizedSymbolicBehavior :=\n"
                    f"  (normalizeSymbolicBehavior true region{region_index}.targets "
                    f"candidateBehavior{region_index}).get (by decide)",
                    f"theorem {closed_name} :\n"
                    "    DynamicRangeIndirectCallFiniteTargetsClosed "
                    f"region{region_index}.inputInvariant {original_normalized} "
                    f"{candidate_normalized} {claim_name} :=\n"
                    "  dynamicRangeIndirectCallFiniteTargetsClosed_of_checked "
                    f"region{region_index}.inputInvariant {original_normalized} "
                    f"{candidate_normalized} {claim_name} (by decide)",
                    f"theorem {theorem_name} :\n"
                    "    NodeControlEdgesComplete relationalProductGraph "
                    f"{node_id} staticProofContext region{region_index} "
                    f"originalBehavior{region_index} candidateBehavior{region_index} := by\n"
                    f"  exact Or.inr (Or.inr (Or.inr (Or.inl ⟨{original_normalized}, "
                    f"{candidate_normalized}, {claim_name}, {first_edge_name}, "
                    f"⟨originalBehavior{region_index}CheckedDecoded, "
                    f"candidateBehavior{region_index}CheckedDecoded, by decide, by decide, "
                    f"{match_name}, {closed_name}⟩⟩)))",
                ])
            elif candidate.get("profile") == "inductive_iat_register_call_v1":
                original_normalized = f"productNode{node_id}OriginalNormalized"
                candidate_normalized = f"productNode{node_id}CandidateNormalized"
                claim_name = f"productNode{node_id}ImportIndirectCallClaim"
                closed_name = f"productNode{node_id}ImportIndirectCallClosed"
                definitions.extend([
                    f"def {original_normalized} : NormalizedSymbolicBehavior :=\n"
                    f"  (normalizeSymbolicBehavior false region{region_index}.targets "
                    f"originalBehavior{region_index}).get (by decide)",
                    f"def {candidate_normalized} : NormalizedSymbolicBehavior :=\n"
                    f"  (normalizeSymbolicBehavior true region{region_index}.targets "
                    f"candidateBehavior{region_index}).get (by decide)",
                    f"def {claim_name} : ImportRegisterIndirectCallClaim := {{\n"
                    f"  imported := {_lean_external_target(candidate['import'])}\n"
                    f"  originalRegister := .{candidate['original_register']}\n"
                    f"  candidateRegister := .{candidate['candidate_register']}\n"
                    f"  continuationTargetId := {int(candidate['continuation_target_id'])}\n"
                    "}",
                    f"theorem {closed_name} :\n"
                    f"    ImportRegisterIndirectCallTargetsClosed "
                    f"region{region_index}.inputInvariant {original_normalized} "
                    f"{candidate_normalized} {claim_name} :=\n"
                    "  importRegisterIndirectCallTargetsClosed_of_checked "
                    f"region{region_index}.inputInvariant {original_normalized} "
                    f"{candidate_normalized} {claim_name} (by decide)",
                    f"theorem {theorem_name} :\n"
                    "    NodeControlEdgesComplete relationalProductGraph "
                    f"{node_id} staticProofContext region{region_index} "
                    f"originalBehavior{region_index} candidateBehavior{region_index} := by\n"
                    f"  exact Or.inr (Or.inr (Or.inl ⟨{original_normalized}, "
                    f"{candidate_normalized}, {claim_name}, "
                    f"⟨originalBehavior{region_index}CheckedDecoded, "
                    f"candidateBehavior{region_index}CheckedDecoded, by decide, by decide, "
                    f"by decide, {closed_name}⟩⟩))",
                ])
            else:
                definitions.append(
                    f"theorem {theorem_name} :\n"
                    "    NodeControlEdgesComplete relationalProductGraph "
                    f"{node_id} staticProofContext region{region_index} "
                    f"originalBehavior{region_index} candidateBehavior{region_index} :=\n"
                    f"  Or.inl ⟨originalBehavior{region_index}CheckedDecoded, "
                    f"candidateBehavior{region_index}CheckedDecoded, by decide⟩"
                )
        source = (
            "import StageA.RelationalProductGraphContext\n"
            + "".join(f"import StageA.{item}\n" for item in sorted(extra_imports))
            + "".join(
                f"import StageA.RelationalProofOriginalDecodeChunk{index}\n"
                f"import StageA.RelationalProofCandidateDecodeChunk{index}\n"
                for index in imported_decode_chunks
            )
            + "\nnamespace StageA.GeneratedRelational\n\n"
            "open StageA.Formal StageA.Relational\n\n"
            "set_option maxRecDepth 1000000\nset_option maxHeartbeats 0\n\n"
            + "\n\n".join(definitions)
            + "\n\nend StageA.GeneratedRelational\n"
        )
        _write_text_if_changed(lean_dir / "StageA" / f"{module}.lean", source)

    decoded_control_witnesses = [
        (
            f"⟨region{int(candidate['region_index'])}, "
            f"originalBehavior{int(candidate['region_index'])}, "
            f"candidateBehavior{int(candidate['region_index'])}, "
            f"productNode{int(candidate['node_id'])}DecodedControlEdgesComplete⟩"
        )
        for candidate in decoded_control_candidates
    ]
    decoded_control_proof = (
        "".join(f"And.intro {witness} (" for witness in decoded_control_witnesses)
        + "True.intro"
        + ")" * len(decoded_control_witnesses)
    )
    decoded_control_complete = (
        evidence["decoded_control_complete_node_ids"] == list(range(len(nodes)))
    )
    decoded_control_source = (
        "import StageA.RelationalProductGraphCertificate\n"
        + "".join(f"import StageA.{module}\n" for module in decoded_control_modules)
        + "\nnamespace StageA.GeneratedRelational\n\n"
        "open StageA.Formal StageA.Relational\n\n"
        "set_option maxRecDepth 1000000\nset_option maxHeartbeats 0\n\n"
        "theorem relationalDecodedControlEvidenceValidChecked :\n"
        "    relationalDecodedControlEvidence.valid relationalProductGraph = true := by decide\n\n"
        "theorem relationalDecodedControlEvidenceCompletenessChecked :\n"
        "    relationalDecodedControlEvidence.complete relationalProductGraph = "
        f"{_lean_bool(decoded_control_complete)} := by decide\n\n"
        "theorem allListedDecodedControlNodesCompleteChecked :\n"
        "    AllListedDecodedControlNodesComplete relationalProductGraph staticProofContext\n"
        "      relationalDecodedControlEvidence.completeNodeIds := by\n"
        f"  exact {decoded_control_proof}\n\n"
        "def GeneratedPartialDecodedControlCompletenessCertificate : Prop :=\n"
        "  PartialDecodedControlCompletenessCertificate relationalProductGraph "
        "staticProofContext\n"
        "    relationalDecodedControlEvidence\n\n"
        "theorem generatedPartialDecodedControlCompletenessCertificateChecked :\n"
        "    GeneratedPartialDecodedControlCompletenessCertificate :=\n"
        "  ⟨relationalDecodedControlEvidenceValidChecked, "
        "allListedDecodedControlNodesCompleteChecked⟩\n\n"
        "end StageA.GeneratedRelational\n"
    )
    _write_text_if_changed(
        lean_dir / "StageA" / "RelationalProductDecodedControlCertificate.lean",
        decoded_control_source,
    )

    reachability_modules: list[str] = []
    reachability_claims: list[tuple[str, str]] = []
    for chunk_index, (start, size) in enumerate(node_ranges):
        module = f"RelationalProductReachabilityChunk{chunk_index}"
        reachability_modules.append(module)
        range_name = f"productReachabilityNodeRange{chunk_index}"
        theorem_name = f"productReachabilityNodeRange{chunk_index}Checked"
        source = (
            "import StageA.RelationalProductGraphContext\n\n"
            "namespace StageA.GeneratedRelational\n\n"
            "open StageA.Formal StageA.Relational\n\n"
            "set_option maxRecDepth 1000000\nset_option maxHeartbeats 0\n\n"
            + _lean_static_range(range_name, start, size)
            + "\n\n"
            + f"theorem {theorem_name} :\n"
            "    IndexedBoolRangeHolds\n"
            "      (RelationalProductReachabilityEvidence.nodeClosedAt\n"
            "        relationalProductGraph relationalProductReachabilityEvidence)\n"
            f"      {range_name} :=\n"
            "  indexedBoolRangeHolds_of_checked\n"
            "    (RelationalProductReachabilityEvidence.nodeClosedAt\n"
            "      relationalProductGraph relationalProductReachabilityEvidence)\n"
            f"    {range_name} (by decide)\n\n"
            "end StageA.GeneratedRelational\n"
        )
        _write_text_if_changed(lean_dir / "StageA" / f"{module}.lean", source)
        reachability_claims.append((range_name, theorem_name))

    reachability_source = (
        "import StageA.RelationalProductGraphCertificate\n"
        + "".join(f"import StageA.{module}\n" for module in reachability_modules)
        + "\nnamespace StageA.GeneratedRelational\n\n"
        "open StageA.Formal StageA.Relational\n\n"
        "set_option maxRecDepth 1000000\nset_option maxHeartbeats 0\n\n"
        + range_certificate_source(
            "ReachabilityNodes",
            reachability_claims,
            "(RelationalProductReachabilityEvidence.nodeClosedAt "
            "relationalProductGraph relationalProductReachabilityEvidence)",
            len(nodes),
        )
        + "def GeneratedDeclaredGraphReachabilityCertificate : Prop :=\n"
        "  RelationalProductReachabilityEvidence.SoundlyClosed staticProofContext\n"
        "    relationalProductGraph relationalProductReachabilityEvidence\n\n"
        "theorem generatedDeclaredGraphReachabilityCertificateChecked :\n"
        "    GeneratedDeclaredGraphReachabilityCertificate := by\n"
        "  unfold GeneratedDeclaredGraphReachabilityCertificate\n"
        "  exact ⟨relationalProductGraphIndexedValidChecked,\n"
        "    ⟨by decide, by decide, productReachabilityNodesChecked⟩,\n"
        "    RelationalProductGraph.infeasibleEdgesSound_of_indexedValid\n"
        "      staticProofContext relationalProductGraph\n"
        "      relationalProductGraphIndexedValidChecked⟩\n\n"
        "end StageA.GeneratedRelational\n"
    )
    _write_text_if_changed(
        lean_dir / "StageA" / "RelationalProductReachabilityCertificate.lean",
        reachability_source,
    )

    segment_module_by_edge = {
        int(edge_id): str(item["module"])
        for item in segment_refinement_modules
        for edge_id in item["edge_ids"]
    }
    missing_segment_modules = sorted(
        set(candidate_by_edge) - set(segment_module_by_edge)
    )
    if missing_segment_modules:
        raise StageAInputError(
            "segment refinement candidates lack generated Lean modules for edges "
            + ", ".join(str(edge_id) for edge_id in missing_segment_modules)
        )

    edge_refinement_modules: list[str] = []
    edge_module_by_id: dict[int, str] = {}
    for chunk_index, offset in enumerate(
        range(0, len(segment_candidates), proof_chunk_size)
    ):
        selected = segment_candidates[offset : offset + proof_chunk_size]
        module = f"RelationalProductEdgeRefinementChunk{chunk_index}"
        edge_refinement_modules.append(module)
        definitions: list[str] = []
        imports = sorted({
            segment_module_by_edge[int(candidate["edge_index"])]
            for candidate in selected
        })
        for candidate in selected:
            edge_id = int(candidate["edge_index"])
            edge_module_by_id[edge_id] = module
            source_index = int(candidate["source_region_index"])
            target_index = int(candidate["target_region_index"])
            resolved_name = f"productEdge{edge_id}Resolved"
            refined_name = f"productEdge{edge_id}Refined"
            definitions.extend([
                (
                    f"theorem {resolved_name} : relationalProductGraph.getEdge? {edge_id} = "
                    f"some relationalProductGraph.edges[{edge_id}] := by decide"
                ),
                (
                    f"theorem {refined_name} :\n"
                    "    RelationalProductEdgeRefinement staticProofContext "
                    f"relationalProductGraph {edge_id} segmentRefinementEdge{edge_id}Spec\n"
                    f"      region{source_index}.inputInvariant "
                    f"region{target_index}.inputInvariant := by\n"
                    "  unfold RelationalProductEdgeRefinement\n"
                    f"  rw [{resolved_name}]\n"
                    f"  exact ⟨rfl, rfl, segmentRefinementEdge{edge_id}Checked⟩"
                ),
            ])
        source = (
            "import StageA.RelationalProductGraphContext\n"
            + "".join(f"import StageA.{name}\n" for name in imports)
            + "\nnamespace StageA.GeneratedRelational\n\n"
            "open StageA.Formal StageA.Relational\n\n"
            "set_option maxRecDepth 1000000\nset_option maxHeartbeats 0\n\n"
            + "\n\n".join(definitions)
            + "\n\nend StageA.GeneratedRelational\n"
        )
        _write_text_if_changed(lean_dir / "StageA" / f"{module}.lean", source)

    edge_witnesses = [
        (
            f"⟨segmentRefinementEdge{edge_id}Spec, "
            f"region{int(candidate_by_edge[edge_id]['source_region_index'])}.inputInvariant, "
            f"region{int(candidate_by_edge[edge_id]['target_region_index'])}.inputInvariant, "
            f"productEdge{edge_id}Refined⟩"
        )
        for edge_id in evidence["proved_edge_ids"]
    ]
    listed_edge_proof = (
        "".join(f"And.intro {witness} (" for witness in edge_witnesses)
        + "True.intro"
        + ")" * len(edge_witnesses)
    )
    complete_source = ""
    if complete:
        witness_cases: list[str] = []
        for edge in edges:
            edge_id = int(edge["id"])
            candidate = candidate_by_edge[edge_id]
            source_index = int(candidate["source_region_index"])
            target_index = int(candidate["target_region_index"])
            witness_cases.append(
                f"  by_cases edge{edge_id} : edgeId = {edge_id}\n"
                f"  · subst edgeId\n"
                f"    exact ⟨segmentRefinementEdge{edge_id}Spec, "
                f"region{source_index}.inputInvariant, region{target_index}.inputInvariant, "
                f"productEdge{edge_id}Refined⟩\n"
            )
        complete_source = (
            "\ntheorem allProductEdgesRefinedChecked :\n"
            "    AllProductEdgesRefined staticProofContext relationalProductGraph := by\n"
            "  intro edgeId before\n"
            f"  have edgeCount : relationalProductGraph.edges.size = {len(edges)} := by decide\n"
            "  rw [edgeCount] at before\n"
            + "".join(witness_cases)
            + "  omega\n\n"
            "def completeProductEdgeRefinementCertificate :\n"
            "    CompleteProductEdgeRefinementCertificate staticProofContext "
            "relationalProductGraph := {\n"
            "  structurallyValid := relationalProductGraphIndexedValidChecked\n"
            "  allEdgesRefined := allProductEdgesRefinedChecked\n"
            "}\n"
        )
    edge_certificate_source = (
        "import StageA.RelationalProductGraphCertificate\n"
        + "".join(
            f"import StageA.{module}\n" for module in edge_refinement_modules
        )
        + "\nnamespace StageA.GeneratedRelational\n\n"
        "open StageA.Formal StageA.Relational\n\n"
        "set_option maxRecDepth 1000000\nset_option maxHeartbeats 0\n\n"
        "theorem allListedProductEdgesRefinedChecked :\n"
        "    ListedProductEdgesRefined staticProofContext relationalProductGraph\n"
        "      relationalProductEvidence.provedEdgeIds := by\n"
        f"  exact {listed_edge_proof}\n\n"
        "def GeneratedPartialProductEdgeRefinementCertificate : Prop :=\n"
        "  PartialProductEdgeRefinementCertificate staticProofContext "
        "relationalProductGraph relationalProductEvidence\n\n"
        "theorem generatedPartialProductEdgeRefinementCertificateChecked :\n"
        "    GeneratedPartialProductEdgeRefinementCertificate :=\n"
        "  ⟨relationalProductEvidenceValidChecked, "
        "allListedProductEdgesRefinedChecked⟩\n"
        + complete_source
        + "\nend StageA.GeneratedRelational\n"
    )
    _write_text_if_changed(
        lean_dir / "StageA" / "RelationalProductEdgeRefinementCertificate.lean",
        edge_certificate_source,
    )

    coverage_candidates = evidence["coverage_candidates"]
    node_coverage_modules: list[str] = []
    for chunk_index, offset in enumerate(
        range(0, len(coverage_candidates), proof_chunk_size)
    ):
        selected = coverage_candidates[offset : offset + proof_chunk_size]
        module = f"RelationalProductNodeCoverageChunk{chunk_index}"
        node_coverage_modules.append(module)
        definitions: list[str] = []
        imports = sorted({
            edge_module_by_id[int(coverage["edge_id"])] for coverage in selected
        })
        for coverage in selected:
            node_id = int(coverage["node_id"])
            edge_id = int(coverage["edge_id"])
            candidate = candidate_by_edge[edge_id]
            source_index = int(candidate["source_region_index"])
            target_index = int(candidate["target_region_index"])
            resolved_name = f"productNode{node_id}Resolved"
            theorem_name = f"productNode{node_id}UnconditionalBehaviorCovered"
            definitions.extend([
                (
                    f"theorem {resolved_name} : relationalProductGraph.getNode? {node_id} = "
                    f"some relationalProductGraph.nodes[{node_id}] := by decide"
                ),
                (
                    f"theorem {theorem_name} :\n"
                    "    UnconditionalProductNodeBehaviorCovered staticProofContext "
                    f"relationalProductGraph {node_id} {edge_id} "
                    f"segmentRefinementEdge{edge_id}Spec\n"
                    f"      region{source_index}.inputInvariant "
                    f"region{target_index}.inputInvariant := by\n"
                    "  unfold UnconditionalProductNodeBehaviorCovered\n"
                    f"  rw [{resolved_name}, productEdge{edge_id}Resolved]\n"
                    f"  exact ⟨rfl, rfl, rfl, rfl, rfl, rfl, "
                    f"productEdge{edge_id}Refined⟩"
                ),
            ])
        source = (
            "import StageA.RelationalProductGraphContext\n"
            + "".join(f"import StageA.{name}\n" for name in imports)
            + "\nnamespace StageA.GeneratedRelational\n\n"
            "open StageA.Formal StageA.Relational\n\n"
            "set_option maxRecDepth 1000000\nset_option maxHeartbeats 0\n\n"
            + "\n\n".join(definitions)
            + "\n\nend StageA.GeneratedRelational\n"
        )
        _write_text_if_changed(lean_dir / "StageA" / f"{module}.lean", source)

    coverage_witnesses = []
    for coverage in coverage_candidates:
        node_id = int(coverage["node_id"])
        edge_id = int(coverage["edge_id"])
        candidate = candidate_by_edge[edge_id]
        coverage_witnesses.append(
            f"⟨{edge_id}, segmentRefinementEdge{edge_id}Spec, "
            f"region{int(candidate['source_region_index'])}.inputInvariant, "
            f"region{int(candidate['target_region_index'])}.inputInvariant, "
            f"productNode{node_id}UnconditionalBehaviorCovered⟩"
        )
    coverage_proof = (
        "".join(f"And.intro {witness} (" for witness in coverage_witnesses)
        + "True.intro"
        + ")" * len(coverage_witnesses)
    )
    coverage_source = (
        "import StageA.RelationalProductGraphCertificate\n"
        "import StageA.RelationalProductEdgeRefinementCertificate\n"
        + "".join(
            f"import StageA.{module}\n" for module in node_coverage_modules
        )
        + "\nnamespace StageA.GeneratedRelational\n\n"
        "open StageA.Formal StageA.Relational\n\n"
        "set_option maxRecDepth 1000000\nset_option maxHeartbeats 0\n\n"
        "theorem allCoveredProductNodesChecked :\n"
        "    AllCoveredProductNodes staticProofContext relationalProductGraph\n"
        "      relationalProductCoverageEvidence.coveredNodeIds := by\n"
        f"  exact {coverage_proof}\n\n"
        "def GeneratedPartialProductNodeCoverageCertificate : Prop :=\n"
        "  PartialProductNodeCoverageCertificate staticProofContext relationalProductGraph\n"
        "    relationalProductCoverageEvidence\n\n"
        "theorem generatedPartialProductNodeCoverageCertificateChecked :\n"
        "    GeneratedPartialProductNodeCoverageCertificate :=\n"
        "  ⟨relationalProductCoverageEvidenceValidChecked, "
        "allCoveredProductNodesChecked⟩\n\n"
        "end StageA.GeneratedRelational\n"
    )
    _write_text_if_changed(
        lean_dir / "StageA" / "RelationalProductNodeCoverageCertificate.lean",
        coverage_source,
    )
    return [
        *modules,
        *(item["module"] for item in import_seed_modules),
        *(item["module"] for item in dynamic_call_modules),
        *decoded_control_modules,
        *reachability_modules,
        *edge_refinement_modules,
        *node_coverage_modules,
    ]

def _write_stack_separation_modules(
    lean_dir: Path,
    contract: dict[str, Any],
    definition_modules: list[str],
    shard_groups: list[list[int]],
) -> list[dict[str, str]]:
    definition_by_region = {
        region_index: definition_modules[shard_index]
        for shard_index, region_indices in enumerate(shard_groups)
        for region_index in region_indices
    }
    modules: list[dict[str, str]] = []
    for region_index, region in enumerate(contract.get("regions", [])):
        claims = region.get("stack_address_separation_claims", [])
        if not claims:
            continue
        module = f"RelationalStackSeparationRegion{region_index}"
        claims_name = f"region{region_index}StackSeparationClaims"
        proposition_name = f"region{region_index}StackSeparationInventory"
        theorem_name = f"region{region_index}StackSeparationInventoryChecked"
        claim_rows = ", ".join(
            _lean_stack_address_separation_claim(claim) for claim in claims
        )
        source = (
            "import StageA.RelationalProofOriginal\n"
            "import StageA.RelationalProofCandidate\n"
            f"import StageA.{definition_by_region[region_index]}\n\n"
            "namespace StageA.GeneratedRelational\n\n"
            "open StageA.Formal StageA.Relational\n\n"
            "set_option maxRecDepth 1000000\nset_option maxHeartbeats 0\n\n"
            f"def {claims_name} : List StackAddressSeparationClaim := [{claim_rows}]\n\n"
            f"def {proposition_name} : Prop :=\n"
            "  stackAddressSeparationInventoryChecked originalPe candidatePe "
            f"region{region_index}.inputInvariant {claims_name} = true\n\n"
            f"theorem {theorem_name} : {proposition_name} := by\n"
            f"  unfold {proposition_name} {claims_name}\n"
            "  decide\n\n"
            "end StageA.GeneratedRelational\n"
        )
        _write_text_if_changed(lean_dir / "StageA" / f"{module}.lean", source)
        modules.append({
            "module": module,
            "proposition": proposition_name,
            "theorem": theorem_name,
        })
    return modules
