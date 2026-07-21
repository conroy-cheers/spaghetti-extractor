from __future__ import annotations

from pathlib import Path
from typing import Any, Mapping

from ..relational.interfaces import stage_a_interface_manifest
from ..relational.schema import (
    RELATIONAL_ACCEPTANCE_THEOREM,
    STAGE_A_RELATIONAL_MODEL_ID,
    StageAInterfaceManifest,
)
from ..stage_binary import StageAInputError
from ..util import sha256_file, write_json


ROUNDTRIP_INTERFACE_INVENTORY_FORMAT = "stage-a-roundtrip-interface-inventory-v1"


def roundtrip_interface_inventory() -> dict[str, Any]:
    interface = stage_a_interface_manifest()
    parsed = StageAInterfaceManifest.parse(interface)
    if parsed.acceptance_theorem != RELATIONAL_ACCEPTANCE_THEOREM:
        raise StageAInputError("Stage A interface manifest selected another acceptance theorem")
    cache_artifacts = [
        {
            "id": str(artifact["id"]),
            "path": artifact.get("path"),
            "paths": artifact.get("paths"),
            "producer": str(artifact["producer"]),
            "consumers": list(artifact["consumers"]),
        }
        for artifact in interface["artifacts"]
        if isinstance(artifact, Mapping) and artifact.get("cache_boundary") is True
    ]
    return {
        "format": ROUNDTRIP_INTERFACE_INVENTORY_FORMAT,
        "model": STAGE_A_RELATIONAL_MODEL_ID,
        "acceptance": {
            "theorem": RELATIONAL_ACCEPTANCE_THEOREM,
            "only_pass_authority": True,
        },
        "public_stage_a_pipeline": [
            {
                "phase": "mapping_proposal",
                "python": "relational.mapping.stage_a_generate_map",
                "cli": "stage-a-generate-map",
                "proof_authority": False,
            },
            {
                "phase": "relation_contract",
                "python": "relational.contract.stage_a_generate_relation_contract",
                "cli": "stage-a-generate-relation-contract",
                "proof_authority": False,
            },
            {
                "phase": "proof_preparation",
                "python": "relational.pipeline.stage_a_prepare_relational",
                "cli": "stage-a-prepare-relational",
                "proof_authority": False,
            },
            {
                "phase": "proof_build_and_audit",
                "python": "relational.build.stage_a_build_relational",
                "cli": "stage-a-build-relational",
                "proof_authority": True,
            },
            {
                "phase": "independent_replay",
                "python": "relational.pipeline.stage_a_check_relational_proof",
                "cli": "stage-a-check-proof",
                "proof_authority": False,
            },
        ],
        "public_stage_b_pipeline": [
            {
                "phase": "static_contract_export",
                "cli": "stage-a-export-reference-contract",
                "opaque_original_only": True,
            },
            {
                "phase": "state_machine_and_skeleton",
                "cli": "stage-b-generate-skeleton",
                "opaque_original_only": True,
            },
            {
                "phase": "semantic_c",
                "cli": "stage-b-generate-semantic-c",
                "opaque_original_only": True,
            },
            {
                "phase": "candidate_provenance",
                "cli": "stage-b-generate-candidate-provenance",
                "opaque_original_only": True,
            },
        ],
        "cache_boundaries": cache_artifacts,
        "interface_manifest": interface,
    }


def write_roundtrip_interface_inventory(*, out: Path) -> dict[str, Any]:
    out = Path(out)
    payload = roundtrip_interface_inventory()
    write_json(out, payload)
    return {
        "format": "stage-a-roundtrip-interface-inventory-export-v1",
        "status": "generated",
        "path": str(out),
        "sha256": sha256_file(out),
        "acceptance_theorem": RELATIONAL_ACCEPTANCE_THEOREM,
        "cache_boundaries": len(payload["cache_boundaries"]),
    }
