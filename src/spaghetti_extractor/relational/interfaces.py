from __future__ import annotations

from pathlib import Path
from typing import Any

from ..util import sha256_file, write_json

from .schema import (
    EXTERNAL_ENVIRONMENT_PROFILE_FORMAT,
    PROTOCOL_CALLBACK_CONTROL_FORMAT,
    RELATION_CONTRACT_FORMAT,
    RELATIONAL_ACCEPTANCE_THEOREM,
    RELATIONAL_PROOF_IR_FORMAT,
    RELATIONAL_SEGMENT_CERTIFICATE_FORMAT,
    STAGE_A_INTERFACE_MANIFEST_FORMAT,
    STAGE_A_RELATIONAL_MODEL_ID,
    StageAInterfaceManifest,
)


def stage_a_interface_manifest() -> dict[str, Any]:
    """Return the checked ownership boundary for parallel Stage A development."""
    payload = {
        "format": STAGE_A_INTERFACE_MANIFEST_FORMAT,
        "model": STAGE_A_RELATIONAL_MODEL_ID,
        "acceptance": {
            "theorem": RELATIONAL_ACCEPTANCE_THEOREM,
            "only_pass_authority": True,
            "integration_owner": "acceptance-integration",
        },
        "schemas": [
            {
                "id": "relation-contract",
                "format": RELATION_CONTRACT_FORMAT,
                "python_boundary": "relational.contract._normalize_contract",
            },
            {
                "id": "protocol-callback-control",
                "format": PROTOCOL_CALLBACK_CONTROL_FORMAT,
                "python_boundary": "relational.schema.ProtocolCallbackControl",
            },
            {
                "id": "external-environment-profile",
                "format": EXTERNAL_ENVIRONMENT_PROFILE_FORMAT,
                "python_boundary": "relational.contract._normalize_contract",
            },
            {
                "id": "proof-ir",
                "format": RELATIONAL_PROOF_IR_FORMAT,
                "python_boundary": "relational.schema.RelationalProofIR",
            },
            {
                "id": "segment-certificate",
                "format": RELATIONAL_SEGMENT_CERTIFICATE_FORMAT,
                "python_boundary": "relational.schema.RelationalSegmentCertificate",
            },
        ],
        "artifacts": [
            {
                "id": "normalized-contract",
                "path": "relation-contract.json",
                "producer": "contract-normalization",
                "consumers": ["all-analysis-workstreams"],
                "cache_boundary": True,
            },
            {
                "id": "semantic-ir",
                "path": "relational-semantic-ir.json",
                "producer": "instruction-semantics",
                "consumers": ["state-and-frame-analysis", "control-composition"],
                "cache_boundary": True,
            },
            {
                "id": "state-products",
                "paths": [
                    "relational-register-relations.json",
                    "relational-stack-windows.json",
                    "relational-memory-contracts.json",
                    "relational-static-word-relations.json",
                    "relational-invariants.json",
                ],
                "producer": "state-and-frame-analysis",
                "consumers": ["control-composition", "external-protocol"],
                "cache_boundary": True,
            },
            {
                "id": "product-graph",
                "path": "relational-product-graph.json",
                "producer": "control-composition",
                "consumers": ["acceptance-integration", "contract-diagnostics"],
                "cache_boundary": True,
            },
            {
                "id": "isa-requirements",
                "path": "isa-requirements.json",
                "producer": "instruction-semantics",
                "consumers": ["isa-conformance", "contract-diagnostics"],
                "cache_boundary": True,
                "proof_authority": False,
            },
            {
                "id": "isa-semantic-qualification",
                "path": "isa-semantic-qualification.json",
                "producer": "isa-conformance",
                "consumers": ["contract-diagnostics", "semantic-model-development"],
                "cache_boundary": True,
                "proof_authority": False,
            },
            {
                "id": "segment-diagnostics",
                "path": "relational-segment-diagnostics.json",
                "producer": "control-composition",
                "consumers": ["contract-diagnostics", "stage-b-repair"],
                "cache_boundary": True,
            },
            {
                "id": "whole-program-acceptance",
                "path": "whole-program-acceptance.json",
                "producer": "acceptance-integration",
                "consumers": ["proof-build", "contract-diagnostics"],
                "cache_boundary": True,
            },
            {
                "id": "lean-module-graph",
                "path": "module-graph.json",
                "producer": "proof-build",
                "consumers": ["distributed-nix-execution"],
                "cache_boundary": True,
            },
        ],
        "lean_interfaces": [
            {
                "module": "StageA.Relational",
                "declarations": ["StateRel", "StaticProofContext"],
            },
            {
                "module": "StageA.RelationalPEExecution",
                "declarations": [
                    "PE32InstructionExecution",
                    "stepPE32Instruction",
                    "RegionInstructionAdequate",
                ],
            },
            {
                "module": "StageA.RelationalLoader",
                "declarations": [
                    "PE32LoaderPolicy",
                    "preferredBaseOnlyLoaderPolicy",
                    "pe32LoaderImageValid",
                ],
            },
            {
                "module": "StageA.RelationalSegment",
                "declarations": ["RelationalSegmentRefinement"],
            },
            {
                "module": "StageA.RelationalCallbacks",
                "declarations": [
                    "RelationalRuntimeFrame",
                    "WorldExternalProtocolEnvironment",
                ],
            },
            {
                "module": "StageA.RelationalLinkedFrames",
                "declarations": [
                    "RelationalRuntimeCallFrameLink",
                    "RelationalLinkedRuntimeCallStackHolds",
                    "LinkedProductControlProfile",
                ],
            },
            {
                "module": "StageA.RelationalCertificates",
                "declarations": [
                    "ProofBundle.CoversStaticContext",
                    "ModeledFault",
                    "ExecutionBlock",
                    "ProtocolCallbackTargetProfile",
                    "CallbackRunningProductNodeStepRefined",
                    "WholeProgramCertificate",
                    "pe32ProgramsEquivalent",
                ],
            },
            {
                "module": "StageA.RelationalPEWorldExecution",
                "declarations": [
                    "RawEipWorldExecution",
                    "RawEipPairBridgeClosed",
                    "PE32RawProgramsObservationallyEquivalent",
                ],
            },
        ],
        "workstreams": [
            {
                "id": "instruction-semantics",
                "parallel_safe": True,
                "acceptance_owner": False,
                "owned_paths": [
                    "src/spaghetti_extractor/relational/extraction.py",
                    "src/spaghetti_extractor/lean/StageA/RelationalDecode.lean",
                    "src/spaghetti_extractor/lean/StageA/RelationalPEExecution.lean",
                ],
                "integration_fixtures": ["tests/test_stage_a_relational_pipeline.py"],
            },
            {
                "id": "state-and-frame-analysis",
                "parallel_safe": True,
                "acceptance_owner": False,
                "owned_paths": [
                    "src/spaghetti_extractor/relational/analyses/registers.py",
                    "src/spaghetti_extractor/relational/analyses/stack.py",
                    "src/spaghetti_extractor/relational/analyses/memory.py",
                    "src/spaghetti_extractor/relational/analyses/invariants.py",
                    "src/spaghetti_extractor/relational/analyses/frames.py",
                ],
                "integration_fixtures": ["tests/test_stage_a_relational_state.py"],
            },
            {
                "id": "external-protocol",
                "parallel_safe": True,
                "acceptance_owner": False,
                "owned_paths": [
                    "src/spaghetti_extractor/relational/analyses/external.py",
                    "src/spaghetti_extractor/relational/analyses/callbacks.py",
                    "src/spaghetti_extractor/relational/lean/callbacks.py",
                    "src/spaghetti_extractor/lean/StageA/RelationalCallbacks.lean",
                    "src/spaghetti_extractor/lean/StageA/RelationalEnvironment.lean",
                ],
                "integration_fixtures": [
                    "tests/test_stage_a_relational_acceptance.py::test_protocol_call_and_callback_return_close_whole_program_theorem"
                ],
            },
            {
                "id": "control-composition",
                "parallel_safe": True,
                "acceptance_owner": False,
                "owned_paths": [
                    "src/spaghetti_extractor/relational/analyses/control.py",
                    "src/spaghetti_extractor/relational/lean/composition.py",
                    "src/spaghetti_extractor/lean/StageA/RelationalSegment.lean",
                    "src/spaghetti_extractor/lean/StageA/RelationalComposition.lean",
                    "src/spaghetti_extractor/lean/StageA/RelationalLinkedFrames.lean",
                ],
                "integration_fixtures": ["tests/test_stage_a_relational_acceptance.py"],
            },
            {
                "id": "contract-diagnostics",
                "parallel_safe": True,
                "acceptance_owner": False,
                "owned_paths": [
                    "src/spaghetti_extractor/relational/contract.py",
                    "src/spaghetti_extractor/relational/diagnostics.py",
                    "src/spaghetti_extractor/relational/schema.py",
                ],
                "integration_fixtures": ["tests/test_stage_a_relational_contract.py"],
            },
            {
                "id": "proof-build",
                "parallel_safe": True,
                "acceptance_owner": False,
                "owned_paths": [
                    "src/spaghetti_extractor/relational/build.py",
                    "nix/stage-a-lean-graph.nix",
                ],
                "integration_fixtures": ["tests/test_stage_a_relational_pipeline.py"],
            },
            {
                "id": "acceptance-integration",
                "parallel_safe": False,
                "acceptance_owner": True,
                "owned_paths": [
                    "src/spaghetti_extractor/relational/lean/acceptance.py",
                    "src/spaghetti_extractor/lean/StageA/RelationalCertificates.lean",
                ],
                "integration_fixtures": ["tests/test_stage_a_relational_acceptance.py"],
            },
        ],
        "integration_policy": {
            "generic_fixture_required": True,
            "jq_specific_acceptance_rules_forbidden": True,
            "unknown_schema_versions_fail_closed": True,
            "acceptance_criteria_may_change_only_in_acceptance_integration": True,
        },
    }
    StageAInterfaceManifest.parse(payload)
    return payload


def stage_a_export_interface_manifest(*, out: Path) -> dict[str, Any]:
    out = Path(out)
    write_json(out, stage_a_interface_manifest())
    return {
        "format": "stage-a-interface-manifest-export-v1",
        "status": "generated",
        "out": str(out),
        "sha256": sha256_file(out),
    }
