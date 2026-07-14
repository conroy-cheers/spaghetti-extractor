from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any, Mapping


STAGE_A_RELATIONAL_MODEL_ID = "x86-pe32-relational-v3"
STAGE_A_RELATIONAL_PROFILE_ID = "x86-pe32-lean-relational-v3"
RELATION_CONTRACT_FORMAT = "stage-a-relation-contract-v1"
RELATIONAL_PROOF_IR_FORMAT = "stage-a-relational-proof-ir-v1"
RELATIONAL_SEGMENT_CERTIFICATE_FORMAT = (
    "stage-a-relational-segment-certificate-v1"
)
REGISTERS = {"eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp"}
MACHINE_CALL_ABI_REGISTERS = REGISTERS - {"esp"}
MACHINE_CALL_MEMORY_EFFECTS = {"none", "readOnly", "argumentRanges"}
MACHINE_CALL_WORLD_EFFECTS = {
    "none", "opaqueResources", "dynamicRanges", "tlsState",
}
MACHINE_CALL_ABI_TEMPLATES = {
    "pe32-cdecl-v1": {
        "callee_cleanup": False,
        "preserved_registers": ["ebp", "ebx", "edi", "esi"],
        "clobbered_registers": ["eax", "ecx", "edx"],
    },
    "pe32-stdcall-v1": {
        "callee_cleanup": True,
        "preserved_registers": ["ebp", "ebx", "edi", "esi"],
        "clobbered_registers": ["eax", "ecx", "edx"],
    },
}
MACHINE_CALL_MAX_ARGUMENT_WORDS = 1024
FLAG_BITS = {
    0: "CF",
    2: "PF",
    6: "ZF",
    7: "SF",
    10: "DF",
    11: "OF",
}
RELATIONAL_APPROVED_AXIOMS = {"propext", "Classical.choice", "Quot.sound"}
RELATIONAL_ENVIRONMENT_ID = "adversarial-pe32-external-v1"
RELATIONAL_OBSERVATIONS = ["external_call", "external_jump", "return", "fault"]
RELATIONAL_KERNEL_MODULES = (
    "Formal",
    "RelationalDecode",
    "RelationalMachine",
    "Relational",
    "RelationalInvariant",
    "RelationalExecution",
    "RelationalImage",
    "RelationalSegment",
    "RelationalComposition",
    "RelationalEnvironment",
    "RelationalCertificates",
    "RelationalStaticTree",
)
RELATIONAL_ACCEPTANCE_THEOREM = (
    "StageA.GeneratedRelational.candidatePE32ProgramsEquivalent"
)
RELATIONAL_PREPARED_REPORT_FILES = (
    "prepared-proof.json",
    "module-graph.json",
    "relation-contract.json",
    "relational-proof-ir.json",
    "relational-semantic-ir.json",
    "relational-memory-contracts.json",
    "relational-register-relations.json",
    "relational-stack-windows.json",
    "relational-product-graph.json",
    "relational-invariants.json",
    "relational-machine-import-calls.json",
    "relational-external-call-sites.json",
    "relational-import-register-invariants.json",
    "relational-import-register-seeds.json",
    "relational-indirect-call-targets.json",
    "whole-program-acceptance.json",
    "composition-progress.json",
    "trusted-base.json",
    "semantic-gaps.json",
)


class AcceptanceAuthority(str, Enum):
    EVIDENCE_ONLY = "evidence_only"
    WHOLE_PROGRAM_LEAN = "whole_program_lean"


class SchemaError(ValueError):
    pass


def integer(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        try:
            return int(value, 0)
        except ValueError:
            return None
    return None


def _required_string(payload: Mapping[str, Any], field: str) -> str:
    value = payload.get(field)
    if not isinstance(value, str) or not value:
        raise SchemaError(f"{field} must be a non-empty string")
    return value


def _string_tuple(payload: Mapping[str, Any], field: str) -> tuple[str, ...]:
    value = payload.get(field)
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        raise SchemaError(f"{field} must be a list of strings")
    return tuple(value)


@dataclass(frozen=True)
class ModuleGraphNode:
    id: str
    modules: tuple[str, ...]
    dependencies: tuple[str, ...]
    source_sha256: str
    resource_class: str
    estimated_memory_mb: int

    @classmethod
    def parse(cls, payload: Mapping[str, Any]) -> "ModuleGraphNode":
        memory = integer(payload.get("estimated_memory_mb"))
        if memory is None or memory <= 0:
            raise SchemaError("estimated_memory_mb must be positive")
        return cls(
            id=_required_string(payload, "id"),
            modules=_string_tuple(payload, "modules"),
            dependencies=_string_tuple(payload, "dependencies"),
            source_sha256=_required_string(payload, "source_sha256"),
            resource_class=_required_string(payload, "resource_class"),
            estimated_memory_mb=memory,
        )


@dataclass(frozen=True)
class ModuleGraph:
    format: str
    root_module: str
    expected_final_theorem: str | None
    nodes: tuple[ModuleGraphNode, ...]

    @classmethod
    def parse(cls, payload: Mapping[str, Any]) -> "ModuleGraph":
        raw_nodes = payload.get("nodes")
        if not isinstance(raw_nodes, list):
            raise SchemaError("nodes must be a list")
        nodes = tuple(
            ModuleGraphNode.parse(node)
            for node in raw_nodes
            if isinstance(node, Mapping)
        )
        if len(nodes) != len(raw_nodes):
            raise SchemaError("every module graph node must be an object")
        ids = [node.id for node in nodes]
        if len(ids) != len(set(ids)):
            raise SchemaError("module graph node ids must be unique")
        theorem = payload.get("expected_final_theorem")
        if theorem is not None and not isinstance(theorem, str):
            raise SchemaError("expected_final_theorem must be a string or null")
        return cls(
            format=_required_string(payload, "format"),
            root_module=_required_string(payload, "root_module"),
            expected_final_theorem=theorem,
            nodes=nodes,
        )


@dataclass(frozen=True)
class PreparedProofDigests:
    relation_contract: str
    proof_ir: str
    semantic_ir: str
    memory_contracts: str
    register_relations: str
    stack_windows: str
    product_graph: str
    invariants: str
    whole_program_acceptance: str
    module_graph: str

    @classmethod
    def parse(cls, payload: Mapping[str, Any]) -> "PreparedProofDigests":
        fields = {
            "relation_contract": "relation_contract_sha256",
            "proof_ir": "proof_ir_sha256",
            "semantic_ir": "semantic_ir_sha256",
            "memory_contracts": "memory_contracts_sha256",
            "register_relations": "register_relations_sha256",
            "stack_windows": "stack_windows_sha256",
            "product_graph": "product_graph_sha256",
            "invariants": "invariants_sha256",
            "whole_program_acceptance": "whole_program_acceptance_sha256",
            "module_graph": "module_graph_sha256",
        }
        return cls(**{
            name: _required_string(payload, field)
            for name, field in fields.items()
        })
