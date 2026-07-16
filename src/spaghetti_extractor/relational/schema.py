from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any, Mapping


STAGE_A_RELATIONAL_MODEL_ID = "x86-pe32-relational-v3"
STAGE_A_RELATIONAL_PROFILE_ID = "x86-pe32-lean-relational-v3"
RELATION_CONTRACT_FORMAT = "stage-a-relation-contract-v1"
EXTERNAL_ENVIRONMENT_PROFILE_FORMAT = "stage-a-external-environment-profile-v1"
PROTOCOL_CALLBACK_CONTROL_FORMAT = "stage-a-protocol-callback-control-v1"
STAGE_A_INTERFACE_MANIFEST_FORMAT = "stage-a-interface-manifest-v1"
RELATIONAL_PROOF_IR_FORMAT = "stage-a-relational-proof-ir-v1"
RELATIONAL_SEGMENT_CERTIFICATE_FORMAT = (
    "stage-a-relational-segment-certificate-v1"
)
REGISTERS = {"eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp"}
MACHINE_CALL_ABI_REGISTERS = REGISTERS - {"esp"}
MACHINE_CALL_MEMORY_EFFECTS = {
    "none", "readOnly", "argumentRanges", "newDynamicRanges",
    "relationalState",
}
MACHINE_CALL_DISPOSITIONS = {"returns", "terminates", "protocol"}
MACHINE_CALL_RESULT_RELATIONS = {
    "exact", "related_word", "dynamic_range_base",
}
MACHINE_CALL_RESULT_WORD_RELATIONS = {
    "related_word", "code_pointer", "data_pointer", "nullable_dynamic_pointer",
}
MACHINE_CALL_WORLD_EFFECTS = {
    "none", "opaqueResources", "dynamicRanges", "dynamicRangeRelease",
    "callbackRegistration", "tlsState",
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
    "RelationalCallbacks",
    "RelationalCertificates",
    "RelationalStaticTree",
)
RELATIONAL_ACCEPTANCE_THEOREM = (
    "StageA.GeneratedRelational.candidatePE32ProgramsEquivalent"
)
RELATIONAL_PREPARED_REPORT_FILES = (
    "prepared-proof.json",
    "stage-a-interface-manifest.json",
    "module-graph.json",
    "relation-contract.json",
    "relational-proof-ir.json",
    "relational-semantic-ir.json",
    "relational-memory-contracts.json",
    "relational-static-word-relations.json",
    "relational-register-relations.json",
    "relational-stack-windows.json",
    "relational-segment-diagnostics.json",
    "relational-product-graph.json",
    "relational-invariants.json",
    "relational-machine-import-calls.json",
    "relational-external-call-sites.json",
    "relational-external-result-invariants.json",
    "relational-import-register-invariants.json",
    "relational-import-register-seeds.json",
    "relational-indirect-call-targets.json",
    "relational-bounded-table-call-inputs.json",
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


@dataclass(frozen=True)
class ProtocolCallbackFrameOffset:
    original_register: str
    original: int
    candidate_register: str
    candidate: int

    @classmethod
    def parse(cls, payload: Mapping[str, Any]) -> "ProtocolCallbackFrameOffset":
        if set(payload) != {
            "original_register", "original", "candidate_register", "candidate",
        }:
            raise SchemaError("callback frame offset has unexpected fields")
        original_register = payload.get("original_register")
        candidate_register = payload.get("candidate_register")
        original = integer(payload.get("original"))
        candidate = integer(payload.get("candidate"))
        if original_register not in REGISTERS or candidate_register not in REGISTERS:
            raise SchemaError("callback frame offset registers must be x86 registers")
        if (
            original is None or candidate is None
            or not 0 <= original < 2**32
            or not 0 <= candidate < 2**32
        ):
            raise SchemaError("callback frame offsets must be 32-bit words")
        return cls(
            original_register=str(original_register),
            original=original,
            candidate_register=str(candidate_register),
            candidate=candidate,
        )

    def to_payload(self) -> dict[str, Any]:
        return {
            "original_register": self.original_register,
            "original": self.original,
            "candidate_register": self.candidate_register,
            "candidate": self.candidate,
        }


@dataclass(frozen=True)
class ProtocolCallbackReturnInvariant:
    kind: str
    target_id: int | None = None

    @classmethod
    def parse(cls, payload: Mapping[str, Any]) -> "ProtocolCallbackReturnInvariant":
        kind = payload.get("kind")
        if kind == "terminal" and set(payload) == {"kind"}:
            return cls(kind="terminal")
        if kind == "region_input" and set(payload) == {"kind", "target_id"}:
            target_id = integer(payload.get("target_id"))
            if target_id is not None:
                return cls(kind="region_input", target_id=target_id)
        raise SchemaError("callback return invariant must name a supported invariant")

    def to_payload(self) -> dict[str, Any]:
        payload: dict[str, Any] = {"kind": self.kind}
        if self.target_id is not None:
            payload["target_id"] = self.target_id
        return payload


@dataclass(frozen=True)
class ProtocolCallbackControlState:
    target_id: int
    active_frame_offset: ProtocolCallbackFrameOffset
    return_invariant: ProtocolCallbackReturnInvariant

    @classmethod
    def parse(cls, payload: Mapping[str, Any]) -> "ProtocolCallbackControlState":
        if set(payload) != {
            "target_id", "active_frame_offset", "return_invariant",
        }:
            raise SchemaError("callback control state has unexpected fields")
        target_id = integer(payload.get("target_id"))
        active_frame_offset = payload.get("active_frame_offset")
        return_invariant = payload.get("return_invariant")
        if target_id is None:
            raise SchemaError("callback target_id must be an integer")
        if not isinstance(active_frame_offset, Mapping):
            raise SchemaError("callback active_frame_offset must be an object")
        if not isinstance(return_invariant, Mapping):
            raise SchemaError("callback return_invariant must be an object")
        return cls(
            target_id=target_id,
            active_frame_offset=ProtocolCallbackFrameOffset.parse(active_frame_offset),
            return_invariant=ProtocolCallbackReturnInvariant.parse(return_invariant),
        )

    def to_payload(self) -> dict[str, Any]:
        return {
            "target_id": self.target_id,
            "active_frame_offset": self.active_frame_offset.to_payload(),
            "return_invariant": self.return_invariant.to_payload(),
        }


@dataclass(frozen=True)
class ProtocolCallbackControl:
    states: tuple[ProtocolCallbackControlState, ...]
    format: str = PROTOCOL_CALLBACK_CONTROL_FORMAT

    @classmethod
    def parse(cls, payload: Mapping[str, Any]) -> "ProtocolCallbackControl":
        if set(payload) != {"format", "states"}:
            raise SchemaError("callback control inventory has unexpected fields")
        if payload.get("format") != PROTOCOL_CALLBACK_CONTROL_FORMAT:
            raise SchemaError("unsupported callback control inventory format")
        raw_states = payload.get("states")
        if not isinstance(raw_states, list):
            raise SchemaError("callback control states must be a list")
        states: list[ProtocolCallbackControlState] = []
        for raw_state in raw_states:
            if not isinstance(raw_state, Mapping):
                raise SchemaError("callback control state must be an object")
            states.append(ProtocolCallbackControlState.parse(raw_state))
        target_ids = [state.target_id for state in states]
        if len(target_ids) != len(set(target_ids)):
            raise SchemaError("callback control target ids must be unique")
        return cls(states=tuple(states))

    @classmethod
    def empty(cls) -> "ProtocolCallbackControl":
        return cls(states=())

    def to_payload(self) -> dict[str, Any]:
        return {
            "format": self.format,
            "states": [state.to_payload() for state in self.states],
        }


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
    interface_manifest: str
    relation_contract: str
    proof_ir: str
    semantic_ir: str
    memory_contracts: str
    static_word_relations: str
    register_relations: str
    stack_windows: str
    segment_diagnostics: str
    product_graph: str
    invariants: str
    whole_program_acceptance: str
    composition_progress: str
    module_graph: str

    @classmethod
    def parse(cls, payload: Mapping[str, Any]) -> "PreparedProofDigests":
        fields = {
            "interface_manifest": "interface_manifest_sha256",
            "relation_contract": "relation_contract_sha256",
            "proof_ir": "proof_ir_sha256",
            "semantic_ir": "semantic_ir_sha256",
            "memory_contracts": "memory_contracts_sha256",
            "static_word_relations": "static_word_relations_sha256",
            "register_relations": "register_relations_sha256",
            "stack_windows": "stack_windows_sha256",
            "segment_diagnostics": "segment_diagnostics_sha256",
            "product_graph": "product_graph_sha256",
            "invariants": "invariants_sha256",
            "whole_program_acceptance": "whole_program_acceptance_sha256",
            "composition_progress": "composition_progress_sha256",
            "module_graph": "module_graph_sha256",
        }
        return cls(**{
            name: _required_string(payload, field)
            for name, field in fields.items()
        })


@dataclass(frozen=True)
class StageAInterfaceManifest:
    format: str
    model: str
    acceptance_theorem: str
    schema_ids: tuple[str, ...]
    artifact_ids: tuple[str, ...]
    workstream_ids: tuple[str, ...]

    @classmethod
    def parse(cls, payload: Mapping[str, Any]) -> "StageAInterfaceManifest":
        if payload.get("format") != STAGE_A_INTERFACE_MANIFEST_FORMAT:
            raise SchemaError("unsupported Stage A interface manifest format")

        def unique_ids(field: str) -> tuple[str, ...]:
            rows = payload.get(field)
            if not isinstance(rows, list) or any(
                not isinstance(row, Mapping)
                or not isinstance(row.get("id"), str)
                or not row["id"]
                for row in rows
            ):
                raise SchemaError(f"{field} must be a list of identified objects")
            ids = tuple(str(row["id"]) for row in rows)
            if len(ids) != len(set(ids)):
                raise SchemaError(f"{field} ids must be unique")
            return ids

        workstreams = payload.get("workstreams")
        workstream_ids = unique_ids("workstreams")
        assert isinstance(workstreams, list)
        acceptance_owners = [
            row for row in workstreams
            if isinstance(row, Mapping) and row.get("acceptance_owner") is True
        ]
        if len(acceptance_owners) != 1:
            raise SchemaError("exactly one workstream must own acceptance integration")
        if any(
            not isinstance(row.get("parallel_safe"), bool)
            or not isinstance(row.get("owned_paths"), list)
            or not isinstance(row.get("integration_fixtures"), list)
            for row in workstreams
            if isinstance(row, Mapping)
        ):
            raise SchemaError("workstreams must declare ownership and integration fixtures")
        owned_paths = [
            str(path)
            for row in workstreams
            if isinstance(row, Mapping)
            for path in row.get("owned_paths", [])
        ]
        if len(owned_paths) != len(set(owned_paths)):
            raise SchemaError("workstream owned paths must be disjoint")
        if acceptance_owners[0].get("parallel_safe") is not False:
            raise SchemaError("acceptance integration must remain a serial merge point")
        acceptance = payload.get("acceptance")
        if not isinstance(acceptance, Mapping):
            raise SchemaError("interface manifest acceptance must be an object")
        theorem = _required_string(acceptance, "theorem")
        if acceptance.get("only_pass_authority") is not True:
            raise SchemaError("interface manifest must preserve the sole pass authority")
        return cls(
            format=str(payload["format"]),
            model=_required_string(payload, "model"),
            acceptance_theorem=theorem,
            schema_ids=unique_ids("schemas"),
            artifact_ids=unique_ids("artifacts"),
            workstream_ids=workstream_ids,
        )
