"""Generate exact static evidence for native x87 replay bridge targets.

This module deliberately has no acceptance path.  It binds a candidate PE to
its Stage B build manifest, discovers the native replay descriptor table from
exact data rather than symbols, and emits Lean proposals whose checks re-read
the candidate PE and relocation directory.  Runtime target preservation and
the nested call/return path remain Lean proof obligations.
"""

from __future__ import annotations

import json
import re
import struct
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Sequence

import capstone

from ...stage_binary import StageABinary, StageAInputError, _parse_stage_a_pe
from ...util import sha256_bytes, sha256_file, write_json


X87_REPLAY_BRIDGE_TARGET_PLAN_FORMAT = (
    "stage-a-relational-x87-replay-bridge-target-plan-v1"
)
X87_REPLAY_BRIDGE_TARGET_PLAN_FILENAME = "x87-replay-bridge-target-plan.json"
X87_REPLAY_BRIDGE_TARGET_LEAN_BUNDLE = (
    "GeneratedRelationalInterpreterX87ReplayBridgeTarget"
)
X87_REPLAY_BRIDGE_TARGET_PACK_PREFIX = (
    "GeneratedRelationalInterpreterX87ReplayBridgeTargetPack"
)
X87_REPLAY_BRIDGE_RELOCATION_DATA_MODULE = (
    "GeneratedInterpreterKernelDataRelocationBundle"
)
X87_REPLAY_BRIDGE_DESCRIPTOR_SIZE = 36
X87_REPLAY_BRIDGE_POINTER_OFFSETS = (16, 20, 24, 28, 32)
X87_REPLAY_BRIDGE_FUNCTION_POINTER_OFFSET = 32
X87_REPLAY_BRIDGE_PACK_SIZE = 8
X87_REPLAY_BRIDGE_BODY_SIZE = 176
X87_REPLAY_BRIDGE_INSTRUCTION_OFFSET = 52
X87_REPLAY_BRIDGE_CAPTURE_OFFSET = 72
X87_REPLAY_BRIDGE_RETURN_OFFSET = 171
X87_REPLAY_BRIDGE_ENTRY_ACTIVE_OPERAND_OFFSET = 5
X87_REPLAY_BRIDGE_CAPTURE_ACTIVE_OPERAND_OFFSET = 75

_BUILD_MANIFEST_FORMAT = "stage-b-interpreter-native-build-v1"
_ENGINE_PLAN_FORMAT = "stage-b-native-engine-plan-v1"
_X87_REPLAY_FORMAT = "stage-b-native-exact-x87-command-replay-program-v1"
_CHECKED_DECODER = "StageA.Relational.X87.decodeSingletonCommand"
_CHECKED_EXECUTOR = "StageA.Relational.X87.executeSingletonCommand"
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")


class X87ReplayBridgeTargetGenerationError(StageAInputError):
    """The requested artifact cannot be read as a bounded evidence input."""


class _EvidenceFailure(Exception):
    def __init__(self, code: str, message: str, *, rva: int | None = None):
        super().__init__(message)
        self.code = code
        self.message = message
        self.rva = rva


@dataclass(frozen=True)
class X87ReplayBridgeIssue:
    code: str
    message: str
    rva: int | None = None

    def payload(self) -> dict[str, Any]:
        result: dict[str, Any] = {"code": self.code, "message": self.message}
        if self.rva is not None:
            result["rva"] = self.rva
        return result


@dataclass(frozen=True)
class X87ReplayBridgeDescriptorPlan:
    id: int
    descriptor_rva: int
    image_base: int
    rva_start: int
    rva_end: int
    instruction_bytes: bytes
    instruction_bytes_sha256: str
    transfer_instruction_bytes_sha256: str
    contract_sha256: str
    checked_decoder: str
    checked_executor: str
    instruction_bytes_rva: int
    instruction_digest_rva: int
    transfer_digest_rva: int
    contract_digest_rva: int
    bridge_target_rva: int
    bridge_entry_bytes: bytes

    @property
    def pointer_cell_rvas(self) -> tuple[int, ...]:
        return tuple(
            self.descriptor_rva + offset for offset in X87_REPLAY_BRIDGE_POINTER_OFFSETS
        )

    def payload(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "descriptor_rva": self.descriptor_rva,
            "image_base": self.image_base,
            "rva_start": self.rva_start,
            "rva_end": self.rva_end,
            "instruction_bytes": self.instruction_bytes.hex(),
            "instruction_bytes_sha256": self.instruction_bytes_sha256,
            "transfer_instruction_bytes_sha256": (
                self.transfer_instruction_bytes_sha256
            ),
            "contract_sha256": self.contract_sha256,
            "checked_decoder": self.checked_decoder,
            "checked_executor": self.checked_executor,
            "instruction_bytes_rva": self.instruction_bytes_rva,
            "instruction_digest_rva": self.instruction_digest_rva,
            "transfer_digest_rva": self.transfer_digest_rva,
            "contract_digest_rva": self.contract_digest_rva,
            "bridge_target_rva": self.bridge_target_rva,
            "bridge_entry_bytes": self.bridge_entry_bytes.hex(),
            "pointer_cell_rvas": list(self.pointer_cell_rvas),
        }


@dataclass(frozen=True)
class X87ReplayBridgeFrameMappingPlan:
    descriptor_id: int
    bridge_target_rva: int
    instruction_rva: int
    capture_rva: int
    return_rva: int
    bridge_body_bytes: bytes
    instruction_path_bytes: bytes

    @property
    def entry_active_operand_rva(self) -> int:
        return (
            self.bridge_target_rva
            + X87_REPLAY_BRIDGE_ENTRY_ACTIVE_OPERAND_OFFSET
        )

    @property
    def capture_active_operand_rva(self) -> int:
        return (
            self.bridge_target_rva
            + X87_REPLAY_BRIDGE_CAPTURE_ACTIVE_OPERAND_OFFSET
        )

    def payload(self) -> dict[str, Any]:
        return {
            "descriptor_id": self.descriptor_id,
            "bridge_target_rva": self.bridge_target_rva,
            "instruction_rva": self.instruction_rva,
            "capture_rva": self.capture_rva,
            "return_rva": self.return_rva,
            "bridge_body_bytes": self.bridge_body_bytes.hex(),
            "instruction_path_bytes": self.instruction_path_bytes.hex(),
            "entry_active_operand_rva": self.entry_active_operand_rva,
            "capture_active_operand_rva": self.capture_active_operand_rva,
            "frame_offsets": {
                "parent": 0,
                "input": 4,
                "output": 8,
                "private_esp": 12,
                "status": 16,
                "input_x87": 20,
                "output_x87": 128,
            },
        }


@dataclass(frozen=True)
class X87ReplayBridgeTablePlan:
    table_rva: int
    call_site_rva: int
    call_instruction_bytes: bytes
    continuation_rva: int
    active_frame_pointer_rva: int
    active_frame_store_rva: int
    active_frame_store_bytes: bytes
    descriptor_load_rva: int
    descriptor_load_bytes: bytes
    target_load_rva: int
    target_load_bytes: bytes
    active_frame_load_rva: int
    active_frame_load_bytes: bytes
    descriptors: tuple[X87ReplayBridgeDescriptorPlan, ...]
    frame_mappings: tuple[X87ReplayBridgeFrameMappingPlan, ...]

    @property
    def active_frame_store_operand_rva(self) -> int:
        return self.active_frame_store_rva + 1

    @property
    def active_frame_load_operand_rva(self) -> int:
        return self.active_frame_load_rva + 2

    def payload(self) -> dict[str, Any]:
        targets = tuple(row.bridge_target_rva for row in self.descriptors)
        return {
            "table_rva": self.table_rva,
            "descriptor_size": X87_REPLAY_BRIDGE_DESCRIPTOR_SIZE,
            "descriptor_count": len(self.descriptors),
            "table_size": len(self.descriptors) * X87_REPLAY_BRIDGE_DESCRIPTOR_SIZE,
            "call_site_rva": self.call_site_rva,
            "call_instruction_bytes": self.call_instruction_bytes.hex(),
            "continuation_rva": self.continuation_rva,
            "active_frame_pointer_rva": self.active_frame_pointer_rva,
            "active_frame_store_rva": self.active_frame_store_rva,
            "active_frame_store_bytes": self.active_frame_store_bytes.hex(),
            "active_frame_store_operand_rva": self.active_frame_store_operand_rva,
            "descriptor_load_rva": self.descriptor_load_rva,
            "descriptor_load_bytes": self.descriptor_load_bytes.hex(),
            "target_load_rva": self.target_load_rva,
            "target_load_bytes": self.target_load_bytes.hex(),
            "active_frame_load_rva": self.active_frame_load_rva,
            "active_frame_load_bytes": self.active_frame_load_bytes.hex(),
            "active_frame_load_operand_rva": self.active_frame_load_operand_rva,
            "target_count": len(targets),
            "target_rvas": list(targets),
            "descriptors": [row.payload() for row in self.descriptors],
            "frame_mappings": [row.payload() for row in self.frame_mappings],
        }


@dataclass(frozen=True)
class X87ReplayBridgeTargetPlan:
    candidate_path: Path
    candidate_sha256: str
    candidate_size: int
    build_manifest_sha256: str
    native_engine_plan_sha256: str
    requested_call_site_rva: int | None
    table: X87ReplayBridgeTablePlan | None
    issues: tuple[X87ReplayBridgeIssue, ...]

    @property
    def evidence_ready(self) -> bool:
        return self.table is not None and not self.issues

    @property
    def obligations(self) -> tuple[dict[str, Any], ...]:
        if not self.evidence_ready:
            return tuple(
                {
                    "id": f"x87-replay-bridge-frontier:{index:04d}",
                    "family": "x87_replay_bridge_target_frontier",
                    "status": "incomplete",
                    "reason_code": issue.code,
                    "rva": issue.rva,
                    "message": issue.message,
                }
                for index, issue in enumerate(self.issues)
            )
        assert self.table is not None
        stem = f"x87-replay-bridge:{self.table.call_site_rva:08x}"
        return (
            {
                "id": f"{stem}:static-table-and-relocations",
                "family": "x87_replay_bridge_static_inventory",
                "status": "pending_lean_check",
            },
            {
                "id": f"{stem}:runtime-target-preservation",
                "family": "x87_replay_bridge_runtime_target",
                "status": "pending_lean_theorem",
                "requirements": [
                    "selected_descriptor_membership",
                    "target_cell_holds_before_call",
                    "target_cell_holds_after_return",
                ],
            },
            {
                "id": f"{stem}:nested-runtime-frame",
                "family": "x87_replay_bridge_nested_runtime_frame",
                "status": "pending_lean_theorem",
                "requirements": [
                    "active_frame_pointer_preserved",
                    "parent_frame_pointer_preserved",
                    "private_stack_established",
                    "input_and_output_x87_frames_exact",
                ],
            },
            {
                "id": f"{stem}:exact-event-world-effects",
                "family": "x87_replay_bridge_execution",
                "status": "pending_lean_theorem",
                "requirements": [
                    "exact_indirect_call_transition",
                    "event_free_nested_path",
                    "external_event_index_preserved",
                    "external_events_preserved",
                    "relational_world_preserved",
                    "external_callback_frames_preserved",
                ],
            },
        )

    def payload(self) -> dict[str, Any]:
        core: dict[str, Any] = {
            "format": X87_REPLAY_BRIDGE_TARGET_PLAN_FORMAT,
            "status": "evidence_ready" if self.evidence_ready else "incomplete",
            "acceptance_authority": False,
            "authority": (
                "untrusted static proposal; Lean must check exact PE evidence and "
                "the dynamic nested execution refinement"
            ),
            "candidate": {
                "path": self.candidate_path.name,
                "sha256": self.candidate_sha256,
                "size": self.candidate_size,
            },
            "inputs": {
                "build_manifest_sha256": self.build_manifest_sha256,
                "native_engine_plan_sha256": self.native_engine_plan_sha256,
            },
            "requested_call_site_rva": self.requested_call_site_rva,
            "counts": {
                "descriptors": 0 if self.table is None else len(self.table.descriptors),
                "finite_targets": 0
                if self.table is None
                else len(self.table.descriptors),
                "dynamic_frame_mappings": 0
                if self.table is None
                else len(self.table.frame_mappings),
                "static_frontiers": len(self.issues),
                "pending_lean_obligations": 0 if self.table is None else 4,
            },
            "table": None if self.table is None else self.table.payload(),
            "issues": [issue.payload() for issue in self.issues],
            "proof_obligations": list(self.obligations),
        }
        core["artifact_sha256"] = sha256_bytes(
            json.dumps(core, sort_keys=True, separators=(",", ":")).encode()
        )
        return core


@dataclass(frozen=True)
class _CallPathEvidence:
    active_frame_pointer_rva: int
    active_frame_store_rva: int
    active_frame_store_bytes: bytes
    descriptor_load_rva: int
    descriptor_load_bytes: bytes
    target_load_rva: int
    target_load_bytes: bytes
    active_frame_load_rva: int
    active_frame_load_bytes: bytes


def build_x87_replay_bridge_target_plan(
    *,
    candidate_pe: Path | str,
    build_manifest: Path | str,
    native_engine_plan: Path | str,
    call_site_rva: int | None = None,
) -> X87ReplayBridgeTargetPlan:
    """Build a fail-closed static proposal for one x87 replay call site.

    When no RVA is supplied, the exact candidate must contain one unique call
    path satisfying the full descriptor-flow, relocation, and active-frame
    checks.  Zero or multiple matching paths remain incomplete.
    """

    candidate_path = _file(candidate_pe, "candidate PE")
    manifest_path = _file(build_manifest, "candidate build manifest")
    engine_path = _file(native_engine_plan, "native engine plan")
    if call_site_rva is not None and (
        isinstance(call_site_rva, bool) or not 0 <= call_site_rva < 2**32
    ):
        raise X87ReplayBridgeTargetGenerationError(
            "x87 replay call site RVA must be a uint32"
        )

    candidate_sha256 = sha256_file(candidate_path)
    candidate_size = candidate_path.stat().st_size
    manifest_sha256 = sha256_file(manifest_path)
    engine_sha256 = sha256_file(engine_path)
    binary = _parse_stage_a_pe(candidate_path)
    table: X87ReplayBridgeTablePlan | None = None
    issues: tuple[X87ReplayBridgeIssue, ...] = ()
    try:
        manifest = _json_object(manifest_path, "candidate build manifest")
        engine = _json_object(engine_path, "native engine plan")
        _check_manifest_binding(
            manifest,
            candidate_sha256=candidate_sha256,
            candidate_size=candidate_size,
            native_engine_plan_sha256=engine_sha256,
        )
        replay_rows = _validated_replay_rows(engine, binary)
        descriptors = _discover_descriptor_table(binary, replay_rows)
        selected_call_site_rva = call_site_rva
        if selected_call_site_rva is None:
            selected_call_site_rva, call = _discover_unique_call_path(binary)
        else:
            call = _validate_call_path(binary, selected_call_site_rva)
        frame_mappings = _discover_bridge_frame_mappings(
            binary,
            descriptors,
            active_frame_pointer_rva=call.active_frame_pointer_rva,
        )
        table = X87ReplayBridgeTablePlan(
            table_rva=descriptors[0].descriptor_rva,
            call_site_rva=selected_call_site_rva,
            call_instruction_bytes=b"\xff\xd0",
            continuation_rva=selected_call_site_rva + 2,
            active_frame_pointer_rva=call.active_frame_pointer_rva,
            active_frame_store_rva=call.active_frame_store_rva,
            active_frame_store_bytes=call.active_frame_store_bytes,
            descriptor_load_rva=call.descriptor_load_rva,
            descriptor_load_bytes=call.descriptor_load_bytes,
            target_load_rva=call.target_load_rva,
            target_load_bytes=call.target_load_bytes,
            active_frame_load_rva=call.active_frame_load_rva,
            active_frame_load_bytes=call.active_frame_load_bytes,
            descriptors=descriptors,
            frame_mappings=frame_mappings,
        )
    except _EvidenceFailure as exc:
        issues = (X87ReplayBridgeIssue(exc.code, exc.message, exc.rva),)
    finally:
        binary.pe.close()

    return X87ReplayBridgeTargetPlan(
        candidate_path=candidate_path,
        candidate_sha256=candidate_sha256,
        candidate_size=candidate_size,
        build_manifest_sha256=manifest_sha256,
        native_engine_plan_sha256=engine_sha256,
        requested_call_site_rva=call_site_rva,
        table=table,
        issues=issues,
    )


def x87_replay_bridge_target_lean_sources(
    plan: X87ReplayBridgeTargetPlan,
    *,
    candidate_data_module: str = "GeneratedInterpreterKernelDataBase",
    relocation_data_module: str | None = None,
    pack_size: int = X87_REPLAY_BRIDGE_PACK_SIZE,
) -> dict[str, str]:
    """Render cacheable generated Lean modules for a complete static proposal."""

    if not plan.evidence_ready or plan.table is None:
        raise X87ReplayBridgeTargetGenerationError(
            "cannot emit Lean for an incomplete x87 replay bridge target plan"
        )
    if isinstance(pack_size, bool) or pack_size <= 0:
        raise X87ReplayBridgeTargetGenerationError("pack size must be positive")
    if relocation_data_module is None:
        relocation_data_module = (
            X87_REPLAY_BRIDGE_RELOCATION_DATA_MODULE
            if candidate_data_module == "GeneratedInterpreterKernelDataBase"
            else candidate_data_module
        )
    for role, module in (
        ("candidate data", candidate_data_module),
        ("relocation data", relocation_data_module),
    ):
        if not re.fullmatch(r"[A-Za-z][A-Za-z0-9_]*", module):
            raise X87ReplayBridgeTargetGenerationError(
                f"{role} module must be a simple Lean module name"
            )

    data_imports = [f"import StageA.{candidate_data_module}"]
    if relocation_data_module != candidate_data_module:
        data_imports.append(f"import StageA.{relocation_data_module}")
    data_import_block = "\n".join(data_imports)

    sources: dict[str, str] = {}
    descriptor_names: list[str] = []
    frame_mapping_names: list[str] = []
    frame_mapping_checked_names: list[str] = []
    target_binding_names: list[str] = []
    pack_names: list[str] = []
    pack_modules: list[str] = []
    rows = plan.table.descriptors
    mappings = plan.table.frame_mappings
    if tuple(row.id for row in rows) != tuple(
        mapping.descriptor_id for mapping in mappings
    ):
        raise X87ReplayBridgeTargetGenerationError(
            "descriptor and dynamic-frame mapping inventories differ"
        )
    for pack_index, start in enumerate(range(0, len(rows), pack_size)):
        pack_rows = rows[start : start + pack_size]
        pack_mappings = mappings[start : start + pack_size]
        module = f"{X87_REPLAY_BRIDGE_TARGET_PACK_PREFIX}{pack_index:04d}"
        pack_modules.append(module)
        names = [f"generatedX87ReplayBridgeDescriptor{row.id:04d}" for row in pack_rows]
        descriptor_names.extend(names)
        mapping_names = [
            f"generatedX87ReplayBridgeFrameMapping{row.id:04d}"
            for row in pack_rows
        ]
        mapping_checked_names = [f"{name}Checked" for name in mapping_names]
        frame_mapping_names.extend(mapping_names)
        frame_mapping_checked_names.extend(mapping_checked_names)
        target_binding_names.extend(
            f"generatedX87ReplayBridgeTargetBinding{row.id:04d}"
            for row in pack_rows
        )
        pack_name = f"generatedX87ReplayBridgeDescriptorPack{pack_index:04d}"
        pack_names.append(pack_name)
        definitions = "\n\n".join(
            "\n\n".join(
                (
                    _lean_descriptor(name, row),
                    _lean_frame_mapping(mapping_name, mapping),
                    (
                        f"theorem {checked_name} :\n"
                        f"    {mapping_name}.checked "
                        f"{plan.table.active_frame_pointer_rva} {name} "
                        "generatedInterpreterKernelCandidatePe "
                        "generatedInterpreterKernelImports "
                        "generatedInterpreterKernelRelocations = true := by\n"
                        "  decide +kernel"
                    ),
                )
            )
            for name, mapping_name, checked_name, row, mapping in zip(
                names,
                mapping_names,
                mapping_checked_names,
                pack_rows,
                pack_mappings,
            )
        )
        sources[
            f"{module}.lean"
        ] = f"""import StageA.RelationalInterpreterX87ReplayBridgeTarget
{data_import_block}

set_option autoImplicit false

namespace StageA.GeneratedRelational.InterpreterX87ReplayBridgeTarget

open StageA.Formal StageA.Relational
open StageA.Relational.InterpreterKernel
open StageA.Relational.InterpreterKernelCallback
open StageA.Relational.InterpreterKernelData
open StageA.Relational.InterpreterX87ReplayBridgeTarget
open StageA.GeneratedRelational.InterpreterKernelData

set_option maxRecDepth 1000000
set_option maxHeartbeats 0

{definitions}

def {pack_name} : NativeX87ReplayBridgeDescriptorPack
    generatedInterpreterKernelCandidatePe generatedInterpreterKernelImports
    generatedInterpreterKernelRelocations := {{
  descriptors := [{", ".join(names)}]
  checked := by decide +kernel
}}

end StageA.GeneratedRelational.InterpreterX87ReplayBridgeTarget
"""

    pack_imports = "\n".join(f"import StageA.{module}" for module in pack_modules)
    sources[f"{X87_REPLAY_BRIDGE_TARGET_LEAN_BUNDLE}.lean"] = f"""{pack_imports}

set_option autoImplicit false

namespace StageA.GeneratedRelational.InterpreterX87ReplayBridgeTarget

open StageA.Formal StageA.Relational
open StageA.Relational.InterpreterKernel
open StageA.Relational.InterpreterKernelData
open StageA.Relational.InterpreterNativeWorld
open StageA.Relational.InterpreterX87
open StageA.Relational.InterpreterX87ReplayBridgeTarget
open StageA.GeneratedRelational.InterpreterKernelData

set_option maxRecDepth 1000000
set_option maxHeartbeats 0

def generatedX87ReplayBridgeDescriptors :
    List NativeX87ReplayBridgeDescriptor :=
  [{", ".join(descriptor_names)}]

def generatedX87ReplayBridgeTable : NativeX87ReplayBridgeTable := {{
  tableRva := {plan.table.table_rva}
  activeFramePointerRva := {plan.table.active_frame_pointer_rva}
  activeFrameStoreInstruction := {{
    rva := {plan.table.active_frame_store_rva}
    bytes := {_lean_bytes(plan.table.active_frame_store_bytes)}
  }}
  descriptorLoadInstruction := {{
    rva := {plan.table.descriptor_load_rva}
    bytes := {_lean_bytes(plan.table.descriptor_load_bytes)}
  }}
  targetLoadInstruction := {{
    rva := {plan.table.target_load_rva}
    bytes := {_lean_bytes(plan.table.target_load_bytes)}
  }}
  callInstruction := {{
    rva := {plan.table.call_site_rva}
    bytes := {_lean_bytes(plan.table.call_instruction_bytes)}
  }}
  activeFrameLoadInstruction := {{
    rva := {plan.table.active_frame_load_rva}
    bytes := {_lean_bytes(plan.table.active_frame_load_bytes)}
  }}
  continuationRva := {plan.table.continuation_rva}
  descriptors := generatedX87ReplayBridgeDescriptors
}}

def generatedX87ReplayBridgeDescriptorPacks : List
    (NativeX87ReplayBridgeDescriptorPack
      generatedInterpreterKernelCandidatePe generatedInterpreterKernelImports
      generatedInterpreterKernelRelocations) :=
  [{", ".join(pack_names)}]

def generatedX87ReplayBridgeCandidateSha256 : String :=
  {json.dumps(plan.candidate_sha256)}

def generatedX87ReplayBridgeCandidateSize : Nat := {plan.candidate_size}

theorem generatedX87ReplayBridgeCandidateSizeExact :
    generatedX87ReplayBridgeCandidateSize =
      generatedInterpreterKernelCandidatePe.bytes.length := by
  decide +kernel

theorem generatedX87ReplayBridgeCandidateDigestShape :
    generatedX87ReplayBridgeCandidateSha256.length = 64 := by
  decide +kernel

def generatedX87ReplayBridgeNativeTargetInventory :
    NativeIndirectTargetInventory :=
  generatedX87ReplayBridgeTable.nativeTargetInventory

def generatedX87ReplayBridgeStaticCertificate :
    ExactNativeX87ReplayBridgeStaticCertificate
      generatedX87ReplayBridgeTable generatedInterpreterKernelCandidatePe
      generatedInterpreterKernelImports generatedInterpreterKernelRelocations
      generatedX87ReplayBridgeDescriptorPacks := {{
  relocationsParsed := generatedInterpreterKernelRelocationsParsed
  packsExact := by decide +kernel
  shapeChecked := by decide +kernel
}}

{"".join(
    _lean_target_binding(
        binding_name,
        descriptor_name,
        mapping_name,
        mapping_checked_name,
    )
    for binding_name, descriptor_name, mapping_name, mapping_checked_name in zip(
        target_binding_names,
        descriptor_names,
        frame_mapping_names,
        frame_mapping_checked_names,
    )
)}

def generatedX87ReplayBridgeTargetBindings : List
    (ExactNativeX87ReplayBridgeTargetBinding generatedX87ReplayBridgeTable
      generatedInterpreterKernelCandidatePe generatedInterpreterKernelImports
      generatedInterpreterKernelRelocations
      generatedX87ReplayBridgeDescriptorPacks) :=
  [{", ".join(target_binding_names)}]

def generatedX87ReplayBridgeTargetInventory :
    ExactNativeX87ReplayBridgeTargetInventory generatedX87ReplayBridgeTable
      generatedInterpreterKernelCandidatePe generatedInterpreterKernelImports
      generatedInterpreterKernelRelocations
      generatedX87ReplayBridgeDescriptorPacks := {{
  bindings := generatedX87ReplayBridgeTargetBindings
  descriptorsExact := by decide +kernel
  candidateDigestExact := by
    exact ⟨generatedX87ReplayBridgeCandidateSha256, by decide +kernel⟩
}}

def GeneratedX87ReplayBridgeExecutionGoal
    (program : ExactNestedNativeWorldProgram)
    (handler : CandidateReplayHandler)
    (sourceInvariant : NativeX87ReplayBridgeDescriptor ->
      MachineState -> MachineState -> Prop) : Prop :=
  ExactNativeX87ReplayBridgeExecutionRefinement program
    generatedX87ReplayBridgeTable handler sourceInvariant

def GeneratedX87ReplayBridgeTargetRuntimeGoal
    (targetId : Fin generatedX87ReplayBridgeTargetBindings.length)
    (program : ExactNestedNativeWorldProgram)
    (handler : CandidateReplayHandler)
    (sourceInvariant : NativeX87ReplayBridgeDescriptor ->
      MachineState -> MachineState -> Prop) : Prop :=
  (generatedX87ReplayBridgeTargetBindings.get targetId).RuntimeGoal
    program handler sourceInvariant

end StageA.GeneratedRelational.InterpreterX87ReplayBridgeTarget
"""
    return sources


def write_x87_replay_bridge_target_bundle(
    *,
    candidate_pe: Path | str,
    build_manifest: Path | str,
    native_engine_plan: Path | str,
    call_site_rva: int | None = None,
    out_dir: Path | str,
    candidate_data_module: str = "GeneratedInterpreterKernelDataBase",
    relocation_data_module: str | None = None,
    pack_size: int = X87_REPLAY_BRIDGE_PACK_SIZE,
) -> X87ReplayBridgeTargetPlan:
    output = Path(out_dir)
    output.mkdir(parents=True, exist_ok=True)
    plan = build_x87_replay_bridge_target_plan(
        candidate_pe=candidate_pe,
        build_manifest=build_manifest,
        native_engine_plan=native_engine_plan,
        call_site_rva=call_site_rva,
    )
    write_json(output / X87_REPLAY_BRIDGE_TARGET_PLAN_FILENAME, plan.payload())
    bundle_path = output / f"{X87_REPLAY_BRIDGE_TARGET_LEAN_BUNDLE}.lean"
    if not plan.evidence_ready:
        bundle_path.unlink(missing_ok=True)
        for old_pack in output.glob(f"{X87_REPLAY_BRIDGE_TARGET_PACK_PREFIX}*.lean"):
            old_pack.unlink()
        return plan
    sources = x87_replay_bridge_target_lean_sources(
        plan,
        candidate_data_module=candidate_data_module,
        relocation_data_module=relocation_data_module,
        pack_size=pack_size,
    )
    for filename, source in sources.items():
        (output / filename).write_text(source, encoding="ascii")
    return plan


def _check_manifest_binding(
    manifest: Mapping[str, Any],
    *,
    candidate_sha256: str,
    candidate_size: int,
    native_engine_plan_sha256: str,
) -> None:
    if manifest.get("format") != _BUILD_MANIFEST_FORMAT:
        _fail(
            "unsupported_build_manifest", "unsupported candidate build manifest format"
        )
    outputs = _mapping(manifest.get("outputs"), "build manifest outputs")
    candidate = _mapping(outputs.get("candidate"), "build manifest candidate")
    if (
        candidate.get("sha256") != candidate_sha256
        or candidate.get("size") != candidate_size
    ):
        _fail(
            "candidate_manifest_mismatch",
            "candidate bytes do not match the build manifest SHA-256 and size",
        )
    inputs = _mapping(manifest.get("inputs"), "build manifest inputs")
    runtime = _mapping(inputs.get("runtime_plan"), "build manifest runtime plan")
    linked = _mapping(runtime.get("native_engine_plan"), "linked native engine plan")
    if linked.get("sha256") != native_engine_plan_sha256:
        _fail(
            "native_engine_plan_manifest_mismatch",
            "native engine plan does not match the plan linked by the candidate",
        )
    package = _mapping(inputs.get("native_engine_package"), "native engine package")
    artifacts = _list(package.get("artifacts"), "native engine artifacts")
    plan_hashes = [
        _mapping(row, "native engine artifact").get("sha256")
        for row in artifacts
        if _mapping(row, "native engine artifact").get("role") == "plan"
    ]
    if plan_hashes != [native_engine_plan_sha256]:
        _fail(
            "native_engine_package_plan_mismatch",
            "candidate package does not contain exactly the linked native engine plan",
        )


def _validated_replay_rows(
    engine: Mapping[str, Any], binary: StageABinary
) -> tuple[Mapping[str, Any], ...]:
    if engine.get("format") != _ENGINE_PLAN_FORMAT or engine.get("status") != "ready":
        _fail("native_engine_plan_not_ready", "native engine plan is not ready")
    if _list(engine.get("blockers"), "native engine blockers"):
        _fail("native_engine_plan_blocked", "native engine plan contains blockers")
    rows = _list(engine.get("x87_replays"), "native engine x87 replays")
    if not rows:
        _fail("missing_x87_replays", "native engine plan has no x87 replay descriptors")
    result: list[Mapping[str, Any]] = []
    for index, raw in enumerate(rows):
        row = _mapping(raw, f"x87 replay {index}")
        if row.get("format") != _X87_REPLAY_FORMAT:
            _fail(
                "unsupported_x87_replay",
                f"x87 replay {index} has an unsupported format",
            )
        if _u32(row.get("id"), f"x87 replay {index} id") != index:
            _fail(
                "noncanonical_x87_ids", "x87 replay IDs are not contiguous and ordered"
            )
        if _u32(row.get("image_base"), "x87 replay image base") != binary.image_base:
            _fail(
                "x87_image_base_mismatch",
                f"x87 replay {index} has the wrong image base",
            )
        data = _hex_bytes(row.get("instruction_bytes"), "x87 instruction bytes")
        start = _u32(row.get("rva_start"), "x87 replay start RVA")
        end = _u32(row.get("rva_end"), "x87 replay end RVA")
        if not data or end != start + len(data):
            _fail("invalid_x87_span", f"x87 replay {index} has an invalid byte span")
        if row.get("instruction_count") != 1:
            _fail(
                "unsupported_x87_instruction_count",
                f"x87 replay {index} is not a singleton",
            )
        _validate_embedded_relocation(
            row.get("base_relocation"), data, start, binary.image_base, index
        )
        digest = _digest(row.get("instruction_bytes_sha256"), "x87 instruction digest")
        if sha256_bytes(data) != digest:
            _fail(
                "x87_instruction_digest_mismatch",
                f"x87 replay {index} byte digest is stale",
            )
        _digest(row.get("transfer_instruction_bytes_sha256"), "x87 transfer digest")
        _digest(row.get("contract_sha256"), "x87 contract digest")
        if row.get("checked_decoder") != _CHECKED_DECODER:
            _fail(
                "unsupported_x87_decoder",
                f"x87 replay {index} names an unsupported decoder",
            )
        if row.get("checked_executor") != _CHECKED_EXECUTOR:
            _fail(
                "unsupported_x87_executor",
                f"x87 replay {index} names an unsupported executor",
            )
        result.append(row)
    return tuple(result)


def _validate_embedded_relocation(
    raw: Any, instruction: bytes, start_rva: int, image_base: int, index: int
) -> None:
    """Check proposal consistency; the original-side Lean schedule owns authority."""

    if raw is None:
        return
    relocation = _mapping(raw, f"x87 replay {index} base relocation")
    offset = _u32(
        relocation.get("operand_byte_offset"), "x87 relocation operand offset"
    )
    if (
        relocation.get("kind") != "highlow"
        or relocation.get("type") != 3
        or relocation.get("width") != 4
        or offset + 4 > len(instruction)
        or relocation.get("source_rva") != start_rva + offset
    ):
        _fail(
            "malformed_x87_embedded_relocation",
            f"x87 replay {index} has inconsistent HIGHLOW relocation metadata",
        )
    preferred = struct.unpack_from("<I", instruction, offset)[0]
    if relocation.get("preferred_value") != preferred:
        _fail(
            "x87_embedded_relocation_value_mismatch",
            f"x87 replay {index} relocation value disagrees with its exact bytes",
        )
    target_rva = _u32(relocation.get("target_rva"), "x87 relocation target RVA")
    if preferred < image_base or preferred - image_base != target_rva:
        _fail(
            "x87_embedded_relocation_target_mismatch",
            f"x87 replay {index} relocation target is inconsistent",
        )
    _digest(relocation.get("pe_sha256"), "x87 relocation PE digest")
    _digest(
        relocation.get("reference_contract_sha256"),
        "x87 relocation reference contract digest",
    )


def _discover_descriptor_table(
    binary: StageABinary, rows: Sequence[Mapping[str, Any]]
) -> tuple[X87ReplayBridgeDescriptorPlan, ...]:
    first = rows[0]
    first_bytes = _hex_bytes(first.get("instruction_bytes"), "first replay bytes")
    needle = struct.pack(
        "<IIII",
        binary.image_base,
        _u32(first.get("rva_start"), "first replay start"),
        _u32(first.get("rva_end"), "first replay end"),
        len(first_bytes),
    )
    image = binary.path.read_bytes()
    candidates: list[tuple[int, bool]] = []
    for section in binary.sections:
        if section.raw_size < len(needle):
            continue
        raw = image[section.raw_pointer : section.raw_pointer + section.raw_size]
        cursor = 0
        while True:
            found = raw.find(needle, cursor)
            if found < 0:
                break
            rva = section.rva_start + found
            if rva % 4 == 0 and _scalar_table_matches(binary, rva, rows):
                candidates.append((rva, section.writable))
            cursor = found + 1
    if not candidates:
        _fail(
            "missing_x87_descriptor_table",
            "no exact x87 replay descriptor table was found",
        )
    if len(candidates) != 1:
        _fail(
            "ambiguous_x87_descriptor_table",
            f"found {len(candidates)} immutable x87 replay descriptor tables",
        )
    table_rva, writable = candidates[0]
    if writable:
        _fail(
            "mutable_x87_descriptor_table",
            f"exact x87 replay descriptor table at RVA 0x{table_rva:x} is writable",
            rva=table_rva,
        )
    _immutable_bytes(
        binary,
        table_rva,
        len(rows) * X87_REPLAY_BRIDGE_DESCRIPTOR_SIZE,
        "x87 descriptor table",
    )
    relocation_counts = _highlow_relocation_counts(binary)
    descriptors = tuple(
        _validate_descriptor(binary, relocation_counts, table_rva, index, row)
        for index, row in enumerate(rows)
    )
    target_rvas = [row.bridge_target_rva for row in descriptors]
    if len(set(target_rvas)) != len(target_rvas):
        _fail(
            "ambiguous_x87_bridge_targets",
            "x87 replay bridge target RVAs are not unique",
        )
    return descriptors


def _scalar_table_matches(
    binary: StageABinary, table_rva: int, rows: Sequence[Mapping[str, Any]]
) -> bool:
    try:
        for index, row in enumerate(rows):
            rva = table_rva + index * X87_REPLAY_BRIDGE_DESCRIPTOR_SIZE
            data = _candidate_bytes(binary, rva, 16, "x87 descriptor scalars")
            expected = (
                binary.image_base,
                _u32(row.get("rva_start"), "x87 replay start"),
                _u32(row.get("rva_end"), "x87 replay end"),
                len(_hex_bytes(row.get("instruction_bytes"), "x87 replay bytes")),
            )
            if struct.unpack("<IIII", data) != expected:
                return False
    except _EvidenceFailure:
        return False
    return True


def _validate_descriptor(
    binary: StageABinary,
    relocation_counts: Mapping[int, int],
    table_rva: int,
    index: int,
    row: Mapping[str, Any],
) -> X87ReplayBridgeDescriptorPlan:
    descriptor_rva = table_rva + index * X87_REPLAY_BRIDGE_DESCRIPTOR_SIZE
    raw = _immutable_bytes(
        binary, descriptor_rva, X87_REPLAY_BRIDGE_DESCRIPTOR_SIZE, "x87 descriptor"
    )
    words = struct.unpack("<IIIIIIIII", raw)
    for offset in X87_REPLAY_BRIDGE_POINTER_OFFSETS:
        field_rva = descriptor_rva + offset
        if relocation_counts.get(field_rva, 0) != 1:
            _fail(
                "x87_pointer_relocation_not_unique",
                f"x87 descriptor pointer at RVA 0x{field_rva:x} does not have exactly one HIGHLOW relocation",
                rva=field_rva,
            )
    pointer_rvas = tuple(
        _pointer_to_rva(binary, words[offset // 4], f"x87 descriptor {index} pointer")
        for offset in X87_REPLAY_BRIDGE_POINTER_OFFSETS
    )
    data = _hex_bytes(row.get("instruction_bytes"), "x87 replay bytes")
    instruction_digest = _digest(
        row.get("instruction_bytes_sha256"), "x87 instruction digest"
    )
    transfer_digest = _digest(
        row.get("transfer_instruction_bytes_sha256"), "x87 transfer digest"
    )
    contract_digest = _digest(row.get("contract_sha256"), "x87 contract digest")
    if _immutable_bytes(binary, pointer_rvas[0], len(data), "x87 replay bytes") != data:
        _fail(
            "x87_replay_bytes_mismatch",
            f"x87 descriptor {index} points to different instruction bytes",
        )
    expected_strings = (instruction_digest, transfer_digest, contract_digest)
    for pointer_rva, expected in zip(pointer_rvas[1:4], expected_strings):
        if _immutable_cstring(binary, pointer_rva, "x87 descriptor digest") != expected:
            _fail(
                "x87_replay_digest_pointer_mismatch",
                f"x87 descriptor {index} points to a different digest",
            )
    bridge_entry = _exact_instruction(binary, pointer_rvas[4], "x87 bridge target")
    return X87ReplayBridgeDescriptorPlan(
        id=index,
        descriptor_rva=descriptor_rva,
        image_base=binary.image_base,
        rva_start=_u32(row.get("rva_start"), "x87 replay start"),
        rva_end=_u32(row.get("rva_end"), "x87 replay end"),
        instruction_bytes=data,
        instruction_bytes_sha256=instruction_digest,
        transfer_instruction_bytes_sha256=transfer_digest,
        contract_sha256=contract_digest,
        checked_decoder=_string(row.get("checked_decoder"), "x87 checked decoder"),
        checked_executor=_string(row.get("checked_executor"), "x87 checked executor"),
        instruction_bytes_rva=pointer_rvas[0],
        instruction_digest_rva=pointer_rvas[1],
        transfer_digest_rva=pointer_rvas[2],
        contract_digest_rva=pointer_rvas[3],
        bridge_target_rva=pointer_rvas[4],
        bridge_entry_bytes=bridge_entry,
    )


def _discover_bridge_frame_mappings(
    binary: StageABinary,
    descriptors: Sequence[X87ReplayBridgeDescriptorPlan],
    *,
    active_frame_pointer_rva: int,
) -> tuple[X87ReplayBridgeFrameMappingPlan, ...]:
    relocation_counts = _highlow_relocation_counts(binary)
    mappings = tuple(
        _validate_bridge_frame_mapping(
            binary,
            descriptor,
            active_frame_pointer_rva=active_frame_pointer_rva,
            relocation_counts=relocation_counts,
        )
        for descriptor in descriptors
    )
    if tuple(row.descriptor_id for row in mappings) != tuple(
        row.id for row in descriptors
    ):
        _fail(
            "x87_bridge_frame_inventory_mismatch",
            "x87 replay bridge frame mappings do not cover every descriptor in order",
        )
    body_ranges = sorted(
        (
            row.bridge_target_rva,
            row.bridge_target_rva + len(row.bridge_body_bytes),
        )
        for row in mappings
    )
    for previous, current in zip(body_ranges, body_ranges[1:]):
        if current[0] < previous[1]:
            _fail(
                "overlapping_x87_bridge_bodies",
                "x87 replay bridge target bodies overlap",
                rva=current[0],
            )
    instruction_rvas = [row.instruction_rva for row in mappings]
    if len(set(instruction_rvas)) != len(instruction_rvas):
        _fail(
            "ambiguous_x87_instruction_paths",
            "multiple x87 replay descriptors select the same instruction path",
        )
    return mappings


def _validate_bridge_frame_mapping(
    binary: StageABinary,
    descriptor: X87ReplayBridgeDescriptorPlan,
    *,
    active_frame_pointer_rva: int,
    relocation_counts: Mapping[int, int],
) -> X87ReplayBridgeFrameMappingPlan:
    entry = descriptor.bridge_target_rva
    body = _immutable_bytes(
        binary,
        entry,
        X87_REPLAY_BRIDGE_BODY_SIZE,
        f"x87 bridge body {descriptor.id}",
    )
    section = _section_for_range(
        binary,
        entry,
        len(body),
        f"x87 bridge body {descriptor.id}",
    )
    if not section.executable:
        _fail(
            "x87_bridge_body_not_executable",
            f"x87 bridge body {descriptor.id} is not executable",
            rva=entry,
        )

    exact_slices = (
        (0, bytes.fromhex("55535657a1")),
        (9, bytes.fromhex("89600c")),
        (12, bytes.fromhex("dd6014")),
        (15, bytes.fromhex("8b4004")),
        (18, bytes.fromhex("8b5804")),
        (21, bytes.fromhex("8b4808")),
        (24, bytes.fromhex("8b7010")),
        (27, bytes.fromhex("8b7814")),
        (30, bytes.fromhex("8b6818")),
        (33, bytes.fromhex("8b601c")),
        (36, bytes.fromhex("ffb0f0000000")),
        (42, bytes.fromhex("ff30")),
        (44, bytes.fromhex("8b500c")),
        (47, bytes.fromhex("589d909090")),
        (72, bytes.fromhex("9c50a1")),
        (79, bytes.fromhex("ddb080000000")),
        (85, bytes.fromhex("8b5008")),
        (88, bytes.fromhex("8b0c24890a")),
        (93, bytes.fromhex("0f924220")),
        (97, bytes.fromhex("0f9a4230")),
        (101, bytes.fromhex("0f944224")),
        (105, bytes.fromhex("0f984228")),
        (109, bytes.fromhex("0f90422c")),
        (113, bytes.fromhex("8b5c2404")),
        (117, bytes.fromhex("8b4804")),
        (120, bytes.fromhex("8b89f0000000")),
        (126, bytes.fromhex("81e12af3ffff")),
        (132, bytes.fromhex("81e3d50c0000")),
        (138, bytes.fromhex("09d9")),
        (140, bytes.fromhex("898af0000000")),
        (146, bytes.fromhex("90909090909090909090")),
        (156, bytes.fromhex("c7401000000000")),
        (163, bytes.fromhex("8b600c")),
        (166, bytes.fromhex("fc5f5e5b5dc390909090")),
    )
    for offset, expected in exact_slices:
        if body[offset : offset + len(expected)] != expected:
            _fail(
                "x87_bridge_dynamic_frame_mapping_unproved",
                (
                    f"x87 bridge {descriptor.id} does not match the checked "
                    f"dynamic-frame template at body offset 0x{offset:x}"
                ),
                rva=entry + offset,
            )

    active_va = binary.image_base + active_frame_pointer_rva
    entry_active = struct.unpack_from(
        "<I", body, X87_REPLAY_BRIDGE_ENTRY_ACTIVE_OPERAND_OFFSET
    )[0]
    capture_active = struct.unpack_from(
        "<I", body, X87_REPLAY_BRIDGE_CAPTURE_ACTIVE_OPERAND_OFFSET
    )[0]
    if entry_active != active_va or capture_active != active_va:
        _fail(
            "x87_bridge_active_frame_mapping_mismatch",
            (
                f"x87 bridge {descriptor.id} does not use the handler's "
                "active-frame pointer"
            ),
            rva=entry,
        )
    for operand_rva in (
        entry + X87_REPLAY_BRIDGE_ENTRY_ACTIVE_OPERAND_OFFSET,
        entry + X87_REPLAY_BRIDGE_CAPTURE_ACTIVE_OPERAND_OFFSET,
    ):
        if relocation_counts.get(operand_rva, 0) != 1:
            _fail(
                "x87_bridge_active_frame_relocation_not_unique",
                (
                    f"x87 bridge {descriptor.id} active-frame operand at "
                    f"RVA 0x{operand_rva:x} lacks one HIGHLOW relocation"
                ),
                rva=operand_rva,
            )

    instruction_rva = entry + X87_REPLAY_BRIDGE_INSTRUCTION_OFFSET
    capture_rva = entry + X87_REPLAY_BRIDGE_CAPTURE_OFFSET
    return_rva = entry + X87_REPLAY_BRIDGE_RETURN_OFFSET
    instruction_size = len(descriptor.instruction_bytes)
    if instruction_rva + instruction_size > capture_rva:
        _fail(
            "x87_instruction_path_overlaps_capture",
            f"x87 instruction path {descriptor.id} overlaps its capture path",
            rva=instruction_rva,
        )
    instruction_path = _immutable_bytes(
        binary,
        instruction_rva,
        instruction_size,
        f"x87 instruction path {descriptor.id}",
    )
    instruction_section = _section_for_range(
        binary,
        instruction_rva,
        len(instruction_path),
        f"x87 instruction path {descriptor.id}",
    )
    if not instruction_section.executable:
        _fail(
            "x87_instruction_path_not_executable",
            f"x87 instruction path {descriptor.id} is not executable",
            rva=instruction_rva,
        )
    padding = body[
        X87_REPLAY_BRIDGE_INSTRUCTION_OFFSET + instruction_size :
        X87_REPLAY_BRIDGE_CAPTURE_OFFSET
    ]
    if instruction_path != descriptor.instruction_bytes or padding != (
        b"\x90" * len(padding)
    ):
        _fail(
            "x87_instruction_path_mapping_unproved",
            (
                f"x87 instruction path {descriptor.id} is not the exact "
                "descriptor bytes followed by checked NOP padding"
            ),
            rva=instruction_rva,
        )
    return X87ReplayBridgeFrameMappingPlan(
        descriptor_id=descriptor.id,
        bridge_target_rva=entry,
        instruction_rva=instruction_rva,
        capture_rva=capture_rva,
        return_rva=return_rva,
        bridge_body_bytes=body,
        instruction_path_bytes=instruction_path,
    )


def _rel32_target(instruction_rva: int, encoded: bytes) -> int:
    if len(encoded) != 4:
        _fail(
            "malformed_x87_bridge_rel32",
            "x87 bridge rel32 displacement is not four bytes",
            rva=instruction_rva,
        )
    displacement = struct.unpack("<i", encoded)[0]
    target = instruction_rva + 5 + displacement
    if not 0 <= target < 2**32:
        _fail(
            "x87_bridge_rel32_out_of_range",
            "x87 bridge rel32 destination leaves the PE32 address space",
            rva=instruction_rva,
        )
    return target


def _validate_call_path(binary: StageABinary, call_site_rva: int) -> _CallPathEvidence:
    expected = _candidate_bytes(binary, call_site_rva, 2, "x87 replay call")
    if expected != b"\xff\xd0":
        matches = _x87_call_pattern_matches(binary)
        suffix = (
            ""
            if not matches
            else "; matching sites: " + ", ".join(f"0x{rva:x}" for rva in matches)
        )
        _fail(
            "x87_replay_call_site_changed",
            f"requested candidate RVA 0x{call_site_rva:x} is not call eax{suffix}",
            rva=call_site_rva,
        )
    prefix = _candidate_bytes(binary, call_site_rva - 11, 11, "x87 replay call prefix")
    suffix = _candidate_bytes(binary, call_site_rva + 2, 6, "x87 replay call suffix")
    if prefix[0] != 0xA3 or prefix[5:7] != b"\x8b\x45" or prefix[8:] != b"\x8b\x40\x20":
        _fail(
            "x87_replay_descriptor_flow_unproved",
            "call eax is not immediately fed by descriptor field offset 32 after active-frame installation",
            rva=call_site_rva,
        )
    if suffix[:2] != b"\x8b\x15":
        _fail(
            "x87_replay_active_frame_unpreserved",
            "x87 replay call does not immediately re-read the active frame pointer",
            rva=call_site_rva,
        )
    stored_va = struct.unpack("<I", prefix[1:5])[0]
    loaded_va = struct.unpack("<I", suffix[2:6])[0]
    if stored_va != loaded_va:
        _fail(
            "x87_replay_active_frame_ambiguous",
            "x87 replay call stores and reloads different active frame globals",
            rva=call_site_rva,
        )
    active_rva = _pointer_to_rva(binary, stored_va, "active x87 frame pointer")
    section = _section_for_range(binary, active_rva, 4, "active x87 frame pointer")
    if not section.writable or section.executable:
        _fail(
            "x87_replay_active_frame_layout_invalid",
            "active x87 frame pointer is not in writable non-executable candidate memory",
            rva=active_rva,
        )
    counts = _highlow_relocation_counts(binary)
    store_operand_rva = call_site_rva - 10
    load_operand_rva = call_site_rva + 4
    for operand_rva in (store_operand_rva, load_operand_rva):
        if counts.get(operand_rva, 0) != 1:
            _fail(
                "x87_active_frame_operand_relocation_not_unique",
                f"absolute active-frame operand at RVA 0x{operand_rva:x} lacks one HIGHLOW relocation",
                rva=operand_rva,
            )
    return _CallPathEvidence(
        active_frame_pointer_rva=active_rva,
        active_frame_store_rva=call_site_rva - 11,
        active_frame_store_bytes=prefix[:5],
        descriptor_load_rva=call_site_rva - 6,
        descriptor_load_bytes=prefix[5:8],
        target_load_rva=call_site_rva - 3,
        target_load_bytes=prefix[8:11],
        active_frame_load_rva=call_site_rva + 2,
        active_frame_load_bytes=suffix,
    )


def _discover_unique_call_path(
    binary: StageABinary,
) -> tuple[int, _CallPathEvidence]:
    valid: list[tuple[int, _CallPathEvidence]] = []
    for call_site_rva in _x87_call_pattern_matches(binary):
        try:
            valid.append((call_site_rva, _validate_call_path(binary, call_site_rva)))
        except _EvidenceFailure:
            continue
    if not valid:
        _fail(
            "x87_replay_call_site_not_found",
            "candidate contains no unique relocation-checked x87 replay call path",
        )
    if len(valid) != 1:
        _fail(
            "x87_replay_call_site_ambiguous",
            "candidate contains multiple relocation-checked x87 replay call paths: "
            + ", ".join(f"0x{rva:x}" for rva, _ in valid),
        )
    return valid[0]


def _x87_call_pattern_matches(binary: StageABinary) -> tuple[int, ...]:
    matches: list[int] = []
    image = binary.path.read_bytes()
    for section in binary.sections:
        if not section.executable:
            continue
        raw = image[section.raw_pointer : section.raw_pointer + section.raw_size]
        cursor = 0
        while True:
            found = raw.find(b"\x8b\x40\x20\xff\xd0\x8b\x15", cursor)
            if found < 0:
                break
            matches.append(section.rva_start + found + 3)
            cursor = found + 1
    return tuple(matches)


def _exact_instruction(binary: StageABinary, rva: int, label: str) -> bytes:
    section = _section_for_range(binary, rva, 1, label)
    if not section.executable or section.writable:
        _fail(
            "x87_bridge_target_not_immutable_code",
            f"{label} RVA 0x{rva:x} is not immutable executable code",
            rva=rva,
        )
    raw = _candidate_bytes(binary, rva, min(15, section.rva_end - rva), label)
    decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    decoded = list(decoder.disasm(raw, binary.image_base + rva, count=1))
    if len(decoded) != 1 or decoded[0].address != binary.image_base + rva:
        _fail(
            "x87_bridge_target_decode_failed",
            f"{label} RVA 0x{rva:x} does not decode",
            rva=rva,
        )
    return bytes(decoded[0].bytes)


def _highlow_relocation_counts(binary: StageABinary) -> dict[int, int]:
    counts: dict[int, int] = {}
    for block in getattr(binary.pe, "DIRECTORY_ENTRY_BASERELOC", ()) or ():
        for entry in block.entries:
            if int(entry.type) == 3:
                rva = int(entry.rva)
                counts[rva] = counts.get(rva, 0) + 1
    return counts


def _immutable_cstring(binary: StageABinary, rva: int, label: str) -> str:
    raw = _immutable_bytes(binary, rva, 65, label)
    if raw[-1] != 0 or 0 in raw[:-1]:
        _fail(
            "noncanonical_x87_digest_string",
            f"{label} at RVA 0x{rva:x} is not a 64-byte C string",
            rva=rva,
        )
    try:
        value = raw[:-1].decode("ascii")
    except UnicodeDecodeError:
        _fail(
            "nonascii_x87_digest_string",
            f"{label} at RVA 0x{rva:x} is not ASCII",
            rva=rva,
        )
    return _digest(value, label)


def _immutable_bytes(binary: StageABinary, rva: int, size: int, label: str) -> bytes:
    section = _section_for_range(binary, rva, size, label)
    if section.writable:
        _fail("mutable_x87_evidence", f"{label} at RVA 0x{rva:x} is writable", rva=rva)
    offset = rva - section.rva_start
    if offset + size > section.raw_size:
        _fail(
            "zero_fill_x87_evidence",
            f"{label} at RVA 0x{rva:x} is not fully backed by file bytes",
            rva=rva,
        )
    return _candidate_bytes(binary, rva, size, label)


def _candidate_bytes(binary: StageABinary, rva: int, size: int, label: str) -> bytes:
    if rva < 0 or size < 0:
        _fail(
            "candidate_range_out_of_bounds",
            f"{label} has an invalid candidate range",
            rva=max(rva, 0),
        )
    data = bytes(binary.pe.get_data(rva, size))
    if len(data) != size:
        _fail(
            "candidate_range_truncated",
            f"{label} at RVA 0x{rva:x} is truncated",
            rva=rva,
        )
    return data


def _section_for_range(binary: StageABinary, rva: int, size: int, label: str) -> Any:
    matches = [
        section
        for section in binary.sections
        if section.rva_start <= rva and rva + size <= section.rva_end
    ]
    if len(matches) != 1:
        _fail(
            "ambiguous_candidate_range",
            f"{label} at RVA 0x{rva:x} is not in exactly one section",
            rva=rva,
        )
    return matches[0]


def _pointer_to_rva(binary: StageABinary, value: int, label: str) -> int:
    if not binary.image_base <= value < binary.image_base + binary.size_of_image:
        _fail(
            "x87_pointer_outside_image",
            f"{label} value 0x{value:x} is outside the candidate image",
        )
    return value - binary.image_base


def _lean_descriptor(name: str, row: X87ReplayBridgeDescriptorPlan) -> str:
    return f"""def {name} : NativeX87ReplayBridgeDescriptor := {{
  id := {row.id}
  descriptorRva := {row.descriptor_rva}
  instructionBytesRva := {row.instruction_bytes_rva}
  instructionDigestRva := {row.instruction_digest_rva}
  transferDigestRva := {row.transfer_digest_rva}
  contractDigestRva := {row.contract_digest_rva}
  replay := {{
    imageBase := {row.image_base}
    rvaStart := {row.rva_start}
    rvaEnd := {row.rva_end}
    instructionCount := 1
    instructionBytes := {_lean_bytes(row.instruction_bytes)}
    instructionBytesSha256 := {json.dumps(row.instruction_bytes_sha256)}
    transferInstructionBytesSha256 := {json.dumps(row.transfer_instruction_bytes_sha256)}
    contractSha256 := {json.dumps(row.contract_sha256)}
    checkedDecoder := {json.dumps(row.checked_decoder)}
    checkedExecutor := {json.dumps(row.checked_executor)}
  }}
  bridge := {{
    id := {row.id}
    entry := {{ rva := {row.bridge_target_rva}, bytes := {_lean_bytes(row.bridge_entry_bytes)} }}
  }}
}}"""


def _lean_frame_mapping(
    name: str, row: X87ReplayBridgeFrameMappingPlan
) -> str:
    return f"""def {name} : NativeX87ReplayBridgeFrameMapping := {{
  descriptorId := {row.descriptor_id}
  bridgeTargetRva := {row.bridge_target_rva}
  instructionRva := {row.instruction_rva}
  captureRva := {row.capture_rva}
  returnRva := {row.return_rva}
  bridgeBodyBytes := {_lean_bytes(row.bridge_body_bytes)}
  instructionPathBytes := {_lean_bytes(row.instruction_path_bytes)}
}}"""


def _lean_target_binding(
    binding_name: str,
    descriptor_name: str,
    mapping_name: str,
    mapping_checked_name: str,
) -> str:
    return f"""
def {binding_name} :
    ExactNativeX87ReplayBridgeTargetBinding generatedX87ReplayBridgeTable
      generatedInterpreterKernelCandidatePe generatedInterpreterKernelImports
      generatedInterpreterKernelRelocations
      generatedX87ReplayBridgeDescriptorPacks := {{
  candidateSha256 := generatedX87ReplayBridgeCandidateSha256
  candidateSize := generatedX87ReplayBridgeCandidateSize
  candidateSizeExact := generatedX87ReplayBridgeCandidateSizeExact
  digestShape := generatedX87ReplayBridgeCandidateDigestShape
  static := generatedX87ReplayBridgeStaticCertificate
  descriptor := {descriptor_name}
  descriptorMember := by decide +kernel
  frameMapping := {mapping_name}
  frameMappingChecked := {mapping_checked_name}
}}

def {binding_name}RuntimeGoal
    (program : ExactNestedNativeWorldProgram)
    (handler : CandidateReplayHandler)
    (sourceInvariant : NativeX87ReplayBridgeDescriptor ->
      MachineState -> MachineState -> Prop) : Prop :=
  {binding_name}.RuntimeGoal program handler sourceInvariant
"""


def _lean_bytes(data: bytes) -> str:
    return "[" + ", ".join(str(value) for value in data) + "]"


def _file(value: Path | str, label: str) -> Path:
    path = Path(value)
    if not path.is_file() or path.is_symlink():
        raise X87ReplayBridgeTargetGenerationError(
            f"{label} is not a regular file: {path}"
        )
    return path


def _json_object(path: Path, label: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise X87ReplayBridgeTargetGenerationError(
            f"cannot read {label}: {exc}"
        ) from exc
    if not isinstance(value, dict):
        raise X87ReplayBridgeTargetGenerationError(f"{label} must be an object")
    return value


def _mapping(value: Any, label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        _fail("malformed_evidence", f"{label} must be an object")
    return value


def _list(value: Any, label: str) -> list[Any]:
    if not isinstance(value, list):
        _fail("malformed_evidence", f"{label} must be a list")
    return value


def _string(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value:
        _fail("malformed_evidence", f"{label} must be a nonempty string")
    return value


def _u32(value: Any, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value < 2**32:
        _fail("malformed_evidence", f"{label} must be a uint32")
    return value


def _digest(value: Any, label: str) -> str:
    if not isinstance(value, str) or _SHA256.fullmatch(value) is None:
        _fail("malformed_evidence", f"{label} must be a lowercase SHA-256")
    return value


def _hex_bytes(value: Any, label: str) -> bytes:
    if not isinstance(value, str) or len(value) % 2:
        _fail("malformed_evidence", f"{label} must be even-length hexadecimal")
    try:
        return bytes.fromhex(value)
    except ValueError:
        _fail("malformed_evidence", f"{label} must be hexadecimal")


def _fail(code: str, message: str, *, rva: int | None = None) -> None:
    raise _EvidenceFailure(code, message, rva=rva)


__all__ = [
    "X87_REPLAY_BRIDGE_DESCRIPTOR_SIZE",
    "X87_REPLAY_BRIDGE_FUNCTION_POINTER_OFFSET",
    "X87_REPLAY_BRIDGE_PACK_SIZE",
    "X87_REPLAY_BRIDGE_RELOCATION_DATA_MODULE",
    "X87_REPLAY_BRIDGE_TARGET_LEAN_BUNDLE",
    "X87_REPLAY_BRIDGE_TARGET_PACK_PREFIX",
    "X87_REPLAY_BRIDGE_TARGET_PLAN_FILENAME",
    "X87_REPLAY_BRIDGE_TARGET_PLAN_FORMAT",
    "X87ReplayBridgeDescriptorPlan",
    "X87ReplayBridgeFrameMappingPlan",
    "X87ReplayBridgeIssue",
    "X87ReplayBridgeTablePlan",
    "X87ReplayBridgeTargetGenerationError",
    "X87ReplayBridgeTargetPlan",
    "build_x87_replay_bridge_target_plan",
    "write_x87_replay_bridge_target_bundle",
    "x87_replay_bridge_target_lean_sources",
]
