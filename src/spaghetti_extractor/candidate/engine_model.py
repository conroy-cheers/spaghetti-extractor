"""Generate the freestanding wrapper for a Stage B semantic engine.

This module is candidate-generation machinery.  Its output has no proof
authority: Stage A must decode the linked PE and prove the EngineRep macro
steps before the candidate can be accepted.
"""

from __future__ import annotations

import copy
import json
import re
from collections import deque
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any, Iterable, Mapping

from ..artifact_formats import (
    INSTRUCTION_ORDERED_EFFECT_SCHEDULE_FORMAT,
    NATIVE_ENGINE_PACKAGE_FORMAT,
    NATIVE_ENGINE_PLAN_FORMAT,
)
from ..callback_contracts import (
    CallbackABI,
    CallbackSource,
    parse_callback_abi,
    parse_callback_source,
)
from ..external.contracts import (
    CheckedExternalSiteContract,
    CheckedExternalSiteContractError,
    ExternalSiteIdentity,
    checked_external_site_contract_from_event,
    parse_checked_external_site_contract,
)
from ..external.runtime_projection import load_authoritative_external_sites
from ..external.machine_import_profiles import (
    MachineImportIdentity,
    load_machine_import_profile_set,
)
from ..stage_binary import StageAInputError
from .engine_layout import (
    render_stage_b_engine_layout_c,
)
from .x87 import (
    TYPED_NATIVE_X87_OPERATION_FORMAT,
    TypedX87Operation,
    X87_MEMORY_NO_SIZE_MNEMONICS as _X87_MEMORY_NO_SIZE_MNEMONICS,
    X87_MEMORY_SIZE_KEYWORDS as _X87_MEMORY_SIZE_KEYWORDS,
    extract_typed_x87_operation,
    typed_x87_operation_from_micro_op,
)
from .machine_ir_scope import partition_candidate_machine_ir_units
from .modes import (
    STATIC_CLOSED_CANDIDATE_MODE,
    STRUCTURAL_DIAGNOSTIC_CANDIDATE_MODE,
    require_candidate_mode,
)
from ..recovered_executable_data import (
    RecoveredExecutableDataRange,
    load_recovered_executable_data_contract,
)
from ..util import sha256_bytes, sha256_file, write_json


_MACHINE_IR_FORMAT = "stage-a-machine-ir-v2"
_STRICT_INPUT_MODE = "strict_exact_state_machine_v1"
_MACHINE_IR_INPUT_MODE = "sanitized_machine_ir_v2"
_CALL_KINDS = frozenset({"external_call", "indirect_call"})
_SEMANTIC_RUNTIME_EVENT_KINDS = frozenset(
    {"rep_movsd", "rep_movs", "rep_stos", "rep_scas"}
)
_HEX_BYTES = re.compile(r"(?:[0-9a-fA-F]{2})+")
_SHA256 = re.compile(r"[0-9a-f]{64}")
_X87_REPLAY_MODEL = "native_exact_x87_command_replay_obligation_v1"
_X87_REPLAY_FORMAT = "stage-a-native-exact-x87-command-replay-obligation-v1"
_X87_REPLAY_PROGRAM_FORMAT = "stage-b-native-exact-x87-command-replay-program-v1"
_X87_CHECKED_DECODER = "StageA.Formal.decodeInstructionExact"
_X87_CHECKED_EXECUTOR = "StageA.Formal.executeInstruction"
PE32_BASE_RELOCATION_EVIDENCE_FORMAT = "stage-b-pe32-base-relocation-evidence-v1"
_X87_PHYSICAL_FIELDS = (
    "stack", "tags", "control", "status", "pending_exception", "last_opcode",
    "instruction_pointer", "code_selector", "data_pointer", "data_selector",
)
_FNSAVE_IMAGE_SIZE = 108
_MACHINE_STATE_SIZE = 252
_MACHINE_REGISTERS = ("eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp")
_MACHINE_FLAGS = ("cf", "zf", "sf", "of", "pf", "df")
_PE32_CALLEE_PRESERVED_REGISTERS = frozenset({"ebx", "esi", "edi", "ebp"})
_CALLBACK_ADAPTER_RECEIPT_FORMAT = (
    "stage-b-native-callback-adapter-receipt-v1"
)
_IMPLEMENTATION_DISPATCH_RECEIPT_FORMAT = (
    "stage-b-native-implementation-dispatch-receipt-v3"
)
_RAW_INSTRUCTION_FIELDS = frozenset({
    "bytes", "instruction_bytes", "opcode_bytes", "raw_bytes",
    "encoded_instruction",
})


def _canonical_sha256(value: Any) -> str:
    try:
        encoded = json.dumps(
            value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
        ).encode("ascii")
    except (TypeError, UnicodeEncodeError) as exc:
        raise StageAInputError("machine-IR metadata is not canonical JSON") from exc
    return sha256_bytes(encoded)


class _X87ReplayASLRUnsafe(StageAInputError):
    """Exact replay bytes would embed an unrelocated absolute address."""


@dataclass(frozen=True)
class NativeTerminationImport:
    """Exact imported tail boundary used when the native engine cannot return."""

    dll: str
    symbol: str | None
    ordinal: int | None
    iat_va: int

    def payload(self) -> dict[str, Any]:
        return {
            "dll": self.dll,
            "symbol": self.symbol,
            "ordinal": self.ordinal,
            "iat_va": self.iat_va,
            "transfer": "tail_jump",
            "argument_source": "cdecl-stack-word-0-from-eax",
            "required_disposition": "terminates",
        }

# The assembly bridge is deliberately coupled to the canonical PE32 runtime
# structure.  The emitted C static assertions make any backend layout drift a
# compile-time error rather than silently corrupting physical state.
_STATE_OFFSETS = {
    "eax": 0,
    "ebx": 4,
    "ecx": 8,
    "edx": 12,
    "esi": 16,
    "edi": 20,
    "ebp": 24,
    "esp": 28,
    "cf": 32,
    "zf": 36,
    "sf": 40,
    "of": 44,
    "pf": 48,
    "df": 52,
    "x87_stack": 56,
    "x87_control": 216,
    "x87_status": 218,
    "x87_pending_exception": 220,
    "x87_last_opcode": 222,
    "x87_instruction_pointer": 224,
    "x87_code_selector": 228,
    "x87_data_pointer": 232,
    "x87_data_selector": 236,
    "eflags": 240,
    "fs_base": 244,
    "original_rva": 248,
}
_X87_VALUE_SIZE = 20
_X87_VALUE_EMPTY_OFFSET = 12
_X87_VALUE_TAG_OFFSET = 16
_FRAME_OFFSETS = {
    "parent": 0,
    "input": 4,
    "output": 8,
    "private_esp": 12,
    "call_target": 16,
    "status": 20,
    "saved_continuation": 24,
    "continuation_replaced": 28,
    "input_x87": 32,
    "output_x87": 32 + _FNSAVE_IMAGE_SIZE,
}
_CALLBACK_FRAME_OFFSETS = {
    "parent": 0,
    "parent_bridge": 4,
    "physical_esp": 8,
    "return_target": 12,
    "status": 16,
    "input": 20,
    "output": 20 + _MACHINE_STATE_SIZE,
    "input_x87": 20 + 2 * _MACHINE_STATE_SIZE,
    "output_x87": 20 + 2 * _MACHINE_STATE_SIZE + _FNSAVE_IMAGE_SIZE,
}
_CALLBACK_FRAME_SIZE = 20 + 2 * _MACHINE_STATE_SIZE + 2 * _FNSAVE_IMAGE_SIZE
_X87_FRAME_OFFSETS = {
    "parent": 0,
    "input": 4,
    "output": 8,
    "private_esp": 12,
    "status": 16,
    "input_x87": 20,
    "output_x87": 20 + _FNSAVE_IMAGE_SIZE,
}
_X87_REPLAY_INLINE_INSTRUCTION_OFFSET = 52
_X87_REPLAY_INLINE_CAPTURE_OFFSET = 72
_X87_REPLAY_INLINE_RETURN_OFFSET = 171
_X87_REPLAY_INLINE_BODY_SIZE = 176


@dataclass(frozen=True)
class NativeExternalSite:
    id: int
    transfer_id: str
    event_index: int
    instruction_rva: int
    return_rva: int
    instruction_bytes: bytes | None
    source_instruction_sha256: str
    site_kind: str
    dll: str | None
    symbol: str | None
    ordinal: int | None
    disposition: str
    iat_va: int | None
    transfer_sha256: str
    event_identity_sha256: str | None = None
    abi_metadata_sha256: str | None = None
    target_expression: Any = None
    callback_source_kind: str | None = None
    callback_argument_index: int | None = None
    callback_argument_offset: int | None = None
    callback_pointee_offset: int = 0
    callback_nullable: bool = False
    external_protocol: Mapping[str, Any] | None = None
    interface_argument_words: int | None = None
    out_interface_relations: tuple[Mapping[str, Any], ...] = ()
    checked_external_contract: CheckedExternalSiteContract | None = None
    checked_external_contract_required: bool = False
    target_resolution_evidence: Mapping[str, Any] | None = None

    def payload(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "transfer_id": self.transfer_id,
            "event_index": self.event_index,
            "instruction_rva": self.instruction_rva,
            "return_rva": self.return_rva,
            "source_encoding_sha256": self.source_instruction_sha256,
            "event_identity_sha256": self.event_identity_sha256,
            "abi_metadata_sha256": self.abi_metadata_sha256,
            "target_expression": self.target_expression,
            "callback_registration": (
                {
                    "source_kind": self.callback_source_kind,
                    "argument_index": self.callback_argument_index,
                    "stack_offset": self.callback_argument_offset,
                    "pointee_offset": self.callback_pointee_offset,
                    "nullable": self.callback_nullable,
                }
                if self.callback_argument_index is not None
                else None
            ),
            "external_protocol": (
                None
                if self.external_protocol is None
                else dict(self.external_protocol)
            ),
            "interface_argument_words": self.interface_argument_words,
            "out_interface_relations": [
                dict(relation) for relation in self.out_interface_relations
            ],
            "checked_external_contract": (
                None
                if self.checked_external_contract is None
                else self.checked_external_contract.payload()
            ),
            "checked_external_contract_required": (
                self.checked_external_contract_required
            ),
            "target_resolution_evidence": (
                None
                if self.target_resolution_evidence is None
                else dict(self.target_resolution_evidence)
            ),
            "disposition": self.disposition,
            "transfer_sha256": self.transfer_sha256,
            "continuation_evidence": (
                {
                    "kind": "replace-saved-caller-return",
                    "stack_offset": 0,
                    "width": 4,
                    "restored_at_capture": True,
                    "normal_call_frame_shift": False,
                }
                if self.disposition == "tail_jump"
                else None
            ),
            "site_kind": self.site_kind,
            "iat_va": self.iat_va,
            "import": (
                {
                    "dll": self.dll,
                    "symbol": self.symbol,
                    "ordinal": self.ordinal,
                }
                if self.dll is not None
                else None
            ),
        }


@dataclass(frozen=True)
class NativeCallbackTarget:
    id: int
    rva: int
    transfer_id: str
    transfer_sha256: str
    kind: str
    stack_cleanup_bytes: int

    @property
    def symbol(self) -> str:
        return f"stage_b_payload_callback_{self.rva:08x}"

    @property
    def dispatch_return_symbol(self) -> str:
        return f"stage_b_native_callback_dispatch_return_{self.rva:08x}"

    def payload(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "rva": self.rva,
            "transfer_id": self.transfer_id,
            "transfer_sha256": self.transfer_sha256,
            "kind": self.kind,
            "stack_cleanup_bytes": self.stack_cleanup_bytes,
            "symbol": self.symbol,
            "dispatch_return_symbol": self.dispatch_return_symbol,
        }


@dataclass(frozen=True)
class NativeImportBinding:
    dll: str
    symbol: str | None
    ordinal: int | None
    iat_va: int
    iat_rva: int

    def payload(self) -> dict[str, Any]:
        return {
            "dll": self.dll,
            "symbol": self.symbol,
            "ordinal": self.ordinal,
            "iat_va": self.iat_va,
            "iat_rva": self.iat_rva,
        }


@dataclass(frozen=True)
class NativeCallbackAdapter:
    id: int
    instruction_rva: int
    argument_index: int
    original_rva: int
    callback_rva: int

    @property
    def symbol(self) -> str:
        return f"stage_b_payload_callback_{self.callback_rva:08x}"

    def payload(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "instruction_rva": self.instruction_rva,
            "argument_index": self.argument_index,
            "original_rva": self.original_rva,
            "callback_rva": self.callback_rva,
            "symbol": self.symbol,
            "matching": "runtime-image-base-plus-rva",
        }


@dataclass(frozen=True)
class NativeCallbackAdapterReceipt:
    site_id: int
    transfer_id: str
    event_index: int
    instruction_rva: int
    checked_external_contract_sha256: str
    source: Any
    abi: Any
    lifetime: Any
    invocation: str
    target_rvas: tuple[int, ...]
    adapter_entries: tuple[NativeCallbackAdapter, ...]

    def _body(self) -> dict[str, Any]:
        return {
            "site_id": self.site_id,
            "transfer_id": self.transfer_id,
            "event_index": self.event_index,
            "instruction_rva": self.instruction_rva,
            "checked_external_contract_sha256": (
                self.checked_external_contract_sha256
            ),
            "source": self.source,
            "abi": self.abi,
            "lifetime": self.lifetime,
            "invocation": self.invocation,
            "target_rvas": list(self.target_rvas),
            "adapter_entries": [
                adapter.payload() for adapter in self.adapter_entries
            ],
        }

    def payload(self) -> dict[str, Any]:
        body = self._body()
        return {
            "format": _CALLBACK_ADAPTER_RECEIPT_FORMAT,
            **body,
            "receipt_sha256": _canonical_sha256(body),
        }


@dataclass(frozen=True)
class NativeImplementationEntry:
    unit_id: str
    rva: int
    transfer_sha256: str
    reachability: str
    implementation_class: str
    dispatch_lookup: str
    replacement_id: str | None = None
    cluster_id: str | None = None
    component_manifest_sha256: str | None = None
    component_entry_rva: int | None = None

    def _body(self) -> dict[str, Any]:
        return {
            "unit_id": self.unit_id,
            "rva": self.rva,
            "transfer_sha256": self.transfer_sha256,
            "reachability": self.reachability,
            "implementation_class": self.implementation_class,
            "dispatch_lookup": self.dispatch_lookup,
            "replacement_id": self.replacement_id,
            "cluster_id": self.cluster_id,
            "component_manifest_sha256": self.component_manifest_sha256,
            "component_entry_rva": self.component_entry_rva,
            "fallback_on_unimplemented": False,
        }

    def payload(self) -> dict[str, Any]:
        body = self._body()
        return {**body, "entry_sha256": _canonical_sha256(body)}


@dataclass(frozen=True)
class NativeImplementationTarget:
    kind: str
    source_unit_id: str
    source_rva: int
    source_event_index: int | None
    target_unit_id: str
    target_rva: int

    def payload(self) -> dict[str, Any]:
        body = {
            "kind": self.kind,
            "source_unit_id": self.source_unit_id,
            "source_rva": self.source_rva,
            "source_event_index": self.source_event_index,
            "target_unit_id": self.target_unit_id,
            "target_rva": self.target_rva,
        }
        return {**body, "target_sha256": _canonical_sha256(body)}


@dataclass(frozen=True)
class NativeImplementationDispatchReceipt:
    candidate_mode: str
    semantic_input_sha256: str
    machine_ir_manifest_sha256: str | None
    reachability_status: str
    roots: tuple[str, ...]
    reachable_unit_ids: tuple[str, ...]
    potential_unit_ids: tuple[str, ...]
    confirmed_unreachable_unit_ids: tuple[str, ...]
    reachability_frontiers: tuple[dict[str, Any], ...]
    entries: tuple[NativeImplementationEntry, ...]
    targets: tuple[NativeImplementationTarget, ...]
    blockers: tuple[dict[str, Any], ...]

    @property
    def status(self) -> str:
        if self.blockers:
            return "incomplete"
        if self.reachability_status == "complete":
            return "complete"
        if (
            self.candidate_mode == STRUCTURAL_DIAGNOSTIC_CANDIDATE_MODE
            and self.reachability_status == "incomplete"
        ):
            return "diagnostic"
        return "unbound"

    def _body(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "semantic_input_sha256": self.semantic_input_sha256,
            "machine_ir_manifest_sha256": self.machine_ir_manifest_sha256,
            "reachability": {
                "status": self.reachability_status,
                "roots": list(self.roots),
                "reachable_unit_ids": list(self.reachable_unit_ids),
                "potential_unit_ids": list(self.potential_unit_ids),
                "confirmed_unreachable_unit_ids": list(
                    self.confirmed_unreachable_unit_ids
                ),
                "frontiers": list(self.reachability_frontiers),
            },
            "policy": {
                "candidate_mode": self.candidate_mode,
                "one_implementation_class_per_transfer": True,
                "rooted_targets_require_implementation": (
                    self.candidate_mode == STATIC_CLOSED_CANDIDATE_MODE
                ),
                "runtime_code_target_lookup": "exact-active-transfer-rva",
                "unresolved_dispatch": "fail-closed-as-unimplemented",
                "portable_component_fallback_on_unimplemented": False,
                "static_hybrid_closure_receipt_required_for_candidate": (
                    self.candidate_mode == STATIC_CLOSED_CANDIDATE_MODE
                ),
                "acceptance_authority": False,
            },
            "counts": {
                "dispatch_entries": len(self.entries),
                "rooted_reachable_units": len(self.reachable_unit_ids),
                "rooted_targets": len(self.targets),
                "machine_ir_fallback": sum(
                    entry.implementation_class == "machine_ir_fallback"
                    for entry in self.entries
                ),
                "selected_portable_component": sum(
                    entry.implementation_class == "selected_portable_component"
                    for entry in self.entries
                ),
                "selected_portable_component_member": sum(
                    entry.implementation_class
                    == "selected_portable_component_member"
                    for entry in self.entries
                ),
                "blockers": len(self.blockers),
            },
            "entries": [entry.payload() for entry in self.entries],
            "targets": [target.payload() for target in self.targets],
            "blockers": list(self.blockers),
        }

    def payload(self) -> dict[str, Any]:
        body = self._body()
        return {
            "format": _IMPLEMENTATION_DISPATCH_RECEIPT_FORMAT,
            **body,
            "receipt_sha256": _canonical_sha256(body),
        }


@dataclass(frozen=True)
class NativeCallbackPassthrough:
    instruction_rva: int
    argument_index: int
    storage_va: int
    storage_invariant: str

    def payload(self) -> dict[str, Any]:
        return {
            "instruction_rva": self.instruction_rva,
            "argument_index": self.argument_index,
            "storage_va": self.storage_va,
            "origin": "previous_registered_callback",
            "storage_invariant": self.storage_invariant,
            "runtime_action": "pass_through_environment_pointer",
        }


@dataclass(frozen=True)
class NativeX87Operation:
    id: int
    transfer_id: str
    contract_sha256: str
    image_base: int
    rva_start: int
    rva_end: int
    operation: TypedX87Operation
    relocation_source_rva: int | None = None
    preferred_value: int | None = None
    target_rva: int | None = None
    relocation_type: int | None = None
    relocation_width: int | None = None
    relocation_pe_sha256: str | None = None
    relocation_reference_contract_sha256: str | None = None
    fixed_image_base: int | None = None

    def payload(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "format": TYPED_NATIVE_X87_OPERATION_FORMAT,
            "transfer_id": self.transfer_id,
            "contract_sha256": self.contract_sha256,
            "image_base": self.image_base,
            "rva_start": self.rva_start,
            "rva_end": self.rva_end,
            "operation": self.operation.payload(),
            "checked_decoder": _X87_CHECKED_DECODER,
            "checked_executor": _X87_CHECKED_EXECUTOR,
            "base_relocation": (
                {
                    "source_rva": self.relocation_source_rva,
                    "preferred_value": self.preferred_value,
                    "target_rva": self.target_rva,
                    "type": self.relocation_type,
                    "kind": "highlow",
                    "width": self.relocation_width,
                    "pe_sha256": self.relocation_pe_sha256,
                    "reference_contract_sha256": (
                        self.relocation_reference_contract_sha256
                    ),
                }
                if self.relocation_source_rva is not None
                else None
            ),
            "address_binding": (
                {
                    "kind": "pe32_highlow_relocation",
                    "image_base": self.image_base,
                    "target_rva": self.target_rva,
                }
                if self.relocation_source_rva is not None
                else {
                    "kind": "fixed_image_base",
                    "image_base": self.fixed_image_base,
                    "target_rva": self.target_rva,
                }
                if self.fixed_image_base is not None
                else {"kind": "position_independent"}
            ),
        }


@dataclass(frozen=True)
class _PEBaseRelocation:
    source_rva: int
    type: int
    width: int
    preferred_value: int


@dataclass(frozen=True)
class _PEBaseRelocationEvidence:
    pe_sha256: str
    reference_contract_sha256: str
    image_base: int
    relocations: tuple[_PEBaseRelocation, ...]


@dataclass(frozen=True)
class NativeEnginePlan:
    candidate_mode: str
    input_mode: str
    entry_rva: int
    transfer_count: int
    external_sites: tuple[NativeExternalSite, ...]
    import_bindings: tuple[NativeImportBinding, ...]
    indirect_call_count: int
    callback_targets: tuple[NativeCallbackTarget, ...]
    callback_adapters: tuple[NativeCallbackAdapter, ...]
    callback_adapter_receipts: tuple[NativeCallbackAdapterReceipt, ...]
    implementation_dispatch_receipt: NativeImplementationDispatchReceipt
    callback_passthroughs: tuple[NativeCallbackPassthrough, ...]
    x87_operations: tuple[NativeX87Operation, ...]
    termination_import: NativeTerminationImport | None
    deferred_transfers: tuple[dict[str, Any], ...]
    recovered_executable_data_ranges: tuple[RecoveredExecutableDataRange, ...]
    fixed_image_base: int | None
    diagnostic_frontiers: tuple[dict[str, Any], ...]
    blockers: tuple[dict[str, Any], ...]

    @property
    def status(self) -> str:
        return "ready" if not self.blockers else "incomplete"

    def payload(self, *, state_machine_sha256: str) -> dict[str, Any]:
        return {
            "format": NATIVE_ENGINE_PLAN_FORMAT,
            "status": self.status,
            "state_machine_sha256": state_machine_sha256,
            "candidate_mode": self.candidate_mode,
            "input_mode": self.input_mode,
            "entry_rva": self.entry_rva,
            "counts": {
                "input_transfers": self.transfer_count + len(self.deferred_transfers),
                "transfers": self.transfer_count,
                "deferred_transfers": len(self.deferred_transfers),
                "recovered_executable_data_ranges": len(
                    self.recovered_executable_data_ranges
                ),
                "external_sites": len(self.external_sites),
                "import_bindings": len(self.import_bindings),
                "indirect_calls": self.indirect_call_count,
                "callback_targets": len(self.callback_targets),
                "callback_adapters": len(self.callback_adapters),
                "callback_adapter_receipts": len(
                    self.callback_adapter_receipts
                ),
                "implementation_dispatch_entries": len(
                    self.implementation_dispatch_receipt.entries
                ),
                "callback_passthroughs": len(self.callback_passthroughs),
                "x87_operations": len(self.x87_operations),
                "diagnostic_frontiers": len(self.diagnostic_frontiers),
                "blockers": len(self.blockers),
            },
            "external_sites": [site.payload() for site in self.external_sites],
            "import_bindings": [binding.payload() for binding in self.import_bindings],
            "callback_targets": [target.rva for target in self.callback_targets],
            "callback_abis": [target.payload() for target in self.callback_targets],
            "callback_adapters": [
                adapter.payload() for adapter in self.callback_adapters
            ],
            "callback_adapter_receipts": [
                receipt.payload() for receipt in self.callback_adapter_receipts
            ],
            "implementation_dispatch_receipt": (
                self.implementation_dispatch_receipt.payload()
            ),
            "callback_passthroughs": [
                passthrough.payload() for passthrough in self.callback_passthroughs
            ],
            "x87_mode": "sanitized_typed_native_v1",
            "x87_operations": [operation.payload() for operation in self.x87_operations],
            "termination_import": (
                self.termination_import.payload()
                if self.termination_import is not None
                else None
            ),
            "semantic_coverage": {
                "status": "complete" if not self.deferred_transfers else "incomplete",
                "deferred_transfers": len(self.deferred_transfers),
                "acceptance_authority": False,
            },
            "execution_policy": (
                "complete_transfer_inventory_v1"
                if not self.deferred_transfers
                else "fail_closed_on_deferred_potential_transfer_v1"
            ),
            "deferred_transfers": list(self.deferred_transfers),
            "recovered_executable_data": {
                "dispatch_policy": "fail_closed_as_noncode",
                "ranges": [
                    {
                        "id": item.identity,
                        "rva_start": item.rva_start,
                        "rva_end": item.rva_end,
                        "bytes_sha256": item.bytes_sha256,
                    }
                    for item in self.recovered_executable_data_ranges
                ],
            },
            "image_base_policy": (
                {"kind": "fixed", "image_base": self.fixed_image_base}
                if self.fixed_image_base is not None
                else {"kind": "relocatable"}
            ),
            "launch_wrapper_symbols": {
                "entry_dispatch_return": "stage_b_native_entry_dispatch_return",
                "entry_return": "stage_b_native_entry_return",
                "termination": "stage_b_native_termination",
                "callback_dispatch_returns": [
                    target.dispatch_return_symbol
                    for target in self.callback_targets
                ],
            },
            "relocation_policy": {
                "original_evidence": "complete-hash-bound-pe32-inventory-when-required",
                "payload_evidence": "complete-pe32-highlow-inventory-required",
                "raw_absolute_operands": "forbidden",
                "x87_instruction_payloads": "forbidden-after-typed-extraction",
            },
            "diagnostic_frontiers": list(self.diagnostic_frontiers),
            "blockers": list(self.blockers),
            "authority": "candidate generation only; candidate assurance remains required",
        }
