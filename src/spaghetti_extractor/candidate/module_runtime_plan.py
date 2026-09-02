"""Model the canonical shared-module runtime plan.

This module is candidate-generation machinery. Its output has no proof
authority: acceptance comes only from the exact linked, composed, deployed,
and candidate-observed receipt chain.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any, Mapping

from ..artifacts.formats import (
    IMPLEMENTATION_DISPATCH_RECEIPT_FORMAT as _IMPLEMENTATION_DISPATCH_RECEIPT_FORMAT,
)
from .formats import MODULE_RUNTIME_PLAN_FORMAT
from ..external.contracts import (
    CheckedExternalSiteContract,
)
from ..errors import ToolkitInputError
from ..transfer.x87 import (
    TYPED_NATIVE_X87_OPERATION_FORMAT,
    TypedX87Operation,
    X87_CHECKED_DECODER,
    X87_CHECKED_EXECUTOR,
)
from ..pe32.recovered_executable_data import (
    RecoveredExecutableDataRange,
)
from ..util import sha256_bytes
from .runtime_model import NativeGuestDispatchSite
from .runtime_model import NativeGuestDispatchDomain


_MACHINE_IR_INPUT_MODE = "sanitized_machine_ir_v3"
_CALL_KINDS = frozenset({"external_call", "indirect_call"})
_SEMANTIC_RUNTIME_EVENT_KINDS = frozenset(
    {"rep_movsd", "rep_movs", "rep_stos", "rep_scas"}
)
_HEX_BYTES = re.compile(r"(?:[0-9a-fA-F]{2})+")
_SHA256 = re.compile(r"[0-9a-f]{64}")
_X87_CHECKED_DECODER = X87_CHECKED_DECODER
_X87_CHECKED_EXECUTOR = X87_CHECKED_EXECUTOR
PE32_BASE_RELOCATION_EVIDENCE_FORMAT = "spaghetti-extractor-pe32-base-relocation-evidence-v1"
_FNSAVE_IMAGE_SIZE = 108
_MACHINE_STATE_SIZE = 252
_MACHINE_REGISTERS = ("eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp")
_MACHINE_FLAGS = ("cf", "zf", "sf", "of", "pf", "df")
_PE32_CALLEE_PRESERVED_REGISTERS = frozenset({"ebx", "esi", "edi", "ebp"})


def _canonical_sha256(value: Any) -> str:
    try:
        encoded = json.dumps(
            value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
        ).encode("ascii")
    except (TypeError, UnicodeEncodeError) as exc:
        raise ToolkitInputError("machine-IR metadata is not canonical JSON") from exc
    return sha256_bytes(encoded)


class _X87ReplayASLRUnsafe(ToolkitInputError):
    """Exact replay bytes would embed an unrelocated absolute address."""


@dataclass(frozen=True)
class NativeTerminationImport:
    """Exact imported tail boundary used when the module runtime cannot return."""

    dll: str
    symbol: str | None
    ordinal: int | None
    iat_va: int
    slot_id: str

    def payload(self) -> dict[str, Any]:
        return {
            "dll": self.dll,
            "symbol": self.symbol,
            "ordinal": self.ordinal,
            "iat_va": self.iat_va,
            "slot_id": self.slot_id,
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
    "tail_jump": 28,
    "argument_source": 32,
    "argument_words": 36,
    "cleanup_bytes": 40,
    "logical_result_esp": 44,
    "expected_capture_esp": 48,
    "input_x87": 52,
    "output_x87": 52 + _FNSAVE_IMAGE_SIZE,
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
    source_instruction_sha256: str
    site_kind: str
    dll: str | None
    symbol: str | None
    ordinal: int | None
    disposition: str
    iat_rva: int | None
    transfer_sha256: str
    event_identity_sha256: str | None = None
    abi_metadata_sha256: str | None = None
    target_expression: Any = None
    callback_source_kind: str | None = None
    callback_argument_index: int | None = None
    callback_argument_offset: int | None = None
    callback_pointee_offset: int = 0
    callback_nullable: bool = False
    checked_external_contract: CheckedExternalSiteContract | None = None
    target_resolution_evidence: Mapping[str, Any] | None = None
    loader_service: Mapping[str, Any] | None = None

    def payload(self, *, copy_checked_contract: bool = True) -> dict[str, Any]:
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
            "checked_external_contract": (
                None
                if self.checked_external_contract is None
                else self.checked_external_contract.payload(
                    copy_json=copy_checked_contract
                )
            ),
            "target_resolution_evidence": (
                None
                if self.target_resolution_evidence is None
                else dict(self.target_resolution_evidence)
            ),
            "loader_service": (
                None if self.loader_service is None else dict(self.loader_service)
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
            "iat_rva": self.iat_rva,
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


_EXTERNAL_SITE_TARGET_FIELDS = frozenset({
    "abi_metadata_sha256",
    "callback_registration",
    "checked_external_contract",
    "target_resolution_evidence",
    "loader_service",
    "iat_rva",
    "import",
})


def normalized_external_site_inventory_v2(
    sites: tuple[NativeExternalSite, ...],
) -> tuple[
    list[dict[str, Any]],
    list[dict[str, Any]],
    list[dict[str, Any]],
    list[dict[str, Any]],
    int,
]:
    """Factor site x target rows into one checked catalog and domain table.

    The planner deliberately keeps its convenient in-memory expanded model.
    Only the serialized plan is normalized: every target contract is stored
    once, every distinct may-domain is stored once, and a physical call site
    names exactly one content-bound domain.  Expanding these three tables is a
    lossless projection and does not perform analysis or prune authority.
    """

    catalog: dict[str, dict[str, Any]] = {}
    callback_target_domains: dict[str, dict[str, Any]] = {}
    grouped: dict[tuple[str, int, int], tuple[dict[str, Any], set[str]]] = {}
    order: list[tuple[str, int, int]] = []
    for site in sites:
        # The checked contract has already normalized and validated every
        # nested JSON value.  This serializer never mutates those nested
        # values, so avoid serializing and parsing them again merely to copy
        # them for each expanded site-target row.
        payload = site.payload(copy_checked_contract=False)
        target_body = {
            key: payload[key] for key in sorted(_EXTERNAL_SITE_TARGET_FIELDS)
        }
        checked_contract = target_body["checked_external_contract"]
        target_body["checked_external_contract_sha256"] = (
            None
            if checked_contract is None
            else _canonical_sha256(checked_contract)
        )
        if checked_contract is not None:
            # The checked contract payload is already a freshly normalized
            # JSON tree.  Serialization changes only the contract root and
            # callback-adapter dictionaries, so copying the entire tree for
            # every site x target row is both unnecessary and extremely
            # expensive for large callback domains.
            normalized_contract = dict(checked_contract)
            raw_callback_adapter = normalized_contract.get("callback_adapter")
            if raw_callback_adapter is not None:
                callback_adapter = dict(raw_callback_adapter)
                target_rvas = callback_adapter.pop("target_rvas")
                callback_domain_body = {"target_rvas": target_rvas}
                callback_domain_sha256 = _canonical_sha256(
                    callback_domain_body
                )
                prior_callback_domain = callback_target_domains.get(
                    callback_domain_sha256
                )
                if (
                    prior_callback_domain is not None
                    and prior_callback_domain != callback_domain_body
                ):
                    raise ToolkitInputError(
                        "module-runtime callback target-domain identity collides"
                    )
                callback_target_domains[
                    callback_domain_sha256
                ] = callback_domain_body
                callback_adapter[
                    "target_domain_sha256"
                ] = callback_domain_sha256
                normalized_contract["callback_adapter"] = callback_adapter
            target_body["checked_external_contract"] = normalized_contract
        target_id = _canonical_sha256(target_body)
        prior_target = catalog.get(target_id)
        if prior_target is not None and prior_target != target_body:
            raise ToolkitInputError(
                "module-runtime external target-contract identity collides"
            )
        catalog[target_id] = target_body

        key = (site.transfer_id, site.event_index, site.instruction_rva)
        site_body = {
            name: value
            for name, value in payload.items()
            if name not in _EXTERNAL_SITE_TARGET_FIELDS
            and name not in {"id", "event_identity_sha256"}
        }
        prior = grouped.get(key)
        if prior is None:
            grouped[key] = (site_body, {target_id})
            order.append(key)
        else:
            prior_body, members = prior
            if prior_body != site_body:
                raise ToolkitInputError(
                    "module-runtime external target rows disagree on their call site"
                )
            members.add(target_id)

    domains: dict[str, dict[str, Any]] = {}
    normalized_sites: list[dict[str, Any]] = []
    target_pairs = 0
    for key in order:
        site_body, raw_members = grouped[key]
        members = sorted(raw_members)
        domain_body = {"target_contract_ids": members}
        domain_sha256 = _canonical_sha256(domain_body)
        prior_domain = domains.get(domain_sha256)
        if prior_domain is not None and prior_domain != domain_body:
            raise ToolkitInputError(
                "module-runtime external contract-domain identity collides"
            )
        domains[domain_sha256] = domain_body
        identity_body = {
            "transfer_id": site_body["transfer_id"],
            "event_index": site_body["event_index"],
            "instruction_rva": site_body["instruction_rva"],
            "site_kind": site_body["site_kind"],
            "checked_domain_sha256": domain_sha256,
        }
        normalized_sites.append({
            "id": len(normalized_sites),
            **site_body,
            "checked_domain_sha256": domain_sha256,
            "site_identity_sha256": _canonical_sha256(identity_body),
        })
        target_pairs += len(members)

    catalog_rows = [
        {"target_contract_id": identity, **catalog[identity]}
        for identity in sorted(catalog)
    ]
    domain_rows = [
        {"domain_sha256": identity, **domains[identity]}
        for identity in sorted(domains)
    ]
    callback_target_domain_rows = [
        {
            "domain_sha256": identity,
            **callback_target_domains[identity],
        }
        for identity in sorted(callback_target_domains)
    ]
    return (
        catalog_rows,
        domain_rows,
        callback_target_domain_rows,
        normalized_sites,
        target_pairs,
    )


@dataclass(frozen=True)
class NativeExternalServiceRoute:
    """One checked semantic-module service obligation awaiting realization.

    The linked semantic module already owns the protocol and exact site
    domain.  The runtime plan carries that content-bound contract directly so
    native lowering never reconstructs service semantics from the much larger
    external-callthrough table.
    """

    obligation_id: str
    obligation_class: str
    semantic_contract_sha256: str
    admitted_domain: Mapping[str, Any]
    implementation: str = "blocked"

    @property
    def realized(self) -> bool:
        return self.implementation == "checked_runtime"

    def payload(self) -> dict[str, Any]:
        body = {
            "obligation_id": self.obligation_id,
            "obligation_class": self.obligation_class,
            "semantic_contract_sha256": self.semantic_contract_sha256,
            "admitted_domain": dict(self.admitted_domain),
            "implementation": self.implementation,
        }
        return {**body, "route_sha256": _canonical_sha256(body)}

    def blocker(self) -> dict[str, Any]:
        if self.realized:
            raise ToolkitInputError(
                "realized external-service route has no runtime blocker"
            )
        protocol = self.admitted_domain["protocol"]
        return {
            "category": "external_service_runtime_unsupported",
            "obligation_id": self.obligation_id,
            "obligation_class": self.obligation_class,
            "protocol_id": protocol["id"],
            "protocol_kind": protocol["kind"],
        }


@dataclass(frozen=True)
class NativeImportBinding:
    slot_id: str
    image_id: str
    descriptor_index: int
    cell_index: int
    dll: str
    symbol: str | None
    ordinal: int | None
    iat_va: int
    iat_rva: int

    def payload(self) -> dict[str, Any]:
        return {
            "slot_id": self.slot_id,
            "image_id": self.image_id,
            "descriptor_index": self.descriptor_index,
            "cell_index": self.cell_index,
            "dll": self.dll,
            "symbol": self.symbol,
            "ordinal": self.ordinal,
            "iat_va": self.iat_va,
            "iat_rva": self.iat_rva,
        }


@dataclass(frozen=True)
class NativeCodeCapabilityBinding:
    id: int
    instruction_rva: int
    argument_index: int
    original_rva: int
    code_target_rva: int
    capability_id: str

    def payload(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "instruction_rva": self.instruction_rva,
            "argument_index": self.argument_index,
            "original_rva": self.original_rva,
            "code_target_rva": self.code_target_rva,
            "capability_id": self.capability_id,
            "matching": "logical-image-base-plus-rva",
        }


@dataclass(frozen=True)
class NativeCodeCapabilityRegistration:
    instruction_rva: int
    argument_index: int
    logical_target_rva: int
    code_target_rva: int
    capability_id: str
    checked_external_contract_sha256: str
    lifetime: Any
    invocation: str

    def payload(self) -> dict[str, Any]:
        return {
            "instruction_rva": self.instruction_rva,
            "argument_index": self.argument_index,
            "logical_target_rva": self.logical_target_rva,
            "code_target_rva": self.code_target_rva,
            "capability_id": self.capability_id,
            "lifetime": self.lifetime,
            "invocation": self.invocation,
            "checked_external_contract_sha256": (
                self.checked_external_contract_sha256
            ),
        }


@dataclass(frozen=True)
class NativeCompactCodeCapabilityDomain:
    domain_id: str
    protocol_id: str
    target_rvas: tuple[int, ...]
    trampoline_table_symbol: str
    trampoline_stride_bytes: int
    flat_first: int

    def payload(self) -> dict[str, Any]:
        return {
            "domain_id": self.domain_id,
            "protocol_id": self.protocol_id,
            "target_rvas": list(self.target_rvas),
            "trampoline_table_symbol": self.trampoline_table_symbol,
            "trampoline_stride_bytes": self.trampoline_stride_bytes,
            "flat_first": self.flat_first,
        }


@dataclass(frozen=True)
class NativeCompactCodeCapabilityPublication:
    publication_id: str
    domain_id: str
    authority_kind: str
    authority_sha256: str
    instruction_rva: int
    argument_index: int
    lifetime: Any
    invocation: str

    def payload(self) -> dict[str, Any]:
        return {
            "publication_id": self.publication_id,
            "domain_id": self.domain_id,
            "authority_kind": self.authority_kind,
            "authority_sha256": self.authority_sha256,
            "instruction_rva": self.instruction_rva,
            "argument_index": self.argument_index,
            "lifetime": self.lifetime,
            "invocation": self.invocation,
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
                "one_implementation_class_per_transfer": True,
                "rooted_targets_require_implementation": True,
                "runtime_code_target_lookup": "exact-active-transfer-rva",
                "unresolved_dispatch": "fail-closed-as-unimplemented",
                "portable_component_fallback_on_unimplemented": False,
                "linked_semantic_module_selection_required_for_candidate": True,
                "acceptance_authority": False,
            },
            "counts": {
                "dispatch_entries": len(self.entries),
                "rooted_reachable_units": len(self.reachable_unit_ids),
                "rooted_targets": len(self.targets),
                "generated_behavioral_c": sum(
                    entry.implementation_class == "generated_behavioral_c"
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
    relocation_static_program_contract_sha256: str | None = None
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
                    "static_program_contract_sha256": (
                        self.relocation_static_program_contract_sha256
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
    static_program_contract_sha256: str
    image_base: int
    relocations: tuple[_PEBaseRelocation, ...]


@dataclass(frozen=True)
class ModuleRuntimePlan:
    input_mode: str
    native_ingress_plan_id: str
    transfer_count: int
    guest_dispatch_domains: tuple[NativeGuestDispatchDomain, ...]
    guest_dispatch_sites: tuple[NativeGuestDispatchSite, ...]
    external_sites: tuple[NativeExternalSite, ...]
    external_service_routes: tuple[NativeExternalServiceRoute, ...]
    import_bindings: tuple[NativeImportBinding, ...]
    code_capability_bindings: tuple[NativeCodeCapabilityBinding, ...]
    code_capability_registrations: tuple[NativeCodeCapabilityRegistration, ...]
    compact_code_capability_domains: tuple[
        NativeCompactCodeCapabilityDomain, ...
    ]
    compact_code_capability_publications: tuple[
        NativeCompactCodeCapabilityPublication, ...
    ]
    implementation_dispatch_receipt: NativeImplementationDispatchReceipt
    x87_operations: tuple[NativeX87Operation, ...]
    termination_import: NativeTerminationImport | None
    recovered_executable_data_ranges: tuple[RecoveredExecutableDataRange, ...]
    blockers: tuple[dict[str, Any], ...]

    @property
    def status(self) -> str:
        return "ready" if not self.blockers else "incomplete"

    def payload(self, *, state_machine_sha256: str) -> dict[str, Any]:
        capability_bindings = [
            binding.payload() for binding in self.code_capability_bindings
        ]
        capability_registrations = [
            registration.payload()
            for registration in self.code_capability_registrations
        ]
        compact_domains = [
            domain.payload() for domain in self.compact_code_capability_domains
        ]
        compact_publications = [
            publication.payload()
            for publication in self.compact_code_capability_publications
        ]
        (
            external_target_contracts,
            external_contract_domains,
            callback_target_domains,
            external_sites,
            external_site_target_pairs,
        ) = normalized_external_site_inventory_v2(self.external_sites)
        return {
            "format": MODULE_RUNTIME_PLAN_FORMAT,
            "status": self.status,
            "state_machine_sha256": state_machine_sha256,
            "input_mode": self.input_mode,
            "native_ingress_plan_id": self.native_ingress_plan_id,
            "counts": {
                "transfers": self.transfer_count,
                "guest_dispatch_sites": len(self.guest_dispatch_sites),
                "guest_dispatch_domains": len(self.guest_dispatch_domains),
                "guest_dispatch_domain_targets": sum(
                    len(domain.target_rvas)
                    for domain in self.guest_dispatch_domains
                ),
                "recovered_executable_data_ranges": len(
                    self.recovered_executable_data_ranges
                ),
                "external_sites": len(external_sites),
                "external_site_target_pairs": external_site_target_pairs,
                "external_target_contracts": len(external_target_contracts),
                "external_contract_domains": len(external_contract_domains),
                "external_contract_domain_members": sum(
                    len(domain["target_contract_ids"])
                    for domain in external_contract_domains
                ),
                "callback_target_domains": len(callback_target_domains),
                "external_service_routes": len(self.external_service_routes),
                "import_bindings": len(self.import_bindings),
                "code_capability_registrations": len(
                    capability_registrations
                ),
                "code_capability_bindings": len(capability_bindings),
                "compact_code_capability_domains": len(compact_domains),
                "compact_code_capability_domain_targets": sum(
                    len(domain.target_rvas)
                    for domain in self.compact_code_capability_domains
                ),
                "compact_code_capability_publications": len(
                    compact_publications
                ),
                "implementation_dispatch_entries": len(
                    self.implementation_dispatch_receipt.entries
                ),
                "x87_operations": len(self.x87_operations),
                "blockers": len(self.blockers),
            },
            "external_target_contracts": external_target_contracts,
            "external_contract_domains": external_contract_domains,
            "callback_target_domains": callback_target_domains,
            "external_sites": external_sites,
            "external_service_routes": [
                route.payload() for route in self.external_service_routes
            ],
            "guest_dispatch": {
                "policy": "content_addressed_admitted_domains_v2",
                "unknown_site": "fail_closed",
                "domains": [
                    domain.payload() for domain in self.guest_dispatch_domains
                ],
                "sites": [site.payload() for site in self.guest_dispatch_sites],
            },
            "import_bindings": [binding.payload() for binding in self.import_bindings],
            "code_capability_bindings": capability_bindings,
            "code_capability_registrations": capability_registrations,
            "compact_code_capability_domains": compact_domains,
            "compact_code_capability_publications": compact_publications,
            "implementation_dispatch_receipt": (
                self.implementation_dispatch_receipt.payload()
            ),
            "x87_mode": "sanitized_typed_native_v1",
            "x87_operations": [operation.payload() for operation in self.x87_operations],
            "termination_import": (
                self.termination_import.payload()
                if self.termination_import is not None
                else None
            ),
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
            "blockers": list(self.blockers),
        }
