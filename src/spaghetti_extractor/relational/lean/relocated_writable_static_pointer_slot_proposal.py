"""Propose checked authorities for relocation-backed writable code pointers.

The scanner is intentionally narrow and generic.  It recognizes an indirect
internal call whose normalized target is a read from one writable PE32 word.
The word must contain one canonical code address and have exactly one HIGHLOW
relocation.  Direct memory calls and register-mediated calls use the same
normalized-behavior authority.

The report remains proposal-only.  Generated Lean reparses the PE, decodes the
source region, checks the relocation and code map, and validates the exact
normalized call outcome.  Runtime preservation is reported separately for
internal writes and external memory-effect classes.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any, Mapping

import capstone
import pefile
from capstone.x86 import X86_OP_MEM, X86_OP_REG

from ...errors import StageAInputError
from .callable_external_proposal import CallableResolverRouteEvidence
from .finite_static_word_provenance import (
    FiniteStaticWordOriginEvidence,
    FiniteStaticWordProvenanceError,
    StaticWordWriteOriginEvidence,
    discover_finite_static_word_origins,
)
from .interpreter_mixed_original import (
    InterpreterMixedOriginalPlan,
    OriginalAddressSeparation,
    OriginalCallableExternalRouteBinding,
    OriginalFiniteOriginStaticWordJumpBinding,
    OriginalIndirectSite,
    OriginalRegisterOffsetWrite,
    OriginalStaticWordJumpSlotBinding,
    OriginalStaticWordSlotBinding,
)


AUTHORITY_FORMAT = "stage-a-relocated-writable-static-pointer-slot-authorities-v2"
AUTHORITY_PROFILE = "relocated_writable_static_code_pointer_v1"

_IMAGE_SCN_MEM_EXECUTE = 0x20000000
_IMAGE_SCN_MEM_WRITE = 0x80000000
_REGISTERS = {"eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp"}
_U32_LIMIT = 1 << 32


class RelocatedWritableStaticPointerSlotProposalError(StageAInputError):
    """The exact proposal inputs are malformed or inconsistent."""


@dataclass(frozen=True)
class ProposalBlocker:
    category: str
    location_rva: int | None
    detail: str

    def to_json(self) -> dict[str, Any]:
        return {
            "category": self.category,
            "detail": self.detail,
            "location_rva": self.location_rva,
        }


@dataclass(frozen=True)
class ExternalPreservationClass:
    memory_effect: str
    signature_ids: tuple[int, ...]
    authority: str

    def to_json(self) -> dict[str, Any]:
        return {
            "authority": self.authority,
            "memory_effect": self.memory_effect,
            "signature_ids": list(self.signature_ids),
        }


@dataclass(frozen=True)
class ExternalCallbackProtocol:
    callback_mode: str
    signature_ids: tuple[int, ...]
    authority: str

    def to_json(self) -> dict[str, Any]:
        return {
            "authority": self.authority,
            "callback_mode": self.callback_mode,
            "signature_ids": list(self.signature_ids),
        }


@dataclass(frozen=True)
class SiteAuthorityBinding:
    site_id: int
    source_target_id: int
    source_rva: int
    instruction_rva: int
    instruction_bytes: bytes
    instruction_form: str
    transfer_kind: str
    continuation_target_id: int | None
    continuation_rva: int | None
    slot_rva: int
    slot_va: int
    slot_bytes: bytes
    target_id: int
    target_rva: int
    target_va: int
    assembled_read: bool
    writes: tuple[OriginalRegisterOffsetWrite, ...]
    address_separations: tuple[OriginalAddressSeparation, ...]
    recovered_from_unresolved_target: bool
    internal_target_ids: tuple[int, ...] = ()
    external_routes: tuple[OriginalCallableExternalRouteBinding, ...] = ()
    write_origin_evidence: tuple[StaticWordWriteOriginEvidence, ...] = ()

    @property
    def finite_origin(self) -> bool:
        return bool(self.external_routes)

    @property
    def static_binding(
        self,
    ) -> (
        OriginalStaticWordSlotBinding
        | OriginalStaticWordJumpSlotBinding
        | OriginalFiniteOriginStaticWordJumpBinding
    ):
        if self.finite_origin:
            if self.transfer_kind != "jump":
                raise RelocatedWritableStaticPointerSlotProposalError(
                    "finite-origin writable calls are not yet supported"
                )
            return OriginalFiniteOriginStaticWordJumpBinding(
                slot_id=self.slot_rva,
                slot_rva=self.slot_rva,
                slot_va=self.slot_va,
                slot_bytes=tuple(self.slot_bytes),
                initial_target_id=self.target_id,
                initial_target_rva=self.target_rva,
                initial_target_va=self.target_va,
                internal_target_ids=self.internal_target_ids,
                external_routes=self.external_routes,
                assembled_read=self.assembled_read,
                writes=self.writes,
                address_separations=self.address_separations,
            )
        common = {
            "slot_id": self.slot_rva,
            "slot_rva": self.slot_rva,
            "slot_va": self.slot_va,
            "slot_bytes": tuple(self.slot_bytes),
            "target_id": self.target_id,
            "target_rva": self.target_rva,
            "target_va": self.target_va,
            "assembled_read": self.assembled_read,
            "writes": self.writes,
            "address_separations": self.address_separations,
        }
        if self.transfer_kind == "jump":
            return OriginalStaticWordJumpSlotBinding(**common)  # type: ignore[arg-type]
        assert self.continuation_target_id is not None
        return OriginalStaticWordSlotBinding(
            continuation_target_id=self.continuation_target_id,
            **common,  # type: ignore[arg-type]
        )

    @property
    def module(self) -> str:
        return (
            "StageA.GeneratedRelocatedWritableStaticPointerSlotAuthority"
            f"{self.site_id:04d}"
        )

    @property
    def namespace(self) -> str:
        return (
            "StageA.GeneratedRelocatedWritableStaticPointerSlotAuthority"
            f"{self.site_id:04d}"
        )

    def to_json(self) -> dict[str, Any]:
        return {
            "assembled_read": self.assembled_read,
            "authorizing_lean_term": {
                "module": self.module,
                "namespace": self.namespace,
                "symbol": "generatedAuthority",
            },
            "continuation_rva": self.continuation_rva,
            "continuation_target_id": self.continuation_target_id,
            "instruction_bytes": self.instruction_bytes.hex(),
            "instruction_form": self.instruction_form,
            "instruction_rva": self.instruction_rva,
            "internal_target_ids": list(
                self.internal_target_ids or (self.target_id,)
            ),
            "profile": AUTHORITY_PROFILE,
            "recovered_from_unresolved_target": (
                self.recovered_from_unresolved_target
            ),
            "site_id": self.site_id,
            "slot_bytes": self.slot_bytes.hex(),
            "slot_rva": self.slot_rva,
            "slot_va": self.slot_va,
            "source_rva": self.source_rva,
            "source_target_id": self.source_target_id,
            "target_id": self.target_id,
            "target_rva": self.target_rva,
            "target_va": self.target_va,
            "transfer_kind": self.transfer_kind,
            "value_relation": (
                "finite_origins" if self.finite_origin else "fixed_code_pointer"
            ),
            "external_routes": [
                {
                    "abi_contract_id": route.abi_contract_id,
                    "capability_id": route.capability_id,
                    "resolver_contract_id": route.resolver_contract_id,
                    "resource_id": route.resource_id,
                }
                for route in self.external_routes
            ],
            "write_origin_evidence": [
                evidence.to_json() for evidence in self.write_origin_evidence
            ],
            "writes": [
                {
                    "offset": write.offset,
                    "register": write.register,
                    "subtract": write.subtract,
                    "value": dict(write.value),
                }
                for write in self.writes
            ],
        }


@dataclass(frozen=True)
class AuthorityPlan:
    original_sha256: str
    state_machine_sha256: str
    machine_import_report_sha256: str
    mixed_original_plan_sha256: str
    bindings: tuple[SiteAuthorityBinding, ...]
    blockers: tuple[ProposalBlocker, ...]
    external_preservation: tuple[ExternalPreservationClass, ...]
    external_callbacks: tuple[ExternalCallbackProtocol, ...]
    internal_exact_slot_writes: tuple[tuple[int, int], ...]
    dynamic_internal_write_regions: tuple[int, ...]
    mixed_original_blocker_count: int

    @property
    def covered_source_rvas(self) -> tuple[int, ...]:
        return tuple(binding.source_rva for binding in self.bindings)

    def to_json(self) -> dict[str, Any]:
        return {
            "artifact_role": {
                "acceptance_authority": False,
                "lean_checker_must_reparse_and_redecode": True,
                "proposal_only": True,
            },
            "blockers": [blocker.to_json() for blocker in self.blockers],
            "counts": {
                "authority_terms": len(self.bindings),
                "mixed_original_blockers_before": (
                    self.mixed_original_blocker_count
                ),
                "potential_mixed_original_blockers_after": (
                    self.mixed_original_blocker_count - len(self.bindings)
                ),
                "register_mediated_sites": sum(
                    binding.instruction_form == "register_indirect"
                    for binding in self.bindings
                ),
                "slots": len({binding.slot_rva for binding in self.bindings}),
            },
            "external_preservation": [
                item.to_json() for item in self.external_preservation
            ],
            "external_callback_protocols": [
                item.to_json() for item in self.external_callbacks
            ],
            "format": AUTHORITY_FORMAT,
            "inputs": {
                "machine_import_report_sha256": (
                    self.machine_import_report_sha256
                ),
                "mixed_original_plan_sha256": (
                    self.mixed_original_plan_sha256
                ),
                "original_sha256": self.original_sha256,
                "state_machine_sha256": self.state_machine_sha256,
            },
            "internal_preservation": {
                "dynamic_write_regions_requiring_world_separation": list(
                    self.dynamic_internal_write_regions
                ),
                "exact_slot_writes": [
                    {"source_rva": source_rva, "slot_rva": slot_rva}
                    for source_rva, slot_rva in self.internal_exact_slot_writes
                ],
                "protocol": (
                    "normalized writes plus checked image-disjoint stack/dynamic "
                    "ranges; exact slot writes must preserve fixed-code-pointer "
                    "relation"
                ),
            },
            "sites": [binding.to_json() for binding in self.bindings],
        }


@dataclass(frozen=True)
class LeanAuthorityBinding:
    dependency_modules: tuple[str, ...]
    context_term: str
    carrier_term: str
    decoded_authority_term: str


def construct_relocated_writable_static_pointer_slot_authorities(
    *,
    original_pe: Path | str,
    state_machine: Path | str,
    machine_import_report: Path | str,
    mixed_original_plan: InterpreterMixedOriginalPlan,
    resolver_routes_by_instruction_rva: Mapping[
        int, CallableResolverRouteEvidence
    ] | None = None,
) -> AuthorityPlan:
    """Discover every exact writable static code-pointer call in a plan."""

    pe_path = Path(original_pe)
    state_path = Path(state_machine)
    machine_path = Path(machine_import_report)
    hashes = {
        "original": _sha256(pe_path),
        "state": _sha256(state_path),
        "machine": _sha256(machine_path),
    }
    if mixed_original_plan.state_machine_sha256 != hashes["state"]:
        raise RelocatedWritableStaticPointerSlotProposalError(
            "mixed-original plan is not bound to the exact state machine"
        )
    plan_sha256 = mixed_original_plan_sha256(mixed_original_plan)
    rows = _jsonl_by_rva(state_path)
    machine = _object(machine_path)
    inputs = _mapping(machine.get("inputs"), "machine import report inputs")
    if (
        inputs.get("original_sha256") != hashes["original"]
        or inputs.get("state_machine_sha256") != hashes["state"]
    ):
        raise RelocatedWritableStaticPointerSlotProposalError(
            "machine import report hashes do not match the exact inputs"
        )

    regions_by_rva = {region.rva: region for region in mixed_original_plan.regions}
    if len(regions_by_rva) != len(mixed_original_plan.regions):
        raise RelocatedWritableStaticPointerSlotProposalError(
            "mixed-original regions have duplicate canonical RVAs"
        )

    blockers: list[ProposalBlocker] = []
    proposed: list[SiteAuthorityBinding] = []
    pe = pefile.PE(str(pe_path), fast_load=False)
    try:
        image_base = int(pe.OPTIONAL_HEADER.ImageBase)
        relocation_counts = _highlow_relocation_counts(pe)
        unresolved_frontiers: set[tuple[int, int]] = set()
        for blocker in mixed_original_plan.blockers:
            if (
                blocker.reason_code != "unresolved_indirect_control"
                or blocker.rva is None
                or " at 0x" not in blocker.detail
            ):
                continue
            instruction = blocker.detail.split(" at 0x", 1)[1].split(":", 1)[0]
            try:
                unresolved_frontiers.add(
                    (blocker.rva, int(instruction, 16))
                )
            except ValueError:
                continue
        candidates = sorted(
            (
                (region, site)
                for region in mixed_original_plan.regions
                for site in region.indirect_sites
                if site.category == "static_pointer_slot"
                and site.static_binding is None
                and (site.source_rva, site.instruction_rva)
                in unresolved_frontiers
            ),
            key=lambda item: (item[1].source_rva, item[1].instruction_rva),
        )
        for site_id, (source, site) in enumerate(candidates):
            try:
                proposed.append(
                    _site_binding(
                        pe=pe,
                        image_base=image_base,
                        relocation_counts=relocation_counts,
                        rows=rows,
                        regions_by_rva=regions_by_rva,
                        source=source,
                        site=site,
                        site_id=site_id,
                    )
                )
            except RelocatedWritableStaticPointerSlotProposalError as error:
                blockers.append(
                    ProposalBlocker(
                        "unsupported_writable_static_pointer_site",
                        site.instruction_rva,
                        str(error),
                    )
                )

        route_evidence = (
            {}
            if resolver_routes_by_instruction_rva is None
            else resolver_routes_by_instruction_rva
        )
        origins_by_slot: dict[int, FiniteStaticWordOriginEvidence] = {}
        unique_bindings = {
            binding.slot_rva: binding for binding in proposed
        }
        for slot_rva, binding in unique_bindings.items():
            try:
                evidence = discover_finite_static_word_origins(
                    pe=pe,
                    image_base=image_base,
                    rows=rows,
                    plan=mixed_original_plan,
                    slot_rva=slot_rva,
                    slot_va=binding.slot_va,
                    initial_target_id=binding.target_id,
                    resolver_routes_by_instruction_rva=route_evidence,
                )
            except FiniteStaticWordProvenanceError as error:
                blockers.append(
                    ProposalBlocker(
                        "slot_value_origin_incomplete",
                        binding.source_rva,
                        str(error),
                    )
                )
                continue
            origins_by_slot[slot_rva] = evidence
        enriched: list[SiteAuthorityBinding] = []
        for binding in proposed:
            evidence = origins_by_slot.get(binding.slot_rva)
            if evidence is None or not evidence.external_routes:
                enriched.append(binding)
                continue
            if binding.transfer_kind != "jump":
                blockers.append(
                    ProposalBlocker(
                        "finite_origin_writable_call_unsupported",
                        binding.instruction_rva,
                        "finite-origin writable slots currently require a "
                        "tail-jump exit",
                    )
                )
                enriched.append(binding)
                continue
            resource_ids = [
                route.resource_id for route in evidence.external_routes
            ]
            if len(resource_ids) != len(set(resource_ids)):
                blockers.append(
                    ProposalBlocker(
                        "ambiguous_callable_abi_route",
                        binding.instruction_rva,
                        "one callable resource has multiple candidate ABI routes",
                    )
                )
                enriched.append(binding)
                continue
            enriched.append(
                replace(
                    binding,
                    internal_target_ids=evidence.internal_target_ids,
                    external_routes=evidence.external_routes,
                    write_origin_evidence=evidence.writes,
                )
            )
        proposed = enriched
        slots = {
            binding.slot_rva: (binding.slot_va, binding.target_va)
            for binding in proposed
        }
        exact_writes, dynamic_regions, write_blockers = (
            _classify_internal_slot_writes(
                {
                    region.rva: rows[region.rva]
                    for region in mixed_original_plan.regions
                    if region.target_id in mixed_original_plan.reachable_target_ids
                    and region.rva in rows
                },
                slots,
                origins_by_slot,
            )
        )
        blockers.extend(write_blockers)
    finally:
        pe.close()

    return AuthorityPlan(
        original_sha256=hashes["original"],
        state_machine_sha256=hashes["state"],
        machine_import_report_sha256=hashes["machine"],
        mixed_original_plan_sha256=plan_sha256,
        bindings=tuple(proposed),
        blockers=tuple(blockers),
        external_preservation=_external_preservation_classes(machine),
        external_callbacks=_external_callback_protocols(machine),
        internal_exact_slot_writes=exact_writes,
        dynamic_internal_write_regions=dynamic_regions,
        mixed_original_blocker_count=len(mixed_original_plan.blockers),
    )


def write_relocated_writable_static_pointer_slot_authorities(
    out: Path | str,
    plan: AuthorityPlan,
    lean: LeanAuthorityBinding,
) -> tuple[Path, tuple[Path, ...]]:
    """Write the proposal report and independently checkable Lean terms."""

    if not lean.dependency_modules:
        raise RelocatedWritableStaticPointerSlotProposalError(
            "Lean authority generation requires at least one dependency module"
        )
    root = Path(out)
    stage_a = root / "StageA"
    stage_a.mkdir(parents=True, exist_ok=True)
    sources: list[Path] = []
    for binding in plan.bindings:
        path = stage_a / f"{binding.module.removeprefix('StageA.')}.lean"
        path.write_text(_authority_source(binding, lean), encoding="utf-8")
        sources.append(path)
    report = root / "relocated-writable-static-pointer-slot-authorities.json"
    report.write_text(
        json.dumps(plan.to_json(), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return report, tuple(sources)


def _site_binding(
    *,
    pe: pefile.PE,
    image_base: int,
    relocation_counts: Mapping[int, int],
    rows: Mapping[int, Mapping[str, Any]],
    regions_by_rva: Mapping[int, Any],
    source: Any,
    site: OriginalIndirectSite,
    site_id: int,
) -> SiteAuthorityBinding:
    if site.target_va is None or site.target_va < image_base:
        raise RelocatedWritableStaticPointerSlotProposalError(
            "target expression is not one absolute word in the preferred image"
        )
    slot_va = site.target_va
    slot_rva = slot_va - image_base
    if slot_va + 4 > _U32_LIMIT:
        raise RelocatedWritableStaticPointerSlotProposalError(
            "slot word overflows the PE32 address space"
        )
    sections = [
        section
        for section in pe.sections
        if int(section.VirtualAddress) <= slot_rva
        and slot_rva + 4
        <= int(section.VirtualAddress)
        + max(int(section.Misc_VirtualSize), int(section.SizeOfRawData))
    ]
    if len(sections) != 1:
        raise RelocatedWritableStaticPointerSlotProposalError(
            "slot is not contained in exactly one mapped section"
        )
    characteristics = int(sections[0].Characteristics)
    if (
        not characteristics & _IMAGE_SCN_MEM_WRITE
        or characteristics & _IMAGE_SCN_MEM_EXECUTE
    ):
        raise RelocatedWritableStaticPointerSlotProposalError(
            "slot is not writable, non-executable PE data"
        )
    if relocation_counts.get(slot_rva, 0) != 1:
        raise RelocatedWritableStaticPointerSlotProposalError(
            "slot does not have exactly one HIGHLOW relocation"
        )
    slot_bytes = bytes(pe.get_data(slot_rva, 4))
    if len(slot_bytes) != 4:
        raise RelocatedWritableStaticPointerSlotProposalError(
            "slot is not backed by four exact PE bytes"
        )
    target_va = int.from_bytes(slot_bytes, "little")
    if not image_base <= target_va < _U32_LIMIT:
        raise RelocatedWritableStaticPointerSlotProposalError(
            "preferred slot value is not an in-image code address"
        )
    target_rva = target_va - image_base
    target = regions_by_rva.get(target_rva)
    if target is None or target.alias_rvas:
        raise RelocatedWritableStaticPointerSlotProposalError(
            "preferred slot value is not one canonical code target"
        )
    if (
        site.resolved_target_rva is not None
        and site.resolved_target_rva != target_rva
    ):
        raise RelocatedWritableStaticPointerSlotProposalError(
            "planner target conflicts with the exact relocated slot value"
        )
    continuation = None
    if site.is_call:
        if site.continuation_rva is None:
            raise RelocatedWritableStaticPointerSlotProposalError(
                "indirect call lacks an exact continuation"
            )
        continuation = regions_by_rva.get(site.continuation_rva)
        if continuation is None:
            raise RelocatedWritableStaticPointerSlotProposalError(
                "indirect-call continuation is not a canonical code target"
            )
    elif site.continuation_rva is not None:
        raise RelocatedWritableStaticPointerSlotProposalError(
            "indirect jump unexpectedly carries a continuation"
        )
    expected_expression = {
        "op": "load",
        "width": 4,
        "address": {"op": "const", "value": slot_va, "width": 32},
    }
    if site.target_expression != expected_expression:
        raise RelocatedWritableStaticPointerSlotProposalError(
            "normalized target is not an exact read from the proposed slot"
        )
    instruction_bytes, instruction_form, target_read_rva = _indirect_control_bytes(
        pe, image_base, source, site.instruction_rva, slot_va,
        is_call=site.is_call,
    )
    row = rows.get(source.rva)
    if row is None:
        raise RelocatedWritableStaticPointerSlotProposalError(
            "source region has no exact state-machine row"
        )
    if site.is_call:
        assert site.continuation_rva is not None
        writes, assembled = _pre_call_writes(
            row,
            site.instruction_rva,
            target_read_rva,
            site.continuation_rva,
            slot_va,
            target_rva,
        )
    else:
        writes, assembled = _pre_jump_writes(
            row,
            target_read_rva,
            slot_va,
        )
    separations = tuple(
        OriginalAddressSeparation(
            register=write.register,
            offset=write.offset + write_byte,
            address=slot_va + slot_byte,
        )
        for write in writes
        for slot_byte in range(4)
        for write_byte in range(4)
    )
    return SiteAuthorityBinding(
        site_id=site_id,
        source_target_id=source.target_id,
        source_rva=source.rva,
        instruction_rva=site.instruction_rva,
        instruction_bytes=instruction_bytes,
        instruction_form=instruction_form,
        transfer_kind="call" if site.is_call else "jump",
        continuation_target_id=(
            None if continuation is None else continuation.target_id
        ),
        continuation_rva=(
            None if continuation is None else continuation.rva
        ),
        slot_rva=slot_rva,
        slot_va=slot_va,
        slot_bytes=slot_bytes,
        target_id=target.target_id,
        target_rva=target.rva,
        target_va=target_va,
        assembled_read=assembled,
        writes=writes,
        address_separations=separations,
        recovered_from_unresolved_target=site.resolved_target_rva is None,
    )


def _indirect_control_bytes(
    pe: pefile.PE,
    image_base: int,
    source: Any,
    instruction_rva: int,
    slot_va: int,
    *,
    is_call: bool,
) -> tuple[bytes, str, int]:
    if not source.rva <= instruction_rva < source.rva + source.size:
        raise RelocatedWritableStaticPointerSlotProposalError(
            "indirect control instruction is outside its exact source span"
        )
    data = bytes(
        pe.get_data(
            instruction_rva,
            source.rva + source.size - instruction_rva,
        )
    )
    decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    decoder.detail = True
    instruction = next(
        iter(decoder.disasm(data, image_base + instruction_rva)), None
    )
    expected_mnemonic = "call" if is_call else "jmp"
    if instruction is None or instruction.mnemonic != expected_mnemonic:
        raise RelocatedWritableStaticPointerSlotProposalError(
            f"exact control instruction is not an indirect {expected_mnemonic}"
        )
    if len(instruction.operands) != 1:
        raise RelocatedWritableStaticPointerSlotProposalError(
            "indirect control does not have exactly one operand"
        )
    operand = instruction.operands[0]
    if operand.type == X86_OP_REG:
        form = "register_indirect"
        target_read_rva = _register_target_read_rva(
            pe,
            image_base,
            source,
            instruction_rva,
            instruction.reg_name(operand.reg),
            slot_va,
        )
    elif operand.type == X86_OP_MEM and operand.size == 4:
        memory = operand.mem
        if (
            memory.base != 0
            or memory.index != 0
            or (memory.disp & 0xFFFFFFFF) != slot_va
        ):
            raise RelocatedWritableStaticPointerSlotProposalError(
                "memory-indirect control does not read the proposed absolute slot"
            )
        form = "memory_indirect"
        target_read_rva = instruction_rva
    else:
        raise RelocatedWritableStaticPointerSlotProposalError(
            "indirect control operand is outside the supported PE32 forms"
        )
    return bytes(instruction.bytes), form, target_read_rva


def _register_target_read_rva(
    pe: pefile.PE,
    image_base: int,
    source: Any,
    instruction_rva: int,
    target_register: str,
    slot_va: int,
) -> int:
    """Locate the exact slot read that determines a register-indirect target."""

    data = bytes(pe.get_data(source.rva, source.size))
    if len(data) != source.size:
        raise RelocatedWritableStaticPointerSlotProposalError(
            "register-indirect source is not backed by its complete PE span"
        )
    decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    decoder.detail = True
    instructions = list(decoder.disasm(data, image_base + source.rva))
    if not instructions or sum(item.size for item in instructions) != source.size:
        raise RelocatedWritableStaticPointerSlotProposalError(
            "register-indirect source does not decode over its complete PE span"
        )
    control_indexes = [
        index
        for index, item in enumerate(instructions)
        if item.address - image_base == instruction_rva
    ]
    if len(control_indexes) != 1:
        raise RelocatedWritableStaticPointerSlotProposalError(
            "register-indirect control is not unique in the exact source span"
        )
    control_index = control_indexes[0]
    writers: list[tuple[int, Any]] = []
    for index, item in enumerate(instructions[:control_index]):
        try:
            _reads, writes = item.regs_access()
        except capstone.CsError as error:
            raise RelocatedWritableStaticPointerSlotProposalError(
                "register-indirect source has unavailable register-access metadata"
            ) from error
        if target_register in {item.reg_name(register) for register in writes}:
            writers.append((index, item))
    if not writers:
        raise RelocatedWritableStaticPointerSlotProposalError(
            "register-indirect target has no exact in-region producer"
        )
    producer_index, producer = writers[-1]
    if any(
        item.mnemonic in {"call", "lcall"}
        for item in instructions[producer_index + 1 : control_index]
    ):
        raise RelocatedWritableStaticPointerSlotProposalError(
            "register-indirect target crosses an uncontracted call after its slot read"
        )
    if producer.mnemonic != "mov" or len(producer.operands) != 2:
        raise RelocatedWritableStaticPointerSlotProposalError(
            "register-indirect target producer is not an exact mov"
        )
    destination, source_operand = producer.operands
    if (
        destination.type != X86_OP_REG
        or producer.reg_name(destination.reg) != target_register
        or source_operand.type != X86_OP_MEM
        or source_operand.size != 4
        or source_operand.mem.base != 0
        or source_operand.mem.index != 0
        or (source_operand.mem.disp & 0xFFFFFFFF) != slot_va
    ):
        raise RelocatedWritableStaticPointerSlotProposalError(
            "register-indirect target producer is not an exact read from the proposed slot"
        )
    return producer.address - image_base


def _pre_call_writes(
    row: Mapping[str, Any],
    instruction_rva: int,
    target_read_rva: int,
    continuation_rva: int,
    slot_va: int,
    target_rva: int,
) -> tuple[tuple[OriginalRegisterOffsetWrite, ...], bool]:
    ordered = row.get("ordered_events")
    if not isinstance(ordered, list):
        raise RelocatedWritableStaticPointerSlotProposalError(
            "source lacks ordered memory framing"
        )
    calls = [
        (index, event)
        for index, event in enumerate(ordered)
        if isinstance(event, Mapping)
        and event.get("kind") in {"internal_call", "indirect_call"}
        and event.get("instruction_rva") == instruction_rva
    ]
    if len(calls) != 1:
        raise RelocatedWritableStaticPointerSlotProposalError(
            "source does not contain exactly one matching ordered call event"
        )
    event_index, call = calls[0]
    if call.get("return_rva") != continuation_rva:
        raise RelocatedWritableStaticPointerSlotProposalError(
            "ordered call continuation differs from the exact code map"
        )
    if (
        call.get("kind") == "internal_call"
        and call.get("target_rva") != target_rva
    ):
        raise RelocatedWritableStaticPointerSlotProposalError(
            "ordered internal-call target differs from the relocated slot"
        )
    return _pre_target_writes(
        row, ordered[:event_index], target_read_rva, slot_va
    )


def _pre_jump_writes(
    row: Mapping[str, Any],
    target_read_rva: int,
    slot_va: int,
) -> tuple[tuple[OriginalRegisterOffsetWrite, ...], bool]:
    outcome = row.get("outcome")
    if not isinstance(outcome, Mapping) or outcome.get("kind") != "indirect_jump":
        raise RelocatedWritableStaticPointerSlotProposalError(
            "source row does not end in one exact indirect jump"
        )
    ordered = row.get("ordered_events")
    if not isinstance(ordered, list):
        raise RelocatedWritableStaticPointerSlotProposalError(
            "source lacks ordered memory framing"
        )
    return _pre_target_writes(row, ordered, target_read_rva, slot_va)


def _pre_target_writes(
    row: Mapping[str, Any],
    ordered: list[Any],
    target_read_rva: int,
    slot_va: int,
) -> tuple[tuple[OriginalRegisterOffsetWrite, ...], bool]:
    instructions = row.get("instructions")
    if not isinstance(instructions, list) or not all(
        isinstance(instruction, Mapping) for instruction in instructions
    ):
        raise RelocatedWritableStaticPointerSlotProposalError(
            "source lacks an exact decoded instruction inventory"
        )
    write_address_forms = {
        int(instruction["rva"]): (
            "raw_modulo" if instruction.get("mnemonic") == "push" else "semantic_ir"
        )
        for instruction in instructions
        if isinstance(instruction.get("rva"), int)
    }
    writes: list[OriginalRegisterOffsetWrite] = []
    for event in ordered:
        if not isinstance(event, Mapping) or event.get("kind") != "write":
            continue
        event_instruction_rva = event.get("instruction_rva")
        if not isinstance(event_instruction_rva, int):
            raise RelocatedWritableStaticPointerSlotProposalError(
                "pre-call write is not tied to one exact decoded instruction"
            )
        # A register-indirect target is fixed when its producer reads the slot.
        # Later argument/frame writes affect the call state, but cannot alter the
        # already-loaded target expression checked by the Lean certificate.
        if event_instruction_rva >= target_read_rva:
            continue
        if event.get("width") != 4:
            raise RelocatedWritableStaticPointerSlotProposalError(
                "pre-call frame contains a non-word memory write"
            )
        address = event.get("address")
        constant = _const_value(address)
        if constant is not None:
            if constant < slot_va + 4 and slot_va < constant + 4:
                raise RelocatedWritableStaticPointerSlotProposalError(
                    "pre-call memory write overlaps the target slot"
                )
            continue
        register_offset = _register_offset_address(address)
        if register_offset is None:
            raise RelocatedWritableStaticPointerSlotProposalError(
                "pre-call write lacks register-offset separation evidence"
            )
        if (
            event_instruction_rva not in write_address_forms
        ):
            raise RelocatedWritableStaticPointerSlotProposalError(
                "pre-call write is not tied to one exact decoded instruction"
            )
        address_form = write_address_forms[event_instruction_rva]
        if address_form not in {"raw_modulo", "semantic_ir"}:
            raise RelocatedWritableStaticPointerSlotProposalError(
                "pre-call write has an unsupported exact address form"
            )
        value = event.get("value")
        if not _write_value_supported(value):
            raise RelocatedWritableStaticPointerSlotProposalError(
                "pre-call write value is outside the checked expression subset"
            )
        register, offset, subtract = register_offset
        if address_form == "raw_modulo":
            subtract = False
        writes = [
            prior
            for prior in writes
            if (prior.register, prior.offset) != (register, offset)
        ]
        writes.append(
            OriginalRegisterOffsetWrite(
                register=register,
                offset=offset,
                value=value,
                subtract=subtract,
            )
        )
    return tuple(writes), bool(writes)


def _classify_internal_slot_writes(
    rows: Mapping[int, Mapping[str, Any]],
    slots: Mapping[int, tuple[int, int]],
    origins_by_slot: Mapping[int, FiniteStaticWordOriginEvidence],
) -> tuple[
    tuple[tuple[int, int], ...],
    tuple[int, ...],
    tuple[ProposalBlocker, ...],
]:
    exact: set[tuple[int, int]] = set()
    dynamic: set[int] = set()
    blockers: list[ProposalBlocker] = []
    for source_rva, row in rows.items():
        events = row.get("ordered_events")
        if not isinstance(events, list):
            continue
        for event in events:
            if not isinstance(event, Mapping) or event.get("kind") != "write":
                continue
            address = _const_value(event.get("address"))
            if address is None:
                dynamic.add(source_rva)
                continue
            width = event.get("width")
            if not isinstance(width, int) or isinstance(width, bool):
                blockers.append(
                    ProposalBlocker(
                        "unknown_internal_write_width",
                        source_rva,
                        "internal write has no exact byte width",
                    )
                )
                continue
            for slot_rva, (slot_va, target_va) in slots.items():
                if address < slot_va + 4 and slot_va < address + width:
                    evidence = origins_by_slot.get(slot_rva)
                    instruction_rva = event.get("instruction_rva")
                    if (
                        evidence is not None
                        and isinstance(instruction_rva, int)
                        and any(
                            write.source_rva == source_rva
                            and write.instruction_rva == instruction_rva
                            for write in evidence.writes
                        )
                    ):
                        exact.add((source_rva, slot_rva))
                        continue
                    if (
                        width == 4
                        and address == slot_va
                        and _const_value(event.get("value")) == target_va
                    ):
                        exact.add((source_rva, slot_rva))
                    else:
                        blockers.append(
                            ProposalBlocker(
                                "slot_value_may_change",
                                source_rva,
                                f"write may change static slot RVA 0x{slot_rva:x}",
                            )
                        )
    return tuple(sorted(exact)), tuple(sorted(dynamic)), tuple(blockers)


def _external_preservation_classes(
    report: Mapping[str, Any],
) -> tuple[ExternalPreservationClass, ...]:
    by_effect: dict[str, list[int]] = {}
    for row in _object_list(report.get("signatures"), "machine signatures"):
        effect = row.get("memory_effect")
        signature_id = row.get("id")
        if not isinstance(effect, str) or not isinstance(signature_id, int):
            raise RelocatedWritableStaticPointerSlotProposalError(
                "machine signature lacks an exact memory effect or ID"
            )
        by_effect.setdefault(effect, []).append(signature_id)
    authority = {
        "none": "footprint frame: memory unchanged",
        "readOnly": "footprint frame: memory unchanged",
        "argumentRanges": (
            "runtime footprint-avoidance witness against the static slot"
        ),
        "newDynamicRanges": (
            "fresh dynamic-range/image-disjointness frame required"
        ),
        "relationalState": "explicit finite-set slot frame required",
    }
    return tuple(
        ExternalPreservationClass(
            memory_effect=effect,
            signature_ids=tuple(sorted(ids)),
            authority=authority.get(effect, "unsupported effect; fail closed"),
        )
        for effect, ids in sorted(by_effect.items())
    )


def _external_callback_protocols(
    report: Mapping[str, Any],
) -> tuple[ExternalCallbackProtocol, ...]:
    by_mode: dict[str, list[int]] = {}
    for row in _object_list(report.get("signatures"), "machine signatures"):
        mode = row.get("callback_mode", "none")
        signature_id = row.get("id")
        if not isinstance(mode, str) or not isinstance(signature_id, int):
            raise RelocatedWritableStaticPointerSlotProposalError(
                "machine signature lacks an exact callback mode or ID"
            )
        if mode != "none":
            by_mode.setdefault(mode, []).append(signature_id)
    authority = {
        "registration": (
            "checked callback-address registration and later invocation pairing"
        ),
        "nestedFrames": (
            "nested external/internal call frames preserving the static slot"
        ),
    }
    return tuple(
        ExternalCallbackProtocol(
            callback_mode=mode,
            signature_ids=tuple(sorted(ids)),
            authority=authority.get(mode, "unsupported callback mode; fail closed"),
        )
        for mode, ids in sorted(by_mode.items())
    )


def _authority_source(
    binding: SiteAuthorityBinding, lean: LeanAuthorityBinding
) -> str:
    imports = "\n".join(
        f"import {module}" for module in dict.fromkeys(
            (
                "StageA.RelationalRelocatedWritableStaticPointerSlot",
                *lean.dependency_modules,
            )
        )
    )
    writes = ", ".join(_lean_write(write) for write in binding.writes)
    if binding.finite_origin:
        if binding.transfer_kind != "jump":
            raise RelocatedWritableStaticPointerSlotProposalError(
                "finite-origin authority requires a tail jump"
            )
        certificate_type = "FiniteJumpCertificate"
        authority_type = "CheckedFiniteJumpAuthority"
        continuation = ""
        target_fields = (
            f"initialTargetId := {binding.target_id}\n"
            f"  initialTargetRva := {binding.target_rva}\n"
            f"  internalTargetIds := {list(binding.internal_target_ids)}\n"
            "  externalResourceIds := "
            f"{list(dict.fromkeys(route.resource_id for route in binding.external_routes))}"
        )
    elif binding.transfer_kind == "call":
        assert binding.continuation_target_id is not None
        certificate_type = "Certificate"
        authority_type = "CheckedAuthority"
        continuation = (
            f"\n  continuationTargetId := {binding.continuation_target_id}"
        )
        target_fields = (
            f"targetId := {binding.target_id}\n"
            f"  targetRva := {binding.target_rva}"
        )
    elif binding.transfer_kind == "jump":
        certificate_type = "JumpCertificate"
        authority_type = "CheckedJumpAuthority"
        continuation = ""
        target_fields = (
            f"targetId := {binding.target_id}\n"
            f"  targetRva := {binding.target_rva}"
        )
    else:
        raise RelocatedWritableStaticPointerSlotProposalError(
            f"unsupported transfer kind {binding.transfer_kind!r}"
        )
    return f"""{imports}

namespace {binding.namespace}

open StageA.Formal StageA.Relational
open StageA.Relational.RelocatedWritableStaticPointerSlot

set_option maxRecDepth 1000000
set_option maxHeartbeats 0

def generatedCertificate : {certificate_type} := {{
  sourceTargetId := {binding.source_target_id}
  instructionRva := {binding.instruction_rva}
  instructionBytes := {list(binding.instruction_bytes)}
  slotRva := {binding.slot_rva}
  slotBytes := {list(binding.slot_bytes)}
  {target_fields}
  {continuation.strip()}
  assembledRead := {str(binding.assembled_read).lower()}
  writes := [{writes}]
}}

theorem generatedCertificateChecked :
    generatedCertificate.checked {lean.context_term} {lean.carrier_term} = true := by
  decide +kernel

def generatedAuthority :
    {authority_type} {lean.context_term} {lean.carrier_term} := {{
  decodedAuthority := {lean.decoded_authority_term}
  certificate := generatedCertificate
  checked := generatedCertificateChecked
}}

#print axioms generatedCertificateChecked

end {binding.namespace}
"""


def _lean_write(write: OriginalRegisterOffsetWrite) -> str:
    value = write.value
    if value.get("op") == "const":
        expression = f".constant {int(value['value'])}"
    elif value.get("op") == "reg" and value.get("name") in _REGISTERS:
        expression = f".inputReg .{value['name']}"
    else:
        raise RelocatedWritableStaticPointerSlotProposalError(
            "validated write expression disappeared during Lean emission"
        )
    return (
        f"{{ register := .{write.register}, offset := {write.offset}, "
        f"value := {expression}, "
        f"subtract := {str(write.subtract).lower()} }}"
    )


def _highlow_relocation_counts(pe: pefile.PE) -> dict[int, int]:
    counts: dict[int, int] = {}
    for block in getattr(pe, "DIRECTORY_ENTRY_BASERELOC", ()):
        for entry in block.entries:
            if int(entry.type) == 3:
                rva = int(entry.rva)
                counts[rva] = counts.get(rva, 0) + 1
    return counts


def _jsonl_by_rva(path: Path) -> dict[int, Mapping[str, Any]]:
    result: dict[int, Mapping[str, Any]] = {}
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as error:
        raise RelocatedWritableStaticPointerSlotProposalError(
            f"cannot read state-machine JSONL: {error}"
        ) from error
    for line_number, line in enumerate(lines, 1):
        if not line.strip():
            continue
        try:
            value = json.loads(line)
        except json.JSONDecodeError as error:
            raise RelocatedWritableStaticPointerSlotProposalError(
                f"state-machine line {line_number} is invalid JSON: {error}"
            ) from error
        row = _mapping(value, f"state-machine line {line_number}")
        original = _mapping(
            row.get("original"), f"state-machine line {line_number}.original"
        )
        rva = original.get("rva_start")
        if not isinstance(rva, int) or isinstance(rva, bool) or rva < 0:
            raise RelocatedWritableStaticPointerSlotProposalError(
                f"state-machine line {line_number} lacks an exact source RVA"
            )
        if rva in result:
            raise RelocatedWritableStaticPointerSlotProposalError(
                f"state-machine has duplicate source RVA 0x{rva:x}"
            )
        result[rva] = row
    return result


def _register_offset_address(value: Any) -> tuple[str, int, bool] | None:
    def affine(expression: Any) -> tuple[dict[str, int], int] | None:
        if not isinstance(expression, Mapping):
            return None
        if (
            expression.get("op") == "reg"
            and expression.get("name") in _REGISTERS
        ):
            return {str(expression["name"]): 1}, 0
        constant = _const_value(expression)
        if constant is not None:
            return {}, constant
        args = expression.get("args")
        operation = expression.get("op")
        if (
            operation not in {"add32", "sub32"}
            or not isinstance(args, list)
            or len(args) != 2
        ):
            return None
        left = affine(args[0])
        right = affine(args[1])
        if left is None or right is None:
            return None
        sign = 1 if operation == "add32" else -1
        coefficients = dict(left[0])
        for register, coefficient in right[0].items():
            coefficients[register] = (
                coefficients.get(register, 0) + sign * coefficient
            )
            if coefficients[register] == 0:
                del coefficients[register]
        return coefficients, (left[1] + sign * right[1]) % _U32_LIMIT

    normalized = affine(value)
    if normalized is None or len(normalized[0]) != 1:
        return None
    ((register, coefficient),) = normalized[0].items()
    if coefficient != 1:
        return None
    offset = normalized[1]
    subtract = False
    if (
        isinstance(value, Mapping)
        and value.get("op") == "sub32"
        and isinstance(value.get("args"), list)
        and len(value["args"]) == 2
        and isinstance(value["args"][0], Mapping)
        and value["args"][0].get("op") == "reg"
        and value["args"][0].get("name") == register
        and (amount := _const_value(value["args"][1])) is not None
        and (-amount) % _U32_LIMIT == offset
        and offset != 0
    ):
        subtract = True
    return register, offset, subtract


def _write_value_supported(value: Any) -> bool:
    return isinstance(value, Mapping) and (
        (
            value.get("op") == "const"
            and isinstance(value.get("value"), int)
            and not isinstance(value.get("value"), bool)
        )
        or (
            value.get("op") == "reg"
            and value.get("name") in _REGISTERS
        )
    )


def _const_value(value: Any) -> int | None:
    if not isinstance(value, Mapping) or value.get("op") != "const":
        return None
    result = value.get("value")
    if isinstance(result, bool) or not isinstance(result, int):
        return None
    return result % _U32_LIMIT


def _object(path: Path) -> Mapping[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise RelocatedWritableStaticPointerSlotProposalError(
            f"cannot read JSON artifact {path}: {error}"
        ) from error
    return _mapping(value, str(path))


def _object_list(value: Any, field: str) -> list[Mapping[str, Any]]:
    if not isinstance(value, list):
        raise RelocatedWritableStaticPointerSlotProposalError(
            f"{field} must be a list"
        )
    return [_mapping(item, f"{field}[{index}]") for index, item in enumerate(value)]


def _mapping(value: Any, field: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise RelocatedWritableStaticPointerSlotProposalError(
            f"{field} must be an object"
        )
    return value


def _sha256(path: Path) -> str:
    try:
        return hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError as error:
        raise RelocatedWritableStaticPointerSlotProposalError(
            f"cannot hash {path}: {error}"
        ) from error


def mixed_original_plan_sha256(
    plan: InterpreterMixedOriginalPlan,
) -> str:
    """Hash the canonical diagnostic representation used by this handoff."""

    return hashlib.sha256(
        json.dumps(
            plan.to_json(),
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()


__all__ = [
    "AUTHORITY_FORMAT",
    "AUTHORITY_PROFILE",
    "AuthorityPlan",
    "ExternalCallbackProtocol",
    "ExternalPreservationClass",
    "LeanAuthorityBinding",
    "ProposalBlocker",
    "RelocatedWritableStaticPointerSlotProposalError",
    "SiteAuthorityBinding",
    "construct_relocated_writable_static_pointer_slot_authorities",
    "mixed_original_plan_sha256",
    "write_relocated_writable_static_pointer_slot_authorities",
]
