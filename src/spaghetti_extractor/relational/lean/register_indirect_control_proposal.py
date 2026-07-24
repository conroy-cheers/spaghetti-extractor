"""Propose exact authorities for register-mediated original indirect control.

The proposal is intentionally non-authoritative.  It binds the current mixed
original plan, original PE, state-machine export, machine import inventory, and
any relocated-writable-slot authorities by hash.  Lean must still reparse the
PE, decode every site and carry boundary, validate the finite target inventory,
and consume a runtime closure proof.
"""

from __future__ import annotations

import hashlib
import json
import textwrap
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any, Literal, Mapping, Sequence

import capstone
import pefile
from capstone.x86 import X86_OP_IMM, X86_OP_MEM, X86_OP_REG

from ...errors import StageAInputError
from .interpreter_mixed_original import (
    InterpreterMixedOriginalPlan,
    OriginalGenerationBlocker,
    OriginalRegion,
)
from .relocated_writable_static_pointer_slot_proposal import (
    mixed_original_plan_sha256,
)


AUTHORITY_FORMAT = "stage-a-register-indirect-control-authorities-v1"
AUTHORITY_PROFILE = "register_indirect_control_v1"
_U32_LIMIT = 1 << 32
_REGISTER_BLOCKER_CATEGORIES = {
    "register_function_pointer",
    "register_tail_target",
}
_REGISTER_NAMES = frozenset(("eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp"))


class RegisterIndirectControlProposalError(StageAInputError):
    """The exact proposal inputs are malformed or cannot be reconciled."""

    def __init__(
        self,
        message: str,
        *,
        reason_code: str = "register_indirect_control_unresolved",
    ) -> None:
        super().__init__(message)
        self.reason_code = reason_code


@dataclass(frozen=True)
class ImportIdentity:
    dll: str
    symbol: str | None
    ordinal: int | None
    iat_rva: int
    iat_va: int
    contract_id: int | None

    def to_json(self) -> dict[str, Any]:
        return {
            "contract_id": self.contract_id,
            "dll": self.dll,
            "iat_rva": self.iat_rva,
            "iat_va": self.iat_va,
            "ordinal": self.ordinal,
            "symbol": self.symbol,
        }


@dataclass(frozen=True)
class ResolverQuery:
    resolver: ImportIdentity
    call_rva: int
    identity_rva: int
    identity_bytes: bytes
    resource_id: int

    def to_json(self) -> dict[str, Any]:
        return {
            "call_rva": self.call_rva,
            "identity_bytes": self.identity_bytes.hex(),
            "identity_rva": self.identity_rva,
            "resolver": self.resolver.to_json(),
            "resource_id": self.resource_id,
        }


@dataclass(frozen=True)
class ProducerEvidence:
    kind: Literal[
        "absolute_slot",
        "memory_load",
        "resolver_call",
        "immediate_code",
    ]
    instruction_rva: int
    instruction_bytes: bytes
    register: str
    slot_rva: int | None = None
    resource_id: int | None = None
    target_id: int | None = None

    def to_json(self) -> dict[str, Any]:
        return {
            "instruction_bytes": self.instruction_bytes.hex(),
            "instruction_rva": self.instruction_rva,
            "kind": self.kind,
            "register": self.register,
            "resource_id": self.resource_id,
            "slot_rva": self.slot_rva,
            "target_id": self.target_id,
        }


@dataclass(frozen=True)
class TargetInventory:
    kind: Literal[
        "internal_code",
        "imported_address",
        "resolver_result",
        "registered_callback_slot",
        "nullable_code_table",
    ]
    target_ids: tuple[int, ...] = ()
    target_rvas: tuple[int, ...] = ()
    imported: ImportIdentity | None = None
    resolver: ImportIdentity | None = None
    resolver_queries: tuple[ResolverQuery, ...] = ()
    identity_rva: int | None = None
    identity_bytes: bytes = b""
    resource_ids: tuple[int, ...] = ()
    slot_rva: int | None = None
    slot_va: int | None = None
    table_start_rva: int | None = None
    table_end_rva: int | None = None
    table_entries: tuple[int | None, ...] = ()
    producers: tuple[ProducerEvidence, ...] = ()

    def to_json(self) -> dict[str, Any]:
        return {
            "identity_bytes": self.identity_bytes.hex(),
            "identity_rva": self.identity_rva,
            "imported": None if self.imported is None else self.imported.to_json(),
            "kind": self.kind,
            "producers": [producer.to_json() for producer in self.producers],
            "resolver": None if self.resolver is None else self.resolver.to_json(),
            "resolver_queries": [query.to_json() for query in self.resolver_queries],
            "resource_ids": list(self.resource_ids),
            "slot_rva": self.slot_rva,
            "slot_va": self.slot_va,
            "table_end_rva": self.table_end_rva,
            "table_entries": list(self.table_entries),
            "table_start_rva": self.table_start_rva,
            "target_ids": list(self.target_ids),
            "target_rvas": list(self.target_rvas),
        }


@dataclass(frozen=True)
class CarryBoundary:
    source_target_id: int
    source_rva: int
    instruction_rva: int
    instruction_bytes: bytes
    continuation_target_id: int
    continuation_rva: int
    register: str
    kind: Literal[
        "internal_call",
        "machine_import",
        "target_call",
        "stack_restore",
    ]
    callee_target_id: int | None = None
    contract_id: int | None = None
    save_rva: int | None = None
    save_bytes: bytes = b""
    restore_rva: int | None = None
    restore_bytes: bytes = b""
    authority_requirement: str = ""

    def to_json(self) -> dict[str, Any]:
        return {
            "authority_requirement": self.authority_requirement,
            "callee_target_id": self.callee_target_id,
            "continuation_rva": self.continuation_rva,
            "continuation_target_id": self.continuation_target_id,
            "contract_id": self.contract_id,
            "instruction_bytes": self.instruction_bytes.hex(),
            "instruction_rva": self.instruction_rva,
            "kind": self.kind,
            "register": self.register,
            "restore_rva": self.restore_rva,
            "restore_bytes": self.restore_bytes.hex(),
            "save_rva": self.save_rva,
            "save_bytes": self.save_bytes.hex(),
            "source_rva": self.source_rva,
            "source_target_id": self.source_target_id,
        }


@dataclass(frozen=True)
class SiteProposal:
    site_id: int
    source_target_id: int
    source_rva: int
    instruction_rva: int
    instruction_bytes: bytes
    transfer: Literal["call", "jump"]
    target_register: str
    continuation_target_id: int | None
    continuation_rva: int | None
    inventory: TargetInventory
    carries: tuple[CarryBoundary, ...]
    blocker_detail: str

    @property
    def module(self) -> str:
        return f"StageA.GeneratedRegisterIndirectControlAuthority{self.site_id:04d}"

    @property
    def namespace(self) -> str:
        return self.module

    def to_json(self) -> dict[str, Any]:
        return {
            "authorizing_lean_term": {
                "module": self.module,
                "namespace": self.namespace,
                "symbol": "generatedAuthority",
            },
            "blocker_detail": self.blocker_detail,
            "carries": [carry.to_json() for carry in self.carries],
            "continuation_rva": self.continuation_rva,
            "continuation_target_id": self.continuation_target_id,
            "instruction_bytes": self.instruction_bytes.hex(),
            "instruction_rva": self.instruction_rva,
            "inventory": self.inventory.to_json(),
            "profile": AUTHORITY_PROFILE,
            "site_id": self.site_id,
            "source_rva": self.source_rva,
            "source_target_id": self.source_target_id,
            "target_register": self.target_register,
            "transfer": self.transfer,
        }


@dataclass(frozen=True)
class ProposalBlocker:
    category: str
    reason_code: str
    location_rva: int | None
    detail: str

    def to_json(self) -> dict[str, Any]:
        return {
            "category": self.category,
            "detail": self.detail,
            "location_rva": self.location_rva,
            "reason_code": self.reason_code,
        }


@dataclass(frozen=True)
class ProposalPlan:
    original_sha256: str
    state_machine_sha256: str
    machine_import_report_sha256: str
    mixed_original_plan_sha256: str
    writable_slot_report_sha256: str | None
    sites: tuple[SiteProposal, ...]
    blockers: tuple[ProposalBlocker, ...]
    untouched_blockers: tuple[OriginalGenerationBlocker, ...]

    def to_json(self) -> dict[str, Any]:
        return {
            "artifact_role": {
                "acceptance_authority": False,
                "lean_checker_must_reparse_and_redecode": True,
                "proposal_only": True,
                "report_status_is_authority": False,
            },
            "blockers": [blocker.to_json() for blocker in self.blockers],
            "counts": {
                "register_sites": len(self.sites),
                "register_sites_unresolved": len(self.blockers),
                "untouched_nonregister_blockers": len(self.untouched_blockers),
            },
            "format": AUTHORITY_FORMAT,
            "inputs": {
                "machine_import_report_sha256": self.machine_import_report_sha256,
                "mixed_original_plan_sha256": self.mixed_original_plan_sha256,
                "original_sha256": self.original_sha256,
                "state_machine_sha256": self.state_machine_sha256,
                "writable_slot_report_sha256": self.writable_slot_report_sha256,
            },
            "sites": [site.to_json() for site in self.sites],
            "untouched_blockers": [
                blocker.to_json() for blocker in self.untouched_blockers
            ],
        }


@dataclass(frozen=True)
class LeanBindings:
    context_module: str
    context_term: str
    exact_authority_term: str
    runtime_premise_module: str
    runtime_reachability_term: str
    runtime_premise_term: str


@dataclass(frozen=True)
class _DecodedRow:
    index: int
    start: int
    stop: int
    instructions: tuple[Mapping[str, Any], ...]


def construct_register_indirect_control_authorities(
    *,
    original: Path | str,
    state_machine: Path | str,
    machine_import_report: Path | str,
    mixed_original_plan: InterpreterMixedOriginalPlan,
    writable_slot_authority_report: Path | str | None = None,
    callable_resource_ids_by_instruction_rva: Mapping[int, int] | None = None,
) -> ProposalPlan:
    """Construct proposal-only evidence for every register/tail blocker."""

    original_path = Path(original)
    state_machine_path = Path(state_machine)
    import_report_path = Path(machine_import_report)
    callable_resource_ids = (
        {}
        if callable_resource_ids_by_instruction_rva is None
        else callable_resource_ids_by_instruction_rva
    )
    rows = _state_rows(state_machine_path)
    writable = _writable_slot_inventory(writable_slot_authority_report)
    regions_by_rva = {region.rva: region for region in mixed_original_plan.regions}
    target_by_rva = {
        region.rva: region.target_id for region in mixed_original_plan.regions
    }

    pe = pefile.PE(str(original_path), fast_load=False)
    try:
        image_base = int(pe.OPTIONAL_HEADER.ImageBase)
        imports, contracts = _machine_import_inventory(
            import_report_path, image_base=image_base, pe=pe
        )
        decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
        decoder.detail = True
        register_blockers = tuple(
            blocker
            for blocker in mixed_original_plan.blockers
            if _blocker_category(blocker.detail) in _REGISTER_BLOCKER_CATEGORIES
        )
        untouched = tuple(
            blocker
            for blocker in mixed_original_plan.blockers
            if _blocker_category(blocker.detail) not in _REGISTER_BLOCKER_CATEGORIES
        )
        proposals: list[SiteProposal] = []
        blockers: list[ProposalBlocker] = []
        for site_id, blocker in enumerate(register_blockers):
            try:
                proposal = _site_proposal(
                    site_id=site_id,
                    blocker=blocker,
                    pe=pe,
                    image_base=image_base,
                    decoder=decoder,
                    rows=rows,
                    regions_by_rva=regions_by_rva,
                    target_by_rva=target_by_rva,
                    imports=imports,
                    contracts=contracts,
                    writable=writable,
                    callable_resource_ids_by_instruction_rva=callable_resource_ids,
                    plan=mixed_original_plan,
                )
            except RegisterIndirectControlProposalError as error:
                blockers.append(
                    ProposalBlocker(
                        category="register_indirect_control_unresolved",
                        reason_code=error.reason_code,
                        location_rva=blocker.rva,
                        detail=str(error),
                    )
                )
                continue
            proposals.append(proposal)
    finally:
        pe.close()

    return ProposalPlan(
        original_sha256=_sha256(original_path),
        state_machine_sha256=_sha256(state_machine_path),
        machine_import_report_sha256=_sha256(import_report_path),
        mixed_original_plan_sha256=mixed_original_plan_sha256(mixed_original_plan),
        writable_slot_report_sha256=(
            None
            if writable_slot_authority_report is None
            else _sha256(Path(writable_slot_authority_report))
        ),
        sites=tuple(proposals),
        blockers=tuple(blockers),
        untouched_blockers=untouched,
    )


def write_register_indirect_control_authorities(
    out: Path | str,
    plan: ProposalPlan,
    bindings: Mapping[int, LeanBindings],
) -> Path:
    """Emit independently cacheable Lean authority constructors and a report."""

    root = Path(out)
    stage_a = root / "StageA"
    stage_a.mkdir(parents=True, exist_ok=True)
    for site in plan.sites:
        binding = bindings.get(site.site_id)
        if binding is None:
            raise RegisterIndirectControlProposalError(
                f"site {site.site_id} has no Lean binding"
            )
        path = (
            stage_a
            / f"GeneratedRegisterIndirectControlAuthority{site.site_id:04d}.lean"
        )
        path.write_text(_authority_source(site, binding), encoding="utf-8")
    report = root / "register-indirect-control-authorities.json"
    report.write_text(
        json.dumps(plan.to_json(), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return report


def _site_proposal(
    *,
    site_id: int,
    blocker: OriginalGenerationBlocker,
    pe: pefile.PE,
    image_base: int,
    decoder: capstone.Cs,
    rows: Mapping[int, _DecodedRow],
    regions_by_rva: Mapping[int, OriginalRegion],
    target_by_rva: Mapping[int, int],
    imports: Mapping[int, ImportIdentity],
    contracts: Mapping[int, int],
    writable: Mapping[int, Mapping[str, Any]],
    callable_resource_ids_by_instruction_rva: Mapping[int, int],
    plan: InterpreterMixedOriginalPlan,
) -> SiteProposal:
    if blocker.rva is None:
        raise RegisterIndirectControlProposalError("register site has no RVA")
    source_row = _row_at(rows, blocker.rva)
    region = regions_by_rva.get(source_row.start)
    if region is None:
        raise RegisterIndirectControlProposalError(
            f"site 0x{blocker.rva:x} has no canonical source region"
        )
    indirect = _last_indirect(decoder, source_row)
    register = indirect.reg_name(indirect.operands[0].reg)
    if register not in _REGISTER_NAMES:
        raise RegisterIndirectControlProposalError(
            f"site 0x{blocker.rva:x} uses unsupported register {register!r}"
        )
    transfer: Literal["call", "jump"] = (
        "call" if indirect.mnemonic == "call" else "jump"
    )
    continuation_rva = None if transfer == "jump" else indirect.address + indirect.size
    continuation_target_id = (
        None if continuation_rva is None else target_by_rva.get(continuation_rva)
    )
    if transfer == "call" and continuation_target_id is None:
        raise RegisterIndirectControlProposalError(
            f"site 0x{blocker.rva:x} has no exact continuation target",
            reason_code="missing_exact_continuation",
        )

    inventory, seed_rva = _target_inventory(
        pe=pe,
        image_base=image_base,
        decoder=decoder,
        site_instruction=indirect,
        register=register,
        imports=imports,
        contracts=contracts,
        writable=writable,
        callable_resource_ids_by_instruction_rva=(
            callable_resource_ids_by_instruction_rva
        ),
        target_by_rva=target_by_rva,
        rows=rows,
        source_target_id=region.target_id,
        plan=plan,
    )
    carries = _carry_boundaries(
        blocker=blocker,
        image_base=image_base,
        source_target_id=region.target_id,
        register=register,
        seed_rva=seed_rva,
        site_instruction_rva=indirect.address,
        decoder=decoder,
        rows=rows,
        regions_by_rva=regions_by_rva,
        target_by_rva=target_by_rva,
        imports=imports,
        contracts=contracts,
        writable=writable,
        plan=plan,
        producer_call_rvas=tuple(
            query.call_rva for query in inventory.resolver_queries
        ),
    )
    return SiteProposal(
        site_id=site_id,
        source_target_id=region.target_id,
        source_rva=source_row.start,
        instruction_rva=indirect.address,
        instruction_bytes=bytes(indirect.bytes),
        transfer=transfer,
        target_register=register,
        continuation_target_id=continuation_target_id,
        continuation_rva=continuation_rva,
        inventory=inventory,
        carries=carries,
        blocker_detail=blocker.detail,
    )


def _target_inventory(
    *,
    pe: pefile.PE,
    image_base: int,
    decoder: capstone.Cs,
    site_instruction: Any,
    register: str,
    imports: Mapping[int, ImportIdentity],
    contracts: Mapping[int, int],
    writable: Mapping[int, Mapping[str, Any]],
    callable_resource_ids_by_instruction_rva: Mapping[int, int],
    target_by_rva: Mapping[int, int],
    rows: Mapping[int, _DecodedRow],
    source_target_id: int,
    plan: InterpreterMixedOriginalPlan,
) -> tuple[TargetInventory, int]:
    decoded = _decoded_cfg_predecessors(
        rows=rows,
        decoder=decoder,
        plan=plan,
        source_target_id=source_target_id,
        stop=int(site_instruction.address),
    )

    if site_instruction.mnemonic == "jmp" and register == "eax":
        resolver_matches = _resolver_calls(decoded, imports)
        if resolver_matches:
            missing = tuple(
                call_rva
                for _resolver, call_rva in resolver_matches
                if call_rva not in callable_resource_ids_by_instruction_rva
            )
            if missing:
                locations = ", ".join(f"0x{rva:x}" for rva in missing)
                raise RegisterIndirectControlProposalError(
                    "resolver call(s) have no canonical callable capability: "
                    f"{locations}",
                    reason_code="resolver_capability_unbound",
                )
            queries = tuple(
                ResolverQuery(
                    resolver=resolver,
                    call_rva=call_rva,
                    identity_rva=identity_rva,
                    identity_bytes=identity,
                    resource_id=callable_resource_ids_by_instruction_rva[
                        call_rva
                    ],
                )
                for resolver, call_rva in resolver_matches
                for identity_rva, identity in (
                    (_resolver_identity(pe, decoded, call_rva)),
                )
            )
            static_target_ids, static_target_rvas = _immediate_code_targets(
                instructions=decoded,
                register=register,
                image_base=image_base,
                target_by_rva=target_by_rva,
            )
            instructions_by_rva = {
                int(instruction.address): instruction for instruction in decoded
            }
            producers = [
                ProducerEvidence(
                    kind="resolver_call",
                    instruction_rva=query.call_rva,
                    instruction_bytes=bytes(
                        instructions_by_rva[query.call_rva].bytes
                    ),
                    register=instructions_by_rva[query.call_rva].reg_name(
                        instructions_by_rva[query.call_rva].operands[0].reg
                    ),
                    resource_id=query.resource_id,
                )
                for query in queries
            ]
            producers.extend(
                _immediate_code_producers(
                    instructions=decoded,
                    register=register,
                    image_base=image_base,
                    target_by_rva=target_by_rva,
                )
            )
            return (
                TargetInventory(
                    kind="resolver_result",
                    resolver=queries[0].resolver,
                    resolver_queries=queries,
                    target_ids=static_target_ids,
                    target_rvas=static_target_rvas,
                    resource_ids=tuple(query.resource_id for query in queries),
                    producers=tuple(producers),
                ),
                min(query.call_rva for query in queries) + 1,
            )

    for instruction in decoded:
        absolute = _absolute_load(instruction, register)
        if absolute is not None:
            inventory, _ = _inventory_for_absolute_slot(
                pe=pe,
                image_base=image_base,
                slot_va=absolute,
                imports=imports,
                writable=writable,
                target_by_rva=target_by_rva,
                decoder=decoder,
                rows=rows,
                plan=plan,
            )
            slot_rva = (
                inventory.imported.iat_rva
                if inventory.kind == "imported_address"
                and inventory.imported is not None
                else inventory.slot_rva
            )
            assert slot_rva is not None
            return (
                replace(
                    inventory,
                    producers=(
                        ProducerEvidence(
                            kind="absolute_slot",
                            instruction_rva=int(instruction.address),
                            instruction_bytes=bytes(instruction.bytes),
                            register=register,
                            slot_rva=slot_rva,
                        ),
                    ),
                ),
                instruction.address,
            )
        memory_base = _register_memory_load_base(instruction, register)
        if memory_base is not None and memory_base != "esp":
            table = _nullable_table_from_callers(
                pe=pe,
                image_base=image_base,
                target_by_rva=target_by_rva,
                plan=plan,
            )
            return (
                replace(
                    table,
                    producers=(
                        ProducerEvidence(
                            kind="memory_load",
                            instruction_rva=int(instruction.address),
                            instruction_bytes=bytes(instruction.bytes),
                            register=register,
                        ),
                    ),
                ),
                instruction.address,
            )
        if memory_base == "esp":
            continue
        if _writes_register(instruction, register):
            raise RegisterIndirectControlProposalError(
                f"nearest write to {register} at 0x{instruction.address:x} "
                "has no finite static provenance",
                reason_code="register_provenance_unresolved",
            )
    raise RegisterIndirectControlProposalError(
        f"cannot recover a finite origin for {register} at "
        f"0x{site_instruction.address:x}",
        reason_code="register_provenance_unresolved",
    )


def _inventory_for_absolute_slot(
    *,
    pe: pefile.PE,
    image_base: int,
    slot_va: int,
    imports: Mapping[int, ImportIdentity],
    writable: Mapping[int, Mapping[str, Any]],
    target_by_rva: Mapping[int, int],
    decoder: capstone.Cs,
    rows: Mapping[int, _DecodedRow],
    plan: InterpreterMixedOriginalPlan,
) -> tuple[TargetInventory, int]:
    slot_rva = slot_va - image_base
    imported = imports.get(slot_rva)
    if imported is not None:
        return TargetInventory(kind="imported_address", imported=imported), slot_rva
    writable_site = writable.get(slot_rva)
    if writable_site is not None:
        target_rva = _natural(writable_site.get("target_rva"), "writable target RVA")
        target_id = target_by_rva.get(target_rva)
        if target_id is None:
            raise RegisterIndirectControlProposalError(
                f"writable slot 0x{slot_rva:x} names absent target 0x{target_rva:x}"
            )
        return (
            TargetInventory(
                kind="internal_code",
                target_ids=(target_id,),
                target_rvas=(target_rva,),
                slot_rva=slot_rva,
                slot_va=slot_va,
            ),
            slot_rva,
        )
    value = int.from_bytes(pe.get_data(slot_rva, 4), "little")
    if value == 0 and _writable_nonexec(pe, slot_rva):
        target_ids, target_rvas = _callback_slot_targets(
            pe=pe,
            image_base=image_base,
            slot_va=slot_va,
            decoder=decoder,
            rows=rows,
            plan=plan,
            target_by_rva=target_by_rva,
        )
        return (
            TargetInventory(
                kind="registered_callback_slot",
                slot_rva=slot_rva,
                slot_va=slot_va,
                target_ids=target_ids,
                target_rvas=target_rvas,
            ),
            slot_rva,
        )
    raise RegisterIndirectControlProposalError(
        f"absolute slot 0x{slot_rva:x} is neither IAT, checked relocated code, "
        "nor a zero-initialized callback slot"
    )


def _callback_slot_targets(
    *,
    pe: pefile.PE,
    image_base: int,
    slot_va: int,
    decoder: capstone.Cs,
    rows: Mapping[int, _DecodedRow],
    plan: InterpreterMixedOriginalPlan,
    target_by_rva: Mapping[int, int],
) -> tuple[tuple[int, ...], tuple[int, ...]]:
    writers: list[tuple[_DecodedRow, Any, Any]] = []
    decoded_rows: dict[int, tuple[Any, ...]] = {}
    for row in rows.values():
        instructions = _decode_row(decoder, row)
        decoded_rows[row.start] = instructions
        for instruction in instructions:
            if instruction.mnemonic != "mov" or len(instruction.operands) != 2:
                continue
            destination, source = instruction.operands
            if (
                destination.type == X86_OP_MEM
                and destination.mem.base == 0
                and destination.mem.index == 0
                and (int(destination.mem.disp) & 0xFFFFFFFF) == slot_va
            ):
                writers.append((row, instruction, source))

    values: list[int] = []
    for row, writer, source in writers:
        if source.type == X86_OP_IMM:
            values.append(int(source.imm) & 0xFFFFFFFF)
            continue
        if source.type != X86_OP_REG:
            raise RegisterIndirectControlProposalError(
                f"callback slot 0x{slot_va - image_base:x} has unsupported "
                f"writer at 0x{writer.address:x}",
                reason_code="callback_target_inventory_incomplete",
            )
        writer_entry = row.start
        caller_values: list[int] = []
        for caller in plan.regions:
            instructions = decoded_rows.get(caller.rva, ())
            for index, instruction in enumerate(instructions):
                if instruction.mnemonic != "call" or not instruction.operands:
                    continue
                operand = instruction.operands[0]
                if operand.type != X86_OP_IMM:
                    continue
                target = int(operand.imm) & 0xFFFFFFFF
                target_rva = target - image_base if target >= image_base else target
                if target_rva != writer_entry:
                    continue
                argument = _nearest_stack_argument(instructions[:index])
                if argument is None:
                    raise RegisterIndirectControlProposalError(
                        f"callback writer 0x{writer_entry:x} has a caller at "
                        f"0x{instruction.address:x} without a constant argument",
                        reason_code="callback_target_inventory_incomplete",
                    )
                caller_values.append(argument)
        if not caller_values:
            raise RegisterIndirectControlProposalError(
                f"register callback writer 0x{writer_entry:x} has no exact "
                "direct caller inventory",
                reason_code="callback_target_inventory_incomplete",
            )
        values.extend(caller_values)

    target_ids: list[int] = []
    target_rvas: list[int] = []
    for value in values:
        if value == 0:
            continue
        target_rva = value - image_base if value >= image_base else value
        target_id = target_by_rva.get(target_rva)
        if target_id is None:
            raise RegisterIndirectControlProposalError(
                f"callback slot 0x{slot_va - image_base:x} receives "
                f"noncanonical target 0x{target_rva:x}"
            )
        target_ids.append(target_id)
        target_rvas.append(target_rva)
    return (
        tuple(dict.fromkeys(target_ids)),
        tuple(dict.fromkeys(target_rvas)),
    )


def _nearest_stack_argument(instructions: Sequence[Any]) -> int | None:
    for instruction in reversed(instructions):
        if instruction.mnemonic != "mov" or len(instruction.operands) != 2:
            continue
        destination, source = instruction.operands
        if (
            destination.type == X86_OP_MEM
            and instruction.reg_name(destination.mem.base) == "esp"
            and destination.mem.index == 0
            and int(destination.mem.disp) == 0
            and source.type == X86_OP_IMM
        ):
            return int(source.imm) & 0xFFFFFFFF
    return None


def _nullable_table_from_callers(
    *,
    pe: pefile.PE,
    image_base: int,
    target_by_rva: Mapping[int, int],
    plan: InterpreterMixedOriginalPlan,
) -> TargetInventory:
    candidates: list[tuple[int, int]] = []
    for region in plan.regions:
        data = pe.get_data(region.rva, region.size)
        if b"\xc7\x04\x24" not in data or b"\xc7\x44\x24\x04" not in data:
            continue
        immediates = [
            int.from_bytes(data[index + 3 : index + 7], "little")
            for index in range(max(0, len(data) - 6))
            if data[index : index + 3] == b"\xc7\x04\x24"
        ]
        second = [
            int.from_bytes(data[index + 4 : index + 8], "little")
            for index in range(max(0, len(data) - 7))
            if data[index : index + 4] == b"\xc7\x44\x24\x04"
        ]
        for start in immediates:
            for end in second:
                if (
                    image_base
                    <= start
                    < end
                    <= image_base + int(pe.OPTIONAL_HEADER.SizeOfImage)
                ):
                    if (end - start) % 4 == 0 and end - start <= 4096:
                        candidates.append((start - image_base, end - image_base))
    if not candidates:
        raise RegisterIndirectControlProposalError(
            "memory-derived register target has no bounded PE pointer-table caller"
        )
    start_rva, end_rva = min(candidates, key=lambda pair: pair[1] - pair[0])
    entries: list[int | None] = []
    target_ids: list[int] = []
    target_rvas: list[int] = []
    for slot_rva in range(start_rva, end_rva, 4):
        word = int.from_bytes(pe.get_data(slot_rva, 4), "little")
        if word == 0:
            entries.append(None)
            continue
        target_rva = word - image_base
        target_id = target_by_rva.get(target_rva)
        if target_id is None:
            raise RegisterIndirectControlProposalError(
                f"table slot 0x{slot_rva:x} names noncanonical target 0x{target_rva:x}"
            )
        entries.append(target_id)
        target_ids.append(target_id)
        target_rvas.append(target_rva)
    return TargetInventory(
        kind="nullable_code_table",
        target_ids=tuple(dict.fromkeys(target_ids)),
        target_rvas=tuple(dict.fromkeys(target_rvas)),
        table_start_rva=start_rva,
        table_end_rva=end_rva,
        table_entries=tuple(entries),
    )


def _carry_boundaries(
    *,
    blocker: OriginalGenerationBlocker,
    image_base: int,
    source_target_id: int,
    register: str,
    seed_rva: int,
    site_instruction_rva: int,
    decoder: capstone.Cs,
    rows: Mapping[int, _DecodedRow],
    regions_by_rva: Mapping[int, OriginalRegion],
    target_by_rva: Mapping[int, int],
    imports: Mapping[int, ImportIdentity],
    contracts: Mapping[int, int],
    writable: Mapping[int, Mapping[str, Any]],
    plan: InterpreterMixedOriginalPlan,
    producer_call_rvas: tuple[int, ...],
) -> tuple[CarryBoundary, ...]:
    del blocker
    calls = _cfg_slice_calls(
        seed_rva=seed_rva,
        site_instruction_rva=site_instruction_rva,
        source_target_id=source_target_id,
        decoder=decoder,
        rows=rows,
        plan=plan,
    )
    restored = _stack_restore_crossing(
        rows=rows,
        decoder=decoder,
        register=register,
        start=seed_rva,
        stop=site_instruction_rva,
        regions_by_rva=regions_by_rva,
        target_by_rva=target_by_rva,
        calls=calls,
    )
    boundaries: list[CarryBoundary] = []
    for call in calls:
        if call.address in producer_call_rvas:
            continue
        if (
            restored is not None
            and restored.save_rva is not None
            and restored.restore_rva is not None
            and restored.save_rva <= call.address < restored.restore_rva
        ):
            continue
        row = _row_at(rows, call.address)
        region = regions_by_rva.get(row.start)
        continuation = call.address + call.size
        continuation_id = target_by_rva.get(continuation)
        if region is None or continuation_id is None:
            raise RegisterIndirectControlProposalError(
                f"carry call 0x{call.address:x} has no exact endpoints",
                reason_code="carry_endpoint_missing",
            )
        kind, callee_id, contract_id, requirement = _carry_kind(
            call=call,
            image_base=image_base,
            register=register,
            imports=imports,
            contracts=contracts,
            writable=writable,
            target_by_rva=target_by_rva,
        )
        boundaries.append(
            CarryBoundary(
                source_target_id=region.target_id,
                source_rva=row.start,
                instruction_rva=call.address,
                instruction_bytes=bytes(call.bytes),
                continuation_target_id=continuation_id,
                continuation_rva=continuation,
                register=register,
                kind=kind,
                callee_target_id=callee_id,
                contract_id=contract_id,
                authority_requirement=requirement,
            )
        )
    if restored is not None:
        boundaries.append(restored)
    return tuple(sorted(boundaries, key=lambda boundary: boundary.instruction_rva))


def _cfg_slice_calls(
    *,
    seed_rva: int,
    site_instruction_rva: int,
    source_target_id: int,
    decoder: capstone.Cs,
    rows: Mapping[int, _DecodedRow],
    plan: InterpreterMixedOriginalPlan,
) -> tuple[Any, ...]:
    regions = {region.target_id: region for region in plan.regions}
    successors = _carrier_successors(
        plan=plan,
        rows=rows,
        decoder=decoder,
    )
    seed_row = _row_at(rows, seed_rva)
    seed_region = next(
        (region for region in plan.regions if region.rva == seed_row.start),
        None,
    )
    if seed_region is None:
        raise RegisterIndirectControlProposalError(
            f"register seed 0x{seed_rva:x} has no canonical region"
        )

    forward: set[int] = set()
    pending = [seed_region.target_id]
    while pending and len(forward) <= len(regions):
        target_id = pending.pop()
        if target_id in forward:
            continue
        forward.add(target_id)
        if target_id == source_target_id:
            continue
        pending.extend(successors.get(target_id, ()))

    predecessors: dict[int, list[int]] = {}
    for region in plan.regions:
        for target_id in successors.get(region.target_id, ()):
            predecessors.setdefault(target_id, []).append(region.target_id)
    backward: set[int] = set()
    pending = [source_target_id]
    while pending and len(backward) <= len(regions):
        target_id = pending.pop()
        if target_id in backward:
            continue
        backward.add(target_id)
        if target_id == seed_region.target_id:
            continue
        pending.extend(predecessors.get(target_id, ()))

    slice_ids = forward & backward
    calls: dict[int, Any] = {}
    for target_id in slice_ids:
        region = regions[target_id]
        row = rows.get(region.rva)
        if row is None:
            raise RegisterIndirectControlProposalError(
                f"CFG slice target {target_id} has no decoded row"
            )
        for instruction in _decode_row(decoder, row):
            if instruction.mnemonic != "call":
                continue
            if target_id == seed_region.target_id and instruction.address < seed_rva:
                continue
            if (
                target_id == source_target_id
                and site_instruction_rva <= instruction.address
            ):
                continue
            calls[instruction.address] = instruction
    return tuple(calls[address] for address in sorted(calls))


def _carrier_successors(
    *,
    plan: InterpreterMixedOriginalPlan,
    rows: Mapping[int, _DecodedRow],
    decoder: capstone.Cs,
) -> dict[int, tuple[int, ...]]:
    target_by_rva = {region.rva: region.target_id for region in plan.regions}
    result: dict[int, tuple[int, ...]] = {}
    for region in plan.regions:
        row = rows.get(region.rva)
        if row is None:
            result[region.target_id] = region.successor_ids
            continue
        instructions = _decode_row(decoder, row)
        if any(instruction.mnemonic.startswith("ret") for instruction in instructions):
            result[region.target_id] = ()
            continue
        calls = [
            instruction
            for instruction in instructions
            if instruction.mnemonic == "call"
        ]
        if not calls:
            result[region.target_id] = region.successor_ids
            continue
        continuation_rva = calls[-1].address + calls[-1].size
        continuation_id = target_by_rva.get(continuation_rva)
        if continuation_id is None:
            result[region.target_id] = ()
            continue
        if continuation_id not in region.successor_ids:
            result[region.target_id] = region.successor_ids
            continue
        result[region.target_id] = (continuation_id,)
    return result


def _carry_kind(
    *,
    call: Any,
    image_base: int,
    register: str,
    imports: Mapping[int, ImportIdentity],
    contracts: Mapping[int, int],
    writable: Mapping[int, Mapping[str, Any]],
    target_by_rva: Mapping[int, int],
) -> tuple[str, int | None, int | None, str]:
    operand = call.operands[0]
    if operand.type == X86_OP_IMM:
        target = int(operand.imm) & 0xFFFFFFFF
        target_rva = target - image_base if target >= image_base else target
        target_id = target_by_rva.get(target_rva)
        if target_id is None:
            raise RegisterIndirectControlProposalError(
                f"direct carry call 0x{call.address:x} has no canonical callee"
            )
        return (
            "internal_call",
            target_id,
            None,
            "CheckedDirectCallRegisterControlContract",
        )
    if operand.type == X86_OP_MEM and operand.mem.base == 0:
        slot = int(operand.mem.disp) & 0xFFFFFFFF
        slot_rva = slot - image_base if slot >= image_base else slot
        imported = imports.get(slot_rva)
        if imported is not None:
            contract_id = imported.contract_id
            if contract_id is None:
                raise RegisterIndirectControlProposalError(
                    f"import carry call 0x{call.address:x} has no machine contract",
                    reason_code="machine_import_preservation_missing",
                )
            return (
                "machine_import",
                None,
                contract_id,
                "StaticMachineImportBoundaryContractCertificate",
            )
    if operand.type == X86_OP_REG:
        return (
            "target_call",
            None,
            None,
            "target inventory ABI preservation theorem",
        )
    raise RegisterIndirectControlProposalError(
        f"carry call 0x{call.address:x} has unsupported operand",
        reason_code="carry_boundary_unsupported",
    )


def _stack_restore_crossing(
    *,
    rows: Mapping[int, _DecodedRow],
    decoder: capstone.Cs,
    register: str,
    start: int,
    stop: int,
    regions_by_rva: Mapping[int, OriginalRegion],
    target_by_rva: Mapping[int, int],
    calls: Sequence[Any],
) -> CarryBoundary | None:
    instructions: list[Any] = []
    for row in rows.values():
        if row.stop <= start or stop <= row.start:
            continue
        instructions.extend(_decode_row(decoder, row))
    saves: dict[int, list[Any]] = {}
    restores: list[tuple[int, Any]] = []
    for instruction in sorted(instructions, key=lambda item: item.address):
        if instruction.mnemonic != "mov" or len(instruction.operands) != 2:
            continue
        left, right = instruction.operands
        if (
            left.type == X86_OP_MEM
            and instruction.reg_name(left.mem.base) == "esp"
            and left.mem.index == 0
            and right.type == X86_OP_REG
            and instruction.reg_name(right.reg) == register
        ):
            saves.setdefault(int(left.mem.disp), []).append(instruction)
        if (
            left.type == X86_OP_REG
            and instruction.reg_name(left.reg) == register
            and right.type == X86_OP_MEM
            and instruction.reg_name(right.mem.base) == "esp"
            and right.mem.index == 0
        ):
            restores.append((int(right.mem.disp), instruction))
    candidates: list[tuple[Any, Any, Any]] = []
    for displacement, restore in restores:
        for save in reversed(saves.get(displacement, ())):
            if restore.address <= save.address:
                continue
            crossing = next(
                (
                    call
                    for call in calls
                    if save.address + save.size <= call.address
                    and call.address + call.size <= restore.address
                ),
                None,
            )
            if crossing is not None:
                candidates.append((save, crossing, restore))
                break
    if not candidates:
        return None
    save, crossing_call, restore = min(
        candidates,
        key=lambda item: (item[2].address - item[0].address, item[0].address),
    )
    row = _row_at(rows, crossing_call.address)
    region = regions_by_rva.get(row.start)
    continuation = crossing_call.address + crossing_call.size
    continuation_id = target_by_rva.get(continuation)
    if region is None or continuation_id is None:
        return None
    return CarryBoundary(
        source_target_id=region.target_id,
        source_rva=row.start,
        instruction_rva=crossing_call.address,
        instruction_bytes=bytes(crossing_call.bytes),
        continuation_target_id=continuation_id,
        continuation_rva=continuation,
        register=register,
        kind="stack_restore",
        save_rva=save.address,
        save_bytes=bytes(save.bytes),
        restore_rva=restore.address,
        restore_bytes=bytes(restore.bytes),
        authority_requirement="exact stack save/call/restore segment theorem",
    )


def _authority_source(site: SiteProposal, bindings: LeanBindings) -> str:
    transfer = (
        f".call {site.continuation_target_id}" if site.transfer == "call" else ".jump"
    )
    carries = ",\n  ".join(_lean_carry(carry) for carry in site.carries)
    imports = "\n".join(
        f"import {module}"
        for module in dict.fromkeys(
            (bindings.context_module, bindings.runtime_premise_module)
        )
    )
    return f"""import StageA.RelationalRegisterIndirectControlAuthority
{imports}

namespace {site.namespace}

open StageA.Formal StageA.Relational
open StageA.Relational.InterpreterMixedOriginal
open StageA.Relational.OriginalIndirectControlAuthority
open StageA.Relational.RegisterIndirectControlAuthority

def generatedContext :
    StageA.Relational.InterpreterMixedContext.OriginalDecodedStaticContext :=
  {bindings.context_term}

def generatedSite : OriginalIndirectControlSite := {{
  sourceTargetId := {site.source_target_id}
  instructionRva := {site.instruction_rva}
  instructionBytes := {_lean_bytes(site.instruction_bytes)}
  target := .register .{site.target_register}
  transfer := {transfer}
}}

def generatedCertificate : Certificate := {{
  site := generatedSite
  register := .{site.target_register}
  inventory := {_lean_inventory(site.inventory)}
  producers := [{", ".join(_lean_producer(producer) for producer in site.inventory.producers)}]
  carries := [{carries}]
}}

set_option maxRecDepth 100000 in
theorem generatedCertificateChecked :
    generatedCertificate.checked generatedContext = true := by
  decide +kernel

def generatedCheckedCertificate :
    CheckedCertificate generatedContext := {{
  authority := {bindings.exact_authority_term}
  certificate := generatedCertificate
  checked := generatedCertificateChecked
}}

noncomputable def generatedAuthority : CheckedAuthority generatedContext := {{
  certificate := generatedCheckedCertificate
  reachable := {bindings.runtime_reachability_term}
  runtime := (
{textwrap.indent(bindings.runtime_premise_term, "    ")}
  )
}}

#print axioms generatedCertificateChecked
#print axioms generatedAuthority

end {site.namespace}
"""


def _lean_inventory(inventory: TargetInventory) -> str:
    if inventory.kind == "internal_code":
        assert inventory.slot_rva is not None
        if len(inventory.target_ids) != 1:
            raise RegisterIndirectControlProposalError(
                "relocated writable code inventory must name one target"
            )
        return f".relocatedWritableCode {inventory.slot_rva} {inventory.target_ids[0]}"
    if inventory.kind == "imported_address":
        assert inventory.imported is not None
        return (
            f".importedAddress {inventory.imported.iat_rva} "
            f"{_lean_external(inventory.imported)}"
        )
    if inventory.kind == "resolver_result":
        queries = ", ".join(
            _lean_resolver_query(query) for query in inventory.resolver_queries
        )
        return f".resolverResults [{queries}] {_lean_nats(inventory.target_ids)}"
    if inventory.kind == "registered_callback_slot":
        assert inventory.slot_rva is not None
        return (
            f".registeredCallbackSlot {inventory.slot_rva} "
            f"{_lean_nats(inventory.target_ids)}"
        )
    if inventory.kind == "nullable_code_table":
        assert inventory.table_start_rva is not None
        assert inventory.table_end_rva is not None
        entries = ", ".join(
            "none" if entry is None else f"some {entry}"
            for entry in inventory.table_entries
        )
        return (
            f".nullableCodeTable {inventory.table_start_rva} "
            f"{inventory.table_end_rva} [{entries}]"
        )
    raise AssertionError(inventory.kind)


def _lean_carry(carry: CarryBoundary) -> str:
    if carry.kind == "internal_call":
        kind = f".internalCall {carry.callee_target_id}"
    elif carry.kind == "machine_import":
        kind = f".machineImport {carry.contract_id}"
    elif carry.kind == "target_call":
        kind = ".targetCall"
    else:
        kind = (
            f".stackRestore {carry.save_rva} {_lean_bytes(carry.save_bytes)} "
            f"{carry.restore_rva} {_lean_bytes(carry.restore_bytes)}"
        )
    return (
        f"{{ sourceTargetId := {carry.source_target_id}, "
        f"instructionRva := {carry.instruction_rva}, "
        f"instructionBytes := {_lean_bytes(carry.instruction_bytes)}, "
        f"continuationTargetId := {carry.continuation_target_id}, "
        f"register := .{carry.register}, kind := {kind} }}"
    )


def _lean_producer(producer: ProducerEvidence) -> str:
    if producer.kind == "absolute_slot":
        kind = f".absoluteSlot {producer.slot_rva}"
    elif producer.kind == "memory_load":
        kind = ".memoryLoad"
    elif producer.kind == "resolver_call":
        kind = f".resolverCall {producer.resource_id}"
    else:
        kind = f".immediateCode {producer.target_id}"
    return (
        f"{{ instructionRva := {producer.instruction_rva}, "
        f"instructionBytes := {_lean_bytes(producer.instruction_bytes)}, "
        f"register := .{producer.register}, kind := {kind} }}"
    )


def _lean_external(imported: ImportIdentity) -> str:
    dll = _lean_bytes(imported.dll.lower().encode("ascii"))
    if imported.symbol is not None:
        selector = f".symbol {_lean_bytes(imported.symbol.encode('ascii'))}"
    else:
        selector = f".ordinal {imported.ordinal}"
    return f"{{ dll := {dll}, name := {selector} }}"


def _lean_resolver_query(query: ResolverQuery) -> str:
    return (
        f"{{ resolver := {_lean_external(query.resolver)}, "
        f"callRva := {query.call_rva}, "
        f"identityRva := {query.identity_rva}, "
        f"identity := {_lean_bytes(query.identity_bytes)}, "
        f"resourceId := {query.resource_id} }}"
    )


def _state_rows(path: Path) -> dict[int, _DecodedRow]:
    result: dict[int, _DecodedRow] = {}
    for index, line in enumerate(path.read_text(encoding="utf-8").splitlines()):
        if not line.strip():
            continue
        value = _mapping(json.loads(line), f"state row {index}")
        original = _mapping(value.get("original"), f"state row {index}.original")
        start = _natural(original.get("rva_start"), f"state row {index}.start")
        stop = _natural(original.get("rva_end"), f"state row {index}.stop")
        instructions = tuple(
            _mapping(item, f"state row {index}.instructions")
            for item in _list(value.get("instructions"), "instructions")
        )
        result[start] = _DecodedRow(index, start, stop, instructions)
    return result


def _machine_import_inventory(
    path: Path,
    *,
    image_base: int,
    pe: pefile.PE,
) -> tuple[dict[int, ImportIdentity], dict[int, int]]:
    report = _mapping(json.loads(path.read_text(encoding="utf-8")), "import report")
    signatures = _list(report.get("signatures"), "signatures")
    contract_by_identity: dict[tuple[str, str | int], int] = {}
    for row in signatures:
        signature = _mapping(row, "signature")
        imported = _mapping(signature.get("import"), "signature.import")
        selector = imported.get("symbol")
        if selector is None:
            selector = _natural(imported.get("ordinal"), "signature ordinal")
        contract_by_identity[(str(imported.get("dll", "")).lower(), selector)] = (
            _natural(signature.get("id"), "signature id")
        )
    imports: dict[int, ImportIdentity] = {}
    for descriptor in getattr(pe, "DIRECTORY_ENTRY_IMPORT", ()):
        dll = bytes(descriptor.dll).decode("ascii").lower()
        for imported in descriptor.imports:
            symbol = (
                None if imported.name is None else bytes(imported.name).decode("ascii")
            )
            ordinal = int(imported.ordinal) if imported.name is None else None
            selector: str | int = symbol if symbol is not None else int(ordinal)
            iat_va = int(imported.address)
            iat_rva = iat_va - image_base
            identity = ImportIdentity(
                dll=dll,
                symbol=symbol,
                ordinal=ordinal,
                iat_rva=iat_rva,
                iat_va=iat_va,
                contract_id=contract_by_identity.get((dll, selector)),
            )
            previous = imports.get(iat_rva)
            if previous is not None and previous != identity:
                raise RegisterIndirectControlProposalError(
                    f"IAT slot 0x{iat_rva:x} has conflicting import identities"
                )
            imports[iat_rva] = identity
    return imports, {
        identity.iat_rva: identity.contract_id
        for identity in imports.values()
        if identity.contract_id is not None
    }


def _writable_slot_inventory(
    path: Path | str | None,
) -> dict[int, Mapping[str, Any]]:
    if path is None:
        return {}
    report = _mapping(
        json.loads(Path(path).read_text(encoding="utf-8")), "writable report"
    )
    result: dict[int, Mapping[str, Any]] = {}
    for row in _list(report.get("sites"), "writable sites"):
        item = _mapping(row, "writable site")
        slot_rva = _natural(item.get("slot_rva"), "writable slot RVA")
        previous = result.get(slot_rva)
        if previous is not None and previous.get("target_rva") != item.get(
            "target_rva"
        ):
            raise RegisterIndirectControlProposalError(
                f"writable slot 0x{slot_rva:x} has conflicting targets"
            )
        result[slot_rva] = item
    return result


def _last_indirect(decoder: capstone.Cs, row: _DecodedRow) -> Any:
    instructions = _decode_row(decoder, row)
    for instruction in reversed(instructions):
        if instruction.mnemonic not in {"call", "jmp"}:
            continue
        if instruction.operands and instruction.operands[0].type == X86_OP_REG:
            return instruction
    raise RegisterIndirectControlProposalError(
        f"row 0x{row.start:x} has no register indirect transfer"
    )


def _last_call(decoder: capstone.Cs, row: _DecodedRow) -> Any | None:
    for instruction in reversed(_decode_row(decoder, row)):
        if instruction.mnemonic == "call":
            return instruction
    return None


def _decode_row(decoder: capstone.Cs, row: _DecodedRow) -> tuple[Any, ...]:
    data = b"".join(bytes.fromhex(str(item["bytes"])) for item in row.instructions)
    return tuple(decoder.disasm(data, row.start))


def _absolute_load(instruction: Any, register: str) -> int | None:
    if instruction.mnemonic != "mov" or len(instruction.operands) != 2:
        return None
    destination, source = instruction.operands
    if (
        destination.type != X86_OP_REG
        or instruction.reg_name(destination.reg) != register
        or source.type != X86_OP_MEM
        or source.mem.base != 0
        or source.mem.index != 0
    ):
        return None
    return int(source.mem.disp) & 0xFFFFFFFF


def _register_memory_load_base(instruction: Any, register: str) -> str | None:
    if instruction.mnemonic != "mov" or len(instruction.operands) != 2:
        return None
    destination, source = instruction.operands
    if not (
        destination.type == X86_OP_REG
        and instruction.reg_name(destination.reg) == register
        and source.type == X86_OP_MEM
        and source.mem.base != 0
    ):
        return None
    return instruction.reg_name(source.mem.base)


def _writes_register(instruction: Any, register: str) -> bool:
    if instruction.mnemonic in {"call", "jmp"}:
        return False
    try:
        _, writes = instruction.regs_access()
    except capstone.CsError:
        return False
    return any(instruction.reg_name(register_id) == register for register_id in writes)


def _decoded_cfg_predecessors(
    *,
    rows: Mapping[int, _DecodedRow],
    decoder: capstone.Cs,
    plan: InterpreterMixedOriginalPlan,
    source_target_id: int,
    stop: int,
) -> tuple[Any, ...]:
    regions = {region.target_id: region for region in plan.regions}
    successors = _carrier_successors(
        plan=plan,
        rows=rows,
        decoder=decoder,
    )
    predecessors: dict[int, list[int]] = {}
    for region in plan.regions:
        for target_id in successors.get(region.target_id, ()):
            predecessors.setdefault(target_id, []).append(region.target_id)
    pending = [source_target_id]
    seen: set[int] = set()
    ordered: list[Any] = []
    while pending and len(seen) < 4096:
        target_id = pending.pop(0)
        if target_id in seen:
            continue
        seen.add(target_id)
        region = regions.get(target_id)
        if region is None:
            continue
        row = rows.get(region.rva)
        if row is None:
            continue
        data = b"".join(bytes.fromhex(str(item["bytes"])) for item in row.instructions)
        instructions = tuple(decoder.disasm(data, row.start))
        for instruction in reversed(instructions):
            if target_id != source_target_id or instruction.address < stop:
                ordered.append(instruction)
        pending.extend(sorted(predecessors.get(target_id, ())))
    return tuple(ordered)


def _resolver_calls(
    instructions: Sequence[Any], imports: Mapping[int, ImportIdentity]
) -> tuple[tuple[ImportIdentity, int], ...]:
    matches: list[tuple[ImportIdentity, int]] = []
    for instruction in instructions:
        if instruction.mnemonic != "call" or not instruction.operands:
            continue
        operand = instruction.operands[0]
        if operand.type != X86_OP_REG:
            continue
        register = instruction.reg_name(operand.reg)
        seeds = sorted(
            (seed for seed in instructions if seed.address < instruction.address),
            key=lambda seed: instruction.address - seed.address,
        )
        for seed in seeds:
            address = _absolute_load(seed, register)
            if address is None:
                continue
            for imported in imports.values():
                if imported.iat_va == address:
                    matches.append((imported, int(instruction.address)))
                    break
            else:
                continue
            break
    return tuple(dict.fromkeys(matches))


def _immediate_code_targets(
    *,
    instructions: Sequence[Any],
    register: str,
    image_base: int,
    target_by_rva: Mapping[int, int],
) -> tuple[tuple[int, ...], tuple[int, ...]]:
    ids: list[int] = []
    rvas: list[int] = []
    for instruction in instructions:
        if instruction.mnemonic != "mov" or len(instruction.operands) != 2:
            continue
        destination, source = instruction.operands
        if (
            destination.type != X86_OP_REG
            or instruction.reg_name(destination.reg) != register
            or source.type != X86_OP_IMM
        ):
            continue
        value = int(source.imm) & 0xFFFFFFFF
        target_rva = value - image_base if value >= image_base else value
        target_id = target_by_rva.get(target_rva)
        if target_id is not None:
            ids.append(target_id)
            rvas.append(target_rva)
    return tuple(dict.fromkeys(ids)), tuple(dict.fromkeys(rvas))


def _immediate_code_producers(
    *,
    instructions: Sequence[Any],
    register: str,
    image_base: int,
    target_by_rva: Mapping[int, int],
) -> tuple[ProducerEvidence, ...]:
    result: list[ProducerEvidence] = []
    seen: set[int] = set()
    for instruction in instructions:
        if instruction.mnemonic != "mov" or len(instruction.operands) != 2:
            continue
        destination, source = instruction.operands
        if (
            destination.type != X86_OP_REG
            or instruction.reg_name(destination.reg) != register
            or source.type != X86_OP_IMM
        ):
            continue
        value = int(source.imm) & 0xFFFFFFFF
        target_rva = value - image_base if value >= image_base else value
        target_id = target_by_rva.get(target_rva)
        if target_id is None or target_id in seen:
            continue
        seen.add(target_id)
        result.append(
            ProducerEvidence(
                kind="immediate_code",
                instruction_rva=int(instruction.address),
                instruction_bytes=bytes(instruction.bytes),
                register=register,
                target_id=target_id,
            )
        )
    return tuple(result)


def _resolver_identity(
    pe: pefile.PE, instructions: Sequence[Any], resolver_call_rva: int
) -> tuple[int, bytes]:
    image_base = int(pe.OPTIONAL_HEADER.ImageBase)
    candidates = sorted(
        (
            instruction
            for instruction in instructions
            if 0 < resolver_call_rva - int(instruction.address) <= 128
        ),
        key=lambda instruction: resolver_call_rva - int(instruction.address),
    )
    for instruction in candidates:
        if instruction.mnemonic != "mov" or len(instruction.operands) != 2:
            continue
        destination, source = instruction.operands
        if destination.type != X86_OP_MEM or source.type != X86_OP_IMM:
            continue
        value = int(source.imm) & 0xFFFFFFFF
        if not image_base <= value < image_base + int(pe.OPTIONAL_HEADER.SizeOfImage):
            continue
        rva = value - image_base
        data = bytearray()
        for offset in range(512):
            byte = pe.get_data(rva + offset, 1)
            if not byte or byte == b"\0":
                break
            data.extend(byte)
        if data and bytes(data).isascii():
            return rva, bytes(data)
    raise RegisterIndirectControlProposalError(
        f"resolver call 0x{resolver_call_rva:x} has no exact immutable "
        "identity argument"
    )


def _row_at(rows: Mapping[int, _DecodedRow], rva: int) -> _DecodedRow:
    direct = rows.get(rva)
    if direct is not None:
        return direct
    matches = [row for row in rows.values() if row.start <= rva < row.stop]
    if len(matches) != 1:
        raise RegisterIndirectControlProposalError(
            f"RVA 0x{rva:x} is not in one exact state-machine row"
        )
    return matches[0]


def _blocker_category(detail: str) -> str | None:
    return detail.split(" at ", 1)[0] if " at " in detail else None


def _writable_nonexec(pe: pefile.PE, rva: int) -> bool:
    for section in pe.sections:
        start = int(section.VirtualAddress)
        size = max(int(section.Misc_VirtualSize), int(section.SizeOfRawData))
        characteristics = int(section.Characteristics)
        if start <= rva < start + size:
            return bool(characteristics & 0x80000000) and not bool(
                characteristics & 0x20000000
            )
    return False


def _natural(value: object, field: str) -> int:
    if (
        not isinstance(value, int)
        or isinstance(value, bool)
        or not 0 <= value < _U32_LIMIT
    ):
        raise RegisterIndirectControlProposalError(
            f"{field} must be an unsigned 32-bit integer"
        )
    return value


def _mapping(value: object, field: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise RegisterIndirectControlProposalError(f"{field} must be an object")
    return value


def _list(value: object, field: str) -> list[Any]:
    if not isinstance(value, list):
        raise RegisterIndirectControlProposalError(f"{field} must be a list")
    return value


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _lean_bytes(data: bytes) -> str:
    return "[" + ", ".join(str(value) for value in data) + "]"


def _lean_nats(values: Sequence[int]) -> str:
    return "[" + ", ".join(str(value) for value in values) + "]"


__all__ = [
    "AUTHORITY_FORMAT",
    "AUTHORITY_PROFILE",
    "CarryBoundary",
    "ImportIdentity",
    "LeanBindings",
    "ProposalBlocker",
    "ProposalPlan",
    "ProducerEvidence",
    "RegisterIndirectControlProposalError",
    "ResolverQuery",
    "SiteProposal",
    "TargetInventory",
    "construct_register_indirect_control_authorities",
    "write_register_indirect_control_authorities",
]
