"""Untrusted proposals for reachable writable static pointer slots.

This module deliberately stops at proposal construction.  It binds every
input artifact by SHA-256 and rejects facts it cannot classify exactly, but it
does not parse those facts into proof authority.  The generated
``RelationalReachableStaticPointerSlot`` certificate is authoritative only
after the Lean checker reparses the PE, re-decodes the regions, and proves its
Boolean replay.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

import capstone
import pefile
from capstone.x86 import X86_OP_MEM

from ...errors import StageAInputError
from .reachable_static_pointer_slot import (
    GuardedNonzeroEdgeProposal,
    IndirectSlotSiteProposal,
    LeanAuthorityBinding,
    ReachableStaticPointerSlotCertificateSpec,
    RegionBindingProposal,
    WriteClassificationProposal,
    write_reachable_static_pointer_slot_module,
)


PROPOSAL_FORMAT = "stage-a-reachable-static-pointer-slot-proposal-v1"
AUTHORITY_BINDING_FORMAT = (
    "stage-a-exact-original-decoded-authority-binding-v1"
)
MIXED_ORIGINAL_FORMAT = "stage-a-interpreter-mixed-original-v1"
STATE_MACHINE_FORMAT = "stage-a-semantic-transfer-contract-v1"

_IMAGE_SCN_MEM_EXECUTE = 0x20000000
_IMAGE_SCN_MEM_WRITE = 0x80000000
_U32_LIMIT = 1 << 32


class ReachableStaticPointerSlotProposalError(StageAInputError):
    """The exact proposal inputs are malformed or are not hash-bound."""


@dataclass(frozen=True)
class ProposalBlocker:
    category: str
    location_rva: int | None
    detail: str
    next_action: str

    def to_json(self) -> dict[str, Any]:
        return {
            "category": self.category,
            "detail": self.detail,
            "location_rva": self.location_rva,
            "next_action": self.next_action,
        }


@dataclass(frozen=True)
class ReachableStaticPointerSlotProposalPlan:
    original_pe_sha256: str
    state_machine_sha256: str
    mixed_original_plan_sha256: str
    authority_binding_sha256: str
    slot_rva: int
    reachable_target_ids: tuple[int, ...]
    allowed_target_ids: tuple[int, ...]
    regions: tuple[RegionBindingProposal, ...]
    guarded_nonzero_edges: tuple[GuardedNonzeroEdgeProposal, ...]
    indirect_slot_sites: tuple[IndirectSlotSiteProposal, ...]
    proposal: ReachableStaticPointerSlotCertificateSpec | None
    blockers: tuple[ProposalBlocker, ...]

    def to_json(self) -> dict[str, Any]:
        proposal: dict[str, Any] | None = None
        if self.proposal is not None:
            proposal = {
                "allowed_target_ids": list(
                    self.proposal.allowed_target_ids or ()
                ),
                "definition_name": self.proposal.definition_name,
                "guarded_nonzero_edges": [
                    {
                        "source_target_id": item.source_target_id,
                        "nonzero_target_id": item.nonzero_target_id,
                    }
                    for item in self.proposal.guarded_nonzero_edges or ()
                ],
                "indirect_slot_sites": [
                    {"source_target_id": item.source_target_id}
                    for item in self.proposal.indirect_slot_sites or ()
                ],
                "proposal_lean_term": self.proposal.lean(),
                "reachable_target_ids": list(
                    self.proposal.reachable_target_ids or ()
                ),
                "regions": [
                    {
                        "target_id": region.target_id,
                        "writes": [
                            {
                                "kind": write.kind,
                                "target_id": write.target_id,
                            }
                            for write in region.writes or ()
                        ],
                    }
                    for region in self.proposal.regions or ()
                ],
                "slot_rva": self.proposal.slot_rva,
            }
        return {
            "artifact_role": {
                "acceptance_authority": False,
                "lean_checker_must_reparse_and_redecode": True,
                "proof_status_emitted": False,
                "proposal_only": True,
            },
            "blockers": [item.to_json() for item in self.blockers],
            "derived_facts": {
                "allowed_target_ids": list(self.allowed_target_ids),
                "guarded_nonzero_edges": [
                    {
                        "source_target_id": item.source_target_id,
                        "nonzero_target_id": item.nonzero_target_id,
                    }
                    for item in self.guarded_nonzero_edges
                ],
                "indirect_slot_sites": [
                    {"source_target_id": item.source_target_id}
                    for item in self.indirect_slot_sites
                ],
                "may_touch_regions": [
                    {
                        "target_id": region.target_id,
                        "writes": [
                            {
                                "kind": write.kind,
                                "target_id": write.target_id,
                            }
                            for write in region.writes or ()
                        ],
                    }
                    for region in self.regions
                ],
            },
            "format": PROPOSAL_FORMAT,
            "inputs": {
                "authority_binding_sha256": self.authority_binding_sha256,
                "mixed_original_plan_sha256": self.mixed_original_plan_sha256,
                "original_pe_sha256": self.original_pe_sha256,
                "state_machine_sha256": self.state_machine_sha256,
            },
            "proposal": proposal,
            "reachable_target_ids": list(self.reachable_target_ids),
            "slot_rva": self.slot_rva,
        }


@dataclass(frozen=True)
class _Row:
    line_number: int
    rva: int
    size: int
    instructions: tuple[capstone.CsInsn, ...]
    memory_events: tuple[Mapping[str, Any], ...]
    register_writes: tuple[Mapping[str, Any], ...]
    edge_conditions: tuple[Mapping[str, Any], ...]
    outcome: Mapping[str, Any]
    external_events: tuple[Mapping[str, Any], ...]


@dataclass(frozen=True)
class _Target:
    target_id: int
    region_index: int
    rva: int
    size: int
    root: bool
    targets: tuple[int, ...]
    aliases: tuple[int, ...]


@dataclass(frozen=True)
class _Artifacts:
    authority: LeanAuthorityBinding
    rows_by_target: Mapping[int, _Row]
    targets: Mapping[int, _Target]
    reachable_target_ids: tuple[int, ...]


def construct_reachable_static_pointer_slot_proposal(
    original_pe: Path | str,
    state_machine: Path | str,
    mixed_original_plan: Path | str,
    authority_binding: Path | str,
    slot_rva: int,
    *,
    definition_name: str = "generatedReachableStaticPointerSlotCertificate",
) -> ReachableStaticPointerSlotProposalPlan:
    """Construct one deterministic, fail-closed certificate proposal."""

    slot_rva = _u32(slot_rva, "slot_rva")
    pe_path = Path(original_pe)
    state_path = Path(state_machine)
    mixed_path = Path(mixed_original_plan)
    binding_path = Path(authority_binding)
    hashes = {
        "original_pe_sha256": _sha256(pe_path),
        "state_machine_sha256": _sha256(state_path),
        "mixed_original_plan_sha256": _sha256(mixed_path),
        "authority_binding_sha256": _sha256(binding_path),
    }
    mixed = _load_object(mixed_path, "mixed-original diagnostic plan")
    binding = _load_object(binding_path, "exact authority binding")
    _validate_mixed_plan(mixed, hashes["state_machine_sha256"])
    _validate_binding_hashes(binding, hashes)

    pe = _open_pe(pe_path)
    try:
        rows = _load_rows(pe, state_path)
        artifacts = _load_artifacts(binding, mixed, rows)
        blockers = list(_validate_initial_slot(pe, slot_rva))
        slot_va = int(pe.OPTIONAL_HEADER.ImageBase) + slot_rva
        if slot_va >= _U32_LIMIT:
            blockers.append(ProposalBlocker(
                "slot_address_overflow",
                slot_rva,
                "the image base plus slot RVA does not fit in an IA-32 word",
                "choose a four-byte writable slot inside the PE32 address space",
            ))

        allowed_ids: set[int] = set()
        region_bindings: list[RegionBindingProposal] = []
        indirect_sites: list[IndirectSlotSiteProposal] = []
        guarded_edges: list[GuardedNonzeroEdgeProposal] = []
        if slot_va < _U32_LIMIT:
            for target_id in artifacts.reachable_target_ids:
                row = artifacts.rows_by_target.get(target_id)
                target = artifacts.targets[target_id]
                if row is None:
                    blockers.append(ProposalBlocker(
                        "reachable_region_missing_state_machine_record",
                        target.rva,
                        f"reachable target {target_id} has no exact state-machine row",
                        "publish the synthetic/exact region row in the authority binding input",
                    ))
                    continue
                classifications, write_blockers, written_targets = (
                    _classify_writes(pe, row, slot_va, artifacts.targets)
                )
                blockers.extend(write_blockers)
                allowed_ids.update(written_targets)
                if classifications is not None:
                    region_bindings.append(RegionBindingProposal(
                        target_id=target_id,
                        writes=classifications,
                    ))

                site, site_blockers = _classify_slot_indirect_site(
                    row,
                    target_id,
                    slot_va,
                    artifacts,
                )
                blockers.extend(site_blockers)
                if site is not None:
                    indirect_sites.append(site)

                edge = _classify_slot_guard(row, target_id, slot_va, artifacts)
                if edge is not None:
                    guarded_edges.append(edge)

        allowed_target_ids = tuple(sorted(allowed_ids))
        region_bindings_tuple = tuple(sorted(
            region_bindings, key=lambda item: item.target_id
        ))
        guarded_edges_tuple = tuple(sorted(
            guarded_edges,
            key=lambda item: (
                item.source_target_id, item.nonzero_target_id
            ),
        ))
        indirect_sites_tuple = tuple(sorted(
            indirect_sites, key=lambda item: item.source_target_id
        ))
        for site in indirect_sites_tuple:
            missing = tuple(
                target_id for target_id in allowed_target_ids
                if target_id not in artifacts.targets[
                    site.source_target_id
                ].targets
            )
            if missing:
                blockers.append(ProposalBlocker(
                    "slot_site_target_inventory_incomplete",
                    artifacts.targets[site.source_target_id].rva,
                    f"slot indirect site target {site.source_target_id} omits "
                    f"allowed code target IDs {list(missing)}",
                    "add every statically writable slot value to the exact "
                    "decoded target inventory",
                ))
        blockers = sorted(
            set(blockers),
            key=lambda item: (
                item.category,
                -1 if item.location_rva is None else item.location_rva,
                item.detail,
                item.next_action,
            ),
        )
        proposal = None
        if not blockers:
            proposal = ReachableStaticPointerSlotCertificateSpec(
                definition_name=definition_name,
                authority=artifacts.authority,
                slot_rva=slot_rva,
                reachable_target_ids=artifacts.reachable_target_ids,
                allowed_target_ids=allowed_target_ids,
                regions=region_bindings_tuple,
                guarded_nonzero_edges=guarded_edges_tuple,
                indirect_slot_sites=indirect_sites_tuple,
                aliases=(),
            )
        return ReachableStaticPointerSlotProposalPlan(
            **hashes,
            slot_rva=slot_rva,
            reachable_target_ids=artifacts.reachable_target_ids,
            allowed_target_ids=allowed_target_ids,
            regions=region_bindings_tuple,
            guarded_nonzero_edges=guarded_edges_tuple,
            indirect_slot_sites=indirect_sites_tuple,
            proposal=proposal,
            blockers=tuple(blockers),
        )
    finally:
        pe.close()


def write_reachable_static_pointer_slot_proposal(
    out: Path | str,
    plan: ReachableStaticPointerSlotProposalPlan,
    *,
    emit_lean: bool = True,
) -> tuple[Path, Path | None]:
    """Write deterministic JSON and, for a blocker-free plan, Lean source."""

    root = Path(out)
    root.mkdir(parents=True, exist_ok=True)
    report = root / "reachable-static-pointer-slot-proposal.json"
    report.write_text(
        json.dumps(plan.to_json(), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    source = None
    if emit_lean and plan.proposal is not None:
        source = root / "StageA" / "GeneratedRelationalReachableStaticPointerSlot.lean"
        write_reachable_static_pointer_slot_module(source, plan.proposal)
    return report, source


def _load_rows(pe: pefile.PE, path: Path) -> Mapping[int, _Row]:
    decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    decoder.detail = True
    result: dict[int, _Row] = {}
    try:
        source = path.open(encoding="utf-8")
    except OSError as error:
        raise ReachableStaticPointerSlotProposalError(
            f"cannot read state machine {path}: {error}"
        ) from error
    with source:
        for line_number, line in enumerate(source, 1):
            try:
                value = json.loads(line)
            except json.JSONDecodeError as error:
                raise ReachableStaticPointerSlotProposalError(
                    f"invalid state-machine JSON on line {line_number}: {error}"
                ) from error
            row = _mapping(value, f"state-machine line {line_number}")
            if row.get("format") != STATE_MACHINE_FORMAT:
                raise ReachableStaticPointerSlotProposalError(
                    f"state-machine line {line_number} has the wrong format"
                )
            original = _mapping(
                row.get("original"), f"state-machine line {line_number}.original"
            )
            rva = _u32(
                original.get("rva_start"),
                f"state-machine line {line_number} original.rva_start",
            )
            end = _u32(
                original.get("rva_end"),
                f"state-machine line {line_number} original.rva_end",
            )
            size = _positive(
                original.get("size"),
                f"state-machine line {line_number} original.size",
            )
            if rva + size != end or rva in result:
                raise ReachableStaticPointerSlotProposalError(
                    f"state-machine line {line_number} has an inconsistent or duplicate span"
                )
            raw_instructions = row.get("instructions")
            if not isinstance(raw_instructions, list) or not raw_instructions:
                raise ReachableStaticPointerSlotProposalError(
                    f"state-machine line {line_number} has no exact instruction inventory"
                )
            cursor = rva
            instructions: list[capstone.CsInsn] = []
            for index, raw_instruction in enumerate(raw_instructions):
                instruction = _mapping(
                    raw_instruction,
                    f"state-machine line {line_number} instruction {index}",
                )
                instruction_rva = _u32(
                    instruction.get("rva"), "instruction.rva"
                )
                instruction_size = _positive(
                    instruction.get("size"), "instruction.size"
                )
                encoded = instruction.get("bytes")
                if instruction_rva != cursor or not isinstance(encoded, str):
                    raise ReachableStaticPointerSlotProposalError(
                        f"state-machine line {line_number} instruction inventory "
                        "is not exact and contiguous"
                    )
                try:
                    proposed = bytes.fromhex(encoded)
                except ValueError as error:
                    raise ReachableStaticPointerSlotProposalError(
                        f"state-machine line {line_number} has invalid instruction bytes"
                    ) from error
                exact = bytes(pe.get_data(instruction_rva, instruction_size))
                if len(proposed) != instruction_size or proposed != exact:
                    raise ReachableStaticPointerSlotProposalError(
                        "state-machine instruction at "
                        f"0x{instruction_rva:x} does not match the exact PE"
                    )
                decoded = tuple(decoder.disasm(
                    exact,
                    int(pe.OPTIONAL_HEADER.ImageBase) + instruction_rva,
                    count=1,
                ))
                if len(decoded) != 1 or decoded[0].size != instruction_size:
                    raise ReachableStaticPointerSlotProposalError(
                        f"instruction at 0x{instruction_rva:x} does not decode exactly"
                    )
                instructions.append(decoded[0])
                cursor += instruction_size
            if cursor != end:
                raise ReachableStaticPointerSlotProposalError(
                    f"state-machine line {line_number} instruction bytes do not cover its span"
                )
            result[rva] = _Row(
                line_number=line_number,
                rva=rva,
                size=size,
                instructions=tuple(instructions),
                memory_events=_object_list(
                    row.get("memory_events"), f"line {line_number}.memory_events"
                ),
                register_writes=_object_list(
                    row.get("register_writes", []),
                    f"line {line_number}.register_writes",
                ),
                edge_conditions=_object_list(
                    row.get("edge_conditions"),
                    f"line {line_number}.edge_conditions",
                ),
                outcome=_mapping(
                    row.get("outcome"), f"line {line_number}.outcome"
                ),
                external_events=_object_list(
                    row.get("external_events"),
                    f"line {line_number}.external_events",
                ),
            )
    return result


def _load_artifacts(
    binding: Mapping[str, Any],
    mixed: Mapping[str, Any],
    rows_by_rva: Mapping[int, _Row],
) -> _Artifacts:
    lean = _mapping(binding.get("lean"), "authority binding.lean")
    authority = LeanAuthorityBinding(
        module=_string(lean.get("module"), "lean.module"),
        namespace=_string(lean.get("namespace"), "lean.namespace"),
        context_name=_string(lean.get("context_name"), "lean.context_name"),
        authority_name=_string(lean.get("authority_name"), "lean.authority_name"),
    )
    authority.validate()
    code_map = _mapping(binding.get("code_map"), "authority binding.code_map")
    entries = _object_list(code_map.get("entries"), "code_map.entries")
    regions = _object_list(code_map.get("regions"), "code_map.regions")
    regions_by_index: dict[int, Mapping[str, Any]] = {}
    for row in regions:
        index = _natural(row.get("region_index"), "region.region_index")
        if index in regions_by_index:
            raise ReachableStaticPointerSlotProposalError(
                f"duplicate authority region index {index}"
            )
        regions_by_index[index] = row
    targets: dict[int, _Target] = {}
    rows_by_target: dict[int, _Row] = {}
    for entry in entries:
        target_id = _natural(entry.get("target_id"), "entry.target_id")
        region_index = _natural(entry.get("region_index"), "entry.region_index")
        rva = _u32(entry.get("rva"), "entry.rva")
        aliases = _natural_list(entry.get("aliases", []), "entry.aliases")
        region = regions_by_index.get(region_index)
        if region is None:
            raise ReachableStaticPointerSlotProposalError(
                f"target {target_id} names missing region index {region_index}"
            )
        region_rva = _u32(region.get("rva"), "region.rva")
        size = _positive(region.get("size"), "region.size")
        if rva != region_rva:
            raise ReachableStaticPointerSlotProposalError(
                f"target {target_id} canonical RVA differs from its region RVA"
            )
        if target_id in targets:
            raise ReachableStaticPointerSlotProposalError(
                f"duplicate authority target ID {target_id}"
            )
        target = _Target(
            target_id=target_id,
            region_index=region_index,
            rva=rva,
            size=size,
            root=_boolean(region.get("root"), "region.root"),
            targets=_natural_list(region.get("targets"), "region.targets"),
            aliases=aliases,
        )
        targets[target_id] = target
        exact_row = rows_by_rva.get(rva)
        if exact_row is not None:
            if exact_row.size != size:
                raise ReachableStaticPointerSlotProposalError(
                    f"authority target {target_id} span differs from state machine"
                )
            rows_by_target[target_id] = exact_row
    if tuple(sorted(targets)) != tuple(range(len(targets))):
        raise ReachableStaticPointerSlotProposalError(
            "authority target IDs must form the exact indexed code-map range"
        )
    reachable = _natural_list(
        mixed.get("reachable_target_ids"),
        "mixed-original reachable_target_ids",
    )
    if len(reachable) != len(set(reachable)):
        raise ReachableStaticPointerSlotProposalError(
            "mixed-original reachable target inventory contains duplicates"
        )
    for target_id in reachable:
        if target_id not in targets:
            raise ReachableStaticPointerSlotProposalError(
                f"reachable target {target_id} is absent from the authority code map"
            )
    return _Artifacts(
        authority=authority,
        rows_by_target=rows_by_target,
        targets=targets,
        reachable_target_ids=tuple(sorted(reachable)),
    )


def _classify_writes(
    pe: pefile.PE,
    row: _Row,
    slot_va: int,
    targets: Mapping[int, _Target],
) -> tuple[
    tuple[WriteClassificationProposal, ...] | None,
    tuple[ProposalBlocker, ...],
    tuple[int, ...],
]:
    classifications: list[WriteClassificationProposal] = []
    blockers: list[ProposalBlocker] = []
    written_targets: list[int] = []
    has_may_touch = False
    canonical_by_va = {
        int(pe.OPTIONAL_HEADER.ImageBase) + target.rva: target
        for target in targets.values()
        if not target.aliases and _rva_executable(pe, target.rva)
    }
    writes = [event for event in row.memory_events if event.get("kind") == "write"]
    for write_index, event in enumerate(writes):
        width = event.get("width")
        if width != 4:
            blockers.append(ProposalBlocker(
                "unsupported_write_width",
                row.rva,
                f"write {write_index} has width {width!r}; the slot checker "
                "replays exact 32-bit writes",
                "split or extend the generic normalized-write checker for this width",
            ))
            continue
        address = _constant(event.get("address"))
        if address is None:
            blockers.append(ProposalBlocker(
                "dynamic_write_may_alias_slot",
                row.rva,
                f"write {write_index} has a non-constant address",
                "supply a Lean-checked separation witness or make the candidate "
                "expose a statically disjoint address",
            ))
            continue
        if _disjoint_words(address, slot_va):
            classifications.append(WriteClassificationProposal("absolute_disjoint"))
            continue
        has_may_touch = True
        if address != slot_va:
            blockers.append(ProposalBlocker(
                "overlapping_write_may_corrupt_slot",
                row.rva,
                f"write {write_index} at 0x{address:x} partially overlaps slot 0x{slot_va:x}",
                "model the overlapping memory update explicitly; it cannot be "
                "classified as a slot word write",
            ))
            continue
        raw_value = event.get("value")
        value = _constant(raw_value)
        if value == 0:
            classifications.append(WriteClassificationProposal("slot_zero"))
            continue
        target = None if value is None else canonical_by_va.get(value)
        if target is None:
            stack_derived = _expression_reads_stack(raw_value)
            blockers.append(ProposalBlocker(
                (
                    "call_frame_writer_provenance_required"
                    if stack_derived
                    else "unknown_slot_write_target"
                ),
                row.rva,
                f"write {write_index} stores {_expression_detail(event.get('value'))} in the slot",
                (
                    "prove the caller argument, callee stack-frame read, and slot "
                    "write as one checked call-frame provenance chain"
                    if stack_derived
                    else "map the exact value to an unaliased executable code "
                    "target or add a checked non-code/resource relation"
                ),
            ))
            continue
        classifications.append(WriteClassificationProposal(
            "slot_code_target", target.target_id
        ))
        written_targets.append(target.target_id)
    if blockers:
        return None, tuple(blockers), tuple(written_targets)
    if not writes or not has_may_touch:
        return None, (), tuple(written_targets)
    return tuple(classifications), (), tuple(written_targets)


def _classify_slot_indirect_site(
    row: _Row,
    target_id: int,
    slot_va: int,
    artifacts: _Artifacts,
) -> tuple[IndirectSlotSiteProposal | None, tuple[ProposalBlocker, ...]]:
    targets = _indirect_target_expressions(row)
    semantic_direct = any(
        _direct_slot_read(expression, slot_va) for expression in targets
    )
    decoded_direct = _decoded_direct_slot_indirect(row, slot_va)
    if semantic_direct != decoded_direct:
        return None, (ProposalBlocker(
            "state_machine_indirect_target_mismatch",
            row.rva,
            "the exact terminal instruction and semantic target expression "
            "disagree about this pointer slot",
            "regenerate the state-machine transfer from the exact PE before "
            "proposing a slot certificate",
        ),)
    if semantic_direct:
        return IndirectSlotSiteProposal(target_id), ()
    register_targets = {
        expression.get("name")
        for expression in targets
        if isinstance(expression, Mapping)
        and expression.get("op") == "reg"
        and isinstance(expression.get("name"), str)
    }
    if not register_targets:
        return None, ()
    predecessors = [
        (source_id, source_row)
        for source_id, source_row in artifacts.rows_by_target.items()
        if target_id in artifacts.targets[source_id].targets
    ]
    for register in sorted(register_targets):
        for source_id, predecessor in predecessors:
            for write in predecessor.register_writes:
                if write.get("register") == register and _direct_slot_read(
                    write.get("value"), slot_va
                ):
                    return None, (ProposalBlocker(
                        "register_mediated_slot_indirect_unsupported",
                        row.rva,
                        f"target {target_id} uses {register} loaded from slot "
                        f"0x{slot_va:x} by predecessor target {source_id}",
                        "extend the Lean checker with a checked predecessor/register "
                        "provenance bridge before proposing this site",
                    ),)
    return None, ()


def _decoded_direct_slot_indirect(row: _Row, slot_va: int) -> bool:
    instruction = row.instructions[-1]
    if instruction.mnemonic not in {"call", "jmp"}:
        return False
    operands = instruction.operands
    if len(operands) != 1 or operands[0].type != X86_OP_MEM:
        return False
    memory = operands[0].mem
    return (
        memory.base == 0
        and memory.index == 0
        and (int(memory.disp) & 0xFFFFFFFF) == slot_va
    )


def _classify_slot_guard(
    row: _Row,
    target_id: int,
    slot_va: int,
    artifacts: _Artifacts,
) -> GuardedNonzeroEdgeProposal | None:
    zero_target_rva: int | None = None
    nonzero_target_rva: int | None = None
    for edge in row.edge_conditions:
        edge_rva = edge.get("target_rva")
        if not isinstance(edge_rva, int):
            continue
        sense = _slot_zero_sense(edge.get("condition"), slot_va)
        if sense is True:
            zero_target_rva = edge_rva
        elif sense is False:
            nonzero_target_rva = edge_rva
    if zero_target_rva is None or nonzero_target_rva is None:
        return None
    id_by_rva = {target.rva: target.target_id for target in artifacts.targets.values()}
    zero_target_id = id_by_rva.get(zero_target_rva)
    nonzero_target_id = id_by_rva.get(nonzero_target_rva)
    if (
        zero_target_id is None
        or nonzero_target_id is None
        or zero_target_id == nonzero_target_id
        or nonzero_target_id not in artifacts.reachable_target_ids
    ):
        return None
    return GuardedNonzeroEdgeProposal(target_id, nonzero_target_id)


def _indirect_target_expressions(row: _Row) -> tuple[Any, ...]:
    result: list[Any] = []
    if row.outcome.get("kind") in {"indirect_jump", "indirect_call"}:
        result.append(row.outcome.get("target"))
    result.extend(
        event.get("target")
        for event in row.external_events
        if event.get("kind") == "indirect_call"
    )
    return tuple(result)


def _direct_slot_read(value: Any, slot_va: int) -> bool:
    if not isinstance(value, Mapping) or value.get("op") != "load":
        return False
    return value.get("width") == 4 and _constant(value.get("address")) == slot_va


def _slot_zero_sense(value: Any, slot_va: int) -> bool | None:
    if not isinstance(value, Mapping):
        return None
    if value.get("op") == "not":
        args = value.get("args")
        if not isinstance(args, list) or len(args) != 1:
            return None
        inner = _slot_zero_sense(args[0], slot_va)
        return None if inner is None else not inner
    if value.get("op") != "eq":
        return None
    args = value.get("args")
    if not isinstance(args, list) or len(args) != 2:
        return None
    return True if (
        (_direct_slot_read(args[0], slot_va) and _constant(args[1]) == 0)
        or (_direct_slot_read(args[1], slot_va) and _constant(args[0]) == 0)
    ) else None


def _validate_initial_slot(
    pe: pefile.PE, slot_rva: int
) -> tuple[ProposalBlocker, ...]:
    blockers: list[ProposalBlocker] = []
    if slot_rva % 4:
        blockers.append(ProposalBlocker(
            "slot_not_word_aligned",
            slot_rva,
            "the slot RVA is not four-byte aligned",
            "select the canonical aligned pointer word",
        ))
    section = _section_for_rva(pe, slot_rva, 4)
    if section is None or not int(section.Characteristics) & _IMAGE_SCN_MEM_WRITE:
        blockers.append(ProposalBlocker(
            "slot_not_writable_static_word",
            slot_rva,
            "the four-byte slot is not wholly contained in a writable PE section",
            "use a writable image slot or the immutable-pointer checker",
        ))
    value = _read_loader_word(pe, slot_rva)
    if value != 0:
        blockers.append(ProposalBlocker(
            "slot_not_initially_zero",
            slot_rva,
            f"the exact loader image initializes the slot to {value!r}",
            "use a finite initialized-pointer checker or select an initially-zero slot",
        ))
    if _slot_overlaps_import(pe, slot_rva):
        blockers.append(ProposalBlocker(
            "slot_overlaps_import_iat",
            slot_rva,
            "the slot overlaps a loader-populated import thunk",
            "classify it through the machine-import/IAT model",
        ))
    if _slot_overlaps_relocation(pe, slot_rva):
        blockers.append(ProposalBlocker(
            "slot_overlaps_relocation",
            slot_rva,
            "the initially-zero word overlaps a base relocation",
            "model its loader-relocated initial value explicitly",
        ))
    return tuple(blockers)


def _validate_mixed_plan(mixed: Mapping[str, Any], state_sha256: str) -> None:
    if mixed.get("format") != MIXED_ORIGINAL_FORMAT:
        raise ReachableStaticPointerSlotProposalError(
            "mixed-original diagnostic plan has the wrong format"
        )
    if mixed.get("state_machine_sha256") != state_sha256:
        raise ReachableStaticPointerSlotProposalError(
            "mixed-original diagnostic plan is not bound to the exact state machine"
        )


def _validate_binding_hashes(
    binding: Mapping[str, Any], hashes: Mapping[str, str]
) -> None:
    if binding.get("format") != AUTHORITY_BINDING_FORMAT:
        raise ReachableStaticPointerSlotProposalError(
            "exact authority binding has the wrong format"
        )
    inputs = _mapping(binding.get("inputs"), "authority binding.inputs")
    for key in (
        "original_pe_sha256",
        "state_machine_sha256",
        "mixed_original_plan_sha256",
    ):
        if inputs.get(key) != hashes[key]:
            raise ReachableStaticPointerSlotProposalError(
                f"exact authority binding {key} does not match the input artifact"
            )


def _open_pe(path: Path) -> pefile.PE:
    try:
        pe = pefile.PE(str(path), fast_load=False)
    except (OSError, pefile.PEFormatError) as error:
        raise ReachableStaticPointerSlotProposalError(
            f"cannot parse exact PE32 input {path}: {error}"
        ) from error
    if pe.FILE_HEADER.Machine != 0x14C or pe.OPTIONAL_HEADER.Magic != 0x10B:
        pe.close()
        raise ReachableStaticPointerSlotProposalError(
            "reachable static pointer slots require an x86 PE32 input"
        )
    return pe


def _section_for_rva(pe: pefile.PE, rva: int, size: int):
    for section in pe.sections:
        start = int(section.VirtualAddress)
        span = max(int(section.Misc_VirtualSize), int(section.SizeOfRawData))
        if start <= rva and rva + size <= start + span:
            return section
    return None


def _read_loader_word(pe: pefile.PE, rva: int) -> int | None:
    section = _section_for_rva(pe, rva, 4)
    if section is None:
        return None
    offset = rva - int(section.VirtualAddress)
    raw_size = int(section.SizeOfRawData)
    if offset >= raw_size:
        return 0
    available = max(0, min(4, raw_size - offset))
    raw = bytes(pe.get_data(rva, available))
    if len(raw) != available:
        return None
    return int.from_bytes(raw + b"\0" * (4 - available), "little")


def _slot_overlaps_import(pe: pefile.PE, slot_rva: int) -> bool:
    for descriptor in getattr(pe, "DIRECTORY_ENTRY_IMPORT", ()):
        for imported in descriptor.imports:
            rva = int(imported.address) - int(pe.OPTIONAL_HEADER.ImageBase)
            if not _disjoint_words(slot_rva, rva):
                return True
    return False


def _slot_overlaps_relocation(pe: pefile.PE, slot_rva: int) -> bool:
    for block in getattr(pe, "DIRECTORY_ENTRY_BASERELOC", ()):
        for entry in block.entries:
            if int(entry.type) != 0 and not _disjoint_words(slot_rva, int(entry.rva)):
                return True
    return False


def _rva_executable(pe: pefile.PE, rva: int) -> bool:
    section = _section_for_rva(pe, rva, 1)
    return bool(
        section is not None
        and int(section.Characteristics) & _IMAGE_SCN_MEM_EXECUTE
    )


def _disjoint_words(left: int, right: int) -> bool:
    return left + 4 <= right or right + 4 <= left


def _constant(value: Any) -> int | None:
    if not isinstance(value, Mapping) or value.get("op") != "const":
        return None
    result = value.get("value")
    return result if isinstance(result, int) and not isinstance(result, bool) else None


def _expression_detail(value: Any) -> str:
    constant = _constant(value)
    if constant is not None:
        return f"0x{constant:x}"
    if isinstance(value, Mapping):
        return f"dynamic expression {value.get('op')!r}"
    return f"malformed expression {value!r}"


def _expression_reads_stack(value: Any) -> bool:
    if not isinstance(value, Mapping):
        return False
    if value.get("op") == "load" and _expression_mentions_register(
        value.get("address"), "esp"
    ):
        return True
    return any(
        _expression_reads_stack(child)
        for child in value.values()
        if isinstance(child, (Mapping, list))
        for child in (child if isinstance(child, list) else [child])
    )


def _expression_mentions_register(value: Any, register: str) -> bool:
    if isinstance(value, Mapping):
        if value.get("op") == "reg" and value.get("name") == register:
            return True
        return any(
            _expression_mentions_register(child, register)
            for child in value.values()
        )
    if isinstance(value, list):
        return any(_expression_mentions_register(child, register) for child in value)
    return False


def _load_object(path: Path, label: str) -> Mapping[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ReachableStaticPointerSlotProposalError(
            f"cannot read {label} {path}: {error}"
        ) from error
    return _mapping(value, label)


def _mapping(value: Any, label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise ReachableStaticPointerSlotProposalError(f"{label} must be an object")
    return value


def _object_list(value: Any, label: str) -> tuple[Mapping[str, Any], ...]:
    if not isinstance(value, list) or not all(isinstance(item, Mapping) for item in value):
        raise ReachableStaticPointerSlotProposalError(
            f"{label} must be a list of objects"
        )
    return tuple(value)


def _natural_list(value: Any, label: str) -> tuple[int, ...]:
    if not isinstance(value, list):
        raise ReachableStaticPointerSlotProposalError(f"{label} must be a list")
    return tuple(_natural(item, f"{label} item") for item in value)


def _natural(value: Any, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ReachableStaticPointerSlotProposalError(
            f"{label} must be a natural number"
        )
    return value


def _positive(value: Any, label: str) -> int:
    result = _natural(value, label)
    if result == 0:
        raise ReachableStaticPointerSlotProposalError(f"{label} must be positive")
    return result


def _u32(value: Any, label: str) -> int:
    result = _natural(value, label)
    if result >= _U32_LIMIT:
        raise ReachableStaticPointerSlotProposalError(
            f"{label} must fit in an unsigned 32-bit word"
        )
    return result


def _string(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise ReachableStaticPointerSlotProposalError(
            f"{label} must be a non-empty string"
        )
    return value


def _boolean(value: Any, label: str) -> bool:
    if not isinstance(value, bool):
        raise ReachableStaticPointerSlotProposalError(f"{label} must be a Boolean")
    return value


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as source:
            for chunk in iter(lambda: source.read(1024 * 1024), b""):
                digest.update(chunk)
    except OSError as error:
        raise ReachableStaticPointerSlotProposalError(
            f"cannot hash input {path}: {error}"
        ) from error
    return digest.hexdigest()
