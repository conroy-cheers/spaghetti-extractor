"""Construct deterministic proposals for exact internal-call summaries.

The planner in this module is intentionally untrusted.  It checks that the
input artifacts describe one unambiguous finite CFG and serializes a
``LeanInternalDirectCallRegisterSummaryTree``.  It never reports that the
summary is proved: exact decoding, import grounding, inventory closure, and
register preservation remain decisions of the Lean checker.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

import capstone
import pefile
from capstone.x86 import X86_OP_IMM, X86_OP_MEM, X86_OP_REG

from ...errors import StageAInputError
from ..direct_call_proposal_ir import DirectCallSummaryRequest
from .internal_direct_call_register_summary import (
    InternalDirectCallRegisterSummaryLeanBindings,
    LeanCalleeEdge,
    LeanCallerFrameWord,
    LeanExactRegionPair,
    LeanFiniteIndirectJumpDependency,
    LeanFiniteOriginCallDependency,
    LeanFiniteOriginCallTarget,
    LeanFiniteOriginTailDependency,
    LeanFiniteOriginTailTarget,
    LeanInternalDirectCallRegisterCertificate,
    LeanInternalDirectCallRegisterSummaryTree,
    LeanMachineImportDependency,
    LeanMachineImportTerminalDependency,
    LeanMachineImportTailDependency,
    LeanNestedSummaryDependency,
    LeanReturnInventoryEntry,
    LeanSpan,
    LeanStackEntryOffsetWitness,
    LeanStackFrameAnchorWitness,
    LeanStackSaveRestoreFrameWitness,
    LeanStackSaveRestoreWitness,
    internal_direct_call_register_summary_source,
)


PROPOSAL_FORMAT = "stage-a-internal-direct-call-summary-proposals-v1"
STATIC_MACHINE_IMPORT_FORMAT = "stage-a-static-machine-import-contracts-v1"
_SUMMARY_NAMESPACE = (
    "StageA.Generated.RelationalInternalDirectCallRegisterSummary"
)
_REGISTER_ORDER = ("eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp")
_REGISTERS = frozenset(_REGISTER_ORDER)
_MODULE = re.compile(r"[A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z][A-Za-z0-9_]*)*\Z")


class InternalDirectCallSummaryProposalError(StageAInputError):
    """An input artifact cannot safely be used to construct proposals."""


@dataclass(frozen=True)
class FiniteOriginTailAuthorityBinding:
    """Hash-bound route authority for one writable finite-origin tail jump."""

    source_rva: int
    instruction_rva: int
    internal_targets: tuple[LeanFiniteOriginTailTarget, ...]
    internal_target_rvas: tuple[int, ...]
    authority_module: str
    route_term: str
    route_authority_term: str

    def checked(self) -> "FiniteOriginTailAuthorityBinding":
        _u32(self.source_rva, "finite tail authority source_rva")
        _u32(self.instruction_rva, "finite tail authority instruction_rva")
        if not self.internal_targets:
            raise InternalDirectCallSummaryProposalError(
                "finite tail authority internal target inventory is empty"
            )
        if len(self.internal_targets) != len(self.internal_target_rvas):
            raise InternalDirectCallSummaryProposalError(
                "finite tail authority target IDs and RVAs have different lengths"
            )
        for index, (target, target_rva) in enumerate(
            zip(self.internal_targets, self.internal_target_rvas, strict=True)
        ):
            target.lean(f"finite tail authority internal_targets[{index}]")
            _u32(target_rva, f"finite tail authority internal_target_rvas[{index}]")
            if target.region_id != target_rva:
                raise InternalDirectCallSummaryProposalError(
                    "finite tail authority summary region ID must equal its exact RVA"
                )
        if len(set(self.internal_targets)) != len(self.internal_targets):
            raise InternalDirectCallSummaryProposalError(
                "finite tail authority contains duplicate target mappings"
            )
        if _MODULE.fullmatch(self.authority_module) is None:
            raise InternalDirectCallSummaryProposalError(
                "finite tail authority module is not a qualified Lean module"
            )
        for label, term in (
            ("route_term", self.route_term),
            ("route_authority_term", self.route_authority_term),
        ):
            if (
                not isinstance(term, str)
                or re.fullmatch(
                    r"[A-Za-z_][A-Za-z0-9_']*"
                    r"(?:\.[A-Za-z_][A-Za-z0-9_']*)*",
                    term,
                )
                is None
            ):
                raise InternalDirectCallSummaryProposalError(
                    f"finite tail authority {label} is not a qualified Lean term"
                )
        return self


@dataclass(frozen=True)
class FiniteOriginCallAuthorityBinding:
    """Checked finite internal destinations for one returning indirect call."""

    source_rva: int
    instruction_rva: int
    continuation_rva: int
    continuation_target_id: int
    internal_targets: tuple[LeanFiniteOriginTailTarget, ...]
    internal_target_rvas: tuple[int, ...]
    authority_module: str
    indirect_exit_authority_term: str
    indirect_exit_certificate_exact_term: str

    def checked(self) -> "FiniteOriginCallAuthorityBinding":
        _u32(self.source_rva, "finite call authority source_rva")
        _u32(self.instruction_rva, "finite call authority instruction_rva")
        _u32(self.continuation_rva, "finite call authority continuation_rva")
        _u32(
            self.continuation_target_id,
            "finite call authority continuation_target_id",
        )
        if not self.internal_targets:
            raise InternalDirectCallSummaryProposalError(
                "finite call authority internal target inventory is empty"
            )
        if len(self.internal_targets) != len(self.internal_target_rvas):
            raise InternalDirectCallSummaryProposalError(
                "finite call authority target IDs and RVAs have different lengths"
            )
        for index, (target, target_rva) in enumerate(
            zip(self.internal_targets, self.internal_target_rvas, strict=True)
        ):
            target.lean(f"finite call authority internal_targets[{index}]")
            _u32(target_rva, f"finite call authority internal_target_rvas[{index}]")
            if target.region_id != target_rva:
                raise InternalDirectCallSummaryProposalError(
                    "finite call authority summary region ID must equal its exact RVA"
                )
        if len(set(self.internal_targets)) != len(self.internal_targets):
            raise InternalDirectCallSummaryProposalError(
                "finite call authority contains duplicate target mappings"
            )
        if len({target.target_id for target in self.internal_targets}) != len(
            self.internal_targets
        ):
            raise InternalDirectCallSummaryProposalError(
                "finite call authority contains duplicate target IDs"
            )
        if len({target.region_id for target in self.internal_targets}) != len(
            self.internal_targets
        ):
            raise InternalDirectCallSummaryProposalError(
                "finite call authority contains duplicate target regions"
            )
        if len(set(self.internal_target_rvas)) != len(self.internal_target_rvas):
            raise InternalDirectCallSummaryProposalError(
                "finite call authority contains duplicate target RVAs"
            )
        if _MODULE.fullmatch(self.authority_module) is None:
            raise InternalDirectCallSummaryProposalError(
                "finite call authority module is not a qualified Lean module"
            )
        if (
            not isinstance(self.indirect_exit_authority_term, str)
            or re.fullmatch(
                r"[A-Za-z_][A-Za-z0-9_']*"
                r"(?:\.[A-Za-z_][A-Za-z0-9_']*)*",
                self.indirect_exit_authority_term,
            )
            is None
        ):
            raise InternalDirectCallSummaryProposalError(
                "finite call indirect-exit authority is not a qualified Lean term"
            )
        if (
            not isinstance(self.indirect_exit_certificate_exact_term, str)
            or re.fullmatch(
                r"[A-Za-z_][A-Za-z0-9_']*"
                r"(?:\.[A-Za-z_][A-Za-z0-9_']*)*",
                self.indirect_exit_certificate_exact_term,
            )
            is None
        ):
            raise InternalDirectCallSummaryProposalError(
                "finite call indirect-exit certificate equality is not a "
                "qualified Lean term"
            )
        return self


@dataclass(frozen=True)
class ProposalBlocker:
    request: DirectCallSummaryRequest
    category: str
    location_rva: int
    detail: str
    next_action: str
    call_path: tuple[int, ...] = ()

    def to_json(self) -> dict[str, Any]:
        return {
            "call_path": list(self.call_path),
            "category": self.category,
            "detail": self.detail,
            "location_rva": self.location_rva,
            "next_action": self.next_action,
            "request": _request_json(self.request),
        }


@dataclass(frozen=True)
class InternalDirectCallSummaryProposal:
    request: DirectCallSummaryRequest
    tree: LeanInternalDirectCallRegisterSummaryTree
    region_rvas: tuple[int, ...]
    nested_callsite_rvas: tuple[int, ...]
    machine_import_boundary_ids: tuple[int, ...]
    machine_import_tail_signature_ids: tuple[int, ...]
    entry_authority: FiniteOriginCallAuthorityBinding | None = None

    def to_json(self) -> dict[str, Any]:
        return {
            "entry_authority": (
                None
                if self.entry_authority is None
                else {
                    "authority_module": self.entry_authority.authority_module,
                    "continuation_rva": self.entry_authority.continuation_rva,
                    "continuation_target_id": (
                        self.entry_authority.continuation_target_id
                    ),
                    "indirect_exit_authority_term": (
                        self.entry_authority.indirect_exit_authority_term
                    ),
                    "indirect_exit_certificate_exact_term": (
                        self.entry_authority.indirect_exit_certificate_exact_term
                    ),
                    "instruction_rva": self.entry_authority.instruction_rva,
                    "internal_target_ids": [
                        target.target_id
                        for target in self.entry_authority.internal_targets
                    ],
                    "internal_target_rvas": list(
                        self.entry_authority.internal_target_rvas
                    ),
                    "source_rva": self.entry_authority.source_rva,
                }
            ),
            "machine_import_boundary_ids": list(self.machine_import_boundary_ids),
            "machine_import_tail_signature_ids": list(
                self.machine_import_tail_signature_ids
            ),
            "nested_callsite_rvas": list(self.nested_callsite_rvas),
            "proposal_lean_term": self.tree.lean(),
            "region_rvas": list(self.region_rvas),
            "request": _request_json(self.request),
        }


@dataclass(frozen=True)
class InternalDirectCallSummarySourceBindings:
    """Lean names needed only when materializing a proposal source module."""

    checker: InternalDirectCallRegisterSummaryLeanBindings
    static_import_module: str | None = None
    static_import_namespace: str | None = None

    def checked(self, *, needs_imports: bool) -> "InternalDirectCallSummarySourceBindings":
        self.checker.checked()
        if needs_imports:
            if self.static_import_module is None or self.static_import_namespace is None:
                raise InternalDirectCallSummaryProposalError(
                    "machine-import proposals require the generated static-import "
                    "module and namespace"
                )
            for label, value in (
                ("static_import_module", self.static_import_module),
                ("static_import_namespace", self.static_import_namespace),
            ):
                if _MODULE.fullmatch(value) is None:
                    raise InternalDirectCallSummaryProposalError(
                        f"{label} is not a qualified Lean name"
                    )
        return self


@dataclass(frozen=True)
class InternalDirectCallSummaryProposalPlan:
    original_pe_sha256: str
    state_machine_sha256: str
    machine_import_report_sha256: str
    proposals: tuple[InternalDirectCallSummaryProposal, ...]
    blockers: tuple[ProposalBlocker, ...]

    def to_json(self) -> dict[str, Any]:
        """Return proposal evidence and blockers, never a Python proof verdict."""
        return {
            "authority": {
                "lean_structural_checker_is_authoritative": True,
                "python_proof_status_emitted": False,
                "standalone_acceptance_authority": False,
            },
            "blockers": [item.to_json() for item in self.blockers],
            "format": PROPOSAL_FORMAT,
            "inputs": {
                "machine_import_report_sha256": self.machine_import_report_sha256,
                "original_pe_sha256": self.original_pe_sha256,
                "state_machine_sha256": self.state_machine_sha256,
            },
            "proposals": [item.to_json() for item in self.proposals],
        }

    def source(
        self,
        proposal_index: int,
        bindings: InternalDirectCallSummarySourceBindings,
    ) -> str:
        try:
            proposal = self.proposals[proposal_index]
        except IndexError as error:
            raise InternalDirectCallSummaryProposalError(
                f"proposal index {proposal_index} is out of range"
            ) from error
        boundary_ids = proposal.machine_import_boundary_ids
        needs_imports = bool(
            boundary_ids or proposal.machine_import_tail_signature_ids
        )
        bindings.checked(needs_imports=needs_imports)
        checker = bindings.checker
        if needs_imports:
            assert bindings.static_import_module is not None
            imports = tuple(dict.fromkeys(
                (*checker.imports, bindings.static_import_module)
            ))
            checker = InternalDirectCallRegisterSummaryLeanBindings(
                original_pe=checker.original_pe,
                candidate_pe=checker.candidate_pe,
                original_imports=checker.original_imports,
                candidate_imports=checker.candidate_imports,
                imports=imports,
            )
        source = internal_direct_call_register_summary_source(proposal.tree, checker)
        namespace_marker = (
            "namespace StageA.Generated.RelationalInternalDirectCallRegisterSummary\n\n"
        )
        if namespace_marker not in source:
            raise InternalDirectCallSummaryProposalError(
                "summary source emitter no longer exposes the expected namespace boundary"
            )
        source = source.replace(
            namespace_marker,
            namespace_marker
            + "set_option maxRecDepth 1000000\n"
            + "set_option maxHeartbeats 0\n\n",
            1,
        )
        if not needs_imports:
            return source
        assert bindings.static_import_namespace is not None
        static = bindings.static_import_namespace
        definitions = [
            "def generatedSummaryMachineImportRequired :=\n"
            f"  {static}.generatedRequiredImports",
            "def generatedSummaryMachineImportSignatures :=\n"
            f"  {static}.generatedMachineImportSignatures",
        ]
        for boundary_id in boundary_ids:
            definitions.append(
                f"def generatedSummaryMachineImportBoundary{boundary_id} :\n"
                "    StageA.Relational.StaticMachineImportContracts."
                "StaticMachineImportBoundary :=\n"
                f"  ({static}.generatedMachineImportBoundaries.find? "
                f"(fun boundary => boundary.id == {boundary_id})).get (by decide)"
            )
        marker = (
            "open StageA.Relational.InternalDirectCallRegisterSummary\n\n"
        )
        if marker not in source:
            raise InternalDirectCallSummaryProposalError(
                "summary source emitter no longer exposes the expected prelude boundary"
            )
        return source.replace(
            marker,
            marker + "\n\n".join(definitions) + "\n\n",
            1,
        )


@dataclass(frozen=True)
class FiniteDirectCallEvidenceRequest:
    """Exact machine facts requested from one finite internal call.

    The caller offset is relative to ESP immediately before the architectural
    call push.  The callee offset is relative to ESP after that push.
    """

    callsite_rva: int
    caller_rva: int
    argument_code_target_rva: int
    static_slot_rva: int
    caller_argument_offset: int = 0
    callee_argument_offset: int = 4

    def checked(self) -> "FiniteDirectCallEvidenceRequest":
        for name in (
            "callsite_rva",
            "caller_rva",
            "argument_code_target_rva",
            "static_slot_rva",
            "caller_argument_offset",
            "callee_argument_offset",
        ):
            _u32(getattr(self, name), f"finite_evidence.{name}")
        if self.callee_argument_offset != self.caller_argument_offset + 4:
            raise InternalDirectCallSummaryProposalError(
                "finite_evidence callee argument offset must account for the "
                "four-byte IA-32 return-address push"
            )
        return self


@dataclass(frozen=True)
class FiniteDirectCallRegionRank:
    rva: int
    rank: int

    def to_json(self) -> dict[str, int]:
        return {"rank": self.rank, "rva": self.rva}


@dataclass(frozen=True)
class FiniteDirectCallEdge:
    source_rva: int
    target_rva: int
    kind: str

    def to_json(self) -> dict[str, int | str]:
        return {
            "kind": self.kind,
            "source_rva": self.source_rva,
            "target_rva": self.target_rva,
        }


@dataclass(frozen=True)
class FiniteDirectCallEvidenceProposal:
    source_rva: int
    source_size: int
    callsite_rva: int
    call_instruction_size: int
    callee_rva: int
    continuation_rva: int
    argument_code_target_rva: int
    static_slot_rva: int
    caller_argument_offset: int
    callee_argument_offset: int
    ranks: tuple[FiniteDirectCallRegionRank, ...]
    edges: tuple[FiniteDirectCallEdge, ...]
    return_rvas: tuple[int, ...]

    def to_json(self) -> dict[str, Any]:
        return {
            "argument_code_target_rva": self.argument_code_target_rva,
            "call_instruction_size": self.call_instruction_size,
            "callee_argument_offset": self.callee_argument_offset,
            "callee_rva": self.callee_rva,
            "caller_argument_offset": self.caller_argument_offset,
            "callsite_rva": self.callsite_rva,
            "continuation_rva": self.continuation_rva,
            "edges": [edge.to_json() for edge in self.edges],
            "ranks": [rank.to_json() for rank in self.ranks],
            "return_rvas": list(self.return_rvas),
            "source_rva": self.source_rva,
            "source_size": self.source_size,
            "static_slot_rva": self.static_slot_rva,
        }


@dataclass(frozen=True)
class FiniteDirectCallEvidenceBlocker:
    category: str
    location_rva: int
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
class FiniteDirectCallEvidencePlan:
    original_pe_sha256: str
    state_machine_sha256: str
    machine_import_report_sha256: str
    request: FiniteDirectCallEvidenceRequest
    proposal: FiniteDirectCallEvidenceProposal | None
    blockers: tuple[FiniteDirectCallEvidenceBlocker, ...]

    def to_json(self) -> dict[str, Any]:
        return {
            "artifact_role": {
                "acceptance_authority": False,
                "lean_checked_finite_evidence_required": True,
                "proof_status_emitted": False,
                "proposal_only": True,
            },
            "blockers": [blocker.to_json() for blocker in self.blockers],
            "format": "stage-a-finite-direct-call-evidence-proposal-v1",
            "inputs": {
                "machine_import_report_sha256": self.machine_import_report_sha256,
                "original_pe_sha256": self.original_pe_sha256,
                "state_machine_sha256": self.state_machine_sha256,
            },
            "proposal": None if self.proposal is None else self.proposal.to_json(),
            "request": {
                "argument_code_target_rva": self.request.argument_code_target_rva,
                "callee_argument_offset": self.request.callee_argument_offset,
                "caller_argument_offset": self.request.caller_argument_offset,
                "caller_rva": self.request.caller_rva,
                "callsite_rva": self.request.callsite_rva,
                "static_slot_rva": self.request.static_slot_rva,
            },
        }


@dataclass(frozen=True)
class _Instruction:
    rva: int
    size: int
    bytes_: bytes
    decoded: capstone.CsInsn


@dataclass(frozen=True)
class _Row:
    rva: int
    end: int
    size: int
    function: str | None
    instructions: tuple[_Instruction, ...]
    memory_writes: int
    memory_events: tuple[Mapping[str, Any], ...]
    external_events: tuple[Mapping[str, Any], ...]
    outcome: Mapping[str, Any] | None = None
    synthetic: bool = False


@dataclass(frozen=True)
class _Boundary:
    id: int
    signature_id: int
    instruction_rva: int
    source_rva: int
    source_size: int
    continuation_rva: int
    route: str
    payload: Mapping[str, Any]


@dataclass(frozen=True)
class _ImportTail:
    """Canonical external-jump leaf shared by one or more static boundaries."""

    id: int
    signature_id: int
    source_rva: int
    source_size: int
    argument_words: int


@dataclass(frozen=True)
class _ImportInventory:
    boundaries_by_instruction: Mapping[int, tuple[_Boundary, ...]]
    tails_by_execution_rva: Mapping[int, tuple[_ImportTail, ...]]
    signatures_by_id: Mapping[int, Mapping[str, Any]]


@dataclass(frozen=True)
class _Control:
    kind: str
    instruction_rva: int
    targets: tuple[int, ...] = ()
    boundary: _Boundary | None = None
    import_tail: _ImportTail | None = None


class _PlanningFailure(Exception):
    def __init__(
        self,
        category: str,
        location_rva: int,
        detail: str,
        next_action: str,
        call_path: Sequence[int],
    ) -> None:
        super().__init__(detail)
        self.category = category
        self.location_rva = location_rva
        self.detail = detail
        self.next_action = next_action
        self.call_path = tuple(call_path)


class _Planner:
    def __init__(
        self,
        *,
        pe: pefile.PE,
        image_base: int,
        rows: Sequence[_Row],
        imports: _ImportInventory,
        finite_origin_call_authorities: Sequence[
            FiniteOriginCallAuthorityBinding
        ] = (),
        finite_origin_tail_authorities: Sequence[
            FiniteOriginTailAuthorityBinding
        ] = (),
    ) -> None:
        self.pe = pe
        self.image_base = image_base
        self.imports = imports
        checked_call_authorities = tuple(
            authority.checked() for authority in finite_origin_call_authorities
        )
        call_keys = [
            (authority.source_rva, authority.instruction_rva)
            for authority in checked_call_authorities
        ]
        if len(set(call_keys)) != len(call_keys):
            raise InternalDirectCallSummaryProposalError(
                "finite-origin call authorities are ambiguous by source/instruction"
            )
        self.finite_origin_call_authorities = {
            key: authority
            for key, authority in zip(
                call_keys, checked_call_authorities, strict=True
            )
        }
        checked_tail_authorities = tuple(
            authority.checked() for authority in finite_origin_tail_authorities
        )
        tail_keys = [
            (authority.source_rva, authority.instruction_rva)
            for authority in checked_tail_authorities
        ]
        if len(set(tail_keys)) != len(tail_keys):
            raise InternalDirectCallSummaryProposalError(
                "finite-origin tail authorities are ambiguous by source/instruction"
            )
        self.finite_origin_tail_authorities = {
            key: authority
            for key, authority in zip(
                tail_keys, checked_tail_authorities, strict=True
            )
        }
        materialized = self._materialize_missing_control_paths(
            tuple(rows),
            seed_targets=(
                target_rva
                for authority in (
                    *checked_call_authorities,
                    *checked_tail_authorities,
                )
                for target_rva in authority.internal_target_rvas
            ),
        )
        self.rows = self._split_rows_at_control_targets(materialized)
        self.by_start = {row.rva: row for row in self.rows}
        finite_targets: set[int] = set()
        for row in self.rows:
            terminal = row.instructions[-1].decoded
            if (
                terminal.group(capstone.CS_GRP_JUMP)
                and _direct_target(terminal, self.image_base) is None
            ):
                shape = self._finite_indirect_shape(row)
                if shape is None:
                    continue
                base, _index, upper = shape
                if upper is None:
                    continue
                entries = self._finite_indirect_entries(base, upper)
                if entries is not None:
                    finite_targets.update(entries)
        if finite_targets:
            materialized = self._materialize_missing_control_paths(
                self.rows, seed_targets=finite_targets
            )
            self.rows = self._split_rows_at_control_targets(
                materialized, extra_targets=finite_targets
            )
        self.by_start = {row.rva: row for row in self.rows}
        self.known_call_targets = self._known_call_targets()
        self._summary_tree_cache: dict[
            tuple[Any, ...],
            tuple[
                LeanInternalDirectCallRegisterSummaryTree,
                frozenset[int],
            ],
        ] = {}
        self._row_stack_result_cache: dict[tuple[Any, ...], int | None] = {}
        self._entry_frame_cache: dict[
            int,
            tuple[int, dict[str, int], dict[str, int]],
        ] = {}

    def _materialize_missing_control_paths(
        self,
        rows: tuple[_Row, ...],
        *,
        seed_targets: Iterable[int] = (),
    ) -> tuple[_Row, ...]:
        """Decode exact reachable instructions omitted from coarse exports.

        Alignment instructions are commonly classified outside state-machine
        rows even when a direct branch targets them.  Python only proposes
        these one-instruction spans; Lean still decodes every accepted span
        from the embedded PE bytes.
        """

        known = list(rows)
        pending = list(seed_targets)
        for row in rows:
            if (
                isinstance(row.outcome, Mapping)
                and row.outcome.get("kind") == "fallthrough"
            ):
                target = row.outcome.get("target_rva")
                if isinstance(target, int) and not isinstance(target, bool):
                    pending.append(target)
            for item in row.instructions:
                instruction = item.decoded
                if any(
                    instruction.group(group)
                    for group in (capstone.CS_GRP_CALL, capstone.CS_GRP_JUMP)
                ):
                    target = _direct_target(instruction, self.image_base)
                    if target is not None:
                        pending.append(target)
                    if instruction.group(capstone.CS_GRP_CALL) or (
                        instruction.group(capstone.CS_GRP_JUMP)
                        and instruction.mnemonic != "jmp"
                    ):
                        pending.append(item.rva + item.size)
        decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
        decoder.detail = True
        generated = 0
        while pending:
            target = pending.pop()
            containing = [
                row for row in known if row.rva <= target < row.end
            ]
            if containing:
                continue
            if not self._rva_is_executable(target):
                # Global proposal normalization sees unreachable/nonreturning
                # fallthroughs too.  A requested path that needs this target
                # will still fail closed in `_row_at`.
                continue
            raw = bytes(self.pe.get_data(target, 15))
            decoded = list(decoder.disasm(
                raw,
                self.image_base + target,
                count=1,
            ))
            if not decoded:
                raise InternalDirectCallSummaryProposalError(
                    f"direct control target 0x{target:x} does not decode"
                )
            instruction = decoded[0]
            exact = bytes(self.pe.get_data(target, instruction.size))
            item = _Instruction(target, instruction.size, exact, instruction)
            row = _Row(
                rva=target,
                end=target + instruction.size,
                size=instruction.size,
                function=None,
                instructions=(item,),
                memory_writes=self._decoded_memory_write_count((item,)),
                memory_events=(),
                external_events=(),
                outcome=None,
                synthetic=True,
            )
            known.append(row)
            generated += 1
            if generated > 4096:
                raise InternalDirectCallSummaryProposalError(
                    "exact control-target materialization exceeded 4096 instructions"
                )
            is_return = instruction.group(capstone.CS_GRP_RET)
            is_jump = instruction.group(capstone.CS_GRP_JUMP)
            is_call = instruction.group(capstone.CS_GRP_CALL)
            direct = (
                _direct_target(instruction, self.image_base)
                if is_jump or is_call
                else None
            )
            if direct is not None:
                pending.append(direct)
            if not is_return and (
                not is_jump or instruction.mnemonic != "jmp"
            ):
                pending.append(row.end)
        known.sort(key=lambda item: item.rva)
        return tuple(known)

    def _rva_is_executable(self, rva: int) -> bool:
        for section in self.pe.sections:
            start = int(section.VirtualAddress)
            size = max(
                int(section.Misc_VirtualSize),
                int(section.SizeOfRawData),
            )
            if (
                start <= rva < start + size
                and int(section.Characteristics) & 0x20000000
            ):
                return True
        return False

    def _split_rows_at_control_targets(
        self,
        rows: tuple[_Row, ...],
        *,
        extra_targets: Iterable[int] = (),
    ) -> tuple[_Row, ...]:
        """Split proposal rows at exact direct-control instruction targets.

        State-machine exports may coalesce straight-line instructions past an
        internal target.  The split is an untrusted proposal normalization:
        generated Lean regions are decoded again from the exact PE spans.
        """

        targets = set(extra_targets)
        for row in rows:
            for item in row.instructions:
                instruction = item.decoded
                if not any(
                    instruction.group(group)
                    for group in (capstone.CS_GRP_CALL, capstone.CS_GRP_JUMP)
                ):
                    continue
                target = _direct_target(instruction, self.image_base)
                if target is not None:
                    targets.add(target)

        result: list[_Row] = []
        for row in rows:
            interior = sorted(
                target for target in targets if row.rva < target < row.end
            )
            if not interior:
                result.append(row)
                continue
            starts = {item.rva for item in row.instructions}
            invalid = [target for target in interior if target not in starts]
            if invalid:
                raise InternalDirectCallSummaryProposalError(
                    "direct control target "
                    f"0x{invalid[0]:x} enters the middle of a decoded instruction"
                )
            boundaries = (row.rva, *interior, row.end)
            for start, end in zip(boundaries, boundaries[1:]):
                instructions = tuple(
                    item for item in row.instructions
                    if start <= item.rva < end
                )
                if (
                    not instructions
                    or instructions[0].rva != start
                    or instructions[-1].rva + instructions[-1].size != end
                ):
                    raise InternalDirectCallSummaryProposalError(
                        f"cannot split exact state-machine row at 0x{start:x}"
                    )
                terminal_fragment = end == row.end
                result.append(_Row(
                    rva=start,
                    end=end,
                    size=end - start,
                    function=row.function,
                    instructions=instructions,
                    memory_writes=self._decoded_memory_write_count(instructions),
                    memory_events=row.memory_events if terminal_fragment else (),
                    external_events=row.external_events if terminal_fragment else (),
                    outcome=row.outcome if terminal_fragment else None,
                    synthetic=row.synthetic,
                ))
        result.sort(key=lambda item: item.rva)
        return tuple(result)

    @staticmethod
    def _normalize_legacy_word_expression(
        expression: Mapping[str, Any],
    ) -> Mapping[str, Any]:
        operation = expression.get("op")
        if operation == "reg":
            return {"op": "reg", "name": expression.get("name")}
        if operation == "const":
            return {"op": "const", "value": expression.get("value")}
        arguments = expression.get("args")
        if (
            operation not in {"add32", "sub32", "and32", "xor32", "or32", "mul32"}
            or not isinstance(arguments, list)
            or len(arguments) != 2
            or not all(isinstance(argument, Mapping) for argument in arguments)
        ):
            return expression
        left = _Planner._normalize_legacy_word_expression(arguments[0])
        right = _Planner._normalize_legacy_word_expression(arguments[1])
        if (
            operation in {"add32", "and32", "xor32", "or32", "mul32"}
            and left.get("op") == "const"
            and right.get("op") != "const"
        ):
            left, right = right, left
        return {"op": operation, "args": [left, right]}

    @staticmethod
    def _legacy_direct_register(expression: Mapping[str, Any]) -> str | None:
        if expression.get("op") != "reg":
            return None
        register = expression.get("name")
        return register if isinstance(register, str) and register in _REGISTERS else None

    @staticmethod
    def _legacy_bounded_register(expression: Mapping[str, Any]) -> str | None:
        direct = _Planner._legacy_direct_register(expression)
        if direct is not None:
            return direct
        if expression.get("op") != "and32":
            return None
        arguments = expression.get("args")
        if not isinstance(arguments, list):
            return None
        registers = [
            _Planner._legacy_direct_register(argument)
            for argument in arguments
            if isinstance(argument, Mapping)
        ]
        registers = [register for register in registers if register is not None]
        return registers[0] if len(registers) == 1 else None

    @staticmethod
    def _canonical_ia32_register(register: str) -> str | None:
        families = {
            "eax": {"eax", "ax", "al", "ah"},
            "ebx": {"ebx", "bx", "bl", "bh"},
            "ecx": {"ecx", "cx", "cl", "ch"},
            "edx": {"edx", "dx", "dl", "dh"},
            "esi": {"esi", "si"},
            "edi": {"edi", "di"},
            "ebp": {"ebp", "bp"},
            "esp": {"esp", "sp"},
        }
        return next((
            canonical for canonical, aliases in families.items()
            if register in aliases
        ), None)

    @staticmethod
    def _masked_upper_bound(expression: Mapping[str, Any]) -> int | None:
        if expression.get("op") != "and32":
            return None
        arguments = expression.get("args")
        if not isinstance(arguments, list) or len(arguments) != 2:
            return None
        constants = [
            argument.get("value")
            for argument in arguments
            if isinstance(argument, Mapping) and argument.get("op") == "const"
        ]
        if len(constants) != 1 or not isinstance(constants[0], int):
            return None
        upper = constants[0] + 1
        if upper <= 0 or upper > 4096 or upper & (upper - 1):
            return None
        return upper

    def _predecessor_upper_bound(
        self, row: _Row, index: Mapping[str, Any]
    ) -> int | None:
        register = self._legacy_bounded_register(index)
        if register is None:
            return None
        matches: set[int] = set()
        for predecessor in self.rows:
            terminal = predecessor.instructions[-1].decoded
            if (
                not terminal.group(capstone.CS_GRP_JUMP)
                or terminal.mnemonic == "jmp"
            ):
                continue
            direct = _direct_target(terminal, self.image_base)
            taken = direct == row.rva
            fallthrough = predecessor.end == row.rva
            if not taken and not fallthrough:
                continue
            compare = next((
                item.decoded
                for item in reversed(predecessor.instructions[:-1])
                if item.decoded.mnemonic == "cmp"
            ), None)
            if compare is None or len(compare.operands) != 2:
                continue
            left, right = compare.operands
            if (
                left.type != X86_OP_REG
                or self._canonical_ia32_register(compare.reg_name(left.reg)) != register
                or right.type != X86_OP_IMM
            ):
                continue
            immediate = int(right.imm) & 0xFFFFFFFF
            upper: int | None = None
            mnemonic = terminal.mnemonic
            if fallthrough and mnemonic in {"ja", "jnbe"}:
                upper = immediate + 1
            elif fallthrough and mnemonic in {"jae", "jnb", "jnc"}:
                upper = immediate
            elif taken and mnemonic in {"jb", "jnae", "jc"}:
                upper = immediate
            elif taken and mnemonic in {"jbe", "jna"}:
                upper = immediate + 1
            if upper is not None and 0 < upper <= 4096:
                matches.add(upper)
        return next(iter(matches)) if len(matches) == 1 else None

    def _finite_indirect_shape(
        self, row: _Row
    ) -> tuple[int, Mapping[str, Any], int | None] | None:
        outcome = row.outcome
        if not isinstance(outcome, Mapping) or outcome.get("kind") != "indirect_jump":
            return None
        target = outcome.get("target")
        if (
            not isinstance(target, Mapping)
            or target.get("op") != "load"
            or target.get("width") != 4
        ):
            return None
        address = target.get("address")
        if not isinstance(address, Mapping) or address.get("op") != "add32":
            return None
        arguments = address.get("args")
        if (
            not isinstance(arguments, list)
            or len(arguments) != 2
            or not all(isinstance(argument, Mapping) for argument in arguments)
        ):
            return None
        base_terms = [
            argument for argument in arguments if argument.get("op") == "const"
        ]
        scaled_terms = [
            argument for argument in arguments if argument.get("op") == "mul32"
        ]
        if len(base_terms) != 1 or len(scaled_terms) != 1:
            return None
        base = base_terms[0].get("value")
        scaled_arguments = scaled_terms[0].get("args")
        if (
            not isinstance(base, int)
            or not 0 <= base < 1 << 32
            or not isinstance(scaled_arguments, list)
            or len(scaled_arguments) != 2
            or not all(
                isinstance(argument, Mapping) for argument in scaled_arguments
            )
        ):
            return None
        scale_terms = [
            argument
            for argument in scaled_arguments
            if argument.get("op") == "const" and argument.get("value") == 4
        ]
        index_terms = [
            argument for argument in scaled_arguments if argument not in scale_terms
        ]
        if len(scale_terms) != 1 or len(index_terms) != 1:
            return None
        index = self._normalize_legacy_word_expression(index_terms[0])
        candidate_bounds = [
            bound for bound in (
                self._masked_upper_bound(index),
                self._predecessor_upper_bound(row, index),
            )
            if bound is not None
        ]
        upper = min(candidate_bounds) if candidate_bounds else None
        return base, index, upper

    def _finite_indirect_entries(
        self, table_base: int, upper_exclusive: int
    ) -> tuple[int, ...] | None:
        if (
            upper_exclusive <= 0
            or upper_exclusive > 4096
            or table_base < self.image_base
        ):
            return None
        table_rva = table_base - self.image_base
        size = upper_exclusive * 4
        if table_rva + size > 1 << 32:
            return None
        raw = bytes(self.pe.get_data(table_rva, size))
        if len(raw) != size:
            return None
        targets: list[int] = []
        for offset in range(0, size, 4):
            absolute = int.from_bytes(raw[offset:offset + 4], "little")
            if absolute < self.image_base:
                return None
            target = absolute - self.image_base
            if not self._rva_is_executable(target):
                return None
            targets.append(target)
        return tuple(targets)

    def _finite_indirect_dependency(
        self, row: _Row, call_path: tuple[int, ...]
    ) -> LeanFiniteIndirectJumpDependency:
        shape = self._finite_indirect_shape(row)
        if shape is None:
            raise self._failure(
                "finite_indirect_table_shape_not_recovered",
                row.instructions[-1].rva,
                "the indirect jump is not an exact dword table load with scale four",
                "recover a normalized finite-target expression or leave the exit incomplete",
                call_path,
            )
        table_base, index, upper = shape
        if upper is None:
            raise self._failure(
                "finite_indirect_index_bound_not_recovered",
                row.instructions[-1].rva,
                "no unique mask or dominating unsigned branch bounds the table index",
                "supply a Lean-checkable finite index-bound invariant",
                call_path,
            )
        entries = self._finite_indirect_entries(table_base, upper)
        if entries is None:
            raise self._failure(
                "finite_indirect_table_inventory_invalid",
                row.instructions[-1].rva,
                "the proposed table is not a complete in-image executable-target inventory",
                "recover the exact immutable PE table and all executable destinations",
                call_path,
            )
        missing = [target for target in set(entries) if target not in self.by_start]
        if missing:
            raise self._failure(
                "finite_indirect_target_region_missing",
                missing[0],
                "an exact table entry has no materialized target region",
                "materialize and decode every finite table destination from the PE",
                call_path,
            )
        return LeanFiniteIndirectJumpDependency(
            dependency_id=row.instructions[-1].rva,
            source_region_id=row.rva,
            original_table_base=table_base,
            candidate_table_base=table_base,
            upper_exclusive=upper,
            original_index_expression=index,
            candidate_index_expression=index,
            entry_target_region_ids=entries,
        )

    def _constant_indirect_target_rva(
        self, row: _Row, call_path: tuple[int, ...]
    ) -> int | None:
        outcome = row.outcome
        if (
            not isinstance(outcome, Mapping)
            or outcome.get("kind") != "indirect_jump"
        ):
            return None
        target = outcome.get("target")
        if not isinstance(target, Mapping) or target.get("op") != "const":
            return None
        value = target.get("value")
        if (
            not isinstance(value, int)
            or isinstance(value, bool)
            or not 0 <= value < 1 << 32
        ):
            raise self._failure(
                "constant_indirect_target_invalid",
                row.instructions[-1].rva,
                "the normalized indirect target is not an exact 32-bit word",
                "regenerate the normalized state-machine outcome from the exact PE",
                call_path,
            )
        if value < self.image_base:
            raise self._failure(
                "constant_indirect_target_outside_image",
                row.instructions[-1].rva,
                f"the constant target 0x{value:x} is below the PE image base",
                "provide an external-tail contract or an exact in-image code target",
                call_path,
            )
        target_rva = value - self.image_base
        if not self._rva_is_executable(target_rva):
            raise self._failure(
                "constant_indirect_target_not_executable",
                row.instructions[-1].rva,
                f"the constant target RVA 0x{target_rva:x} is not executable",
                "repair the target expression or classify the external/non-code exit",
                call_path,
            )
        return target_rva

    def _finite_origin_tail_dependency(
        self, row: _Row, call_path: tuple[int, ...]
    ) -> LeanFiniteOriginTailDependency | None:
        instruction_rva = row.instructions[-1].rva
        authority = self.finite_origin_tail_authorities.get(
            (row.rva, instruction_rva)
        )
        if authority is None:
            return None
        outcome = row.outcome
        if (
            not isinstance(outcome, Mapping)
            or outcome.get("kind") != "indirect_jump"
        ):
            raise self._failure(
                "finite_origin_tail_outcome_mismatch",
                instruction_rva,
                "the hash-bound finite-origin authority no longer names an indirect jump",
                "regenerate the writable-slot authority from the exact state machine",
                call_path,
            )
        missing = [
            target_rva
            for target_rva in authority.internal_target_rvas
            if target_rva not in self.by_start
        ]
        if missing:
            raise self._failure(
                "finite_origin_tail_target_region_missing",
                missing[0],
                "a checked finite-origin internal target has no materialized region",
                "materialize every code-map target named by the checked route",
                call_path,
            )
        return LeanFiniteOriginTailDependency(
            dependency_id=instruction_rva,
            source_region_id=row.rva,
            route_term=authority.route_term,
            internal_targets=authority.internal_targets,
            authority_module=authority.authority_module,
            route_authority_term=authority.route_authority_term,
        )

    def _finite_origin_call_authority(
        self, row: _Row, call_path: tuple[int, ...]
    ) -> FiniteOriginCallAuthorityBinding | None:
        instruction_rva = row.instructions[-1].rva
        authority = self.finite_origin_call_authorities.get(
            (row.rva, instruction_rva)
        )
        if authority is None:
            return None
        if row.end != authority.continuation_rva:
            raise self._failure(
                "finite_origin_call_continuation_mismatch",
                instruction_rva,
                "the hash-bound indirect-call authority no longer names the exact continuation",
                "regenerate the writable-slot authority from the exact state machine",
                call_path,
            )
        missing = [
            target_rva
            for target_rva in authority.internal_target_rvas
            if target_rva not in self.by_start
        ]
        if missing:
            raise self._failure(
                "finite_origin_call_target_region_missing",
                missing[0],
                "a checked finite-origin internal call target has no materialized region",
                "materialize every code-map target named by the checked authority",
                call_path,
            )
        return authority

    @staticmethod
    def _decoded_memory_write_count(
        instructions: Sequence[_Instruction],
    ) -> int:
        writes = 0
        for item in instructions:
            instruction = item.decoded
            explicit = any(
                operand.type == X86_OP_MEM
                and bool(getattr(operand, "access", 0) & capstone.CS_AC_WRITE)
                for operand in instruction.operands
            )
            if explicit or instruction.mnemonic in {
                "call",
                "push",
                "pushad",
                "pushal",
                "pusha",
            }:
                writes += 1
        return writes

    def proposal(
        self, request: DirectCallSummaryRequest
    ) -> InternalDirectCallSummaryProposal:
        call_row = self._resolve_callsite(request.callsite_rva, ())
        control = self._control(call_row, ())
        if control.kind != "internal_call":
            raise self._failure(
                "requested_site_is_not_internal_direct_call",
                control.instruction_rva,
                "the requested site does not end in an exact direct internal call",
                "select a terminal relative direct call with a decoded internal target",
                (),
            )
        registers = _ordered_registers(request.registers)
        tree = self._summary_tree(
            call_row=call_row,
            caller_rva=request.caller_rva,
            requested_registers=registers,
            caller_frame_words=tuple(
                LeanCallerFrameWord(offset + 4, offset + 4)
                for offset in request.caller_frame_word_offsets
            ),
            active_targets=(),
            call_path=(control.instruction_rva,),
        )
        return self._proposal_from_tree(request, tree)

    def finite_origin_call_proposal(
        self, request: DirectCallSummaryRequest
    ) -> InternalDirectCallSummaryProposal:
        call_row = self._resolve_callsite(request.callsite_rva, ())
        control = self._control(call_row, ())
        if control.kind != "unresolved_indirect_call":
            raise self._failure(
                "requested_site_is_not_finite_origin_internal_call",
                control.instruction_rva,
                "the requested site is not an exact returning indirect call",
                "select a returning indirect call with a checked finite target authority",
                (),
            )
        authority = self._finite_origin_call_authority(call_row, ())
        if authority is None:
            raise self._failure(
                "finite_origin_entry_authority_missing",
                control.instruction_rva,
                "the requested indirect call has no checked finite target authority",
                "supply a hash-bound finite-origin call authority for the exact site",
                (),
            )
        if len(authority.internal_targets) != 1:
            raise self._failure(
                "finite_origin_entry_has_multiple_targets",
                control.instruction_rva,
                "top-level finite-origin call summaries currently require one target",
                "split the proof by checked target guards or add finite-alternative composition",
                (),
            )
        target = authority.internal_targets[0]
        tree = self._summary_tree(
            call_row=call_row,
            caller_rva=request.caller_rva,
            requested_registers=_ordered_registers(request.registers),
            caller_frame_words=tuple(
                LeanCallerFrameWord(offset + 4, offset + 4)
                for offset in request.caller_frame_word_offsets
            ),
            active_targets=(),
            call_path=(control.instruction_rva,),
            indirect_target=target,
            indirect_dependency_id=control.instruction_rva,
        )
        return self._proposal_from_tree(
            request,
            tree,
            entry_authority=authority,
        )

    def _proposal_from_tree(
        self,
        request: DirectCallSummaryRequest,
        tree: LeanInternalDirectCallRegisterSummaryTree,
        *,
        entry_authority: FiniteOriginCallAuthorityBinding | None = None,
    ) -> InternalDirectCallSummaryProposal:
        region_rvas: set[int] = set()
        nested_sites: set[int] = set()
        boundary_ids: set[int] = set()
        tail_signature_ids: set[int] = set()
        self._collect_tree(
            tree,
            region_rvas,
            nested_sites,
            boundary_ids,
            tail_signature_ids,
        )
        return InternalDirectCallSummaryProposal(
            request=request,
            tree=tree,
            region_rvas=tuple(sorted(region_rvas)),
            nested_callsite_rvas=tuple(sorted(nested_sites)),
            machine_import_boundary_ids=tuple(sorted(boundary_ids)),
            machine_import_tail_signature_ids=tuple(sorted(tail_signature_ids)),
            entry_authority=entry_authority,
        )

    def _summary_tree(
        self,
        *,
        call_row: _Row,
        caller_rva: int | None,
        requested_registers: tuple[str, ...],
        caller_frame_words: tuple[LeanCallerFrameWord, ...],
        active_targets: tuple[int, ...],
        call_path: tuple[int, ...],
        indirect_target: LeanFiniteOriginTailTarget | None = None,
        indirect_dependency_id: int | None = None,
        summary_id_override: int | None = None,
    ) -> LeanInternalDirectCallRegisterSummaryTree:
        call_control = self._control(call_row, call_path)
        if indirect_target is None:
            valid_entry = (
                call_control.kind == "internal_call"
                and len(call_control.targets) == 2
            )
            callee_rva, continuation_rva = (
                call_control.targets if valid_entry else (0, 0)
            )
            entry_kind = "direct"
            entry_dependency_id = None
            entry_target_id = None
        else:
            valid_entry = (
                call_control.kind == "unresolved_indirect_call"
                and indirect_dependency_id is not None
            )
            callee_rva = indirect_target.region_id
            continuation_rva = call_row.end
            entry_kind = "finite_origin_call"
            entry_dependency_id = indirect_dependency_id
            entry_target_id = indirect_target.target_id
        if not valid_entry:
            raise self._failure(
                "nested_site_is_not_internal_direct_call",
                call_control.instruction_rva,
                "a nested summary site no longer matches its checked internal call kind",
                "regenerate the state machine and proposal from the exact PE bytes",
                call_path,
            )
        if callee_rva in active_targets:
            raise self._failure(
                "recursive_call_requires_checked_finite_invariant",
                call_control.instruction_rva,
                "the finite summary tree encountered recursion; the standalone checker "
                "has no checked recursion-invariant input",
                "add a Lean-checked finite recursion/ranking invariant interface before "
                "constructing this summary",
                call_path,
            )
        cache_key = (
            call_row.rva,
            caller_rva,
            requested_registers,
            caller_frame_words,
            (
                None
                if indirect_target is None
                else (indirect_target.target_id, indirect_target.region_id)
            ),
            indirect_dependency_id,
            summary_id_override,
        )
        cached = self._summary_tree_cache.get(cache_key)
        if cached is not None:
            tree, callee_entries = cached
            recursive_entries = callee_entries.intersection(active_targets)
            if recursive_entries:
                raise self._failure(
                    "recursive_call_requires_checked_finite_invariant",
                    call_control.instruction_rva,
                    "the cached finite summary tree intersects the active "
                    "call stack; the standalone checker has no checked "
                    "recursion-invariant input",
                    "add a Lean-checked finite recursion/ranking invariant "
                    "interface before constructing this summary",
                    call_path,
                )
            return tree
        continuation = self._row_at(
            continuation_rva,
            category="missing_call_continuation",
            action="split the state machine at the exact return RVA",
            call_path=call_path,
        )
        entry = self._row_at(
            callee_rva,
            category="missing_callee_entry",
            action="recover an exact state-machine region at the direct target",
            call_path=call_path,
        )
        requested_registers = _ordered_registers(
            (*requested_registers, "esp")
        )
        caller = call_row if caller_rva is None else self._row_at(
            caller_rva,
            category="missing_caller_region",
            action="supply a caller region that directly reaches the callsite",
            call_path=call_path,
        )

        pending = [entry]
        discovered: dict[int, _Row] = {}
        controls: dict[int, _Control] = {}
        children_by_source: dict[
            tuple[int, int], LeanInternalDirectCallRegisterSummaryTree
        ] = {}
        nested_dependencies: list[LeanNestedSummaryDependency] = []
        machine_dependencies: list[LeanMachineImportDependency] = []
        machine_tail_dependencies: list[LeanMachineImportTailDependency] = []
        machine_terminal_dependencies: list[
            LeanMachineImportTerminalDependency
        ] = []
        finite_indirect_dependencies: list[LeanFiniteIndirectJumpDependency] = []
        finite_origin_call_dependencies: list[
            LeanFiniteOriginCallDependency
        ] = []
        finite_origin_tail_dependencies: list[
            LeanFiniteOriginTailDependency
        ] = []
        edges: list[LeanCalleeEdge] = []
        returns: list[LeanReturnInventoryEntry] = []

        while pending:
            row = pending.pop()
            if row.rva in discovered:
                continue
            discovered[row.rva] = row
            control = self._control(row, call_path)
            controls[row.rva] = control
            if control.kind == "return":
                returns.append(LeanReturnInventoryEntry(row.rva, continuation.rva))
                continue
            if control.kind == "direct":
                target = self._row_at(
                    control.targets[0],
                    category="missing_direct_successor",
                    action="recover the exact direct successor region",
                    call_path=call_path,
                )
                tails = self.imports.tails_by_execution_rva.get(target.rva, ())
                if len(tails) > 1:
                    raise self._failure(
                        "ambiguous_machine_import_tail",
                        control.instruction_rva,
                        f"the exact direct target has {len(tails)} incompatible "
                        "machine-import tail contracts",
                        "make the import identity and machine-level arity unique",
                        call_path,
                    )
                if tails:
                    tail = tails[0]
                    if target.size != tail.source_size:
                        raise self._failure(
                            "machine_import_tail_span_mismatch",
                            target.rva,
                            "the external-tail contract does not select the exact "
                            "state-machine execution span",
                            "regenerate exact static machine-import boundaries",
                            call_path,
                        )
                    edges.append(LeanCalleeEdge(
                        row.rva,
                        target.rva,
                        "machine_import_tail",
                        tail.id,
                    ))
                else:
                    edge_kind = (
                        "direct_tail"
                        if (
                            target.rva in self.known_call_targets
                            and target.rva != callee_rva
                        )
                        else "direct"
                    )
                    edges.append(LeanCalleeEdge(row.rva, target.rva, edge_kind))
                pending.append(target)
                continue
            if control.kind == "branch":
                taken = self._row_at(
                    control.targets[0],
                    category="missing_branch_successor",
                    action="recover both exact branch successor regions",
                    call_path=call_path,
                )
                fallthrough = self._row_at(
                    control.targets[1],
                    category="missing_branch_successor",
                    action="recover both exact branch successor regions",
                    call_path=call_path,
                )
                edges.extend((
                    LeanCalleeEdge(row.rva, taken.rva, "branch_taken"),
                    LeanCalleeEdge(row.rva, fallthrough.rva, "branch_fallthrough"),
                ))
                pending.extend((fallthrough, taken))
                continue
            if control.kind == "internal_call":
                child_continuation = self._row_at(
                    control.targets[1],
                    category="missing_nested_call_continuation",
                    action="split the state machine at the nested return RVA",
                    call_path=call_path,
                )
                child_registers = _ordered_registers((*requested_registers, "esp"))
                child = self._summary_tree(
                    call_row=row,
                    caller_rva=None,
                    requested_registers=child_registers,
                    caller_frame_words=(),
                    active_targets=(*active_targets, callee_rva),
                    call_path=(*call_path, control.instruction_rva),
                )
                dependency_id = control.instruction_rva
                nested_dependencies.append(LeanNestedSummaryDependency(
                    dependency_id,
                    row.rva,
                    child_continuation.rva,
                    child.certificate.summary_id,
                ))
                edges.append(LeanCalleeEdge(
                    row.rva,
                    child_continuation.rva,
                    "nested_summary",
                    dependency_id,
                ))
                children_by_source[(row.rva, control.targets[0])] = child
                pending.append(child_continuation)
                continue
            if control.kind == "machine_import":
                assert control.boundary is not None
                boundary = control.boundary
                signature = self.imports.signatures_by_id.get(
                    boundary.signature_id
                )
                if (
                    isinstance(signature, Mapping)
                    and signature.get("disposition") == "terminates"
                ):
                    self._check_machine_terminal_contract(boundary, call_path)
                    machine_terminal_dependencies.append(
                        self._machine_terminal_dependency(boundary, row.rva)
                    )
                    continue
                target = self._row_at(
                    boundary.continuation_rva,
                    category="missing_import_continuation",
                    action="split the state machine at the imported call continuation",
                    call_path=call_path,
                )
                self._check_machine_contract(
                    boundary, requested_registers, call_path
                )
                dependency = self._machine_dependency(boundary, row.rva, target.rva)
                machine_dependencies.append(dependency)
                edges.append(LeanCalleeEdge(
                    row.rva,
                    target.rva,
                    "machine_import",
                    boundary.id,
                ))
                pending.append(target)
                continue
            if control.kind == "machine_import_tail":
                assert control.import_tail is not None
                tail = control.import_tail
                self._check_machine_tail_contract(
                    tail, requested_registers, call_path
                )
                machine_tail_dependencies.append(
                    self._machine_tail_dependency(tail, row.rva)
                )
                returns.append(
                    LeanReturnInventoryEntry(row.rva, continuation.rva)
                )
                continue
            if control.kind == "unresolved_indirect_jump":
                constant_target_rva = self._constant_indirect_target_rva(
                    row, call_path
                )
                if constant_target_rva is not None:
                    target = self._row_at(
                        constant_target_rva,
                        category="constant_indirect_target_region_missing",
                        action=(
                            "materialize the exact in-image target named by the "
                            "normalized constant expression"
                        ),
                        call_path=call_path,
                    )
                    edges.append(LeanCalleeEdge(
                        row.rva,
                        target.rva,
                        "constant_indirect",
                    ))
                    pending.append(target)
                    continue
                finite_origin_tail = self._finite_origin_tail_dependency(
                    row, call_path
                )
                if finite_origin_tail is not None:
                    finite_origin_tail_dependencies.append(finite_origin_tail)
                    returns.append(
                        LeanReturnInventoryEntry(row.rva, continuation.rva)
                    )
                    for target_binding in finite_origin_tail.internal_targets:
                        target = self._row_at(
                            target_binding.region_id,
                            category="finite_origin_tail_target_region_missing",
                            action=(
                                "materialize every code-map target named by the "
                                "checked finite-origin route"
                            ),
                            call_path=call_path,
                        )
                        edges.append(LeanCalleeEdge(
                            row.rva,
                            target.rva,
                            "finite_origin_tail",
                            finite_origin_tail.dependency_id,
                        ))
                        pending.append(target)
                    continue
                dependency = self._finite_indirect_dependency(row, call_path)
                finite_indirect_dependencies.append(dependency)
                for target_rva in sorted(set(dependency.entry_target_region_ids)):
                    target = self._row_at(
                        target_rva,
                        category="finite_indirect_target_region_missing",
                        action="materialize every exact finite table destination",
                        call_path=call_path,
                    )
                    edges.append(LeanCalleeEdge(
                        row.rva,
                        target.rva,
                        "finite_indirect",
                        dependency.dependency_id,
                    ))
                    pending.append(target)
                continue
            if control.kind == "unresolved_indirect_call":
                authority = self._finite_origin_call_authority(row, call_path)
                if authority is None:
                    raise self._failure(
                        "unsupported_callee_control",
                        control.instruction_rva,
                        "unresolved_indirect_call",
                        "provide a checked finite-origin indirect-call authority",
                        call_path,
                    )
                child_continuation = self._row_at(
                    authority.continuation_rva,
                    category="missing_indirect_call_continuation",
                    action="split the state machine at the checked indirect-call continuation",
                    call_path=call_path,
                )
                dependency_targets: list[LeanFiniteOriginCallTarget] = []
                dependency_id = control.instruction_rva
                for target in authority.internal_targets:
                    child_summary_id = (
                        (1 << 64)
                        + (control.instruction_rva << 32)
                        + target.region_id
                    )
                    child = self._summary_tree(
                        call_row=row,
                        caller_rva=None,
                        requested_registers=_ordered_registers(
                            (*requested_registers, "esp")
                        ),
                        caller_frame_words=(),
                        active_targets=(*active_targets, callee_rva),
                        call_path=(*call_path, control.instruction_rva),
                        indirect_target=target,
                        indirect_dependency_id=dependency_id,
                        summary_id_override=child_summary_id,
                    )
                    dependency_targets.append(LeanFiniteOriginCallTarget(
                        target_id=target.target_id,
                        region_id=target.region_id,
                        summary_id=child.certificate.summary_id,
                    ))
                    children_by_source[(row.rva, target.region_id)] = child
                finite_origin_call_dependencies.append(
                    LeanFiniteOriginCallDependency(
                        dependency_id=dependency_id,
                        source_region_id=row.rva,
                        continuation_region_id=child_continuation.rva,
                        continuation_target_id=authority.continuation_target_id,
                        internal_targets=tuple(dependency_targets),
                        authority_module=authority.authority_module,
                        indirect_exit_authority_term=(
                            authority.indirect_exit_authority_term
                        ),
                    )
                )
                edges.append(LeanCalleeEdge(
                    row.rva,
                    child_continuation.rva,
                    "finite_origin_call",
                    dependency_id,
                ))
                pending.append(child_continuation)
                continue
            raise self._failure(
                "unsupported_callee_control",
                control.instruction_rva,
                f"callee control kind {control.kind!r} has no standalone checker encoding",
                "add a Lean-checked edge kind or select a finite direct-control callee",
                call_path,
            )

        if not returns:
            raise self._failure(
                "callee_has_no_complete_return_inventory",
                callee_rva,
                "the reachable finite callee CFG contains no decoded return",
                "supply a returning call or add a checked nonreturning-call contract",
                call_path,
            )
        return_ids = {item.return_region_id for item in returns}
        adjacency: dict[int, set[int]] = {rva: set() for rva in discovered}
        for edge in edges:
            adjacency[edge.source_region_id].add(edge.target_region_id)
        can_return = {
            *return_ids,
            *(
                dependency.source_region_id
                for dependency in machine_terminal_dependencies
            ),
        }
        changed = True
        while changed:
            changed = False
            for source, targets in adjacency.items():
                if source not in can_return and targets & can_return:
                    can_return.add(source)
                    changed = True
        trapped = sorted(set(discovered) - can_return)
        if trapped:
            raise self._failure(
                "callee_contains_nonreturning_reachable_region",
                trapped[0],
                f"{len(trapped)} reachable regions cannot reach a decoded return",
                "provide a checked loop invariant with termination/ranking evidence or "
                "select a returning callee",
                call_path,
            )

        returns.sort(key=lambda item: item.return_region_id)
        frame_entries, frame_owners = self._frame_partition(
            entry=entry,
            rows=discovered,
            edges=edges,
            call_path=call_path,
        )
        stack_frame_anchors, frame_anchors = self._stack_frame_anchors(
            frame_entries=frame_entries,
            frame_owners=frame_owners,
            rows=discovered,
            call_path=call_path,
        )
        missing_frame_registers = {
            witness.register
            for witness in stack_frame_anchors
            if witness.register not in requested_registers
        }
        if missing_frame_registers:
            return self._summary_tree(
                call_row=call_row,
                caller_rva=caller_rva,
                requested_registers=_ordered_registers((
                    *requested_registers,
                    *missing_frame_registers,
                )),
                caller_frame_words=caller_frame_words,
                active_targets=active_targets,
                call_path=call_path,
                indirect_target=indirect_target,
                indirect_dependency_id=indirect_dependency_id,
                summary_id_override=summary_id_override,
            )
        (
            stack_entry_offsets,
            dynamic_stack_entry_region_ids,
        ) = self._stack_entry_offsets(
            entry=entry,
            rows=discovered,
            controls=controls,
            edges=edges,
            returns=returns,
            finite_origin_tail_source_ids={
                item.source_region_id
                for item in finite_origin_tail_dependencies
            },
            machine_import_tail_source_ids={
                item.source_region_id for item in machine_tail_dependencies
            },
            frame_owners=frame_owners,
            frame_anchors=frame_anchors,
            call_path=call_path,
        )
        stack_witnesses, frame_bytes = self._stack_witnesses(
            entry=entry,
            rows=tuple(discovered.values()),
            controls=controls,
            edges=tuple(edges),
            return_rows=tuple(
                discovered[item.return_region_id]
                for item in returns
                if controls[item.return_region_id].kind == "return"
            ),
            entry_offsets={
                item.region_id: item.original_offset
                for item in stack_entry_offsets
            },
            requested_registers=requested_registers,
            dependency_sources={
                *(item.call_region_id for item in nested_dependencies),
                *(item.source_region_id for item in machine_dependencies),
                *(
                    item.source_region_id
                    for item in machine_tail_dependencies
                ),
                *(
                    item.source_region_id
                    for item in machine_terminal_dependencies
                ),
                *(
                    item.source_region_id
                    for item in finite_origin_tail_dependencies
                ),
            },
            call_path=call_path,
        )
        region_pairs = tuple(
            _region_pair(discovered[rva]) for rva in sorted(discovered)
        )
        edges.sort(key=lambda item: (
            item.source_region_id,
            item.kind,
            item.target_region_id,
            -1 if item.dependency_id is None else item.dependency_id,
        ))
        nested_dependencies.sort(key=lambda item: item.call_region_id)
        machine_dependencies.sort(key=lambda item: item.source_region_id)
        machine_tail_dependencies.sort(key=lambda item: item.source_region_id)
        machine_terminal_dependencies.sort(
            key=lambda item: item.source_region_id
        )
        finite_indirect_dependencies.sort(key=lambda item: item.source_region_id)
        finite_origin_call_dependencies.sort(
            key=lambda item: item.source_region_id
        )
        finite_origin_tail_dependencies.sort(
            key=lambda item: item.source_region_id
        )
        children = tuple(
            children_by_source[source] for source in sorted(children_by_source)
        )
        depth = 0 if not children else max(
            child.certificate.dependency_depth for child in children
        ) + 1
        certificate = LeanInternalDirectCallRegisterCertificate(
            summary_id=(
                call_control.instruction_rva
                if summary_id_override is None
                else summary_id_override
            ),
            dependency_depth=depth,
            caller=_region_pair(caller),
            callsite=_region_pair(call_row),
            callee_entry=_region_pair(entry),
            continuation=_region_pair(continuation),
            callee_regions=region_pairs,
            edges=tuple(edges),
            returns=tuple(returns),
            requested_registers=requested_registers,
            caller_frame_words=caller_frame_words,
            entry_kind=entry_kind,
            entry_dependency_id=entry_dependency_id,
            entry_target_id=entry_target_id,
            original_frame_bytes=frame_bytes,
            candidate_frame_bytes=frame_bytes,
            nested_dependencies=tuple(nested_dependencies),
            machine_import_dependencies=tuple(machine_dependencies),
            machine_import_tail_dependencies=tuple(machine_tail_dependencies),
            machine_import_terminal_dependencies=tuple(
                machine_terminal_dependencies
            ),
            finite_indirect_dependencies=tuple(finite_indirect_dependencies),
            finite_origin_call_dependencies=tuple(
                finite_origin_call_dependencies
            ),
            finite_origin_tail_dependencies=tuple(
                finite_origin_tail_dependencies
            ),
            stack_frame_anchors=stack_frame_anchors,
            stack_witnesses=stack_witnesses,
            stack_entry_offsets=stack_entry_offsets,
            dynamic_stack_entry_region_ids=dynamic_stack_entry_region_ids,
        )
        tree = LeanInternalDirectCallRegisterSummaryTree(certificate, children)
        callee_entries = frozenset({
            certificate.callee_entry.original.start,
            *(
                entry
                for child in children
                for entry in self._summary_tree_callee_entries(child)
            ),
        })
        self._summary_tree_cache[cache_key] = (tree, callee_entries)
        return tree

    def _summary_tree_callee_entries(
        self,
        tree: LeanInternalDirectCallRegisterSummaryTree,
    ) -> frozenset[int]:
        return frozenset({
            tree.certificate.callee_entry.original.start,
            *(
                entry
                for child in tree.nested
                for entry in self._summary_tree_callee_entries(child)
            ),
        })

    def _machine_stack_result_delta(
        self, boundary: _Boundary, call_path: tuple[int, ...]
    ) -> int:
        signature = self.imports.signatures_by_id.get(boundary.signature_id)
        if signature is None:
            raise self._failure(
                "machine_import_signature_missing",
                boundary.instruction_rva,
                "the exact boundary references an absent machine-import signature",
                "regenerate the exact static machine-import contract report",
                call_path,
            )
        abi = signature.get("abi")
        argument_words = boundary.payload.get("argument_words")
        if (
            abi not in {"cdecl", "stdcall"}
            or not isinstance(argument_words, int)
            or isinstance(argument_words, bool)
            or argument_words < 0
        ):
            raise self._failure(
                "machine_import_stack_delta_not_recoverable",
                boundary.instruction_rva,
                "the exact machine-import boundary has no supported ABI/arity pair",
                "recover a finite cdecl/stdcall machine-call boundary",
                call_path,
            )
        return argument_words * 4 if abi == "stdcall" else 0

    def _machine_tail_stack_result_delta(
        self, tail: _ImportTail, call_path: tuple[int, ...]
    ) -> int:
        signature = self.imports.signatures_by_id.get(tail.signature_id)
        if signature is None:
            raise self._failure(
                "machine_import_signature_missing",
                tail.source_rva,
                "the exact external tail references an absent machine-import signature",
                "regenerate the exact static machine-import contract report",
                call_path,
            )
        abi = signature.get("abi")
        if abi not in {"cdecl", "stdcall"}:
            raise self._failure(
                "machine_import_stack_delta_not_recoverable",
                tail.source_rva,
                "the exact external tail has no supported ABI",
                "recover a finite cdecl/stdcall machine-call boundary",
                call_path,
            )
        cleanup = tail.argument_words * 4 if abi == "stdcall" else 0
        return 4 + cleanup

    def _frame_partition(
        self,
        *,
        entry: _Row,
        rows: Mapping[int, _Row],
        edges: Sequence[LeanCalleeEdge],
        call_path: tuple[int, ...],
    ) -> tuple[tuple[int, ...], dict[int, int]]:
        frame_entries = (entry.rva, *tuple(sorted({
            edge.target_region_id
            for edge in edges
            if edge.kind == "direct_tail"
        })))
        adjacency: dict[int, list[int]] = {rva: [] for rva in rows}
        for edge in edges:
            if edge.kind != "direct_tail":
                adjacency[edge.source_region_id].append(edge.target_region_id)
        owners: dict[int, int] = {}
        for frame_entry in frame_entries:
            pending = [frame_entry]
            while pending:
                rva = pending.pop()
                prior = owners.get(rva)
                if prior is not None:
                    if prior != frame_entry:
                        raise self._failure(
                            "tail_frame_regions_overlap",
                            rva,
                            "two tail-entered stack frames reach the same summary region",
                            "split the summary at a checked cutpoint or provide a "
                            "path-sensitive frame invariant",
                            call_path,
                        )
                    continue
                owners[rva] = frame_entry
                pending.extend(adjacency[rva])
        missing = sorted(set(rows) - set(owners))
        if missing:
            raise self._failure(
                "tail_frame_partition_incomplete",
                missing[0],
                "the exact CFG is not covered by the root and tail-entered frames",
                "regenerate complete direct-tail edge classifications",
                call_path,
            )
        return frame_entries, owners

    def _stack_frame_anchors(
        self,
        *,
        frame_entries: Sequence[int],
        frame_owners: Mapping[int, int],
        rows: Mapping[int, _Row],
        call_path: tuple[int, ...],
    ) -> tuple[
        tuple[LeanStackFrameAnchorWitness, ...],
        dict[int, tuple[str, int]],
    ]:
        result: list[LeanStackFrameAnchorWitness] = []
        by_frame: dict[int, tuple[str, int]] = {}
        for frame_entry in frame_entries:
            _frame_bytes, _saves, established = self._entry_frame(
                rows[frame_entry], call_path
            )
            used: set[str] = set()
            for rva, owner in frame_owners.items():
                if owner != frame_entry:
                    continue
                for item in rows[rva].instructions:
                    instruction = item.decoded
                    operands = instruction.operands
                    if (
                        instruction.mnemonic == "lea"
                        and len(operands) == 2
                        and _operand_register(instruction, operands[0]) == "esp"
                        and operands[1].type == X86_OP_MEM
                        and operands[1].mem.index == 0
                    ):
                        base = _memory_base(instruction, operands[1])
                        if base is not None and base != "esp":
                            used.add(base)
            if not used:
                continue
            if len(used) != 1:
                raise self._failure(
                    "ambiguous_stack_frame_anchor",
                    frame_entry,
                    f"frame-pointer stack recovery uses multiple bases {sorted(used)}",
                    "split the frame or provide one checked affine frame-base invariant",
                    call_path,
                )
            register = next(iter(used))
            offset = established.get(register)
            if offset is None:
                raise self._failure(
                    "stack_frame_anchor_not_established",
                    frame_entry,
                    f"the entry does not establish {register} from incoming ESP",
                    "recover an exact mov/lea frame-base definition at the frame entry",
                    call_path,
                )
            by_frame[frame_entry] = (register, offset)
            result.append(LeanStackFrameAnchorWitness(
                frame_entry_region_id=frame_entry,
                register=register,
                original_offset=offset,
                candidate_offset=offset,
            ))
        return tuple(result), by_frame

    def _row_stack_result_offset(
        self,
        row: _Row,
        control: _Control,
        entry_offset: int | None,
        frame_anchor: tuple[str, int] | None,
        call_path: tuple[int, ...],
    ) -> int | None:
        cache_key = (
            row.rva,
            control.kind,
            control.instruction_rva,
            control.targets,
            None if control.boundary is None else control.boundary.id,
            None if control.import_tail is None else control.import_tail.id,
            entry_offset,
            frame_anchor,
        )
        if cache_key in self._row_stack_result_cache:
            return self._row_stack_result_cache[cache_key]
        absolute = entry_offset

        def adjust(amount: int) -> None:
            nonlocal absolute
            if absolute is not None:
                absolute = (absolute + amount) % (1 << 32)

        for item in row.instructions:
            instruction = item.decoded
            operands = instruction.operands
            if instruction.group(capstone.CS_GRP_CALL):
                continue
            if instruction.mnemonic == "push":
                adjust(-4)
                continue
            if instruction.mnemonic == "pop":
                adjust(4)
                continue
            if instruction.group(capstone.CS_GRP_RET):
                adjust(4)
                if operands and operands[0].type == X86_OP_IMM:
                    adjust(int(operands[0].imm) & 0xFFFF)
                continue
            if (
                instruction.mnemonic in {"add", "sub"}
                and len(operands) == 2
                and _operand_register(instruction, operands[0]) == "esp"
                and operands[1].type == X86_OP_IMM
            ):
                amount = int(operands[1].imm) & 0xFFFFFFFF
                adjust(amount if instruction.mnemonic == "add" else -amount)
                continue
            if (
                instruction.mnemonic == "sub"
                and len(operands) == 2
                and _operand_register(instruction, operands[0]) == "esp"
                and operands[1].type == X86_OP_REG
                and frame_anchor is not None
            ):
                absolute = None
                continue
            if (
                instruction.mnemonic == "lea"
                and len(operands) == 2
                and _operand_register(instruction, operands[0]) == "esp"
                and operands[1].type == X86_OP_MEM
                and operands[1].mem.index == 0
                and frame_anchor is not None
                and _memory_base(instruction, operands[1]) == frame_anchor[0]
            ):
                absolute = (
                    frame_anchor[1]
                    + int(operands[1].mem.disp)
                ) % (1 << 32)
                continue
            if (
                instruction.mnemonic == "mov"
                and len(operands) == 2
                and _operand_register(instruction, operands[0]) == "esp"
                and operands[1].type == X86_OP_MEM
                and operands[1].mem.index == 0
                and frame_anchor is not None
                and _memory_base(instruction, operands[1]) == frame_anchor[0]
            ):
                absolute = None
                continue
            if self._instruction_writes_register(instruction, "esp"):
                raise self._failure(
                    "stack_offset_expression_unsupported",
                    item.rva,
                    f"{instruction.mnemonic} writes ESP outside the checked fixed-offset "
                    "grammar",
                    "add a reviewed stack-expression rule or keep the call frame affine",
                    call_path,
                )
        if control.kind == "machine_import":
            assert control.boundary is not None
            adjust(self._machine_stack_result_delta(
                control.boundary, call_path
            ))
        elif control.kind == "machine_import_tail":
            assert control.import_tail is not None
            adjust(self._machine_tail_stack_result_delta(
                control.import_tail, call_path
            ))
        self._row_stack_result_cache[cache_key] = absolute
        return absolute

    def _stack_entry_offsets(
        self,
        *,
        entry: _Row,
        rows: Mapping[int, _Row],
        controls: Mapping[int, _Control],
        edges: Sequence[LeanCalleeEdge],
        returns: Sequence[LeanReturnInventoryEntry],
        finite_origin_tail_source_ids: set[int],
        machine_import_tail_source_ids: set[int],
        frame_owners: Mapping[int, int],
        frame_anchors: Mapping[int, tuple[str, int]],
        call_path: tuple[int, ...],
    ) -> tuple[tuple[LeanStackEntryOffsetWitness, ...], tuple[int, ...]]:
        offsets: dict[int, int | None] = {entry.rva: 0}
        changed = True
        while changed:
            changed = False
            for edge in edges:
                if edge.source_region_id not in offsets:
                    continue
                source_offset = offsets[edge.source_region_id]
                owner = frame_owners[edge.source_region_id]
                expected = self._row_stack_result_offset(
                    rows[edge.source_region_id],
                    controls[edge.source_region_id],
                    source_offset,
                    frame_anchors.get(owner),
                    call_path,
                )
                if edge.target_region_id not in offsets:
                    offsets[edge.target_region_id] = expected
                    changed = True
                elif offsets[edge.target_region_id] != expected:
                    raise self._failure(
                        "stack_offset_join_mismatch",
                        edge.target_region_id,
                        "incoming call-frame paths establish different fixed ESP offsets",
                        "supply a path-sensitive invariant or normalize the stack joins",
                        call_path,
                    )
        missing = sorted(set(rows) - set(offsets))
        if missing:
            raise self._failure(
                "stack_offset_reachability_incomplete",
                missing[0],
                "the exact summary graph did not establish a stack offset for every region",
                "close the exact CFG before constructing a stack-offset certificate",
                call_path,
            )
        for returned in returns:
            if returned.return_region_id in finite_origin_tail_source_ids:
                continue
            owner = frame_owners[returned.return_region_id]
            absolute = self._row_stack_result_offset(
                rows[returned.return_region_id],
                controls[returned.return_region_id],
                offsets[returned.return_region_id],
                frame_anchors.get(owner),
                call_path,
            )
            if absolute is None:
                raise self._failure(
                    "dynamic_stack_not_restored_at_return",
                    returned.return_region_id,
                    "the dynamic stack offset is not reset by a checked frame anchor",
                    "restore ESP from a checked frame base before returning",
                    call_path,
                )
            if absolute != 4:
                raise self._failure(
                    "stack_return_offset_mismatch",
                    returned.return_region_id,
                    f"the exact return establishes ESP delta 0x{absolute:08x}, not 4",
                    "recover the complete prologue/epilogue and ABI cleanup path",
                    call_path,
                )
        if not machine_import_tail_source_ids.issubset(
            {item.return_region_id for item in returns}
        ):
            missing = sorted(
                machine_import_tail_source_ids
                - {item.return_region_id for item in returns}
            )
            raise self._failure(
                "machine_import_tail_return_inventory_incomplete",
                missing[0],
                "an exact external tail is absent from the return inventory",
                "regenerate the complete external-tail terminal inventory",
                call_path,
            )
        return (
            tuple(
                LeanStackEntryOffsetWitness(
                    rva,
                    0 if offsets[rva] is None else offsets[rva],
                    0 if offsets[rva] is None else offsets[rva],
                )
                for rva in sorted(offsets)
            ),
            tuple(sorted(
                rva for rva, offset in offsets.items() if offset is None
            )),
        )

    def _stack_witnesses(
        self,
        *,
        entry: _Row,
        rows: tuple[_Row, ...],
        controls: Mapping[int, _Control],
        edges: tuple[LeanCalleeEdge, ...],
        return_rows: tuple[_Row, ...],
        entry_offsets: Mapping[int, int],
        requested_registers: tuple[str, ...],
        dependency_sources: set[int],
        call_path: tuple[int, ...],
    ) -> tuple[tuple[LeanStackSaveRestoreWitness, ...], int]:
        rows_by_rva = {row.rva: row for row in rows}
        direct_tail_edges = tuple(
            edge for edge in edges if edge.kind == "direct_tail"
        )
        frame_tail_edges = tuple(
            edge
            for edge in edges
            if edge.kind in {"direct_tail", "machine_import_tail"}
        )
        frame_entries, frame_owners = self._frame_partition(
            entry=entry,
            rows=rows_by_rva,
            edges=edges,
            call_path=call_path,
        )
        _anchor_witnesses, frame_anchors = self._stack_frame_anchors(
            frame_entries=frame_entries,
            frame_owners=frame_owners,
            rows=rows_by_rva,
            call_path=call_path,
        )

        identity = {
            register: all(
                self._region_preserves_register(row, register)
                for row in rows
            )
            for register in requested_registers
            if register != "esp"
        }
        needs_witness = tuple(
            register for register in requested_registers
            if register != "esp" and not identity[register]
        )
        root_frame_bytes, root_save_offsets, _ = self._entry_frame(
            entry, call_path
        )
        if needs_witness and root_frame_bytes == 0:
            raise self._failure(
                "requested_register_not_preserved",
                entry.rva,
                "a requested register is modified and the callee entry has no supported "
                "stack save",
                "preserve the register with a push/sub or fixed [esp+offset] frame save, "
                "or strengthen the checker with another exact witness",
                call_path,
            )
        return_ids = {row.rva for row in return_rows}
        tail_source_ids = {
            edge.source_region_id for edge in frame_tail_edges
        }
        frame_shapes: dict[
            int,
            tuple[int, dict[str, int], tuple[int, ...], dict[int, dict[str, int]]],
        ] = {}
        for frame_entry in frame_entries:
            frame_row = rows_by_rva[frame_entry]
            frame_bytes, save_offsets, _ = self._entry_frame(
                frame_row, call_path
            )
            exit_ids = tuple(sorted(
                rva
                for rva, owner in frame_owners.items()
                if owner == frame_entry
                and (rva in return_ids or rva in tail_source_ids)
            ))
            if not exit_ids:
                raise self._failure(
                    "tail_frame_has_no_exit",
                    frame_entry,
                    "a root or tail-entered frame has no exact return or tail handoff",
                    "recover the complete frame-local CFG",
                    call_path,
                )
            restore_offsets: dict[int, dict[str, int]] = {}
            for rva in exit_ids:
                signed_entry_offset = (
                    entry_offsets[rva]
                    if entry_offsets[rva] < 1 << 31
                    else entry_offsets[rva] - (1 << 32)
                )
                restore_offsets[rva] = (
                    self._return_frame(
                        rows_by_rva[rva],
                        signed_entry_offset,
                        frame_anchors.get(frame_entry),
                        call_path,
                    )
                    if rva in return_ids
                    else self._tail_frame(
                        rows_by_rva[rva],
                        signed_entry_offset,
                        frame_anchors.get(frame_entry),
                        call_path,
                    )
                )
            frame_shapes[frame_entry] = (
                frame_bytes,
                save_offsets,
                exit_ids,
                restore_offsets,
            )
        excluded_frame_regions = {
            *frame_entries,
            *return_ids,
            *tail_source_ids,
        }
        protected_write_region_ids = tuple(sorted(
            row.rva
            for row in rows
            if (
                row.rva not in excluded_frame_regions
                and row.rva not in dependency_sources
                and row.memory_writes
            )
        ))
        protected_machine_import_dependency_ids: list[int] = []
        for source in sorted(dependency_sources):
            control = controls[source]
            if control.kind != "machine_import" or control.boundary is None:
                continue
            signature = self.imports.signatures_by_id.get(
                control.boundary.signature_id
            )
            memory_effect = None if signature is None else signature.get(
                "memory_effect"
            )
            if memory_effect not in {"none", "readOnly"}:
                protected_machine_import_dependency_ids.append(
                    control.boundary.id
                )
        witnesses: list[LeanStackSaveRestoreWitness] = []
        for register in needs_witness:
            frames: list[LeanStackSaveRestoreFrameWitness] = []
            for frame_entry in frame_entries:
                (
                    frame_bytes,
                    save_offsets,
                    exit_ids,
                    restore_offsets,
                ) = frame_shapes[frame_entry]
                save_offset = save_offsets.get(register)
                if save_offset is None:
                    raise self._failure(
                        "requested_register_save_not_recovered",
                        frame_entry,
                        f"{register} is modified across a root or tail-entered frame "
                        "but has no exact entry-frame save",
                        "use a supported fixed stack save/restore frame or add a "
                        "checked identity-frame witness",
                        call_path,
                    )
                wrong = [
                    rva for rva, offsets in restore_offsets.items()
                    if offsets.get(register) != save_offset
                ]
                if wrong:
                    raise self._failure(
                        "requested_register_restore_incomplete",
                        wrong[0],
                        f"{register} is not restored from its frame-local entry save "
                        "at every return or tail handoff",
                        "recover all restore epilogues or select a register the call "
                        "preserves",
                        call_path,
                    )
                frames.append(LeanStackSaveRestoreFrameWitness(
                    save_region_id=frame_entry,
                    restore_region_ids=exit_ids,
                    original_frame_bytes=frame_bytes,
                    candidate_frame_bytes=frame_bytes,
                    original_save_offset=save_offset,
                    candidate_save_offset=save_offset,
                ))
            root_frame, *additional_frames = frames
            witnesses.append(LeanStackSaveRestoreWitness(
                register=register,
                save_region_id=root_frame.save_region_id,
                restore_region_ids=root_frame.restore_region_ids,
                original_frame_bytes=root_frame.original_frame_bytes,
                candidate_frame_bytes=root_frame.candidate_frame_bytes,
                original_save_offset=root_frame.original_save_offset,
                candidate_save_offset=root_frame.candidate_save_offset,
                additional_frames=tuple(additional_frames),
                protected_write_region_ids=protected_write_region_ids,
                protected_machine_import_dependency_ids=tuple(
                    protected_machine_import_dependency_ids
                ),
            ))
        return tuple(witnesses), root_frame_bytes

    def _entry_frame(
        self, row: _Row, call_path: tuple[int, ...]
    ) -> tuple[int, dict[str, int], dict[str, int]]:
        cached = self._entry_frame_cache.get(row.rva)
        if cached is not None:
            return cached
        frame = 0
        saves: dict[str, int] = {}
        anchors: dict[str, int] = {}
        for item in row.instructions:
            instruction = item.decoded
            operands = instruction.operands
            if any(
                instruction.group(group)
                for group in (
                    capstone.CS_GRP_CALL,
                    capstone.CS_GRP_JUMP,
                    capstone.CS_GRP_RET,
                )
            ):
                continue
            if instruction.mnemonic == "push" and len(operands) == 1:
                frame += 4
                if operands[0].type == X86_OP_REG:
                    saves.setdefault(
                        instruction.reg_name(operands[0].reg), frame
                    )
                continue
            if (
                instruction.mnemonic == "sub"
                and len(operands) == 2
                and _operand_register(instruction, operands[0]) == "esp"
                and operands[1].type == X86_OP_IMM
            ):
                amount = int(operands[1].imm) & 0xFFFFFFFF
                if amount == 0 or frame + amount >= 1 << 32:
                    raise self._failure(
                        "unsupported_stack_frame_adjustment",
                        item.rva,
                        "the entry stack subtraction is zero or overflows IA-32",
                        "use a positive fixed-size stack frame",
                        call_path,
                    )
                frame += amount
                continue
            if (
                instruction.mnemonic == "mov"
                and len(operands) == 2
                and operands[0].type == X86_OP_REG
                and _operand_register(instruction, operands[1]) == "esp"
            ):
                register = instruction.reg_name(operands[0].reg)
                if register != "esp":
                    anchors[register] = (-frame) % (1 << 32)
                continue
            if (
                instruction.mnemonic == "lea"
                and len(operands) == 2
                and operands[0].type == X86_OP_REG
                and operands[1].type == X86_OP_MEM
                and _memory_base(instruction, operands[1]) == "esp"
                and operands[1].mem.index == 0
            ):
                register = instruction.reg_name(operands[0].reg)
                if register != "esp":
                    anchors[register] = (
                        -frame + int(operands[1].mem.disp)
                    ) % (1 << 32)
                continue
            if (
                instruction.mnemonic == "mov"
                and len(operands) == 2
                and operands[0].type == X86_OP_MEM
                and operands[1].type == X86_OP_REG
                and _memory_base(instruction, operands[0]) == "esp"
                and operands[0].mem.index == 0
            ):
                offset = frame - int(operands[0].mem.disp)
                if 0 < offset <= frame and offset % 4 == 0:
                    saves.setdefault(
                        instruction.reg_name(operands[1].reg), offset
                    )
                continue
            for register in tuple(anchors):
                if self._instruction_writes_register(instruction, register):
                    del anchors[register]
            if self._instruction_writes_register(instruction, "esp"):
                raise self._failure(
                    "unsupported_stack_frame_instruction",
                    item.rva,
                    f"entry instruction {instruction.mnemonic} writes ESP outside the "
                    "supported push/sub frame grammar",
                    "use a fixed push/sub frame or add an exact Lean frame witness form",
                    call_path,
                )
        result = frame, saves, anchors
        self._entry_frame_cache[row.rva] = result
        return result

    def _return_frame(
        self,
        row: _Row,
        entry_offset: int,
        frame_anchor: tuple[str, int] | None,
        call_path: tuple[int, ...],
    ) -> dict[str, int]:
        offset = entry_offset
        restores: dict[str, int] = {}
        for item in row.instructions:
            instruction = item.decoded
            operands = instruction.operands
            if (
                instruction.mnemonic == "add"
                and len(operands) == 2
                and _operand_register(instruction, operands[0]) == "esp"
                and operands[1].type == X86_OP_IMM
            ):
                offset += int(operands[1].imm) & 0xFFFFFFFF
                continue
            if (
                instruction.mnemonic == "sub"
                and len(operands) == 2
                and _operand_register(instruction, operands[0]) == "esp"
                and operands[1].type == X86_OP_IMM
            ):
                offset -= int(operands[1].imm) & 0xFFFFFFFF
                continue
            if (
                instruction.mnemonic == "lea"
                and len(operands) == 2
                and _operand_register(instruction, operands[0]) == "esp"
                and operands[1].type == X86_OP_MEM
                and operands[1].mem.index == 0
                and frame_anchor is not None
                and _memory_base(instruction, operands[1]) == frame_anchor[0]
            ):
                anchor_offset = (
                    frame_anchor[1]
                    if frame_anchor[1] < 1 << 31
                    else frame_anchor[1] - (1 << 32)
                )
                offset = (
                    anchor_offset + int(operands[1].mem.disp)
                )
                continue
            if instruction.mnemonic == "pop" and len(operands) == 1:
                if operands[0].type == X86_OP_REG:
                    restores[instruction.reg_name(operands[0].reg)] = -offset
                offset += 4
                continue
            if (
                instruction.mnemonic == "mov"
                and len(operands) == 2
                and operands[0].type == X86_OP_REG
                and operands[1].type == X86_OP_MEM
                and _memory_base(instruction, operands[1]) == "esp"
                and operands[1].mem.index == 0
            ):
                restores[instruction.reg_name(operands[0].reg)] = (
                    -(offset + int(operands[1].mem.disp))
                )
                continue
            if instruction.group(capstone.CS_GRP_RET):
                if operands or offset != 0:
                    raise self._failure(
                        "unsupported_return_frame",
                        item.rva,
                        "the return does not use an exact add/pop/ret frame",
                        "normalize the epilogue to add/pop/ret or add a checked epilogue witness",
                        call_path,
                    )
                return restores
            if self._instruction_writes_register(instruction, "esp"):
                raise self._failure(
                    "unsupported_return_frame_instruction",
                    item.rva,
                    f"epilogue instruction {instruction.mnemonic} is outside the supported "
                    "add/pop/ret grammar",
                    "use add/pop/ret or add an exact Lean epilogue witness form",
                    call_path,
                )
        raise self._failure(
            "return_instruction_missing",
            row.rva,
            "a return inventory row did not contain an exact return instruction",
            "regenerate the state-machine region from the exact PE",
            call_path,
        )

    def _tail_frame(
        self,
        row: _Row,
        entry_offset: int,
        frame_anchor: tuple[str, int] | None,
        call_path: tuple[int, ...],
    ) -> dict[str, int]:
        offset = entry_offset
        restores: dict[str, int] = {}
        for item in row.instructions:
            instruction = item.decoded
            operands = instruction.operands
            if (
                instruction.mnemonic == "add"
                and len(operands) == 2
                and _operand_register(instruction, operands[0]) == "esp"
                and operands[1].type == X86_OP_IMM
            ):
                offset += int(operands[1].imm) & 0xFFFFFFFF
                continue
            if (
                instruction.mnemonic == "sub"
                and len(operands) == 2
                and _operand_register(instruction, operands[0]) == "esp"
                and operands[1].type == X86_OP_IMM
            ):
                offset -= int(operands[1].imm) & 0xFFFFFFFF
                continue
            if (
                instruction.mnemonic == "lea"
                and len(operands) == 2
                and _operand_register(instruction, operands[0]) == "esp"
                and operands[1].type == X86_OP_MEM
                and operands[1].mem.index == 0
                and frame_anchor is not None
                and _memory_base(instruction, operands[1]) == frame_anchor[0]
            ):
                anchor_offset = (
                    frame_anchor[1]
                    if frame_anchor[1] < 1 << 31
                    else frame_anchor[1] - (1 << 32)
                )
                offset = (
                    anchor_offset + int(operands[1].mem.disp)
                )
                continue
            if instruction.mnemonic == "pop" and len(operands) == 1:
                if operands[0].type == X86_OP_REG:
                    restores[instruction.reg_name(operands[0].reg)] = -offset
                offset += 4
                continue
            if (
                instruction.mnemonic == "mov"
                and len(operands) == 2
                and operands[0].type == X86_OP_REG
                and operands[1].type == X86_OP_MEM
                and _memory_base(instruction, operands[1]) == "esp"
                and operands[1].mem.index == 0
            ):
                restores[instruction.reg_name(operands[0].reg)] = (
                    -(offset + int(operands[1].mem.disp))
                )
                continue
            if (
                instruction.mnemonic == "jmp"
                and instruction.group(capstone.CS_GRP_JUMP)
                and _direct_target(instruction, self.image_base) is not None
            ):
                if offset != 0:
                    raise self._failure(
                        "unsupported_tail_frame",
                        item.rva,
                        "the direct tail handoff does not restore the incoming ESP",
                        "normalize the tail epilogue or add an exact frame-replacement "
                        "witness",
                        call_path,
                    )
                return restores
            if self._instruction_writes_register(instruction, "esp"):
                raise self._failure(
                    "unsupported_tail_frame_instruction",
                    item.rva,
                    f"tail epilogue instruction {instruction.mnemonic} is outside the "
                    "supported add/pop/jmp grammar",
                    "use add/pop/jmp or add an exact frame-replacement witness",
                    call_path,
                )
        raise self._failure(
            "tail_instruction_missing",
            row.rva,
            "a direct-tail frame exit did not contain an exact direct jump",
            "regenerate the state-machine region from the exact PE",
            call_path,
        )

    def _check_machine_contract(
        self,
        boundary: _Boundary,
        requested_registers: tuple[str, ...],
        call_path: tuple[int, ...],
    ) -> None:
        signature = self.imports.signatures_by_id.get(boundary.signature_id)
        if signature is None:
            raise self._failure(
                "machine_import_signature_missing",
                boundary.instruction_rva,
                "the exact boundary references an absent machine-import signature",
                "regenerate the exact static machine-import contract report",
                call_path,
            )
        if signature.get("disposition") != "returns":
            raise self._failure(
                "machine_import_not_ordinary_returning",
                boundary.instruction_rva,
                "the machine-import contract is nonreturning or protocol-valued",
                "use a checked external protocol dependency instead of a register summary",
                call_path,
            )
        abi = signature.get("abi")
        argument_words = boundary.payload.get("argument_words")
        if not isinstance(argument_words, int) or argument_words < 0:
            raise self._failure(
                "machine_import_argument_inventory_invalid",
                boundary.instruction_rva,
                "the exact boundary has no finite argument-word inventory",
                "recover exact callsite arguments and regenerate the report",
                call_path,
            )
        if abi not in {"cdecl", "stdcall"}:
            raise self._failure(
                "machine_import_stack_delta_not_supported",
                boundary.instruction_rva,
                "the standalone checker requires a cdecl or stdcall boundary",
                "recover a checked cdecl/stdcall machine-call boundary",
                call_path,
            )
        preserved = {"ebp", "ebx", "edi", "esi"}
        missing = sorted(
            register for register in requested_registers
            if register != "esp" and register not in preserved
        )
        if missing:
            raise self._failure(
                "machine_import_clobbers_requested_register",
                boundary.instruction_rva,
                f"the ABI does not preserve requested registers {missing}",
                "choose preserved registers or add a checked save/restore frame around the call",
                call_path,
            )

    def _check_machine_terminal_contract(
        self,
        boundary: _Boundary,
        call_path: tuple[int, ...],
    ) -> None:
        signature = self.imports.signatures_by_id.get(boundary.signature_id)
        if signature is None:
            raise self._failure(
                "machine_import_signature_missing",
                boundary.instruction_rva,
                "the exact terminal boundary references an absent signature",
                "regenerate the exact static machine-import contract report",
                call_path,
            )
        if signature.get("disposition") != "terminates":
            raise self._failure(
                "machine_import_terminal_disposition_mismatch",
                boundary.instruction_rva,
                "the proposed terminal import is not declared terminating",
                "use an ordinary returning or protocol dependency",
                call_path,
            )

    def _check_machine_tail_contract(
        self,
        tail: _ImportTail,
        requested_registers: tuple[str, ...],
        call_path: tuple[int, ...],
    ) -> None:
        signature = self.imports.signatures_by_id.get(tail.signature_id)
        if signature is None:
            raise self._failure(
                "machine_import_signature_missing",
                tail.source_rva,
                "the exact external tail references an absent machine-import signature",
                "regenerate the exact static machine-import contract report",
                call_path,
            )
        if signature.get("disposition") != "returns":
            raise self._failure(
                "machine_import_tail_not_returning",
                tail.source_rva,
                "the external tail contract does not return through the live call frame",
                "use a checked nonreturning or protocol terminal instead",
                call_path,
            )
        arity = signature.get("arity")
        if not isinstance(arity, Mapping):
            raise self._failure(
                "machine_import_argument_inventory_invalid",
                tail.source_rva,
                "the external tail signature has no finite arity",
                "recover exact machine-level argument words",
                call_path,
            )
        kind = arity.get("kind")
        words = arity.get("words")
        minimum = arity.get("minimum_words")
        accepted = (
            kind == "fixed"
            and isinstance(words, int)
            and not isinstance(words, bool)
            and words == tail.argument_words
        ) or (
            kind == "variadic"
            and isinstance(minimum, int)
            and not isinstance(minimum, bool)
            and minimum <= tail.argument_words
        )
        if not accepted:
            raise self._failure(
                "machine_import_argument_inventory_invalid",
                tail.source_rva,
                "the external tail argument inventory does not satisfy its signature",
                "regenerate exact callsite argument evidence",
                call_path,
            )
        abi = signature.get("abi")
        if abi not in {"cdecl", "stdcall"}:
            raise self._failure(
                "machine_import_stack_delta_not_supported",
                tail.source_rva,
                "the standalone checker requires a cdecl or stdcall external tail",
                "recover a checked cdecl/stdcall machine-call boundary",
                call_path,
            )
        preserved = {"ebp", "ebx", "edi", "esi"}
        missing = sorted(
            register for register in requested_registers
            if register != "esp" and register not in preserved
        )
        if missing:
            raise self._failure(
                "machine_import_clobbers_requested_register",
                tail.source_rva,
                f"the ABI does not preserve requested registers {missing}",
                "restore volatile values before the tail or request a proven result relation",
                call_path,
            )

    def _machine_dependency(
        self, boundary: _Boundary, source_rva: int, continuation_rva: int
    ) -> LeanMachineImportDependency:
        local_boundary = (
            f"{_SUMMARY_NAMESPACE}.generatedSummaryMachineImportBoundary{boundary.id}"
        )
        required = f"{_SUMMARY_NAMESPACE}.generatedSummaryMachineImportRequired"
        signatures = (
            f"{_SUMMARY_NAMESPACE}.generatedSummaryMachineImportSignatures"
        )
        return LeanMachineImportDependency(
            dependency_id=boundary.id,
            source_region_id=source_rva,
            continuation_region_id=continuation_rva,
            original_required=required,
            candidate_required=required,
            original_signatures=signatures,
            candidate_signatures=signatures,
            original_boundary=local_boundary,
            candidate_boundary=local_boundary,
        )

    def _machine_tail_dependency(
        self, tail: _ImportTail, source_rva: int
    ) -> LeanMachineImportTailDependency:
        required = f"{_SUMMARY_NAMESPACE}.generatedSummaryMachineImportRequired"
        signatures = (
            f"{_SUMMARY_NAMESPACE}.generatedSummaryMachineImportSignatures"
        )
        return LeanMachineImportTailDependency(
            dependency_id=tail.id,
            source_region_id=source_rva,
            signature_id=tail.signature_id,
            argument_words=tail.argument_words,
            original_required=required,
            candidate_required=required,
            original_signatures=signatures,
            candidate_signatures=signatures,
        )

    def _machine_terminal_dependency(
        self, boundary: _Boundary, source_rva: int
    ) -> LeanMachineImportTerminalDependency:
        local_boundary = (
            f"{_SUMMARY_NAMESPACE}.generatedSummaryMachineImportBoundary{boundary.id}"
        )
        required = f"{_SUMMARY_NAMESPACE}.generatedSummaryMachineImportRequired"
        signatures = (
            f"{_SUMMARY_NAMESPACE}.generatedSummaryMachineImportSignatures"
        )
        return LeanMachineImportTerminalDependency(
            dependency_id=boundary.id,
            source_region_id=source_rva,
            original_required=required,
            candidate_required=required,
            original_signatures=signatures,
            candidate_signatures=signatures,
            original_boundary=local_boundary,
            candidate_boundary=local_boundary,
        )

    def _control(self, row: _Row, call_path: tuple[int, ...]) -> _Control:
        terminal = row.instructions[-1]
        instruction = terminal.decoded
        boundaries = self.imports.boundaries_by_instruction.get(terminal.rva, ())
        if len(boundaries) > 1:
            raise self._failure(
                "ambiguous_machine_import_boundary",
                terminal.rva,
                f"{len(boundaries)} machine-import boundaries select one instruction",
                "regenerate a unique exact boundary inventory",
                call_path,
            )
        boundary = boundaries[0] if boundaries else None
        import_tails = self.imports.tails_by_execution_rva.get(row.rva, ())
        if len(import_tails) > 1:
            raise self._failure(
                "ambiguous_machine_import_tail",
                terminal.rva,
                f"{len(import_tails)} incompatible machine-import tails select "
                "one execution span",
                "make the import identity and machine-level arity unique",
                call_path,
            )
        import_tail = import_tails[0] if import_tails else None
        if import_tail is not None:
            if import_tail.source_size != row.size:
                raise self._failure(
                    "machine_import_tail_span_mismatch",
                    row.rva,
                    "the external-tail contract does not select the exact "
                    "state-machine execution span",
                    "regenerate exact static machine-import boundaries",
                    call_path,
                )
            if not instruction.group(capstone.CS_GRP_JUMP):
                raise self._failure(
                    "machine_import_tail_control_mismatch",
                    terminal.rva,
                    "an external-tail execution span does not end in a jump",
                    "regenerate exact static machine-import boundaries",
                    call_path,
                )
            return _Control(
                "machine_import_tail",
                terminal.rva,
                import_tail=import_tail,
            )
        if instruction.group(capstone.CS_GRP_RET):
            return _Control("return", terminal.rva)
        if instruction.group(capstone.CS_GRP_CALL):
            if boundary is not None:
                if (
                    boundary.source_rva != row.rva
                    or boundary.source_size != row.size
                    or boundary.continuation_rva != row.end
                ):
                    raise self._failure(
                        "machine_import_boundary_span_mismatch",
                        terminal.rva,
                        f"the {boundary.route!r} machine-import boundary does not "
                        "select the exact state-machine source span and continuation",
                        "regenerate exact static machine-import boundaries for this PE",
                        call_path,
                    )
                return _Control(
                    "machine_import",
                    terminal.rva,
                    (boundary.continuation_rva,),
                    boundary,
                )
            target = _direct_target(instruction, self.image_base)
            if target is None:
                return _Control("unresolved_indirect_call", terminal.rva)
            if any(
                event.get("kind") == "external_call" or "dll" in event
                for event in row.external_events
            ):
                return _Control("uncontracted_external_call", terminal.rva)
            matching_events = [
                event for event in row.external_events
                if event.get("kind") == "internal_call"
                and event.get("target_rva") == target
                and event.get("return_rva") == row.end
            ]
            if len(matching_events) != 1 and not row.synthetic:
                raise self._failure(
                    "internal_call_state_machine_event_mismatch",
                    terminal.rva,
                    "the exact direct call has no unique matching state-machine "
                    "internal-call event",
                    "regenerate the Stage A state machine from the exact PE",
                    call_path,
                )
            return _Control("internal_call", terminal.rva, (target, row.end))
        if instruction.group(capstone.CS_GRP_JUMP):
            target = _direct_target(instruction, self.image_base)
            if target is None:
                return _Control("unresolved_indirect_jump", terminal.rva)
            if instruction.mnemonic == "jmp":
                return _Control("direct", terminal.rva, (target,))
            return _Control("branch", terminal.rva, (target, row.end))
        if any(
            instruction.group(group)
            for group in (capstone.CS_GRP_INT, capstone.CS_GRP_IRET)
        ):
            return _Control("unsupported_exception_control", terminal.rva)
        return _Control("direct", terminal.rva, (row.end,))

    def _resolve_callsite(
        self, requested_rva: int, call_path: tuple[int, ...]
    ) -> _Row:
        matches = [
            row for row in self.rows
            if row.instructions[-1].rva == requested_rva or row.rva == requested_rva
        ]
        matches = [
            row for row in matches
            if row.instructions[-1].decoded.group(capstone.CS_GRP_CALL)
        ]
        if len(matches) != 1:
            raise self._failure(
                "callsite_missing_or_ambiguous",
                requested_rva,
                f"the requested RVA selects {len(matches)} terminal call regions",
                "use the exact terminal call instruction RVA",
                call_path,
            )
        return matches[0]

    def _row_at(
        self,
        rva: int,
        *,
        category: str,
        action: str,
        call_path: tuple[int, ...],
    ) -> _Row:
        row = self.by_start.get(rva)
        if row is None:
            raise self._failure(
                category,
                rva,
                "no state-machine region starts at the exact decoded target",
                action,
                call_path,
            )
        return row

    def _known_call_targets(self) -> frozenset[int]:
        targets: set[int] = set()
        for row in self.rows:
            terminal = row.instructions[-1].decoded
            if terminal.group(capstone.CS_GRP_CALL):
                target = _direct_target(terminal, self.image_base)
                if target is not None:
                    targets.add(target)
        return frozenset(targets)

    def _region_preserves_register(self, row: _Row, register: str) -> bool:
        return all(
            not self._instruction_writes_register(item.decoded, register)
            for item in row.instructions
        )

    @staticmethod
    def _instruction_writes_register(
        instruction: capstone.CsInsn, register: str
    ) -> bool:
        try:
            _reads, writes = instruction.regs_access()
        except capstone.CsError as error:
            raise InternalDirectCallSummaryProposalError(
                f"Capstone register-access recovery failed at 0x{instruction.address:x}: {error}"
            ) from error
        return any(instruction.reg_name(reg) == register for reg in writes)

    def _writes_esp(self, row: _Row) -> bool:
        return any(
            self._instruction_writes_register(item.decoded, "esp")
            for item in row.instructions
        )

    @staticmethod
    def _failure(
        category: str,
        location_rva: int,
        detail: str,
        next_action: str,
        call_path: Sequence[int],
    ) -> _PlanningFailure:
        return _PlanningFailure(
            category, location_rva, detail, next_action, call_path
        )

    def _collect_tree(
        self,
        tree: LeanInternalDirectCallRegisterSummaryTree,
        region_rvas: set[int],
        nested_sites: set[int],
        boundary_ids: set[int],
        tail_signature_ids: set[int],
    ) -> None:
        certificate = tree.certificate
        region_rvas.update(region.original.start for region in certificate.callee_regions)
        nested_sites.update(
            dependency.call_region_id
            for dependency in certificate.nested_dependencies
        )
        boundary_ids.update(
            dependency.dependency_id
            for dependency in certificate.machine_import_dependencies
        )
        boundary_ids.update(
            dependency.dependency_id
            for dependency in certificate.machine_import_terminal_dependencies
        )
        tail_signature_ids.update(
            dependency.signature_id
            for dependency in certificate.machine_import_tail_dependencies
        )
        for child in tree.nested:
            self._collect_tree(
                child,
                region_rvas,
                nested_sites,
                boundary_ids,
                tail_signature_ids,
            )


def discover_internal_direct_call_sites(
    original_pe: Path | str,
    state_machine: Path | str,
    machine_import_report: Path | str,
) -> tuple[int, ...]:
    """Return exact terminal internal direct-call instruction RVAs as hints."""
    pe_path = Path(original_pe)
    state_path = Path(state_machine)
    report_path = Path(machine_import_report)
    report, imports = _load_import_report(pe_path, state_path, report_path)
    del report
    pe = _open_pe(pe_path)
    try:
        rows = _load_rows(pe, state_path)
        planner = _Planner(
            pe=pe,
            image_base=int(pe.OPTIONAL_HEADER.ImageBase),
            rows=rows,
            imports=imports,
        )
        result = []
        for row in planner.rows:
            control = planner._control(row, ())
            if control.kind == "internal_call":
                result.append(control.instruction_rva)
        return tuple(sorted(result))
    finally:
        pe.close()


def construct_internal_direct_call_summary_proposals(
    original_pe: Path | str,
    state_machine: Path | str,
    machine_import_report: Path | str,
    requests: Iterable[DirectCallSummaryRequest],
    *,
    finite_origin_entry_requests: Iterable[DirectCallSummaryRequest] = (),
    finite_origin_call_authorities: Iterable[
        FiniteOriginCallAuthorityBinding
    ] = (),
    finite_origin_tail_authorities: Iterable[
        FiniteOriginTailAuthorityBinding
    ] = (),
) -> InternalDirectCallSummaryProposalPlan:
    """Build self-paired proposals and actionable blockers for requested calls."""
    pe_path = Path(original_pe)
    state_path = Path(state_machine)
    report_path = Path(machine_import_report)
    checked_requests = tuple(sorted(
        (request.checked() for request in requests),
        key=lambda item: (
            item.callsite_rva,
            -1 if item.caller_rva is None else item.caller_rva,
            _ordered_registers(item.registers),
            item.caller_frame_word_offsets,
        ),
    ))
    checked_finite_entry_requests = tuple(sorted(
        (request.checked() for request in finite_origin_entry_requests),
        key=lambda item: (
            item.callsite_rva,
            -1 if item.caller_rva is None else item.caller_rva,
            _ordered_registers(item.registers),
            item.caller_frame_word_offsets,
        ),
    ))
    if not checked_requests and not checked_finite_entry_requests:
        raise InternalDirectCallSummaryProposalError(
            "at least one internal-call summary request is required"
        )
    _report, imports = _load_import_report(pe_path, state_path, report_path)
    checked_tail_authorities = tuple(finite_origin_tail_authorities)
    checked_call_authorities = tuple(finite_origin_call_authorities)
    pe = _open_pe(pe_path)
    try:
        rows = _load_rows(pe, state_path)
        planner = _Planner(
            pe=pe,
            image_base=int(pe.OPTIONAL_HEADER.ImageBase),
            rows=rows,
            imports=imports,
            finite_origin_call_authorities=checked_call_authorities,
            finite_origin_tail_authorities=checked_tail_authorities,
        )
        proposals: list[InternalDirectCallSummaryProposal] = []
        blockers: list[ProposalBlocker] = []
        for request in checked_requests:
            try:
                proposals.append(planner.proposal(request))
            except _PlanningFailure as failure:
                blockers.append(ProposalBlocker(
                    request=request,
                    category=failure.category,
                    location_rva=failure.location_rva,
                    detail=failure.detail,
                    next_action=failure.next_action,
                    call_path=failure.call_path,
                ))
        for request in checked_finite_entry_requests:
            try:
                proposals.append(planner.finite_origin_call_proposal(request))
            except _PlanningFailure as failure:
                blockers.append(ProposalBlocker(
                    request=request,
                    category=failure.category,
                    location_rva=failure.location_rva,
                    detail=failure.detail,
                    next_action=failure.next_action,
                    call_path=failure.call_path,
                ))
        return InternalDirectCallSummaryProposalPlan(
            original_pe_sha256=_sha256(pe_path),
            state_machine_sha256=_sha256(state_path),
            machine_import_report_sha256=_sha256(report_path),
            proposals=tuple(proposals),
            blockers=tuple(blockers),
        )
    finally:
        pe.close()


def construct_finite_direct_call_evidence_proposal(
    original_pe: Path | str,
    state_machine: Path | str,
    machine_import_report: Path | str,
    request: FiniteDirectCallEvidenceRequest,
) -> FiniteDirectCallEvidencePlan:
    """Recover an exact acyclic internal-call path and copy witness proposal.

    This is deliberately narrower than the semantic checker.  In particular,
    nested calls and external macro-steps are not flattened into an alleged
    return.  The caller must provide a separate Lean-checked `WorldExecution`
    certificate for those forms.
    """

    request = request.checked()
    pe_path = Path(original_pe)
    state_path = Path(state_machine)
    report_path = Path(machine_import_report)
    _report, imports = _load_import_report(pe_path, state_path, report_path)
    pe = _open_pe(pe_path)
    blockers: list[FiniteDirectCallEvidenceBlocker] = []

    def block(category: str, rva: int, detail: str, action: str) -> None:
        blockers.append(FiniteDirectCallEvidenceBlocker(category, rva, detail, action))

    try:
        rows = _load_rows(pe, state_path)
        planner = _Planner(
            pe=pe,
            image_base=int(pe.OPTIONAL_HEADER.ImageBase),
            rows=rows,
            imports=imports,
        )
        try:
            call_row = planner._resolve_callsite(request.callsite_rva, ())
        except _PlanningFailure as failure:
            block(
                failure.category,
                failure.location_rva,
                failure.detail,
                failure.next_action,
            )
            call_row = None

        if call_row is not None and call_row.rva != request.caller_rva:
            block(
                "caller_region_mismatch",
                call_row.rva,
                f"the terminal call belongs to region 0x{call_row.rva:x}, not "
                f"the requested 0x{request.caller_rva:x}",
                "select the exact state-machine region containing the terminal call",
            )

        control: _Control | None = None
        if call_row is not None:
            boundaries = imports.boundaries_by_instruction.get(request.callsite_rva, ())
            if boundaries:
                routes = sorted({boundary.route for boundary in boundaries})
                block(
                    "external_or_nested_world_execution_required",
                    request.callsite_rva,
                    "the call is part of checked machine-import route(s) "
                    f"{routes}; an internal FiniteReturningExecution cannot skip "
                    "the external transition",
                    "compose a checked external WorldExecution macro-step and prove its "
                    "memory/world footprint preserves the static slot",
                )
            else:
                try:
                    control = planner._control(call_row, ())
                except _PlanningFailure as failure:
                    block(
                        failure.category,
                        failure.location_rva,
                        failure.detail,
                        failure.next_action,
                    )
                if control is not None and control.kind != "internal_call":
                    block(
                        "requested_site_is_not_finite_internal_call",
                        control.instruction_rva,
                        f"decoded control kind is {control.kind!r}",
                        "select a terminal relative internal call with no external boundary",
                    )

        image_base = int(pe.OPTIONAL_HEADER.ImageBase)
        _validate_finite_evidence_addresses(pe, request, block)
        if call_row is not None:
            expected_word = image_base + request.argument_code_target_rva
            caller_writes = [
                event
                for event in call_row.memory_events
                if event.get("kind") == "write"
                and _expr_is_stack_offset(
                    event.get("address"), request.caller_argument_offset
                )
                and _expr_constant(event.get("value")) == expected_word
                and event.get("width") == 4
            ]
            if len(caller_writes) != 1:
                block(
                    "caller_frame_argument_not_unique",
                    request.caller_rva,
                    "the caller does not contain exactly one checked four-byte write of "
                    f"0x{expected_word:x} to [esp+{request.caller_argument_offset}]",
                    "recover an exact caller stack-write event before constructing the "
                    "runtime-frame argument witness",
                )

        proposal: FiniteDirectCallEvidenceProposal | None = None
        if (
            call_row is not None
            and control is not None
            and control.kind == "internal_call"
        ):
            if len(control.targets) != 2:
                block(
                    "ambiguous_direct_call_target",
                    request.callsite_rva,
                    "the direct call does not have one callee and one continuation",
                    "regenerate exact decoded control",
                )
            else:
                callee_rva, continuation_rva = control.targets
                graph = _finite_internal_call_graph(planner, callee_rva, block)
                if graph is not None:
                    path_rows, edges, returns, ranks = graph
                    slot_va = image_base + request.static_slot_rva
                    copies = [
                        (row.rva, event)
                        for row in path_rows
                        for event in row.memory_events
                        if event.get("kind") == "write"
                        and _expr_constant(event.get("address")) == slot_va
                        and event.get("width") == 4
                        and _expr_is_load_from_stack_offset(
                            event.get("value"), request.callee_argument_offset
                        )
                    ]
                    if len(copies) != 1:
                        block(
                            "frame_argument_static_write_not_unique",
                            callee_rva,
                            "the finite callee does not contain exactly one checked copy "
                            f"from [esp+{request.callee_argument_offset}] to static slot "
                            f"RVA 0x{request.static_slot_rva:x}",
                            "recover the exact stack-load/static-write path or select the "
                            "correct writable slot",
                        )
                    if not blockers:
                        proposal = FiniteDirectCallEvidenceProposal(
                            source_rva=call_row.rva,
                            source_size=call_row.size,
                            callsite_rva=request.callsite_rva,
                            call_instruction_size=call_row.instructions[-1].size,
                            callee_rva=callee_rva,
                            continuation_rva=continuation_rva,
                            argument_code_target_rva=request.argument_code_target_rva,
                            static_slot_rva=request.static_slot_rva,
                            caller_argument_offset=request.caller_argument_offset,
                            callee_argument_offset=request.callee_argument_offset,
                            ranks=tuple(
                                FiniteDirectCallRegionRank(rva, ranks[rva])
                                for rva in sorted(ranks)
                            ),
                            edges=tuple(edges),
                            return_rvas=tuple(sorted(returns)),
                        )
        blockers.sort(key=lambda item: (item.location_rva, item.category, item.detail))
        return FiniteDirectCallEvidencePlan(
            original_pe_sha256=_sha256(pe_path),
            state_machine_sha256=_sha256(state_path),
            machine_import_report_sha256=_sha256(report_path),
            request=request,
            proposal=proposal,
            blockers=tuple(blockers),
        )
    finally:
        pe.close()


def _validate_finite_evidence_addresses(
    pe: pefile.PE,
    request: FiniteDirectCallEvidenceRequest,
    block,
) -> None:
    for rva, category, description in (
        (
            request.argument_code_target_rva,
            "argument_code_target_not_executable",
            "argument code target",
        ),
        (request.static_slot_rva, "static_slot_not_writable", "static slot"),
    ):
        section = pe.get_section_by_rva(rva)
        if section is None:
            block(
                category,
                rva,
                f"the {description} is outside every PE section",
                "select an in-image target bound to the exact PE",
            )
            continue
        characteristics = int(section.Characteristics)
        if description == "argument code target":
            if characteristics & 0x20000000 == 0:
                block(
                    category,
                    rva,
                    "the argument target is not in an executable section",
                    "select a canonical executable code target",
                )
        elif characteristics & 0x80000000 == 0:
            block(
                category,
                rva,
                "the static slot is not in a writable section",
                "select a checked writable four-byte slot",
            )


def _finite_internal_call_graph(
    planner: _Planner,
    callee_rva: int,
    block,
) -> (
    tuple[
        tuple[_Row, ...],
        tuple[FiniteDirectCallEdge, ...],
        frozenset[int],
        dict[int, int],
    ]
    | None
):
    pending = [callee_rva]
    rows: dict[int, _Row] = {}
    edges: list[FiniteDirectCallEdge] = []
    returns: set[int] = set()
    while pending:
        rva = pending.pop()
        if rva in rows:
            continue
        row = planner.by_start.get(rva)
        if row is None:
            block(
                "missing_finite_call_edge_target",
                rva,
                "no exact state-machine region starts at a decoded callee target",
                "regenerate the state machine with complete finite callee coverage",
            )
            return None
        rows[rva] = row
        try:
            control = planner._control(row, (callee_rva,))
        except _PlanningFailure as failure:
            block(
                failure.category,
                failure.location_rva,
                failure.detail,
                failure.next_action,
            )
            return None
        if control.kind == "return":
            returns.add(rva)
            continue
        if control.kind not in {"direct", "branch"}:
            block(
                "unsupported_world_execution_step",
                control.instruction_rva,
                f"finite direct-call path contains {control.kind!r}",
                "supply a separately checked nested/external WorldExecution macro-step",
            )
            return None
        kind_rows = (
            ((control.targets[0], "direct"),)
            if control.kind == "direct"
            else (
                (control.targets[0], "branch_taken"),
                (control.targets[1], "branch_fallthrough"),
            )
        )
        for target, kind in kind_rows:
            edges.append(FiniteDirectCallEdge(rva, target, kind))
            pending.append(target)

    adjacency: dict[int, list[int]] = {rva: [] for rva in rows}
    for edge in edges:
        if edge.target_rva not in rows:
            block(
                "missing_finite_call_edge_target",
                edge.target_rva,
                "a submitted direct edge does not have an exact decoded target row",
                "regenerate the complete callee graph",
            )
            return None
        adjacency[edge.source_rva].append(edge.target_rva)
    ranks: dict[int, int] = {}
    visiting: set[int] = set()

    def rank(rva: int) -> int | None:
        if rva in ranks:
            return ranks[rva]
        if rva in visiting:
            block(
                "non_decreasing_scc_requires_checked_ranking",
                rva,
                "the finite call proposal contains a cycle with no state-sensitive "
                "decreasing rank",
                "provide a Lean-checked SCC ranking or keep the call incomplete",
            )
            return None
        visiting.add(rva)
        targets = adjacency[rva]
        if not targets:
            if rva not in returns:
                block(
                    "finite_call_path_has_no_return",
                    rva,
                    "a reachable callee leaf is not a decoded return",
                    "recover a return or a supported terminal macro-step",
                )
                visiting.remove(rva)
                return None
            value = 0
        else:
            child_ranks = [rank(target) for target in targets]
            if any(value is None for value in child_ranks):
                visiting.remove(rva)
                return None
            value = 1 + max(value for value in child_ranks if value is not None)
        visiting.remove(rva)
        ranks[rva] = value
        return value

    if rank(callee_rva) is None:
        return None
    return (
        tuple(rows[rva] for rva in sorted(rows)),
        tuple(
            sorted(
                edges, key=lambda edge: (edge.source_rva, edge.kind, edge.target_rva)
            )
        ),
        frozenset(returns),
        ranks,
    )


def _expr_constant(value: object) -> int | None:
    if not isinstance(value, Mapping) or value.get("op") != "const":
        return None
    result = value.get("value")
    return result if isinstance(result, int) and not isinstance(result, bool) else None


def _expr_is_stack_offset(value: object, offset: int) -> bool:
    if not isinstance(value, Mapping):
        return False
    if offset == 0:
        return value.get("op") == "reg" and value.get("name") == "esp"
    if value.get("op") != "add32" or not isinstance(value.get("args"), list):
        return False
    arguments = value["args"]
    if len(arguments) != 2:
        return False
    return any(
        isinstance(argument, Mapping)
        and argument.get("op") == "reg"
        and argument.get("name") == "esp"
        for argument in arguments
    ) and any(_expr_constant(argument) == offset for argument in arguments)


def _expr_is_load_from_stack_offset(value: object, offset: int) -> bool:
    return (
        isinstance(value, Mapping)
        and value.get("op") == "load"
        and value.get("width") == 4
        and _expr_is_stack_offset(value.get("address"), offset)
    )


def write_internal_direct_call_summary_proposals(
    out: Path | str,
    plan: InternalDirectCallSummaryProposalPlan,
    bindings: InternalDirectCallSummarySourceBindings | None = None,
) -> tuple[Path, tuple[Path, ...]]:
    """Write deterministic proposal JSON and optional Lean source modules."""
    root = Path(out)
    root.mkdir(parents=True, exist_ok=True)
    report = root / "internal-direct-call-summary-proposals.json"
    report.write_text(
        json.dumps(plan.to_json(), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    sources: list[Path] = []
    if bindings is not None:
        for index, proposal in enumerate(plan.proposals):
            destination = (
                root
                / f"summary-{proposal.request.callsite_rva:08x}"
                / "StageA"
                / "GeneratedRelationalInternalDirectCallRegisterSummary.lean"
            )
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_text(plan.source(index, bindings), encoding="utf-8")
            sources.append(destination)
    return report, tuple(sources)


def _load_rows(pe: pefile.PE, path: Path) -> tuple[_Row, ...]:
    decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    decoder.detail = True
    rows: list[_Row] = []
    starts: set[int] = set()
    try:
        source = path.open(encoding="utf-8")
    except OSError as error:
        raise InternalDirectCallSummaryProposalError(
            f"cannot read state machine {path}: {error}"
        ) from error
    with source:
        for line_number, line in enumerate(source, 1):
            try:
                value = json.loads(line)
            except json.JSONDecodeError as error:
                raise InternalDirectCallSummaryProposalError(
                    f"invalid state-machine JSON on line {line_number}: {error}"
                ) from error
            if not isinstance(value, Mapping) or not isinstance(
                value.get("original"), Mapping
            ):
                raise InternalDirectCallSummaryProposalError(
                    f"state-machine line {line_number} has no original span"
                )
            original = value["original"]
            rva = original.get("rva_start")
            end = original.get("rva_end")
            size = original.get("size")
            if not all(isinstance(item, int) for item in (rva, end, size)):
                raise InternalDirectCallSummaryProposalError(
                    f"state-machine line {line_number} has a non-integer span"
                )
            assert isinstance(rva, int) and isinstance(end, int) and isinstance(size, int)
            if size <= 0 or rva + size != end or rva in starts:
                raise InternalDirectCallSummaryProposalError(
                    f"state-machine line {line_number} has an invalid or duplicate span"
                )
            starts.add(rva)
            raw_instructions = value.get("instructions")
            if not isinstance(raw_instructions, list) or not raw_instructions:
                raise InternalDirectCallSummaryProposalError(
                    f"state-machine line {line_number} has no instruction inventory"
                )
            instructions: list[_Instruction] = []
            cursor = rva
            for index, item in enumerate(raw_instructions):
                if not isinstance(item, Mapping):
                    raise InternalDirectCallSummaryProposalError(
                        f"state-machine line {line_number} instruction {index} is not an object"
                    )
                instruction_rva = item.get("rva")
                instruction_size = item.get("size")
                raw_hex = item.get("bytes")
                if (
                    not isinstance(instruction_rva, int)
                    or not isinstance(instruction_size, int)
                    or not isinstance(raw_hex, str)
                    or instruction_rva != cursor
                    or instruction_size <= 0
                ):
                    raise InternalDirectCallSummaryProposalError(
                        f"state-machine line {line_number} has a non-contiguous instruction inventory"
                    )
                try:
                    proposed = bytes.fromhex(raw_hex)
                except ValueError as error:
                    raise InternalDirectCallSummaryProposalError(
                        f"state-machine line {line_number} instruction {index} has invalid bytes"
                    ) from error
                exact = bytes(pe.get_data(instruction_rva, instruction_size))
                if len(proposed) != instruction_size or proposed != exact:
                    raise InternalDirectCallSummaryProposalError(
                        f"state-machine instruction at 0x{instruction_rva:x} does not match the PE"
                    )
                decoded = list(decoder.disasm(
                    exact,
                    int(pe.OPTIONAL_HEADER.ImageBase) + instruction_rva,
                    count=1,
                ))
                if len(decoded) != 1 or decoded[0].size != instruction_size:
                    raise InternalDirectCallSummaryProposalError(
                        f"state-machine instruction at 0x{instruction_rva:x} does not decode exactly"
                    )
                instructions.append(_Instruction(
                    instruction_rva, instruction_size, exact, decoded[0]
                ))
                cursor += instruction_size
            if cursor != end:
                raise InternalDirectCallSummaryProposalError(
                    f"state-machine line {line_number} instructions do not cover its exact span"
                )
            memory_events = value.get("memory_events")
            if not isinstance(memory_events, list):
                raise InternalDirectCallSummaryProposalError(
                    f"state-machine line {line_number} memory_events is not a list"
                )
            memory_writes = sum(
                1 for event in memory_events
                if isinstance(event, Mapping) and event.get("kind") == "write"
            )
            external_events = value.get("external_events")
            if not isinstance(external_events, list) or not all(
                isinstance(event, Mapping) for event in external_events
            ):
                raise InternalDirectCallSummaryProposalError(
                    f"state-machine line {line_number} external_events is not an object list"
                )
            function = value.get("function")
            outcome = value.get("outcome")
            if outcome is not None and not isinstance(outcome, Mapping):
                raise InternalDirectCallSummaryProposalError(
                    f"state-machine line {line_number} outcome is not an object"
                )
            rows.append(_Row(
                rva=rva,
                end=end,
                size=size,
                function=function if isinstance(function, str) and function else None,
                instructions=tuple(instructions),
                memory_writes=memory_writes,
                memory_events=tuple(
                    event for event in memory_events if isinstance(event, Mapping)
                ),
                external_events=tuple(external_events),
                outcome=outcome,
            ))
    rows.sort(key=lambda item: item.rva)
    for left, right in zip(rows, rows[1:]):
        if left.end > right.rva:
            raise InternalDirectCallSummaryProposalError(
                f"state-machine regions overlap at 0x{right.rva:x}"
            )
    return tuple(rows)


def _load_import_report(
    pe_path: Path, state_path: Path, report_path: Path
) -> tuple[Mapping[str, Any], _ImportInventory]:
    try:
        value = json.loads(report_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise InternalDirectCallSummaryProposalError(
            f"cannot read machine-import report {report_path}: {error}"
        ) from error
    if not isinstance(value, Mapping) or value.get("format") != STATIC_MACHINE_IMPORT_FORMAT:
        raise InternalDirectCallSummaryProposalError(
            "machine-import report has the wrong format"
        )
    inputs = value.get("inputs")
    if not isinstance(inputs, Mapping):
        raise InternalDirectCallSummaryProposalError(
            "machine-import report has no hash-bound inputs"
        )
    for label, path, key in (
        ("original PE", pe_path, "original_sha256"),
        ("state machine", state_path, "state_machine_sha256"),
    ):
        expected = inputs.get(key)
        if not isinstance(expected, str) or expected != _sha256(path):
            raise InternalDirectCallSummaryProposalError(
                f"machine-import report {label} hash does not match the exact input"
            )
    raw_signatures = value.get("signatures")
    raw_boundaries = value.get("boundaries")
    if not isinstance(raw_signatures, list) or not isinstance(raw_boundaries, list):
        raise InternalDirectCallSummaryProposalError(
            "machine-import report has no signature/boundary inventories"
        )
    signatures: dict[int, Mapping[str, Any]] = {}
    for index, signature in enumerate(raw_signatures):
        if not isinstance(signature, Mapping) or not isinstance(signature.get("id"), int):
            raise InternalDirectCallSummaryProposalError(
                f"machine-import signature {index} is malformed"
            )
        signature_id = signature["id"]
        if signature_id in signatures:
            raise InternalDirectCallSummaryProposalError(
                f"duplicate machine-import signature id {signature_id}"
            )
        signatures[signature_id] = signature
    boundaries: dict[int, list[_Boundary]] = {}
    tails: dict[int, set[_ImportTail]] = {}
    seen_boundary_ids: set[int] = set()
    for index, boundary in enumerate(raw_boundaries):
        if not isinstance(boundary, Mapping):
            raise InternalDirectCallSummaryProposalError(
                f"machine-import boundary {index} is malformed"
            )
        fields = {
            key: boundary.get(key)
            for key in (
                "id", "signature_id", "instruction_rva", "source_rva",
                "source_size",
            )
        }
        if not all(isinstance(item, int) for item in fields.values()):
            raise InternalDirectCallSummaryProposalError(
                f"machine-import boundary {index} has non-integer fields"
            )
        route = boundary.get("route")
        if not isinstance(route, str):
            raise InternalDirectCallSummaryProposalError(
                f"machine-import boundary {index} has no route"
            )
        boundary_id = fields["id"]
        assert isinstance(boundary_id, int)
        continuation_rva = boundary.get("continuation_rva")
        if continuation_rva is None:
            continuation_rva = int(fields["source_rva"]) + int(fields["source_size"])
        if not isinstance(continuation_rva, int):
            raise InternalDirectCallSummaryProposalError(
                f"machine-import boundary {index} has no integer continuation"
            )
        if boundary_id in seen_boundary_ids:
            raise InternalDirectCallSummaryProposalError(
                f"duplicate machine-import boundary id {boundary_id}"
            )
        seen_boundary_ids.add(boundary_id)
        item = _Boundary(
            id=boundary_id,
            signature_id=int(fields["signature_id"]),
            instruction_rva=int(fields["instruction_rva"]),
            source_rva=int(fields["source_rva"]),
            source_size=int(fields["source_size"]),
            continuation_rva=continuation_rva,
            route=route,
            payload=boundary,
        )
        boundaries.setdefault(item.instruction_rva, []).append(item)
        execution_rva = boundary.get("execution_source_rva")
        argument_words = boundary.get("argument_words")
        tail_span: tuple[int, int] | None = None
        if route in {"via_thunk", "framed_thunk_tail"}:
            thunk_rva = boundary.get("thunk_rva")
            thunk_size = boundary.get("thunk_size")
            if isinstance(thunk_rva, int) and isinstance(thunk_size, int):
                tail_span = (thunk_rva, thunk_size)
        elif route == "framed_direct_tail":
            tail_rva = boundary.get("tail_rva")
            tail_size = boundary.get("tail_size")
            if isinstance(tail_rva, int) and isinstance(tail_size, int):
                tail_span = (tail_rva, tail_size)
        if (
            tail_span is not None
            and isinstance(execution_rva, int)
            and isinstance(argument_words, int)
            and not isinstance(argument_words, bool)
            and argument_words >= 0
            and execution_rva == tail_span[0]
            and tail_span[1] > 0
        ):
            tails.setdefault(execution_rva, set()).add(_ImportTail(
                id=execution_rva,
                signature_id=int(fields["signature_id"]),
                source_rva=tail_span[0],
                source_size=tail_span[1],
                argument_words=argument_words,
            ))
    inventory = _ImportInventory(
        boundaries_by_instruction={
            rva: tuple(sorted(items, key=lambda item: item.id))
            for rva, items in boundaries.items()
        },
        tails_by_execution_rva={
            rva: tuple(sorted(
                items,
                key=lambda item: (
                    item.signature_id,
                    item.argument_words,
                    item.source_size,
                ),
            ))
            for rva, items in tails.items()
        },
        signatures_by_id=signatures,
    )
    return value, inventory


def _open_pe(path: Path) -> pefile.PE:
    try:
        pe = pefile.PE(str(path), fast_load=False)
    except (OSError, pefile.PEFormatError) as error:
        raise InternalDirectCallSummaryProposalError(
            f"cannot parse PE32 input {path}: {error}"
        ) from error
    if pe.FILE_HEADER.Machine != 0x14C or pe.OPTIONAL_HEADER.Magic != 0x10B:
        pe.close()
        raise InternalDirectCallSummaryProposalError(
            "internal direct-call summaries require an x86 PE32 input"
        )
    return pe


def _direct_target(instruction: capstone.CsInsn, image_base: int) -> int | None:
    operands = instruction.operands
    if len(operands) != 1 or operands[0].type != X86_OP_IMM:
        return None
    target_va = int(operands[0].imm) & 0xFFFFFFFF
    if target_va < image_base:
        return None
    target = target_va - image_base
    return target if 0 <= target < 1 << 32 else None


def _operand_register(instruction: capstone.CsInsn, operand: Any) -> str | None:
    return instruction.reg_name(operand.reg) if operand.type == X86_OP_REG else None


def _memory_base(instruction: capstone.CsInsn, operand: Any) -> str | None:
    if operand.type != X86_OP_MEM or operand.mem.base == 0:
        return None
    return instruction.reg_name(operand.mem.base)


def _region_pair(row: _Row) -> LeanExactRegionPair:
    span = LeanSpan(row.rva, row.size)
    return LeanExactRegionPair(row.rva, span, span)


def _ordered_registers(registers: Iterable[str]) -> tuple[str, ...]:
    unique = set(registers)
    return tuple(register for register in _REGISTER_ORDER if register in unique)


def _request_json(request: DirectCallSummaryRequest) -> dict[str, Any]:
    result: dict[str, Any] = {
        "callsite_rva": request.callsite_rva,
        "caller_frame_word_offsets": list(
            request.caller_frame_word_offsets
        ),
        "registers": list(request.registers),
    }
    if request.caller_rva is not None:
        result["caller_rva"] = request.caller_rva
    return result


def _u32(value: int, context: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value < 1 << 32:
        raise InternalDirectCallSummaryProposalError(
            f"{context} must be an unsigned 32-bit integer"
        )
    return value


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as source:
            for chunk in iter(lambda: source.read(1024 * 1024), b""):
                digest.update(chunk)
    except OSError as error:
        raise InternalDirectCallSummaryProposalError(
            f"cannot hash input {path}: {error}"
        ) from error
    return digest.hexdigest()
