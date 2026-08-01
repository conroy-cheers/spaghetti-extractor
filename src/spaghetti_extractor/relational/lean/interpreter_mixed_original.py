"""Generate one-sided decoded-original evidence for mixed Stage A proofs.

The state-machine JSONL is treated as an untrusted proposal.  Generated Lean
rechecks every target and span against an independently generated exact PE
module.  Candidate addresses, candidate mappings, and manifest status fields
are deliberately outside this module's input model.
"""

from __future__ import annotations

import hashlib
import json
import re
from bisect import bisect_right
from collections import deque
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any, Mapping, Sequence

import capstone
from capstone.x86 import X86_OP_IMM, X86_OP_MEM, X86_OP_REG

from ...artifact_formats import STATIC_MACHINE_IMPORT_CONTRACTS_FORMAT
from ...errors import StageAInputError
from ...stage_binary import StageABinary, _parse_stage_a_pe
from ..analyses.registers import (
    REGISTER_CONTROL_AMBIGUOUS_WRITABLE_LOAD,
    RegisterControlBlockedOutput,
    RegisterControlCallContract,
    RegisterControlCopy,
    RegisterControlEdge,
    RegisterControlImportResult,
    RegisterControlProvenanceAtom,
    RegisterControlRegionTransfer,
    RegisterControlRegisterPair,
    RegisterControlUse,
    build_register_control_provenance_witness,
)
from ..contract import _raw_base_relocations
from .interpreter_mixed_terminal import InterpreterMixedTerminalProposal
from ..direct_call_proposal_ir import (
    DirectCallProposalIR,
    DirectCallSummaryRequest,
)


INTERPRETER_MIXED_ORIGINAL_MODULE = "GeneratedRelationalInterpreterMixedOriginal"
INTERPRETER_MIXED_ORIGINAL_BASE_MODULE = (
    "GeneratedRelationalInterpreterMixedOriginalBase"
)
INTERPRETER_MIXED_ORIGINAL_FORMAT = "stage-a-interpreter-mixed-original-v1"
INTERPRETER_MIXED_REGISTER_CONTROL_FORMAT = (
    "stage-a-mixed-original-register-control-proposal-v1"
)
INTERPRETER_MIXED_REGISTER_CONTROL_LEAN_ADAPTER_FORMAT = (
    "stage-a-mixed-original-register-control-lean-adapter-v1"
)
INTERPRETER_MIXED_DIRECT_CALL_AUTHORITY_FORMAT = (
    "stage-a-mixed-original-direct-call-authority-bindings-v2"
)
CHECKED_STACK_FINITE_ORIGIN_ENTRY_AUTHORITY_FORMAT = (
    "stage-a-checked-stack-finite-origin-call-entry-authorities-v1"
)

_REGISTER_CONTROL_REGISTERS = (
    "eax", "ebx", "ecx", "edx", "esi", "edi", "ebp",
)
_REGISTER_CONTROL_EDGE_ID_FORMAT = (
    "mixed-original-register-control-topology-edge-v1"
)


def _stable_register_control_edge_ids(
    edges: Sequence[tuple[int, int, str, int | None]],
) -> dict[tuple[int, int, str, int | None], int]:
    """Assign fail-closed IDs that do not depend on graph-list position."""

    identities: dict[int, tuple[int, int, str]] = {}
    annotations: dict[
        tuple[int, int, str], tuple[int, int, str, int | None]
    ] = {}
    result: dict[tuple[int, int, str, int | None], int] = {}
    for edge in edges:
        source, target, kind, contract_id = edge
        identity = (source, target, kind)
        previous_annotation = annotations.get(identity)
        if previous_annotation is not None and previous_annotation != edge:
            raise InterpreterMixedOriginalGenerationError(
                "one register-control edge has ambiguous contract annotations"
            )
        annotations[identity] = edge
        encoded = json.dumps(
            [
                _REGISTER_CONTROL_EDGE_ID_FORMAT,
                source,
                target,
                kind,
            ],
            separators=(",", ":"),
            allow_nan=False,
        ).encode("ascii")
        edge_id = int.from_bytes(
            hashlib.sha256(encoded).digest()[:4],
            "big",
        )
        previous = identities.get(edge_id)
        if previous is not None and previous != identity:
            raise InterpreterMixedOriginalGenerationError(
                "stable register-control edge ID collision"
            )
        identities[edge_id] = identity
        result[edge] = edge_id
    return result
_REGISTER_ALIASES = {
    "al": "eax", "ah": "eax", "ax": "eax", "eax": "eax",
    "bl": "ebx", "bh": "ebx", "bx": "ebx", "ebx": "ebx",
    "cl": "ecx", "ch": "ecx", "cx": "ecx", "ecx": "ecx",
    "dl": "edx", "dh": "edx", "dx": "edx", "edx": "edx",
    "si": "esi", "esi": "esi", "di": "edi", "edi": "edi",
    "bp": "ebp", "ebp": "ebp",
}
_PE32_CALL_PRESERVED_REGISTERS = ("ebx", "esi", "edi", "ebp")

_LEAN_IDENTIFIER = re.compile(
    r"[A-Za-z_][A-Za-z0-9_']*(?:\.[A-Za-z_][A-Za-z0-9_']*)*\Z"
)
_STAGE_A_MODULE = re.compile(
    r"StageA\.[A-Za-z_][A-Za-z0-9_']*(?:\.[A-Za-z_][A-Za-z0-9_']*)*\Z"
)
_LOCAL_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_']*\Z")
_LEAN_KEYWORDS = {
    "axiom", "by", "def", "else", "end", "import", "in", "inductive",
    "instance", "let", "match", "namespace", "opaque", "partial",
    "private", "protected", "structure", "theorem", "then", "unsafe",
    "where", "with",
}


class InterpreterMixedOriginalGenerationError(StageAInputError):
    """The original-side proposal cannot yield sound generated evidence."""


@dataclass(frozen=True)
class QualifiedLeanSymbol:
    """A separately generated Lean definition consumed by this bundle."""

    module: str
    namespace: str
    symbol: str

    def validate(self, context: str) -> None:
        if not _valid_qualified_identifier(self.module, pattern=_STAGE_A_MODULE):
            raise InterpreterMixedOriginalGenerationError(
                f"{context}.module must be a canonical StageA module"
            )
        if not _valid_qualified_identifier(self.namespace):
            raise InterpreterMixedOriginalGenerationError(
                f"{context}.namespace must be a canonical Lean namespace"
            )
        if not _valid_local_identifier(self.symbol):
            raise InterpreterMixedOriginalGenerationError(
                f"{context}.symbol must be a local Lean identifier"
            )

    @property
    def qualified(self) -> str:
        return f"{self.namespace}.{self.symbol}"


@dataclass(frozen=True)
class OriginalMachineImportBoundaryBindings:
    """Checked boundary-indexed contracts exported by a separate module."""

    signatures: QualifiedLeanSymbol
    boundaries: QualifiedLeanSymbol
    inventory: QualifiedLeanSymbol

    def validate(self) -> None:
        self.signatures.validate("machine_import_signatures")
        self.boundaries.validate("machine_import_boundaries")
        self.inventory.validate("machine_import_boundary_inventory")


@dataclass(frozen=True)
class OriginalMachineImportBoundarySiteProposal:
    """Exact external-event span submitted for one boundary-indexed contract."""

    boundary_id: int
    execution_source_rva: int
    execution_size: int
    continuation_rva: int

    def validate(self, context: str) -> None:
        _u32(self.boundary_id, f"{context}.boundary_id")
        _u32(self.execution_source_rva, f"{context}.execution_source_rva")
        _u32(self.execution_size, f"{context}.execution_size")
        _u32(self.continuation_rva, f"{context}.continuation_rva")
        if self.execution_size == 0:
            raise InterpreterMixedOriginalGenerationError(
                f"{context}.execution_size must be positive"
            )
        if self.execution_source_rva + self.execution_size > 2**32:
            raise InterpreterMixedOriginalGenerationError(
                f"{context} execution span exceeds PE32 address space"
            )


@dataclass(frozen=True)
class OriginalModuleBindings:
    """Names exported by an exact, independently generated original PE module."""

    module: str
    namespace: str
    pe: str = "originalPe"
    import_certificate: str = "originalImportCertificate"
    relocations: str = "originalRelocations"
    pe_parsed: str = "originalParsed"
    imports_parsed: str = "originalImportsChecked"
    relocations_parsed: str = "originalRelocationsParsed"
    machine_import_call_contracts: QualifiedLeanSymbol | None = None
    machine_import_boundaries: OriginalMachineImportBoundaryBindings | None = None

    def validate(self) -> None:
        if not _valid_qualified_identifier(self.module, pattern=_STAGE_A_MODULE):
            raise InterpreterMixedOriginalGenerationError(
                "original module must be a canonical StageA module"
            )
        if not _valid_qualified_identifier(self.namespace):
            raise InterpreterMixedOriginalGenerationError(
                "original namespace must be a canonical Lean namespace"
            )
        for name, value in (
            ("pe", self.pe),
            ("import_certificate", self.import_certificate),
            ("relocations", self.relocations),
            ("pe_parsed", self.pe_parsed),
            ("imports_parsed", self.imports_parsed),
            ("relocations_parsed", self.relocations_parsed),
        ):
            if not _valid_local_identifier(value):
                raise InterpreterMixedOriginalGenerationError(
                    f"{name} must be a local Lean identifier"
                )
        if self.machine_import_call_contracts is not None:
            if not isinstance(
                self.machine_import_call_contracts, QualifiedLeanSymbol
            ):
                raise InterpreterMixedOriginalGenerationError(
                    "machine_import_call_contracts must be a qualified Lean symbol"
                )
            self.machine_import_call_contracts.validate(
                "machine_import_call_contracts"
            )
        if self.machine_import_boundaries is not None:
            if self.machine_import_call_contracts is None:
                raise InterpreterMixedOriginalGenerationError(
                    "boundary-indexed imports require the resolved boundary "
                    "machine-contract list"
                )
            self.machine_import_boundaries.validate()

    def qualified(self, name: str) -> str:
        return f"{self.namespace}.{name}"


@dataclass(frozen=True)
class InterpreterMixedOriginalSpec:
    bindings: OriginalModuleBindings
    entry_rva: int
    tls_callback_rvas: tuple[int, ...] = ()
    output_module: str = INTERPRETER_MIXED_ORIGINAL_MODULE
    namespace: str = "StageA.GeneratedRelational.InterpreterMixedOriginal"
    shard_size: int = 128
    iat_imports: tuple[OriginalIATImport, ...] = ()
    recovery_pe: OriginalPERecoveryInput | None = None
    terminal_boundary_proposals: tuple[InterpreterMixedTerminalProposal, ...] = ()
    machine_import_boundary_sites: tuple[
        OriginalMachineImportBoundarySiteProposal, ...
    ] = ()
    register_control_call_contracts: tuple[
        OriginalRegisterControlCallContractProposal, ...
    ] = ()
    static_word_call_seed_authorities: tuple[
        OriginalRegisterStaticWordSeedAuthority, ...
    ] = ()
    static_data_bindings: tuple[OriginalStaticDataBinding, ...] = ()

    def validate(self) -> None:
        self.bindings.validate()
        if not _valid_local_identifier(self.output_module):
            raise InterpreterMixedOriginalGenerationError(
                "output_module must be a local Lean identifier"
            )
        if not _valid_qualified_identifier(self.namespace):
            raise InterpreterMixedOriginalGenerationError(
                "namespace must be a canonical Lean namespace"
            )
        _u32(self.entry_rva, "entry_rva")
        for index, rva in enumerate(self.tls_callback_rvas):
            _u32(rva, f"tls_callback_rvas[{index}]")
        if len(set(self.tls_callback_rvas)) != len(self.tls_callback_rvas):
            raise InterpreterMixedOriginalGenerationError(
                "TLS callback RVAs must be unique"
            )
        if not 1 <= self.shard_size <= 1024:
            raise InterpreterMixedOriginalGenerationError(
                "shard_size must be between 1 and 1024"
            )
        iat_vas: set[int] = set()
        iat_rvas: set[int] = set()
        for index, imported in enumerate(self.iat_imports):
            imported.validate(f"iat_imports[{index}]")
            if imported.iat_va in iat_vas or imported.iat_rva in iat_rvas:
                raise InterpreterMixedOriginalGenerationError(
                    "IAT import proposals must have unique VAs and RVAs"
                )
            iat_vas.add(imported.iat_va)
            iat_rvas.add(imported.iat_rva)
        if self.recovery_pe is not None:
            self.recovery_pe.validate()
        if self.bindings.machine_import_boundaries is None:
            if self.machine_import_boundary_sites:
                raise InterpreterMixedOriginalGenerationError(
                    "machine-import boundary sites require boundary bindings"
                )
        else:
            if not self.machine_import_boundary_sites:
                raise InterpreterMixedOriginalGenerationError(
                    "boundary bindings require exact boundary-site proposals"
                )
            boundary_ids: set[int] = set()
            for index, site in enumerate(self.machine_import_boundary_sites):
                site.validate(f"machine_import_boundary_sites[{index}]")
                if site.boundary_id in boundary_ids:
                    raise InterpreterMixedOriginalGenerationError(
                        "machine-import boundary site IDs must be unique"
                    )
                boundary_ids.add(site.boundary_id)
        terminal_ids: set[int] = set()
        terminal_edges: set[tuple[int, int]] = set()
        for index, proposal in enumerate(self.terminal_boundary_proposals):
            for field_name, value in (
                ("boundary_id", proposal.boundary_id),
                ("signature_id", proposal.signature_id),
                ("source_rva", proposal.source_rva),
                ("source_size", proposal.source_size),
                ("instruction_rva", proposal.instruction_rva),
                ("execution_source_rva", proposal.execution_source_rva),
                ("continuation_rva", proposal.continuation_rva),
            ):
                _u32(value, f"terminal_boundary_proposals[{index}].{field_name}")
            if proposal.source_size == 0:
                raise InterpreterMixedOriginalGenerationError(
                    "terminal boundary source spans must be nonempty"
                )
            if proposal.source_rva + proposal.source_size > 2**32:
                raise InterpreterMixedOriginalGenerationError(
                    "terminal boundary source span overflows PE32"
                )
            edge = (proposal.source_rva, proposal.continuation_rva)
            if proposal.boundary_id in terminal_ids or edge in terminal_edges:
                raise InterpreterMixedOriginalGenerationError(
                    "terminal boundary proposals must have unique IDs and edges"
                )
            terminal_ids.add(proposal.boundary_id)
            terminal_edges.add(edge)
        contract_ids: set[int] = set()
        contract_sites: set[tuple[int, int]] = set()
        for index, proposal in enumerate(self.register_control_call_contracts):
            proposal.validate(
                f"register_control_call_contracts[{index}]"
            )
            if proposal.contract_id in contract_ids:
                raise InterpreterMixedOriginalGenerationError(
                    "register-control call-contract IDs must be unique"
                )
            site = (proposal.instruction_rva, proposal.continuation_rva)
            if site in contract_sites:
                raise InterpreterMixedOriginalGenerationError(
                    "register-control call-contract sites must be unique"
                )
            contract_ids.add(proposal.contract_id)
            contract_sites.add(site)
        static_word_seed_sites: set[tuple[int, int]] = set()
        for index, authority in enumerate(
            self.static_word_call_seed_authorities
        ):
            authority.validate(
                f"static_word_call_seed_authorities[{index}]"
            )
            site = (authority.source_rva, authority.instruction_rva)
            if site in static_word_seed_sites:
                raise InterpreterMixedOriginalGenerationError(
                    "static-word call seed authorities must have unique sites"
                )
            static_word_seed_sites.add(site)
        static_data_ranges: list[tuple[int, int]] = []
        for index, binding in enumerate(self.static_data_bindings):
            binding.validate(f"static_data_bindings[{index}]")
            static_data_ranges.append((binding.rva, binding.rva + binding.size))
        for left, right in zip(
            sorted(static_data_ranges), sorted(static_data_ranges)[1:]
        ):
            if right[0] < left[1]:
                raise InterpreterMixedOriginalGenerationError(
                    "static data bindings must not overlap"
                )


@dataclass(frozen=True)
class OriginalImportIdentity:
    dll: str
    symbol: str | None = None
    ordinal: int | None = None

    def __post_init__(self) -> None:
        if not self.dll or not self.dll.isascii():
            raise InterpreterMixedOriginalGenerationError(
                "external import DLL identities must be nonempty ASCII"
            )
        if (self.symbol is None) == (self.ordinal is None):
            raise InterpreterMixedOriginalGenerationError(
                "external import identity requires exactly one symbol or ordinal"
            )
        if self.symbol is not None and (not self.symbol or not self.symbol.isascii()):
            raise InterpreterMixedOriginalGenerationError(
                "external import symbols must be nonempty ASCII"
            )
        if self.ordinal is not None and not 0 <= self.ordinal <= 0xFFFF:
            raise InterpreterMixedOriginalGenerationError(
                "external import ordinal is outside the PE16 range"
            )


@dataclass(frozen=True)
class OriginalRegisterControlCallContractProposal:
    """Untrusted call-return summary proposed for exact graph replay.

    The mixed-original adapter checks that the named call and continuation are
    present in the exact decoded PE span.  The proposal remains non-authoritative
    until generated Lean checks the corresponding machine contract.
    """

    contract_id: int
    source_rva: int
    instruction_rva: int
    continuation_rva: int
    preserved_registers: tuple[str, ...]
    import_identity: OriginalImportIdentity | None = None
    return_register: str | None = None
    machine_contract_id: int | None = None
    arity_kind: str | None = None
    argument_words: int | None = None
    origin: str = "machine_import_boundary"
    authorizing_lean_term: QualifiedLeanSymbol | None = None
    finite_target_ids: tuple[int, ...] = ()
    callee_preserved_registers: tuple[str, ...] = ()
    target_carried_registers: tuple[str, ...] = ()

    @property
    def machine_authority_id(self) -> int | None:
        if self.origin == "machine_import_boundary":
            return (
                self.contract_id
                if self.machine_contract_id is None
                else self.machine_contract_id
            )
        return self.machine_contract_id

    def validate(self, context: str) -> None:
        _u32(self.contract_id, f"{context}.contract_id")
        _u32(self.source_rva, f"{context}.source_rva")
        _u32(self.instruction_rva, f"{context}.instruction_rva")
        _u32(self.continuation_rva, f"{context}.continuation_rva")
        if self.origin not in {
            "machine_import_boundary",
            "propagated_machine_import",
            "checked_direct_call_summary",
            "checked_finite_origin_call_summary",
        }:
            raise InterpreterMixedOriginalGenerationError(
                f"{context}.origin is not a checked contract class"
            )
        if self.machine_contract_id is not None:
            _u32(
                self.machine_contract_id,
                f"{context}.machine_contract_id",
            )
        normalized = tuple(
            _canonical_register(register) for register in self.preserved_registers
        )
        if len(set(normalized)) != len(normalized):
            raise InterpreterMixedOriginalGenerationError(
                f"{context}.preserved_registers contains duplicates"
            )
        if any(register not in _REGISTER_CONTROL_REGISTERS for register in normalized):
            raise InterpreterMixedOriginalGenerationError(
                f"{context}.preserved_registers contains an unsupported register"
            )
        callee_preserved = tuple(
            _canonical_register(register)
            for register in self.callee_preserved_registers
        )
        target_carried = tuple(
            _canonical_register(register)
            for register in self.target_carried_registers
        )
        for field_name, registers in (
            ("callee_preserved_registers", callee_preserved),
            ("target_carried_registers", target_carried),
        ):
            if len(set(registers)) != len(registers):
                raise InterpreterMixedOriginalGenerationError(
                    f"{context}.{field_name} contains duplicates"
                )
            if any(
                register not in _REGISTER_CONTROL_REGISTERS
                for register in registers
            ):
                raise InterpreterMixedOriginalGenerationError(
                    f"{context}.{field_name} contains an unsupported register"
                )
        if self.return_register is not None:
            returned = _canonical_register(self.return_register)
            if returned not in _REGISTER_CONTROL_REGISTERS:
                raise InterpreterMixedOriginalGenerationError(
                    f"{context}.return_register is unsupported"
                )
            if self.import_identity is None:
                raise InterpreterMixedOriginalGenerationError(
                    f"{context}.return_register requires an import identity"
                )
        machine_import = self.origin in {
            "machine_import_boundary", "propagated_machine_import"
        }
        if machine_import and self.import_identity is None:
            raise InterpreterMixedOriginalGenerationError(
                f"{context} machine-import contract lacks an import identity"
            )
        if machine_import:
            if self.authorizing_lean_term is not None:
                raise InterpreterMixedOriginalGenerationError(
                    f"{context} machine-import contract must use its canonical "
                    "machine-call authority, not a direct-summary term"
                )
            if self.machine_authority_id is None:
                raise InterpreterMixedOriginalGenerationError(
                    f"{context} machine-import contract lacks its canonical "
                    "machine-contract ID"
                )
            if self.arity_kind not in {"fixed", "variadic"}:
                raise InterpreterMixedOriginalGenerationError(
                    f"{context} machine-import contract lacks a checked arity kind"
                )
            if (
                not isinstance(self.argument_words, int)
                or isinstance(self.argument_words, bool)
                or self.argument_words < 0
            ):
                raise InterpreterMixedOriginalGenerationError(
                    f"{context} machine-import contract has invalid argument words"
                )
            if (
                self.origin == "propagated_machine_import"
                and self.arity_kind != "fixed"
            ):
                raise InterpreterMixedOriginalGenerationError(
                    f"{context} propagated machine-import contracts require "
                    "fixed arity"
                )
        elif self.authorizing_lean_term is None:
            raise InterpreterMixedOriginalGenerationError(
                f"{context} checked direct-call summary lacks an authorizing Lean term"
            )
        else:
            self.authorizing_lean_term.validate(
                f"{context}.authorizing_lean_term"
            )
        for index, target_id in enumerate(self.finite_target_ids):
            _u32(target_id, f"{context}.finite_target_ids[{index}]")
        if len(set(self.finite_target_ids)) != len(self.finite_target_ids):
            raise InterpreterMixedOriginalGenerationError(
                f"{context}.finite_target_ids contains duplicates"
            )
        if self.origin == "checked_finite_origin_call_summary":
            if len(self.finite_target_ids) != 1:
                raise InterpreterMixedOriginalGenerationError(
                    f"{context} finite-origin call requires exactly one checked "
                    "target in the current profile"
                )
            if not target_carried:
                raise InterpreterMixedOriginalGenerationError(
                    f"{context} finite-origin call carries no checked target register"
                )
            if not set(target_carried).issubset(callee_preserved):
                raise InterpreterMixedOriginalGenerationError(
                    f"{context} finite-origin target registers are not callee-preserved"
                )
        elif self.finite_target_ids:
            raise InterpreterMixedOriginalGenerationError(
                f"{context} non-finite call contract carries finite target IDs"
            )
        elif target_carried:
            raise InterpreterMixedOriginalGenerationError(
                f"{context} non-finite call contract carries target registers"
            )


@dataclass(frozen=True)
class OriginalIATImport:
    """Untrusted IAT proposal that generated Lean rechecks against exact PE facts."""

    iat_va: int
    iat_rva: int
    identity: OriginalImportIdentity

    def validate(self, context: str) -> None:
        _u32(self.iat_va, f"{context}.iat_va")
        _u32(self.iat_rva, f"{context}.iat_rva")


@dataclass(frozen=True)
class OriginalPERecoveryInput:
    """SHA-bound original PE used only to propose checked code aliases."""

    path: Path
    sha256: str

    def validate(self) -> None:
        if not re.fullmatch(r"[0-9a-f]{64}", self.sha256):
            raise InterpreterMixedOriginalGenerationError(
                "recovery PE SHA-256 must be 64 lowercase hexadecimal digits"
            )


@dataclass(frozen=True)
class OriginalRecoveredAlias:
    alias_rva: int
    canonical_rva: int
    size: int
    bytes_sha256: str
    instructions: tuple[str, ...]


@dataclass(frozen=True)
class OriginalFixedTargetBinding:
    """A constant internal target resolved through the exact code map."""

    target_id: int
    target_rva: int
    target_va: int

    @property
    def target_ids(self) -> tuple[int, ...]:
        return (self.target_id,)


@dataclass(frozen=True)
class OriginalStaticDataBinding:
    """One exact immutable data range added to the carrier data map.

    This is intentionally independent of indirect-control recovery.  External
    call identities, format strings, and other proof anchors may need a
    canonical static mapping even when no instruction jumps through the
    mapped bytes.
    """

    rva: int
    va: int
    size: int
    bytes_sha256: str
    relocation_offsets: tuple[int, ...] = ()

    def validate(self, context: str) -> None:
        _u32(self.rva, f"{context}.rva")
        _u32(self.va, f"{context}.va")
        if not 0 < self.size < 2**32:
            raise InterpreterMixedOriginalGenerationError(
                f"{context}.size must be a positive PE32 range"
            )
        if self.rva + self.size > 2**32 or self.va + self.size > 2**32:
            raise InterpreterMixedOriginalGenerationError(
                f"{context} range overflows PE32"
            )
        if re.fullmatch(r"[0-9a-f]{64}", self.bytes_sha256) is None:
            raise InterpreterMixedOriginalGenerationError(
                f"{context}.bytes_sha256 must be lowercase SHA-256"
            )
        if tuple(sorted(set(self.relocation_offsets))) != self.relocation_offsets:
            raise InterpreterMixedOriginalGenerationError(
                f"{context}.relocation_offsets must be unique and ordered"
            )
        if any(
            offset % 4 or offset + 4 > self.size
            for offset in self.relocation_offsets
        ):
            raise InterpreterMixedOriginalGenerationError(
                f"{context}.relocation_offsets must name complete aligned words"
            )


@dataclass(frozen=True)
class OriginalImmutableSlotBinding:
    """A relocation-backed code pointer in an immutable PE word."""

    slot_rva: int
    slot_va: int
    target_id: int
    target_rva: int
    target_va: int
    continuation_target_id: int | None
    assembled_read: bool
    writes: tuple[OriginalRegisterOffsetWrite, ...]
    address_separations: tuple[OriginalAddressSeparation, ...]

    @property
    def target_ids(self) -> tuple[int, ...]:
        return (self.target_id,)


@dataclass(frozen=True)
class OriginalRegisterOffsetWrite:
    """One pre-call write represented exactly as register plus PE32 offset."""

    register: str
    offset: int
    value: Mapping[str, Any]
    subtract: bool = False


@dataclass(frozen=True)
class OriginalAddressSeparation:
    """One bytewise non-alias premise for a register-relative word write."""

    register: str
    offset: int
    address: int


@dataclass(frozen=True)
class OriginalStaticWordSlotBinding:
    """A relocation-backed code pointer in a writable static PE word."""

    slot_id: int
    slot_rva: int
    slot_va: int
    slot_bytes: tuple[int, int, int, int]
    target_id: int
    target_rva: int
    target_va: int
    continuation_target_id: int
    assembled_read: bool
    writes: tuple[OriginalRegisterOffsetWrite, ...]
    address_separations: tuple[OriginalAddressSeparation, ...]

    @property
    def target_ids(self) -> tuple[int, ...]:
        return (self.target_id,)


@dataclass(frozen=True)
class OriginalStaticWordJumpSlotBinding:
    """A writable static PE word used by an indirect tail jump."""

    slot_id: int
    slot_rva: int
    slot_va: int
    slot_bytes: tuple[int, int, int, int]
    target_id: int
    target_rva: int
    target_va: int
    assembled_read: bool
    writes: tuple[OriginalRegisterOffsetWrite, ...]
    address_separations: tuple[OriginalAddressSeparation, ...]

    @property
    def target_ids(self) -> tuple[int, ...]:
        return (self.target_id,)


@dataclass(frozen=True)
class OriginalCallableExternalRouteBinding:
    """One exact resolver/capability/ABI route for a finite-origin target."""

    resolver_contract_id: int
    capability_id: int
    abi_contract_id: int
    resource_id: int


@dataclass(frozen=True)
class OriginalFiniteOriginStaticWordJumpBinding:
    """A writable tail slot with bounded internal and callable alternatives."""

    slot_id: int
    slot_rva: int
    slot_va: int
    slot_bytes: tuple[int, int, int, int]
    initial_target_id: int
    initial_target_rva: int
    initial_target_va: int
    internal_target_ids: tuple[int, ...]
    external_routes: tuple[OriginalCallableExternalRouteBinding, ...]
    assembled_read: bool
    writes: tuple[OriginalRegisterOffsetWrite, ...]
    address_separations: tuple[OriginalAddressSeparation, ...]

    @property
    def target_ids(self) -> tuple[int, ...]:
        return self.internal_target_ids


@dataclass(frozen=True)
class OriginalBoundedTableBinding:
    """An immutable relocation table with an exact checked finite bound."""

    table_rva: int
    table_va: int
    index_register: str
    index_mask: int | None
    upper_exclusive: int
    entry_target_ids: tuple[int, ...]
    finite_target_ids: tuple[int, ...]
    bytes_sha256: str
    predecessor_bounds: tuple[OriginalTablePredecessorBound, ...] = ()

    @property
    def target_ids(self) -> tuple[int, ...]:
        return self.finite_target_ids


@dataclass(frozen=True)
class OriginalTablePredecessorBound:
    """A direct predecessor whose selected edge establishes a table bound."""

    predecessor_target_id: int
    predecessor_rva: int
    index_width_bits: int


@dataclass(frozen=True)
class OriginalRegisterProvenanceEdge:
    """One exact direct edge in a register-provenance witness graph."""

    source_target_id: int
    target_target_id: int
    kind: str = "direct"
    contract_id: int | None = None


@dataclass(frozen=True)
class OriginalRegisterStaticWordSeedAuthority:
    """Checked writable-slot source for one register-indirect call entry."""

    source_rva: int
    instruction_rva: int
    binding: OriginalStaticWordSlotBinding

    def validate(self, context: str) -> None:
        _u32(self.source_rva, f"{context}.source_rva")
        _u32(self.instruction_rva, f"{context}.instruction_rva")
        if self.binding.target_id < 0:
            raise InterpreterMixedOriginalGenerationError(
                f"{context}.binding has an invalid target ID"
            )


@dataclass(frozen=True)
class OriginalRegisterStaticWordSeedBinding:
    """One source-region output justified by a checked static-word slot."""

    target_id: int
    slot: OriginalStaticWordSlotBinding


@dataclass(frozen=True)
class OriginalRegisterCodePointerBinding:
    """A singleton internal code pointer carried through one register."""

    register: str
    target_id: int
    target_rva: int
    target_va: int
    continuation_target_id: int | None
    seed_target_ids: tuple[int, ...]
    preserve_target_ids: tuple[int, ...]
    edges: tuple[OriginalRegisterProvenanceEdge, ...]
    seed_relocation_rvas: tuple[int, ...]
    static_word_seed_bindings: tuple[
        OriginalRegisterStaticWordSeedBinding, ...
    ] = ()

    @property
    def target_ids(self) -> tuple[int, ...]:
        return (self.target_id,)


@dataclass(frozen=True)
class OriginalRegisterFiniteOriginCallEntryAuthority:
    """One generated finite-origin call entry certificate."""

    source_rva: int
    instruction_rva: int
    continuation_rva: int
    continuation_target_id: int
    target_ids: tuple[int, ...]
    module: str
    namespace: str
    indirect_exit_authority_term: str
    indirect_exit_certificate_exact_term: str


@dataclass(frozen=True)
class OriginalImportRegisterSeedBinding:
    """Exact IAT load and preceding write frame for one register seed."""

    target_id: int
    instruction_rva: int
    assembled_read: bool
    writes: tuple[OriginalRegisterOffsetWrite, ...]
    address_separations: tuple[OriginalAddressSeparation, ...]


@dataclass(frozen=True)
class OriginalRegisterImportBinding:
    """One imported address carried through one register without a call."""

    register: str
    imported: OriginalIATImport
    continuation_target_id: int
    seed_target_ids: tuple[int, ...]
    seed_bindings: tuple[OriginalImportRegisterSeedBinding, ...]
    preserve_target_ids: tuple[int, ...]
    edges: tuple[OriginalRegisterProvenanceEdge, ...]
    call_contract_ids: tuple[int, ...] = ()

    @property
    def target_ids(self) -> tuple[int, ...]:
        return ()


OriginalStaticIndirectBinding = (
    OriginalFixedTargetBinding
    | OriginalImmutableSlotBinding
    | OriginalStaticWordSlotBinding
    | OriginalStaticWordJumpSlotBinding
    | OriginalFiniteOriginStaticWordJumpBinding
    | OriginalBoundedTableBinding
    | OriginalRegisterCodePointerBinding
    | OriginalRegisterImportBinding
)


@dataclass(frozen=True)
class OriginalIndirectSite:
    source_rva: int
    instruction_rva: int
    category: str
    detail: str
    target_va: int | None = None
    resolved_target_rva: int | None = None
    iat_import: OriginalIATImport | None = None
    is_call: bool = False
    continuation_rva: int | None = None
    target_expression: Mapping[str, Any] | None = None
    static_binding: OriginalStaticIndirectBinding | None = None
    initial_target_ids: tuple[int, ...] = ()

    @property
    def has_checked_binding_proposal(self) -> bool:
        return self.iat_import is not None or self.static_binding is not None


@dataclass(frozen=True)
class OriginalRegion:
    target_id: int
    rva: int
    size: int
    successor_ids: tuple[int, ...]
    root: bool
    alias_rvas: tuple[int, ...] = ()
    missing_successor_rvas: tuple[int, ...] = ()
    import_identities: tuple[OriginalImportIdentity, ...] = ()
    indirect_sites: tuple[OriginalIndirectSite, ...] = ()
    synthetic_terminal_padding: bool = False


@dataclass(frozen=True)
class OriginalTerminalSuccessorCut:
    """One proposed post-call edge discharged by an exact terminal boundary."""

    boundary_id: int
    source_target_id: int
    continuation_target_id: int
    source_rva: int
    continuation_rva: int
    synthetic_padding: bool


@dataclass(frozen=True)
class OriginalStateIndependentFalseEdgeCut:
    """One direct edge proposed for removal by an exact false guard."""

    source_target_id: int
    destination_target_id: int
    source_rva: int
    edge_rva: int


@dataclass(frozen=True)
class OriginalGenerationBlocker:
    reason_code: str
    rva: int | None
    detail: str

    def to_json(self) -> dict[str, Any]:
        return {
            "reason_code": self.reason_code,
            "rva": self.rva,
            "detail": self.detail,
        }


@dataclass(frozen=True)
class OriginalGenerationDiagnostic:
    reason_code: str
    rva: int | None
    detail: str

    def to_json(self) -> dict[str, Any]:
        return {
            "reason_code": self.reason_code,
            "rva": self.rva,
            "detail": self.detail,
        }


@dataclass(frozen=True)
class InterpreterMixedOriginalPlan:
    spec: InterpreterMixedOriginalSpec
    state_machine_sha256: str
    regions: tuple[OriginalRegion, ...]
    import_identities: tuple[OriginalImportIdentity, ...]
    reachable_target_ids: tuple[int, ...]
    recovered_aliases: tuple[OriginalRecoveredAlias, ...] = ()
    terminal_successor_cuts: tuple[OriginalTerminalSuccessorCut, ...] = ()
    state_independent_false_edge_cuts: tuple[
        OriginalStateIndependentFalseEdgeCut, ...
    ] = ()
    indirect_sites: tuple[OriginalIndirectSite, ...] = ()
    register_control_provenance: Mapping[str, Any] | None = None
    blockers: tuple[OriginalGenerationBlocker, ...] = ()
    diagnostics: tuple[OriginalGenerationDiagnostic, ...] = ()
    ignored_fields: tuple[str, ...] = (
        "acceptance",
        "blocker",
        "blocker_category",
        "next_action",
        "reachable",
        "status",
    )

    @property
    def complete(self) -> bool:
        return not self.blockers and not self.reachable_missing_successors

    @property
    def reachable_missing_successors(self) -> tuple[tuple[int, int], ...]:
        reachable = set(self.reachable_target_ids)
        return tuple(
            (region.rva, successor_rva)
            for region in self.regions
            if region.target_id in reachable
            for successor_rva in region.missing_successor_rvas
        )

    def to_json(
        self,
        *,
        include_original_combined_reachability_declarations: bool = False,
    ) -> dict[str, Any]:
        recovered_indirect = [
            site
            for region in self.regions
            for site in region.indirect_sites
            if site.static_binding is not None
        ]
        payload = {
            "format": INTERPRETER_MIXED_ORIGINAL_FORMAT,
            "status": "ready" if self.complete else "incomplete",
            "state_machine_sha256": self.state_machine_sha256,
            "entry_rva": self.spec.entry_rva,
            "tls_callback_rvas": list(self.spec.tls_callback_rvas),
            "static_data_bindings": [
                {
                    "bytes_sha256": binding.bytes_sha256,
                    "relocation_offsets": list(binding.relocation_offsets),
                    "rva": binding.rva,
                    "size": binding.size,
                    "va": binding.va,
                }
                for binding in self.spec.static_data_bindings
            ],
            "counts": {
                "regions": len(self.regions),
                "imports": len(self.import_identities),
                "reachable_targets": len(self.reachable_target_ids),
                "reachable_missing_successors": len(
                    self.reachable_missing_successors
                ),
                "recovered_direct_targets": len(self.recovered_aliases),
                "recovered_static_indirect_controls": len(recovered_indirect),
                "initial_writable_slot_target_proposals": sum(
                    bool(site.initial_target_ids)
                    for region in self.regions
                    for site in region.indirect_sites
                ),
                "terminal_successor_cuts": len(self.terminal_successor_cuts),
                "state_independent_false_edge_cuts": len(
                    self.state_independent_false_edge_cuts
                ),
                "indirect_sites": len(self.indirect_sites),
                "blockers": len(self.blockers),
                "diagnostics": len(self.diagnostics),
                "static_data_bindings": len(self.spec.static_data_bindings),
            },
            "reachable_target_ids": list(self.reachable_target_ids),
            "recovered_direct_targets": [
                {
                    "alias_rva": item.alias_rva,
                    "canonical_rva": item.canonical_rva,
                    "size": item.size,
                    "bytes_sha256": item.bytes_sha256,
                    "instructions": list(item.instructions),
                }
                for item in self.recovered_aliases
            ],
            "terminal_successor_cuts": [
                {
                    "boundary_id": item.boundary_id,
                    "source_target_id": item.source_target_id,
                    "continuation_target_id": item.continuation_target_id,
                    "source_rva": item.source_rva,
                    "continuation_rva": item.continuation_rva,
                    "synthetic_padding": item.synthetic_padding,
                }
                for item in self.terminal_successor_cuts
            ],
            "state_independent_false_edge_cuts": [
                {
                    "source_target_id": item.source_target_id,
                    "destination_target_id": item.destination_target_id,
                    "source_rva": item.source_rva,
                    "edge_rva": item.edge_rva,
                }
                for item in self.state_independent_false_edge_cuts
            ],
            "recovered_static_indirect_controls": [
                _static_indirect_binding_json(site)
                for site in sorted(
                    recovered_indirect,
                    key=lambda item: (item.source_rva, item.instruction_rva),
                )
            ],
            "initial_writable_slot_target_proposals": [
                {
                    "acceptance_authority": False,
                    "instruction_rva": site.instruction_rva,
                    "source_rva": site.source_rva,
                    "target_ids": list(site.initial_target_ids),
                    "target_rvas": [
                        self.regions[target_id].rva
                        for target_id in site.initial_target_ids
                    ],
                }
                for region in self.regions
                for site in region.indirect_sites
                if site.initial_target_ids
            ],
            "register_control_provenance": (
                None
                if self.register_control_provenance is None
                else json.loads(json.dumps(self.register_control_provenance))
            ),
            "rooted_closure_basis": {
                "source": (
                    "state-machine direct edges plus exact initial values of "
                    "relocation-backed writable code-pointer slots"
                ),
                "acceptance_condition": (
                    "the exact mixed component proof must derive every reachable "
                    "transition from exact decoded bytes and preserve "
                    "OriginalExecutionReachable"
                ),
                "unreachable_gaps_authoritative": False,
            },
            "blockers": [blocker.to_json() for blocker in self.blockers],
            "diagnostics": [item.to_json() for item in self.diagnostics],
            "indirect_frontiers_by_category": _category_counts(
                self.indirect_sites
            ),
            "machine_contract_generation_input": (
                None
                if not self.import_identities
                or self.spec.bindings.machine_import_call_contracts is not None
                else {
                    "lean_type": "List MachineImportCallContract",
                    "required_import_identities": [
                        _import_identity_json(identity)
                        for identity in self.import_identities
                    ],
                    "required_binding": {
                        "module": "StageA.<generated-module>",
                        "namespace": "StageA.<generated-namespace>",
                        "symbol": "<machine-contract-list>",
                    },
                    "requirements": [
                        "contracts cover every listed normalized import identity",
                        "machineImportCallContractsValid holds against exact parsed imports",
                        "ABI, memory, result, and world effects are populated",
                    ],
                }
            ),
            "ignored_untrusted_fields": list(self.ignored_fields),
            "remaining_uninhabited_fields": (
                [
                    "GeneratedOriginalFiniteCarrierBinding",
                    "indexed legacy/original lookup equality",
                    "linear-return/original lookup equality",
                    "ExactDecodedOriginalCarrierBinding",
                    "ExactMixedProgramBinding",
                ]
                + (
                    []
                    if self.complete
                    else [
                        "ExactOriginalDecodedAuthority",
                        "ExactOriginalDecodedReachability",
                    ]
                )
            ),
        }
        if include_original_combined_reachability_declarations:
            if not self.complete:
                raise InterpreterMixedOriginalGenerationError(
                    "original-combined reachability declarations require a "
                    "complete rooted mixed-original inventory"
                )
            module = f"StageA.{self.spec.output_module}"
            namespace = self.spec.namespace

            def declaration(symbol: str) -> dict[str, str]:
                return {
                    "module": module,
                    "namespace": namespace,
                    "symbol": symbol,
                }

            payload["original_combined_reachability_declarations"] = {
                "program": declaration("generatedOriginalCombinedProgram"),
                "original_context": declaration(
                    "generatedOriginalStaticContext"
                ),
                "target_ids": declaration(
                    "generatedOriginalCombinedReachableTargetIds"
                ),
                "target_ids_exact": declaration(
                    "generatedOriginalCombinedReachableTargetIdsExact"
                ),
                "target_ids_unique": declaration(
                    "generatedOriginalCombinedReachableTargetIdsUnique"
                ),
                "target_round_trips": declaration(
                    "generatedOriginalCombinedReachableTargetRoundTrips"
                ),
            }
        return payload


@dataclass(frozen=True)
class MixedOriginalDirectCallSummaryRequestPlan:
    state_machine_sha256: str
    requests: tuple[DirectCallSummaryRequest, ...]
    chains: tuple[Mapping[str, Any], ...]
    frontiers: tuple[Mapping[str, Any], ...]
    finite_origin_entry_requests: tuple[DirectCallSummaryRequest, ...] = ()

    def to_json(self) -> dict[str, Any]:
        return {
            "format": "stage-a-mixed-original-direct-call-summary-requests-v1",
            "state_machine_sha256": self.state_machine_sha256,
            "authority": {
                "proposal_only": True,
                "standalone_acceptance_authority": False,
                "authorizing_lean_term": None,
            },
            "requests": [
                {
                    "callsite_rva": request.callsite_rva,
                    "caller_frame_word_offsets": list(
                        request.caller_frame_word_offsets
                    ),
                    "caller_rva": request.caller_rva,
                    "registers": list(request.registers),
                }
                for request in self.requests
            ],
            "finite_origin_entry_requests": [
                {
                    "callsite_rva": request.callsite_rva,
                    "caller_frame_word_offsets": list(
                        request.caller_frame_word_offsets
                    ),
                    "caller_rva": request.caller_rva,
                    "registers": list(request.registers),
                }
                for request in self.finite_origin_entry_requests
            ],
            "chains": [json.loads(json.dumps(row)) for row in self.chains],
            "frontiers": [json.loads(json.dumps(row)) for row in self.frontiers],
            "counts": {
                "requests": len(self.requests),
                "finite_origin_entry_requests": len(
                    self.finite_origin_entry_requests
                ),
                "chains": len(self.chains),
                "frontiers": len(self.frontiers),
            },
        }


def stage_finite_origin_entry_requests(
    plan: MixedOriginalDirectCallSummaryRequestPlan,
    *,
    available_instruction_rvas: Iterable[int],
) -> MixedOriginalDirectCallSummaryRequestPlan:
    """Select the finite-origin calls whose entry authorities exist now.

    Register provenance can cross internal calls only after those calls have
    checked preservation summaries. A proof round must therefore compile the
    currently grounded entries and defer the rest, rather than treating a
    fixed-point dependency as a semantic failure. Later rounds call this same
    function with the newly checked entry inventory.
    """

    available = frozenset(available_instruction_rvas)
    for instruction_rva in available:
        if (
            not isinstance(instruction_rva, int)
            or isinstance(instruction_rva, bool)
            or not 0 <= instruction_rva < 2**32
        ):
            raise InterpreterMixedOriginalGenerationError(
                "available finite-origin entry RVAs must be PE32 integers"
            )
    active = tuple(
        request
        for request in plan.finite_origin_entry_requests
        if request.callsite_rva in available
    )
    deferred = tuple(
        request
        for request in plan.finite_origin_entry_requests
        if request.callsite_rva not in available
    )
    deferred_frontiers = tuple({
        "reason_code": "finite_origin_entry_deferred_until_checked",
        "detail": (
            "the entry target is carried through a call or loop whose checked "
            "preservation summary belongs to an earlier proof round"
        ),
        "callsite_rva": request.callsite_rva,
        "caller_rva": request.caller_rva,
        "registers": list(request.registers),
        "caller_frame_word_offsets": list(
            request.caller_frame_word_offsets
        ),
    } for request in deferred)
    return MixedOriginalDirectCallSummaryRequestPlan(
        state_machine_sha256=plan.state_machine_sha256,
        requests=plan.requests,
        chains=plan.chains,
        frontiers=(*plan.frontiers, *deferred_frontiers),
        finite_origin_entry_requests=active,
    )


def _checked_stack_finite_origin_entries(
    report: Mapping[str, Any] | None,
    *,
    original_sha256: str,
    state_machine_sha256: str,
) -> dict[tuple[int, int, int], Mapping[str, Any]]:
    if report is None:
        return {}
    if report.get("format") != (
        CHECKED_STACK_FINITE_ORIGIN_ENTRY_AUTHORITY_FORMAT
    ):
        raise InterpreterMixedOriginalGenerationError(
            "checked stack finite-origin entry authority has the wrong format"
        )
    inputs = report.get("inputs")
    if not isinstance(inputs, Mapping):
        raise InterpreterMixedOriginalGenerationError(
            "checked stack finite-origin entry authority has no inputs"
        )
    for field, expected in (
        ("original_sha256", original_sha256),
        ("state_machine_sha256", state_machine_sha256),
    ):
        if inputs.get(field) != expected:
            raise InterpreterMixedOriginalGenerationError(
                "checked stack finite-origin entry authority "
                f"{field} does not match"
            )
    rows = report.get("entries")
    if not isinstance(rows, list):
        raise InterpreterMixedOriginalGenerationError(
            "checked stack finite-origin entry authority has no entries"
        )
    result: dict[tuple[int, int, int], Mapping[str, Any]] = {}
    constructor = (
        "StageA.Relational.IndirectExitAdapters."
        "checkedStackFixedIndirectCertificate"
    )
    for index, item in enumerate(rows):
        if not isinstance(item, Mapping):
            raise InterpreterMixedOriginalGenerationError(
                f"checked stack finite-origin entry {index} is malformed"
            )
        source_rva = _u32(
            item.get("source_rva"),
            f"checked stack finite-origin entry {index} source RVA",
        )
        instruction_rva = _u32(
            item.get("instruction_rva"),
            f"checked stack finite-origin entry {index} instruction RVA",
        )
        continuation_rva = _u32(
            item.get("continuation_rva"),
            f"checked stack finite-origin entry {index} continuation RVA",
        )
        for field in (
            "source_target_id",
            "continuation_target_id",
            "callee_target_id",
            "callee_rva",
            "caller_frame_word_offset",
        ):
            _u32(
                item.get(field),
                f"checked stack finite-origin entry {index} {field}",
            )
        static_term = item.get("static_stack_authority_term")
        if not isinstance(static_term, Mapping):
            raise InterpreterMixedOriginalGenerationError(
                f"checked stack finite-origin entry {index} has no named "
                "static stack authority"
            )
        QualifiedLeanSymbol(
            module=str(static_term.get("module", "")),
            namespace=str(static_term.get("namespace", "")),
            symbol=str(static_term.get("symbol", "")),
        ).validate(
            f"checked_stack_finite_origin_entries[{index}]"
            ".static_stack_authority_term"
        )
        kernel_check = item.get("static_stack_authority_kernel_check")
        if (
            not isinstance(kernel_check, Mapping)
            or kernel_check.get("status") != "checked"
            or kernel_check.get("module") != static_term.get("module")
            or kernel_check.get("term") != static_term
            or not isinstance(kernel_check.get("source_sha256"), str)
            or re.fullmatch(
                r"[0-9a-f]{64}", str(kernel_check.get("source_sha256"))
            )
            is None
            or not isinstance(kernel_check.get("olean_sha256"), str)
            or re.fullmatch(
                r"[0-9a-f]{64}", str(kernel_check.get("olean_sha256"))
            )
            is None
        ):
            raise InterpreterMixedOriginalGenerationError(
                f"checked stack finite-origin entry {index} static authority "
                "was not kernel-compiled"
            )
        if item.get("certificate_constructor") != constructor:
            raise InterpreterMixedOriginalGenerationError(
                f"checked stack finite-origin entry {index} does not use "
                "checkedStackFixedIndirectCertificate"
            )
        entry_term = item.get("indirect_exit_authority_term")
        if not isinstance(entry_term, Mapping):
            raise InterpreterMixedOriginalGenerationError(
                f"checked stack finite-origin entry {index} has no checked "
                "indirect-exit authority"
            )
        entry_symbol = QualifiedLeanSymbol(
            module=str(entry_term.get("module", "")),
            namespace=str(entry_term.get("namespace", "")),
            symbol=str(entry_term.get("symbol", "")),
        )
        entry_symbol.validate(
            f"checked_stack_finite_origin_entries[{index}]"
            ".indirect_exit_authority_term"
        )
        if item.get("indirect_exit_authority_module") != entry_symbol.module:
            raise InterpreterMixedOriginalGenerationError(
                f"checked stack finite-origin entry {index} authority module "
                "does not match its Lean term"
            )
        exact_term = item.get("indirect_exit_certificate_exact_term")
        if (
            not isinstance(exact_term, str)
            or re.fullmatch(
                r"[A-Za-z_][A-Za-z0-9_']*"
                r"(?:\.[A-Za-z_][A-Za-z0-9_']*)*",
                exact_term,
            )
            is None
        ):
            raise InterpreterMixedOriginalGenerationError(
                f"checked stack finite-origin entry {index} has no exact "
                "certificate projection theorem"
            )
        entry_kernel_check = item.get(
            "indirect_exit_authority_kernel_check"
        )
        if (
            not isinstance(entry_kernel_check, Mapping)
            or entry_kernel_check.get("status") != "checked"
            or entry_kernel_check.get("module") != entry_symbol.module
            or entry_kernel_check.get("term") != entry_term
            or not isinstance(
                entry_kernel_check.get("source_sha256"), str
            )
            or re.fullmatch(
                r"[0-9a-f]{64}",
                str(entry_kernel_check.get("source_sha256")),
            )
            is None
            or not isinstance(
                entry_kernel_check.get("olean_sha256"), str
            )
            or re.fullmatch(
                r"[0-9a-f]{64}",
                str(entry_kernel_check.get("olean_sha256")),
            )
            is None
        ):
            raise InterpreterMixedOriginalGenerationError(
                f"checked stack finite-origin entry {index} indirect-exit "
                "authority was not kernel-compiled"
            )
        key = (source_rva, instruction_rva, continuation_rva)
        if key in result:
            raise InterpreterMixedOriginalGenerationError(
                "checked stack finite-origin entry authority duplicates an "
                "exact callsite"
            )
        result[key] = item
    return result


def load_checked_stack_finite_origin_call_entry_authorities(
    report: Mapping[str, Any],
    *,
    original_sha256: str,
    state_machine_sha256: str,
) -> tuple[OriginalRegisterFiniteOriginCallEntryAuthority, ...]:
    """Load stack-derived call entries only after both Lean terms are checked."""

    entries = _checked_stack_finite_origin_entries(
        report,
        original_sha256=original_sha256,
        state_machine_sha256=state_machine_sha256,
    )
    return tuple(
        OriginalRegisterFiniteOriginCallEntryAuthority(
            source_rva=source_rva,
            instruction_rva=instruction_rva,
            continuation_rva=continuation_rva,
            continuation_target_id=int(item["continuation_target_id"]),
            target_ids=(int(item["callee_target_id"]),),
            module=str(item["indirect_exit_authority_module"]),
            namespace=str(
                item["indirect_exit_authority_term"]["namespace"]
            ),
            indirect_exit_authority_term=(
                f"{item['indirect_exit_authority_term']['namespace']}."
                f"{item['indirect_exit_authority_term']['symbol']}"
            ),
            indirect_exit_certificate_exact_term=str(
                item["indirect_exit_certificate_exact_term"]
            ),
        )
        for (
            source_rva,
            instruction_rva,
            continuation_rva,
        ), item in sorted(entries.items())
    )


def augment_direct_call_summary_requests_from_runtime_value_carry_hints(
    plan: MixedOriginalDirectCallSummaryRequestPlan,
    hints: Mapping[str, Any],
    proposal_ir: DirectCallProposalIR,
    *,
    original_sha256: str,
    checked_stack_entry_authority: Mapping[str, Any] | None = None,
) -> MixedOriginalDirectCallSummaryRequestPlan:
    """Add caller-frame preservation requests from an untrusted route hint.

    The exact proposal IR supplies all cutpoint and call metadata.  A hint can
    select a route and frame offset, but it cannot invent a callsite, edge, or
    continuation.  Indirect calls remain explicit frontiers until a checked
    finite-origin entry authority is available.
    """

    if hints.get("format") != "stage-a-stack-dynamic-closure-hints-v2":
        raise InterpreterMixedOriginalGenerationError(
            "runtime value-carry hints have the wrong format"
        )
    if hints.get("original_sha256") != original_sha256:
        raise InterpreterMixedOriginalGenerationError(
            "runtime value-carry hints do not match the original PE"
        )
    route_rows = hints.get("runtime_value_carry_routes")
    if not isinstance(route_rows, list):
        raise InterpreterMixedOriginalGenerationError(
            "runtime value-carry hints have no route inventory"
        )

    requests_by_site = {
        (request.callsite_rva, request.caller_rva): request
        for request in plan.requests
    }
    if len(requests_by_site) != len(plan.requests):
        raise InterpreterMixedOriginalGenerationError(
            "direct-call request plan contains duplicate callsites"
        )
    chains = list(plan.chains)
    frontiers = list(plan.frontiers)
    target_ids_by_rva = proposal_ir.target_ids_by_rva
    target_rvas = getattr(proposal_ir, "target_rvas", None)
    if target_rvas is None:
        target_rvas = {
            target_id: rva for rva, target_id in target_ids_by_rva.items()
        }
    stack_entries = _checked_stack_finite_origin_entries(
        checked_stack_entry_authority,
        original_sha256=original_sha256,
        state_machine_sha256=plan.state_machine_sha256,
    )
    finite_requests_by_site = {
        (request.callsite_rva, request.caller_rva): request
        for request in plan.finite_origin_entry_requests
    }
    if len(finite_requests_by_site) != len(plan.finite_origin_entry_requests):
        raise InterpreterMixedOriginalGenerationError(
            "finite-origin direct-call request plan contains duplicate callsites"
        )

    for route_index, route_item in enumerate(route_rows):
        if not isinstance(route_item, Mapping):
            raise InterpreterMixedOriginalGenerationError(
                f"runtime value-carry route {route_index} is malformed"
            )
        stable_id = route_item.get("stable_id")
        fact_rows = route_item.get("facts")
        transfer_rows = route_item.get("transfers")
        if (
            not isinstance(stable_id, str)
            or not stable_id
            or not isinstance(fact_rows, list)
            or not isinstance(transfer_rows, list)
        ):
            raise InterpreterMixedOriginalGenerationError(
                f"runtime value-carry route {route_index} has invalid metadata"
            )
        facts: dict[int, tuple[str, str, int]] = {}
        for fact_index, fact_item in enumerate(fact_rows):
            if not isinstance(fact_item, Mapping):
                raise InterpreterMixedOriginalGenerationError(
                    f"runtime value-carry route {route_index} fact "
                    f"{fact_index} is malformed"
                )
            target_rva = _u32(
                fact_item.get("target_rva"),
                f"runtime value-carry route {route_index} fact "
                f"{fact_index} target RVA",
            )
            location = fact_item.get("location")
            if not isinstance(location, Mapping):
                raise InterpreterMixedOriginalGenerationError(
                    f"runtime value-carry route {route_index} fact "
                    f"{fact_index} has no location"
                )
            kind = location.get("kind")
            register = location.get("register")
            offset = location.get("offset")
            if (
                kind not in {"register", "frame_word"}
                or register not in {
                    "eax", "ebx", "ecx", "edx",
                    "esi", "edi", "ebp", "esp",
                }
                or isinstance(offset, bool)
                or not isinstance(offset, int)
                or not 0 <= offset <= 65528
                or target_rva not in target_ids_by_rva
                or target_rva in facts
            ):
                raise InterpreterMixedOriginalGenerationError(
                    f"runtime value-carry route {route_index} fact "
                    f"{fact_index} has an invalid or duplicate location"
                )
            facts[target_rva] = (str(kind), str(register), offset)

        for transfer_index, transfer_item in enumerate(transfer_rows):
            if (
                not isinstance(transfer_item, Mapping)
                or transfer_item.get("kind") != "call_frame_word_preserve"
            ):
                continue
            source_rva = _u32(
                transfer_item.get("source_rva"),
                f"runtime value-carry route {route_index} transfer "
                f"{transfer_index} source RVA",
            )
            target_rva = _u32(
                transfer_item.get("target_rva"),
                f"runtime value-carry route {route_index} transfer "
                f"{transfer_index} target RVA",
            )
            source_location = facts.get(source_rva)
            target_location = facts.get(target_rva)
            if (
                source_location is None
                or source_location != target_location
                or source_location[0] != "frame_word"
                or source_location[1] != "esp"
            ):
                raise InterpreterMixedOriginalGenerationError(
                    f"runtime value-carry route {route_index} transfer "
                    f"{transfer_index} does not preserve one ESP frame word"
                )
            offset = source_location[2]
            direct_sites = [
                site
                for site in proposal_ir.direct_call_sites
                if site.source_rva == source_rva
                and site.continuation_rva == target_rva
            ]
            if len(direct_sites) == 1:
                site = direct_sites[0]
                key = (site.callsite_rva, site.source_rva)
                prior = requests_by_site.get(key)
                registers = () if prior is None else prior.registers
                offsets = set(
                    () if prior is None else prior.caller_frame_word_offsets
                )
                offsets.add(offset)
                requests_by_site[key] = DirectCallSummaryRequest(
                    callsite_rva=site.callsite_rva,
                    caller_rva=site.source_rva,
                    registers=registers,
                    caller_frame_word_offsets=tuple(sorted(offsets)),
                ).checked()
                chains.append({
                    "source": "runtime_value_carry_hint",
                    "stable_id": stable_id,
                    "use_source_rva": target_rva,
                    "use_instruction_rva": target_rva,
                    "register": "esp",
                    "caller_frame_word_offset": offset,
                    "required_internal_calls": [{
                        "callsite_rva": site.callsite_rva,
                        "caller_rva": site.source_rva,
                        "source_rva": site.source_rva,
                        "source_target_id": site.source_target_id,
                        "continuation_rva": site.continuation_rva,
                        "continuation_target_id": (
                            site.continuation_target_id
                        ),
                        "edge_index": site.edge_index,
                    }],
                    "required_finite_origin_calls": [],
                    "machine_import_carries": [],
                })
                continue

            indirect_sites = [
                site
                for site in proposal_ir.stack_dynamic_control.indirect_sites
                if site.is_call
                and site.source_rva == source_rva
                and site.continuation_rva == target_rva
            ]
            if len(direct_sites) > 1 or len(indirect_sites) > 1:
                raise InterpreterMixedOriginalGenerationError(
                    f"runtime value-carry route {route_index} transfer "
                    f"{transfer_index} has ambiguous call metadata"
                )
            if indirect_sites:
                site = indirect_sites[0]
                entry = stack_entries.get(
                    (source_rva, site.instruction_rva, target_rva)
                )
                if entry is not None:
                    expected_source_id = target_ids_by_rva[source_rva]
                    expected_continuation_id = target_ids_by_rva[target_rva]
                    callee_target_id = int(entry["callee_target_id"])
                    callee_rva = int(entry["callee_rva"])
                    if (
                        entry["source_target_id"] != expected_source_id
                        or entry["continuation_target_id"]
                        != expected_continuation_id
                        or entry["caller_frame_word_offset"] != offset
                        or target_rvas.get(callee_target_id) != callee_rva
                    ):
                        raise InterpreterMixedOriginalGenerationError(
                            f"runtime value-carry route {route_index} transfer "
                            f"{transfer_index} does not match its checked stack "
                            "entry authority"
                        )
                    key = (site.instruction_rva, source_rva)
                    prior = finite_requests_by_site.get(key)
                    registers = () if prior is None else prior.registers
                    offsets = set(
                        ()
                        if prior is None
                        else prior.caller_frame_word_offsets
                    )
                    offsets.add(offset)
                    finite_requests_by_site[key] = DirectCallSummaryRequest(
                        callsite_rva=site.instruction_rva,
                        caller_rva=source_rva,
                        registers=registers,
                        caller_frame_word_offsets=tuple(sorted(offsets)),
                    ).checked()
                    chains.append({
                        "source": (
                            "checked_stack_finite_origin_entry_authority"
                        ),
                        "stable_id": stable_id,
                        "use_source_rva": target_rva,
                        "use_instruction_rva": target_rva,
                        "register": "esp",
                        "caller_frame_word_offset": offset,
                        "required_internal_calls": [],
                        "required_finite_origin_calls": [{
                            "callsite_rva": site.instruction_rva,
                            "caller_rva": source_rva,
                            "source_rva": source_rva,
                            "source_target_id": expected_source_id,
                            "continuation_rva": target_rva,
                            "continuation_target_id": (
                                expected_continuation_id
                            ),
                            "callee_rva": callee_rva,
                            "callee_target_id": callee_target_id,
                            "static_stack_authority_term": dict(
                                entry["static_stack_authority_term"]
                            ),
                            "certificate_constructor": (
                                entry["certificate_constructor"]
                            ),
                        }],
                        "machine_import_carries": [],
                    })
                    continue
            frontiers.append({
                "reason_code": (
                    "caller_frame_word_requires_finite_origin_entry_authority"
                    if indirect_sites
                    else "caller_frame_word_callsite_not_found"
                ),
                "detail": (
                    "the exact call is indirect and needs a checked finite "
                    "target authority"
                    if indirect_sites
                    else "the exact cutpoint graph has no matching call edge"
                ),
                "stable_id": stable_id,
                "source_rva": source_rva,
                "target_rva": target_rva,
                "instruction_rva": (
                    indirect_sites[0].instruction_rva
                    if indirect_sites
                    else None
                ),
                "caller_frame_word_offset": offset,
            })

    requests = tuple(sorted(
        requests_by_site.values(),
        key=lambda request: (
            request.callsite_rva,
            -1 if request.caller_rva is None else request.caller_rva,
            request.registers,
            request.caller_frame_word_offsets,
        ),
    ))
    return MixedOriginalDirectCallSummaryRequestPlan(
        state_machine_sha256=plan.state_machine_sha256,
        requests=requests,
        chains=tuple(chains),
        frontiers=tuple(frontiers),
        finite_origin_entry_requests=tuple(sorted(
            finite_requests_by_site.values(),
            key=lambda request: (
                request.callsite_rva,
                -1 if request.caller_rva is None else request.caller_rva,
                request.registers,
                request.caller_frame_word_offsets,
            ),
        )),
    )


def load_original_iat_import_proposals(
    reference_contract: Path | str,
) -> tuple[OriginalIATImport, ...]:
    """Read only original-side IAT proposals for later exact Lean checking."""

    path = Path(reference_contract)
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise InterpreterMixedOriginalGenerationError(
            f"unable to read reference contract: {error}"
        ) from error
    if not isinstance(payload, Mapping):
        raise InterpreterMixedOriginalGenerationError(
            "reference contract must be an object"
        )
    original = _mapping(payload.get("original"), 0, "original")
    image_base = _u32(original.get("image_base"), "original.image_base")
    rows = original.get("imports")
    if not isinstance(rows, list):
        raise InterpreterMixedOriginalGenerationError(
            "original.imports must be a list"
        )
    proposals: list[OriginalIATImport] = []
    for index, value in enumerate(rows):
        imported = _mapping(value, 0, f"original.imports[{index}]")
        dll = imported.get("dll")
        symbol = imported.get("symbol")
        ordinal = imported.get("ordinal")
        if not isinstance(dll, str):
            raise InterpreterMixedOriginalGenerationError(
                f"original.imports[{index}].dll must be a string"
            )
        if symbol is not None and not isinstance(symbol, str):
            raise InterpreterMixedOriginalGenerationError(
                f"original.imports[{index}].symbol must be a string"
            )
        if ordinal is not None and not isinstance(ordinal, int):
            raise InterpreterMixedOriginalGenerationError(
                f"original.imports[{index}].ordinal must be an integer"
            )
        iat_rva = _u32(
            imported.get("thunk_rva"), f"original.imports[{index}].thunk_rva"
        )
        iat_va = image_base + iat_rva
        if iat_va >= 2**32:
            raise InterpreterMixedOriginalGenerationError(
                f"original.imports[{index}] IAT VA overflows PE32"
            )
        proposals.append(
            OriginalIATImport(
                iat_va=iat_va,
                iat_rva=iat_rva,
                identity=OriginalImportIdentity(dll, symbol, ordinal),
            )
        )
    result = tuple(
        sorted(proposals, key=lambda item: (item.iat_rva, item.iat_va))
    )
    if len({item.iat_rva for item in result}) != len(result):
        raise InterpreterMixedOriginalGenerationError(
            "original import proposal contains duplicate IAT RVAs"
        )
    return result


def load_original_pe_recovery_input(
    reference_contract: Path | str,
) -> OriginalPERecoveryInput:
    """Read only the SHA-bound original PE path from a reference contract."""

    path = Path(reference_contract)
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise InterpreterMixedOriginalGenerationError(
            f"unable to read reference contract: {error}"
        ) from error
    if not isinstance(payload, Mapping):
        raise InterpreterMixedOriginalGenerationError(
            "reference contract must be an object"
        )
    original = _mapping(payload.get("original"), 0, "original")
    original_path = original.get("path")
    sha256 = original.get("sha256")
    if not isinstance(original_path, str) or not original_path:
        raise InterpreterMixedOriginalGenerationError(
            "original.path must be a nonempty string"
        )
    if not isinstance(sha256, str):
        raise InterpreterMixedOriginalGenerationError(
            "original.sha256 must be a string"
        )
    result = OriginalPERecoveryInput(Path(original_path), sha256)
    result.validate()
    return result


def load_original_register_control_call_contract_proposals(
    machine_import_report: Path | str,
    *,
    original_sha256: str | None = None,
    state_machine_sha256: str | None = None,
) -> tuple[OriginalRegisterControlCallContractProposal, ...]:
    """Load hash-bound, proposal-only call summaries from a static report.

    The report itself has no acceptance authority.  Exact instruction and edge
    checks are repeated by the mixed-original adapter, and Lean must later
    replay both those checks and the referenced machine call contract.
    """

    path = Path(machine_import_report)
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise InterpreterMixedOriginalGenerationError(
            f"unable to read machine-import report: {error}"
        ) from error
    if not isinstance(payload, Mapping) or payload.get("format") != (
        STATIC_MACHINE_IMPORT_CONTRACTS_FORMAT
    ):
        raise InterpreterMixedOriginalGenerationError(
            "machine-import report has an unsupported format"
        )
    inputs = payload.get("inputs")
    if not isinstance(inputs, Mapping):
        raise InterpreterMixedOriginalGenerationError(
            "machine-import report has no hash-bound inputs"
        )
    for label, expected in (
        ("original_sha256", original_sha256),
        ("state_machine_sha256", state_machine_sha256),
    ):
        observed = inputs.get(label)
        if expected is not None and observed != expected:
            raise InterpreterMixedOriginalGenerationError(
                f"machine-import report {label} does not match the exact input"
            )
    signatures_value = payload.get("signatures")
    boundaries_value = payload.get("boundaries")
    if not isinstance(signatures_value, list) or not isinstance(
        boundaries_value, list
    ):
        raise InterpreterMixedOriginalGenerationError(
            "machine-import report lacks signature or boundary inventories"
        )
    signatures: dict[int, Mapping[str, Any]] = {}
    for index, value in enumerate(signatures_value):
        if not isinstance(value, Mapping):
            raise InterpreterMixedOriginalGenerationError(
                f"machine-import signature {index} is not an object"
            )
        signature_id = _u32(value.get("id"), f"signatures[{index}].id")
        if signature_id in signatures:
            raise InterpreterMixedOriginalGenerationError(
                "machine-import report has duplicate signature IDs"
            )
        if value.get("abi") not in {"cdecl", "stdcall"}:
            raise InterpreterMixedOriginalGenerationError(
                f"signatures[{index}].abi is outside the PE32 call profile"
            )
        signatures[signature_id] = value

    proposals: list[OriginalRegisterControlCallContractProposal] = []
    for index, value in enumerate(boundaries_value):
        if not isinstance(value, Mapping):
            raise InterpreterMixedOriginalGenerationError(
                f"machine-import boundary {index} is not an object"
            )
        signature_id = _u32(
            value.get("signature_id"), f"boundaries[{index}].signature_id"
        )
        signature = signatures.get(signature_id)
        if signature is None:
            raise InterpreterMixedOriginalGenerationError(
                f"boundary {index} references an absent signature"
            )
        boundary_identity = _original_import_identity_from_json(
            value.get("import"), f"boundaries[{index}].import"
        )
        signature_identity = _original_import_identity_from_json(
            signature.get("import"), f"signatures[{signature_id}].import"
        )
        if boundary_identity != signature_identity:
            raise InterpreterMixedOriginalGenerationError(
                f"boundary {index} import identity differs from its signature"
            )
        disposition = signature.get("disposition")
        if disposition not in {"returns", "terminates", "protocol"}:
            raise InterpreterMixedOriginalGenerationError(
                f"signature {signature_id} has an unsupported disposition"
            )
        arity = signature.get("arity")
        if not isinstance(arity, Mapping):
            raise InterpreterMixedOriginalGenerationError(
                f"signature {signature_id} has no checked arity"
            )
        arity_kind = arity.get("kind")
        if arity_kind == "fixed":
            argument_words = _u32(
                arity.get("words"),
                f"signatures[{signature_id}].arity.words",
            )
        elif arity_kind == "variadic":
            argument_words = _u32(
                value.get("argument_words"),
                f"boundaries[{index}].argument_words",
            )
        else:
            raise InterpreterMixedOriginalGenerationError(
                f"signature {signature_id} has an unsupported arity kind"
            )
        proposal = OriginalRegisterControlCallContractProposal(
            contract_id=_u32(value.get("id"), f"boundaries[{index}].id"),
            source_rva=_u32(
                value.get("source_rva"), f"boundaries[{index}].source_rva"
            ),
            instruction_rva=_u32(
                value.get("instruction_rva"),
                f"boundaries[{index}].instruction_rva",
            ),
            continuation_rva=_u32(
                value.get("continuation_rva"),
                f"boundaries[{index}].continuation_rva",
            ),
            preserved_registers=_PE32_CALL_PRESERVED_REGISTERS,
            import_identity=boundary_identity,
            return_register="eax" if disposition == "returns" else None,
            machine_contract_id=_u32(
                value.get("id"), f"boundaries[{index}].id"
            ),
            arity_kind=str(arity_kind),
            argument_words=argument_words,
        )
        proposal.validate(f"boundaries[{index}]")
        proposals.append(proposal)
    result = tuple(sorted(
        proposals,
        key=lambda item: (
            item.instruction_rva, item.continuation_rva, item.contract_id
        ),
    ))
    if len({item.contract_id for item in result}) != len(result):
        raise InterpreterMixedOriginalGenerationError(
            "machine-import report has duplicate boundary IDs"
        )
    return result


def load_checked_direct_call_summary_contract_proposals(
    authority_report: Path | str,
    *,
    original_sha256: str,
    state_machine_sha256: str,
) -> tuple[OriginalRegisterControlCallContractProposal, ...]:
    """Load term references for semantically authorized direct-call edges.

    No report status is interpreted.  Every returned proposal names a Lean term
    whose exact type is checked by the generated final module.
    """

    path = Path(authority_report)
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise InterpreterMixedOriginalGenerationError(
            f"unable to read direct-call authority report: {error}"
        ) from error
    if not isinstance(payload, Mapping) or payload.get("format") != (
        INTERPRETER_MIXED_DIRECT_CALL_AUTHORITY_FORMAT
    ):
        raise InterpreterMixedOriginalGenerationError(
            "direct-call authority report has an unsupported format"
        )
    inputs = payload.get("inputs")
    if not isinstance(inputs, Mapping):
        raise InterpreterMixedOriginalGenerationError(
            "direct-call authority report has no hash-bound inputs"
        )
    for field_name, expected in (
        ("original_sha256", original_sha256),
        ("state_machine_sha256", state_machine_sha256),
    ):
        if inputs.get(field_name) != expected:
            raise InterpreterMixedOriginalGenerationError(
                f"direct-call authority report {field_name} does not match"
            )
    rows = payload.get("contracts")
    if not isinstance(rows, list):
        raise InterpreterMixedOriginalGenerationError(
            "direct-call authority report contracts must be a list"
        )
    proposals: list[OriginalRegisterControlCallContractProposal] = []
    for index, value in enumerate(rows):
        if not isinstance(value, Mapping):
            raise InterpreterMixedOriginalGenerationError(
                f"direct-call authority contract {index} is not an object"
            )
        term = value.get("authorizing_lean_term")
        if not isinstance(term, Mapping):
            # Missing semantic premises are diagnostics, never contracts.
            continue
        origin = value.get("origin", "checked_direct_call_summary")
        if origin in {
            "checked_direct_call_caller_frame_word_summary",
            "checked_finite_origin_call_caller_frame_word_summary",
        }:
            dedicated_term = value.get(
                "caller_frame_word_authorizing_lean_term"
            )
            offsets = value.get("preserved_caller_frame_word_offsets")
            if dedicated_term != term:
                raise InterpreterMixedOriginalGenerationError(
                    f"direct-call authority contract {index} has no exact "
                    "caller-frame authority term"
                )
            if (
                not isinstance(offsets, list)
                or not offsets
                or len(set(offsets)) != len(offsets)
            ):
                raise InterpreterMixedOriginalGenerationError(
                    f"direct-call authority contract {index} has an invalid "
                    "caller-frame word inventory"
                )
            for offset_index, offset in enumerate(offsets):
                observed = _u32(
                    offset,
                    "contracts"
                    f"[{index}].preserved_caller_frame_word_offsets"
                    f"[{offset_index}]",
                )
                if observed > 65528:
                    raise InterpreterMixedOriginalGenerationError(
                        f"direct-call authority contract {index} has an "
                        "out-of-range caller-frame word"
                    )
            QualifiedLeanSymbol(
                module=str(term.get("module", "")),
                namespace=str(term.get("namespace", "")),
                symbol=str(term.get("symbol", "")),
            ).validate(
                f"contracts[{index}].caller_frame_word_authorizing_lean_term"
            )
            # Caller-frame preservation is consumed by runtime value-carry
            # closure, not by register-control propagation.
            continue
        register_fields: dict[str, tuple[str, ...]] = {}
        for field_name in (
            "preserved_registers",
            "callee_preserved_registers",
            "target_carried_registers",
        ):
            field_value = value.get(field_name)
            if not isinstance(field_value, list) or not all(
                isinstance(register, str) for register in field_value
            ):
                raise InterpreterMixedOriginalGenerationError(
                    f"direct-call authority contract {index} has invalid "
                    f"{field_name}"
                )
            register_fields[field_name] = tuple(field_value)
        symbol = QualifiedLeanSymbol(
            module=str(term.get("module", "")),
            namespace=str(term.get("namespace", "")),
            symbol=str(term.get("symbol", "")),
        )
        if origin not in {
            "checked_direct_call_summary",
            "checked_finite_origin_call_summary",
        }:
            raise InterpreterMixedOriginalGenerationError(
                f"direct-call authority contract {index} has invalid origin"
            )
        finite_target_values = value.get("finite_target_ids", [])
        if not isinstance(finite_target_values, list):
            raise InterpreterMixedOriginalGenerationError(
                f"direct-call authority contract {index} has invalid finite targets"
            )
        finite_target_ids = tuple(
            _u32(
                target_id,
                f"contracts[{index}].finite_target_ids[{target_index}]",
            )
            for target_index, target_id in enumerate(finite_target_values)
        )
        proposal = OriginalRegisterControlCallContractProposal(
            contract_id=_u32(
                value.get("contract_id"), f"contracts[{index}].contract_id"
            ),
            source_rva=_u32(
                value.get("source_rva"), f"contracts[{index}].source_rva"
            ),
            instruction_rva=_u32(
                value.get("callsite_rva"), f"contracts[{index}].callsite_rva"
            ),
            continuation_rva=_u32(
                value.get("continuation_rva"),
                f"contracts[{index}].continuation_rva",
            ),
            preserved_registers=register_fields["preserved_registers"],
            origin=str(origin),
            authorizing_lean_term=symbol,
            finite_target_ids=finite_target_ids,
            callee_preserved_registers=(
                register_fields["callee_preserved_registers"]
            ),
            target_carried_registers=(
                register_fields["target_carried_registers"]
            ),
        )
        proposal.validate(f"contracts[{index}]")
        proposals.append(proposal)
    result = tuple(sorted(
        proposals,
        key=lambda item: (
            item.instruction_rva, item.continuation_rva, item.contract_id
        ),
    ))
    if len({item.contract_id for item in result}) != len(result):
        raise InterpreterMixedOriginalGenerationError(
            "direct-call authority report has duplicate contract IDs"
        )
    return result


def _plan_interpreter_mixed_original_once(
    state_machine: Path | str,
    spec: InterpreterMixedOriginalSpec,
) -> InterpreterMixedOriginalPlan:
    """Parse untrusted state-machine records into a one-sided proof proposal."""

    spec.validate()
    path = Path(state_machine)
    try:
        raw = path.read_bytes()
    except OSError as error:
        raise InterpreterMixedOriginalGenerationError(
            f"unable to read state machine: {error}"
        ) from error

    rows = _read_rows(raw, path)
    parsed: list[dict[str, Any]] = []
    by_rva: dict[int, dict[str, Any]] = {}
    iat_by_va = {item.iat_va: item for item in spec.iat_imports}
    for line_number, row in rows:
        original = _mapping(row.get("original"), line_number, "original")
        rva = _u32(original.get("rva_start"), f"line {line_number} original.rva_start")
        end = _u32(original.get("rva_end"), f"line {line_number} original.rva_end")
        size = _positive_int(original.get("size"), f"line {line_number} original.size")
        if rva + size != end or end > 2**32:
            raise InterpreterMixedOriginalGenerationError(
                f"line {line_number} original span is inconsistent"
            )
        if rva in by_rva:
            raise InterpreterMixedOriginalGenerationError(
                f"duplicate original RVA 0x{rva:x} in state-machine inventory"
            )
        _reject_alias_fields(row, line_number)
        direct_rvas, indirect_sites = _successor_facts(
            row, line_number, rva, iat_by_va
        )
        item = {
            "line": line_number,
            "rva": rva,
            "size": size,
            "row": row,
            "direct_rvas": direct_rvas,
            "aliases": [],
            "indirect_sites": indirect_sites,
            "imports": _import_identities(row, line_number),
            "synthetic_terminal_padding": False,
        }
        parsed.append(item)
        by_rva[rva] = item

    if not parsed:
        raise InterpreterMixedOriginalGenerationError(
            "state-machine JSONL contains no transfer records"
        )
    parsed.sort(key=lambda item: item["rva"])
    for previous, current in zip(parsed, parsed[1:]):
        previous_end = previous["rva"] + previous["size"]
        if current["rva"] < previous_end:
            raise InterpreterMixedOriginalGenerationError(
                "overlapping original regions require an explicit checked alias "
                f"model: 0x{previous['rva']:x}..0x{previous_end:x} overlaps "
                f"0x{current['rva']:x}"
            )
    recovery_binary = _validated_recovery_binary(spec.recovery_pe)
    register_control_provenance: Mapping[str, Any] | None = None
    state_independent_false_edge_cuts: tuple[
        OriginalStateIndependentFalseEdgeCut, ...
    ] = ()
    try:
        if recovery_binary is not None:
            for item in parsed:
                item["indirect_sites"] = _discover_exact_internal_indirect_calls(
                    recovery_binary, item, item["indirect_sites"]
                )
        (
            terminal_edges,
            synthetic_terminal_rvas,
            terminal_recovery_failures,
        ) = _terminal_boundary_edges(
            parsed, spec.terminal_boundary_proposals, recovery_binary
        )
        parsed.sort(key=lambda item: item["rva"])
        for previous, current in zip(parsed, parsed[1:]):
            previous_end = previous["rva"] + previous["size"]
            if current["rva"] < previous_end:
                raise InterpreterMixedOriginalGenerationError(
                    "terminal continuation recovery overlaps an original region: "
                    f"0x{previous['rva']:x}..0x{previous_end:x} overlaps "
                    f"0x{current['rva']:x}"
                )
        id_by_rva = {
            item["rva"]: index for index, item in enumerate(parsed)
        }
        (
            recovered_aliases,
            alias_to_canonical,
            recovery_failures,
        ) = _recover_direct_target_aliases(
            parsed, recovery_binary, recovery_supplied=spec.recovery_pe is not None
        )
        recovery_failures = {
            **terminal_recovery_failures,
            **recovery_failures,
        }
        for alias_rva, canonical_rva in alias_to_canonical.items():
            by_rva[canonical_rva]["aliases"].append(alias_rva)
        resolved_id_by_rva = dict(id_by_rva)
        resolved_id_by_rva.update(
            (alias_rva, id_by_rva[canonical_rva])
            for alias_rva, canonical_rva in alias_to_canonical.items()
        )
        state_independent_false_edge_cuts = (
            _recover_state_independent_false_edge_cuts(
                recovery_binary,
                parsed,
                resolved_id_by_rva,
            )
        )
        relocation_counts = _highlow_relocation_counts(recovery_binary)
        predecessors_by_target_id: dict[int, list[dict[str, Any]]] = {}
        for predecessor in parsed:
            for successor_rva in predecessor["direct_rvas"]:
                successor_id = resolved_id_by_rva.get(successor_rva)
                if successor_id is not None:
                    predecessors_by_target_id.setdefault(successor_id, []).append(
                        predecessor
                    )
        call_contracts_by_edge = _register_control_call_contracts_by_edge(
            spec.register_control_call_contracts,
            resolved_id_by_rva,
        )
        static_word_call_seeds_by_site = {
            (authority.source_rva, authority.instruction_rva): authority
            for authority in spec.static_word_call_seed_authorities
        }
        for item in parsed:
            recovered_sites: list[OriginalIndirectSite] = []
            for site in item["indirect_sites"]:
                binding, failure = _recover_static_indirect_binding(
                    recovery_binary,
                    site,
                    resolved_id_by_rva,
                    parsed,
                    relocation_counts,
                    predecessors_by_target_id,
                    iat_by_va,
                    call_contracts_by_edge,
                    static_word_call_seeds_by_site,
                )
                if binding is not None:
                    recovered_sites.append(
                        replace(
                            site,
                            detail=_static_binding_detail(binding),
                            static_binding=binding,
                        )
                    )
                elif site.iat_import is not None:
                    recovered_sites.append(site)
                else:
                    initial_target_ids: tuple[int, ...] = ()
                    if site.category == "static_pointer_slot":
                        initial_target, _initial_failure = (
                            _recover_writable_slot_initial_target(
                                recovery_binary,
                                site,
                                resolved_id_by_rva,
                                parsed,
                                relocation_counts,
                                iat_by_va,
                            )
                        )
                        if initial_target is not None:
                            initial_target_ids = (initial_target[0],)
                    recovered_sites.append(
                        replace(
                            site,
                            detail=f"{site.detail}; {failure}",
                            initial_target_ids=initial_target_ids,
                        )
                    )
            item["indirect_sites"] = tuple(recovered_sites)
        if recovery_binary is not None:
            register_control_provenance = (
                _build_mixed_original_register_control_provenance(
                    binary=recovery_binary,
                    parsed=parsed,
                    resolved_id_by_rva=resolved_id_by_rva,
                    relocation_counts=relocation_counts,
                    iat_by_va=iat_by_va,
                    roots=(spec.entry_rva, *spec.tls_callback_rvas),
                    call_contract_proposals=(
                        spec.register_control_call_contracts
                    ),
                )
            )
            register_control_provenance = (
                _apply_register_import_flow_bindings_for_lean_replay(
                    binary=recovery_binary,
                    parsed=parsed,
                    resolved_id_by_rva=resolved_id_by_rva,
                    iat_by_va=iat_by_va,
                    call_contract_proposals=(
                        spec.register_control_call_contracts
                    ),
                    proposal=register_control_provenance,
                )
            )
    finally:
        if recovery_binary is not None:
            recovery_binary.pe.close()

    roots = (spec.entry_rva, *spec.tls_callback_rvas)
    for root in roots:
        if root not in id_by_rva:
            raise InterpreterMixedOriginalGenerationError(
                f"launch root 0x{root:x} is absent from the state-machine inventory"
            )

    blockers: list[OriginalGenerationBlocker] = []
    diagnostics: list[OriginalGenerationDiagnostic] = []
    successor_ids_by_rva: dict[int, tuple[int, ...]] = {}
    missing_rvas_by_rva: dict[int, tuple[int, ...]] = {}
    terminal_successor_cuts: list[OriginalTerminalSuccessorCut] = []
    false_cut_by_edge = {
        (cut.source_rva, cut.edge_rva): cut
        for cut in state_independent_false_edge_cuts
    }
    for item in parsed:
        successor_ids: list[int] = []
        missing_rvas: list[int] = []
        for successor_rva in item["direct_rvas"]:
            successor_id = resolved_id_by_rva.get(successor_rva)
            if successor_id is None:
                missing_rvas.append(successor_rva)
            elif (item["rva"], successor_rva) in false_cut_by_edge:
                continue
            elif (
                proposal := terminal_edges.get((item["rva"], successor_rva))
            ) is not None:
                terminal_successor_cuts.append(
                    OriginalTerminalSuccessorCut(
                        boundary_id=proposal.boundary_id,
                        source_target_id=id_by_rva[item["rva"]],
                        continuation_target_id=successor_id,
                        source_rva=item["rva"],
                        continuation_rva=successor_rva,
                        synthetic_padding=successor_rva
                        in synthetic_terminal_rvas,
                    )
                )
            elif successor_id not in successor_ids:
                successor_ids.append(successor_id)
        for site in item["indirect_sites"]:
            target_ids = (
                site.initial_target_ids
                if site.static_binding is None
                else (*site.static_binding.target_ids, *site.initial_target_ids)
            )
            for successor_id in target_ids:
                if successor_id not in successor_ids:
                    successor_ids.append(successor_id)
        successor_ids_by_rva[item["rva"]] = tuple(successor_ids)
        missing_rvas_by_rva[item["rva"]] = tuple(missing_rvas)

    reachable: list[int] = []
    seen: set[int] = set()
    queue = deque(id_by_rva[rva] for rva in roots)
    while queue:
        target_id = queue.popleft()
        if target_id in seen:
            continue
        seen.add(target_id)
        reachable.append(target_id)
        item = parsed[target_id]
        queue.extend(successor_ids_by_rva[item["rva"]])

    if register_control_provenance is not None:
        body = json.loads(json.dumps(register_control_provenance))
        removed_sites = {
            (flow.get("use_source_rva"), flow.get("use_instruction_rva"))
            for flow in body.get("import_address_flows", [])
            if isinstance(flow, Mapping)
            and flow.get("status") == "selected_for_generated_lean_replay"
            and resolved_id_by_rva.get(flow.get("use_source_rva")) in seen
        }
        body["unresolved_indirect_control_blockers_removed"] = len(removed_sites)
        body["adapter_sha256"] = hashlib.sha256(json.dumps(
            {
                key: value for key, value in body.items()
                if key != "adapter_sha256"
            },
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode()).hexdigest()
        register_control_provenance = body

    reachable_imports: set[OriginalImportIdentity] = set()
    reachable_indirect_sites: list[OriginalIndirectSite] = []
    for target_id, item in enumerate(parsed):
        source_reachable = target_id in seen
        for successor_rva in missing_rvas_by_rva[item["rva"]]:
            detail = (
                f"direct successor 0x{successor_rva:x} has no transfer record"
            )
            if successor_rva in recovery_failures:
                detail += f"; recovery failed: {recovery_failures[successor_rva]}"
            if source_reachable:
                blockers.append(
                    OriginalGenerationBlocker(
                        "missing_reachable_successor", item["rva"], detail
                    )
                )
            else:
                diagnostics.append(
                    OriginalGenerationDiagnostic(
                        "unreachable_missing_successor", item["rva"], detail
                    )
                )
        if source_reachable:
            reachable_imports.update(item["imports"])
        for site in item["indirect_sites"]:
            if not source_reachable:
                if site.has_checked_binding_proposal:
                    continue
                diagnostics.append(
                    OriginalGenerationDiagnostic(
                        "unreachable_indirect_control",
                        item["rva"],
                        f"{site.category} at 0x{site.instruction_rva:x}: "
                        f"{site.detail}",
                    )
                )
                continue
            reachable_indirect_sites.append(site)
            if site.iat_import is not None:
                reachable_imports.add(site.iat_import.identity)
                continue
            if isinstance(site.static_binding, OriginalRegisterImportBinding):
                reachable_imports.add(site.static_binding.imported.identity)
                continue
            if site.static_binding is not None:
                continue
            blockers.append(
                OriginalGenerationBlocker(
                    "unresolved_indirect_control",
                    item["rva"],
                    f"{site.category} at 0x{site.instruction_rva:x}: "
                    f"{site.detail}",
                )
            )

    if reachable_imports and spec.bindings.machine_import_call_contracts is None:
        blockers.append(
            OriginalGenerationBlocker(
                "machine_import_contracts_unbound",
                None,
                f"{len(reachable_imports)} reachable normalized import identities "
                "require a qualified exact machine-call contract list binding",
            )
        )

    blockers = sorted(
        set(blockers),
        key=lambda item: (
            item.reason_code,
            -1 if item.rva is None else item.rva,
            item.detail,
        ),
    )
    diagnostics = sorted(
        set(diagnostics),
        key=lambda item: (
            item.reason_code,
            -1 if item.rva is None else item.rva,
            item.detail,
        ),
    )
    root_set = set(roots)
    regions = tuple(
        OriginalRegion(
            target_id=index,
            rva=item["rva"],
            size=item["size"],
            successor_ids=successor_ids_by_rva[item["rva"]],
            root=item["rva"] in root_set,
            alias_rvas=tuple(sorted(item["aliases"])),
            missing_successor_rvas=missing_rvas_by_rva[item["rva"]],
            import_identities=tuple(_sorted_imports(item["imports"])),
            indirect_sites=tuple(item["indirect_sites"]),
            synthetic_terminal_padding=bool(
                item.get("synthetic_terminal_padding", False)
            ),
        )
        for index, item in enumerate(parsed)
    )
    return InterpreterMixedOriginalPlan(
        spec=spec,
        state_machine_sha256=hashlib.sha256(raw).hexdigest(),
        regions=regions,
        import_identities=tuple(_sorted_imports(reachable_imports)),
        reachable_target_ids=tuple(sorted(seen)),
        recovered_aliases=recovered_aliases,
        terminal_successor_cuts=tuple(
            sorted(
                terminal_successor_cuts,
                key=lambda item: (
                    item.source_target_id,
                    item.continuation_target_id,
                    item.boundary_id,
                ),
            )
        ),
        state_independent_false_edge_cuts=state_independent_false_edge_cuts,
        indirect_sites=tuple(
            sorted(
                reachable_indirect_sites,
                key=lambda item: (
                    item.source_rva,
                    item.instruction_rva,
                    item.category,
                ),
            )
        ),
        register_control_provenance=register_control_provenance,
        blockers=tuple(blockers),
        diagnostics=tuple(diagnostics),
    )


def _propagated_machine_import_contract_id(
    site: OriginalIndirectSite,
    identity: OriginalImportIdentity,
    occupied: set[int],
) -> int:
    selector = (
        f"symbol:{identity.symbol}"
        if identity.symbol is not None
        else f"ordinal:{identity.ordinal}"
    )
    seed = hashlib.sha256(
        (
            f"propagated-machine-import-v1\0{site.source_rva}\0"
            f"{site.instruction_rva}\0{site.continuation_rva}\0"
            f"{identity.dll.lower()}\0{selector}"
        ).encode()
    ).digest()
    candidate = 0xC0000000 | (
        int.from_bytes(seed[:4], "little") & 0x3FFFFFFF
    )
    while candidate in occupied:
        candidate = 0xC0000000 | ((candidate + 1) & 0x3FFFFFFF)
    return candidate


def _derived_register_import_call_contracts(
    plan: InterpreterMixedOriginalPlan,
) -> tuple[OriginalRegisterControlCallContractProposal, ...]:
    """Derive exact call-site summaries from checked import provenance.

    The returned rows do not make the provenance proposal authoritative. They
    connect a distinct call-site ID to an existing canonical machine contract;
    generated Lean still checks the import-register invariant, exact indirect
    call bytes, machine-contract lookup, ABI preservation, and continuation.
    Variadic calls remain explicit frontiers because identity alone does not
    determine their concrete argument inventory.
    """

    current = plan.spec.register_control_call_contracts
    sites = {
        (proposal.instruction_rva, proposal.continuation_rva)
        for proposal in current
    }
    occupied = {proposal.contract_id for proposal in current}
    canonical_by_identity: dict[
        OriginalImportIdentity,
        list[OriginalRegisterControlCallContractProposal],
    ] = {}
    for proposal in current:
        if (
            proposal.origin == "machine_import_boundary"
            and proposal.import_identity is not None
            and proposal.arity_kind == "fixed"
        ):
            canonical_by_identity.setdefault(
                proposal.import_identity, []
            ).append(proposal)

    derived: list[OriginalRegisterControlCallContractProposal] = []
    for region in plan.regions:
        for site in region.indirect_sites:
            binding = site.static_binding
            if (
                not site.is_call
                or site.continuation_rva is None
                or not isinstance(binding, OriginalRegisterImportBinding)
                or (site.instruction_rva, site.continuation_rva) in sites
            ):
                continue
            candidates = canonical_by_identity.get(
                binding.imported.identity, []
            )
            shapes = {
                (
                    candidate.machine_authority_id,
                    candidate.preserved_registers,
                    candidate.return_register,
                    candidate.argument_words,
                )
                for candidate in candidates
            }
            # Multiple boundary IDs may instantiate the same fixed signature.
            # Their machine contracts are definitionally equal except for ID,
            # so choose the lowest exact authority deterministically.
            semantic_shapes = {
                (
                    candidate.preserved_registers,
                    candidate.return_register,
                    candidate.argument_words,
                )
                for candidate in candidates
            }
            if not candidates or len(semantic_shapes) != 1:
                continue
            canonical = min(
                candidates,
                key=lambda candidate: (
                    candidate.machine_authority_id
                    if candidate.machine_authority_id is not None
                    else 2**32,
                    candidate.contract_id,
                ),
            )
            if canonical.machine_authority_id is None or len(shapes) == 0:
                continue
            contract_id = _propagated_machine_import_contract_id(
                site, binding.imported.identity, occupied
            )
            occupied.add(contract_id)
            sites.add((site.instruction_rva, site.continuation_rva))
            derived.append(OriginalRegisterControlCallContractProposal(
                contract_id=contract_id,
                source_rva=site.source_rva,
                instruction_rva=site.instruction_rva,
                continuation_rva=site.continuation_rva,
                preserved_registers=canonical.preserved_registers,
                import_identity=binding.imported.identity,
                return_register=canonical.return_register,
                machine_contract_id=canonical.machine_authority_id,
                arity_kind="fixed",
                argument_words=canonical.argument_words,
                origin="propagated_machine_import",
            ))
    return tuple(sorted(
        derived,
        key=lambda proposal: (
            proposal.instruction_rva,
            proposal.continuation_rva,
            proposal.contract_id,
        ),
    ))


def plan_interpreter_mixed_original(
    state_machine: Path | str,
    spec: InterpreterMixedOriginalSpec,
) -> InterpreterMixedOriginalPlan:
    """Plan original semantics and close finite register-import call chains.

    Each iteration is monotone: it may add a call-site contract only after the
    prior iteration selected a unique import-register provenance path. The
    fixed point is bounded by the finite indirect-call inventory.
    """

    current = spec
    prior_sites = len(current.register_control_call_contracts)
    while True:
        plan = _plan_interpreter_mixed_original_once(state_machine, current)
        derived = _derived_register_import_call_contracts(plan)
        if not derived:
            return plan
        current = replace(
            current,
            register_control_call_contracts=(
                *current.register_control_call_contracts,
                *derived,
            ),
        )
        current.validate()
        next_sites = len(current.register_control_call_contracts)
        if next_sites <= prior_sites:
            raise AssertionError(
                "register-import contract fixed point did not advance"
            )
        prior_sites = next_sites


def write_relational_interpreter_mixed_original(
    out: Path | str,
    plan: InterpreterMixedOriginalPlan,
) -> tuple[Path, ...]:
    """Write deterministic sharded Lean data and the proof bundle."""

    if not plan.complete:
        reasons = ", ".join(
            sorted({blocker.reason_code for blocker in plan.blockers})
        )
        raise InterpreterMixedOriginalGenerationError(
            "refusing to emit original authority from an incomplete inventory: "
            + reasons
        )
    write_relational_interpreter_mixed_original_base(out, plan)
    return write_relational_interpreter_mixed_original_final(out, plan)


def _balanced_shard_sizes(row_count: int, maximum_size: int) -> list[int]:
    """Choose deterministic near-equal shard sizes below an upper bound."""

    if row_count < 0:
        raise InterpreterMixedOriginalGenerationError(
            "finite-index row count must be nonnegative"
        )
    if maximum_size <= 0:
        raise InterpreterMixedOriginalGenerationError(
            "finite-index shard size must be positive"
        )
    if row_count == 0:
        return []
    shard_count = (row_count + maximum_size - 1) // maximum_size
    base_size, larger_count = divmod(row_count, shard_count)
    return [
        base_size + (1 if index < larger_count else 0)
        for index in range(shard_count)
    ]


def _balanced_shards[T](rows: Sequence[T], maximum_size: int) -> list[Sequence[T]]:
    """Partition rows without leaving an anomalously small final shard.

    The generated shard indexes are composed as checked AVL trees.  A naive
    fixed-width split can leave one short index whose height differs by more
    than one from every other shard, making an otherwise valid inventory
    impossible to compose.  Distributing the remainder deterministically
    keeps shard heights comparable while preserving the requested upper bound.
    """

    shards: list[Sequence[T]] = []
    offset = 0
    for size in _balanced_shard_sizes(len(rows), maximum_size):
        shards.append(rows[offset : offset + size])
        offset += size
    assert offset == len(rows)
    return shards


def _mixed_original_base_plan(
    plan: InterpreterMixedOriginalPlan,
) -> InterpreterMixedOriginalPlan:
    base_spec = replace(
        plan.spec,
        output_module=INTERPRETER_MIXED_ORIGINAL_BASE_MODULE,
        namespace=f"{plan.spec.namespace}Base",
    )
    return replace(plan, spec=base_spec)


def write_relational_interpreter_mixed_original_base(
    out: Path | str,
    plan: InterpreterMixedOriginalPlan,
) -> tuple[Path, ...]:
    """Emit stable exact context and decoded data without reachability authority."""

    plan = _mixed_original_base_plan(plan)
    root = Path(out)
    stage_a = root / "StageA"
    stage_a.mkdir(parents=True, exist_ok=True)
    spec = plan.spec
    spec.validate()
    shard_regions = _balanced_shards(plan.regions, spec.shard_size)
    written: list[Path] = []
    shard_modules: list[str] = []
    for index, regions in enumerate(shard_regions):
        local_name = f"{spec.output_module}Shard{index:04d}"
        module = f"StageA.{local_name}"
        path = stage_a / f"{local_name}.lean"
        path.write_text(
            _shard_source(plan, index, regions), encoding="utf-8"
        )
        written.append(path)
        shard_modules.append(module)

    bundle_path = stage_a / f"{spec.output_module}.lean"
    bundle_path.write_text(
        _bundle_source(
            plan, shard_modules, shard_regions, emit_final_authority=False
        ),
        encoding="utf-8",
    )
    written.append(bundle_path)
    manifest = root / "interpreter-mixed-original-base-plan.json"
    manifest.write_text(
        json.dumps(plan.to_json(), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    written.append(manifest)
    return tuple(written)


def write_relational_interpreter_mixed_original_final(
    out: Path | str,
    plan: InterpreterMixedOriginalPlan,
) -> tuple[Path, ...]:
    """Emit authority-sensitive carrier data and conditional reachability."""

    root = Path(out)
    stage_a = root / "StageA"
    stage_a.mkdir(parents=True, exist_ok=True)
    spec = plan.spec
    spec.validate()
    shard_regions = _balanced_shards(plan.regions, spec.shard_size)
    written: list[Path] = []
    shard_modules: list[str] = []
    for index, regions in enumerate(shard_regions):
        local_name = f"{spec.output_module}FinalShard{index:04d}"
        module = f"StageA.{local_name}"
        path = stage_a / f"{local_name}.lean"
        path.write_text(
            _final_shard_source(plan, index, regions), encoding="utf-8"
        )
        written.append(path)
        shard_modules.append(module)
    bundle_path = stage_a / f"{spec.output_module}.lean"
    bundle_path.write_text(
        _final_bundle_source(plan, shard_modules, shard_regions),
        encoding="utf-8",
    )
    written.append(bundle_path)
    manifest = root / "interpreter-mixed-original-plan.json"
    manifest.write_text(
        json.dumps(
            plan.to_json(
                include_original_combined_reachability_declarations=True
            ),
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    written.append(manifest)
    return tuple(written)


def write_register_finite_origin_call_entry_authorities(
    out: Path | str,
    plan: InterpreterMixedOriginalPlan,
    *,
    instruction_rvas: Iterable[int],
) -> tuple[OriginalRegisterFiniteOriginCallEntryAuthority, ...]:
    """Emit cacheable call-entry certificates unlocked by prior call proofs."""

    requested = tuple(sorted(set(instruction_rvas)))
    if any(
        not isinstance(value, int)
        or isinstance(value, bool)
        or not 0 <= value < 2**32
        for value in requested
    ):
        raise InterpreterMixedOriginalGenerationError(
            "finite-origin entry instruction RVAs must be 32-bit integers"
        )
    sites_by_instruction: dict[int, OriginalIndirectSite] = {}
    ambiguous: set[int] = set()
    for region in plan.regions:
        for site in region.indirect_sites:
            if site.instruction_rva not in requested:
                continue
            prior = sites_by_instruction.get(site.instruction_rva)
            if prior is not None and prior != site:
                ambiguous.add(site.instruction_rva)
                sites_by_instruction.pop(site.instruction_rva, None)
            elif site.instruction_rva not in ambiguous:
                sites_by_instruction[site.instruction_rva] = site
    if ambiguous:
        raise InterpreterMixedOriginalGenerationError(
            "finite-origin call entry RVAs are ambiguous: "
            + ", ".join(f"0x{value:x}" for value in sorted(ambiguous))
        )

    root = Path(out)
    stage_a = root / "StageA"
    stage_a.mkdir(parents=True, exist_ok=True)
    base_namespace = (
        "StageA.GeneratedRelational.InterpreterMixedOriginalBase"
    )
    results: list[OriginalRegisterFiniteOriginCallEntryAuthority] = []
    for instruction_rva in requested:
        site = sites_by_instruction.get(instruction_rva)
        if (
            site is None
            or not site.is_call
            or site.continuation_rva is None
            or not isinstance(
                site.static_binding, OriginalRegisterCodePointerBinding
            )
            or site.static_binding.continuation_target_id is None
        ):
            continue
        binding = site.static_binding
        source_target_id = _id_for_rva(plan, site.source_rva)
        module_name = (
            "GeneratedRelationalRegisterFiniteOriginCallEntry"
            f"{source_target_id:08d}"
        )
        module = f"StageA.{module_name}"
        namespace = (
            "StageA.Generated.RegisterFiniteOriginCallEntry"
            f"{source_target_id:08d}"
        )
        referenced_contract_ids = {
            edge.contract_id
            for edge in binding.edges
            if edge.kind == "call_return" and edge.contract_id is not None
        }
        imported_modules = [
            "StageA.RelationalInterpreterMixedOriginal",
            "StageA.RelationalIndirectExitAdapters",
            f"StageA.{INTERPRETER_MIXED_ORIGINAL_BASE_MODULE}ContextData",
            *[
                proposal.authorizing_lean_term.module
                for proposal in plan.spec.register_control_call_contracts
                if proposal.contract_id in referenced_contract_ids
                and proposal.authorizing_lean_term is not None
            ],
        ]
        imports = "\n".join(
            f"import {dependency}"
            for dependency in dict.fromkeys(imported_modules)
        )
        source_region = _lean_carrier_region(
            plan, plan.regions[source_target_id]
        )
        certificate_source = _lean_static_indirect_check(plan, 0, site)
        source = f"""{imports}

namespace {namespace}

open StageA.Formal StageA.Relational
open StageA.Relational.InterpreterMixedContext
open StageA.Relational.InterpreterMixedOriginal

set_option maxRecDepth 1000000
set_option maxHeartbeats 0

def generatedOriginalStaticContext : OriginalDecodedStaticContext :=
  {base_namespace}.generatedOriginalStaticContext

def generatedOriginalCarrierContext : StaticProofContext :=
  {base_namespace}.generatedOriginalCarrierContext

def generatedOriginalCarrierRegionIndex : FiniteIndex RegionRelation :=
  {base_namespace}.generatedOriginalCarrierRegionIndex

def generatedOriginalStaticIndirectRegion{source_target_id} : RegionRelation :=
  {source_region}

{certificate_source}

def generatedIndirectExitCertificate :
    StageA.Relational.ValueProvenance.CheckedIndirectExitCertificate
      generatedOriginalCarrierContext
      generatedOriginalStaticIndirectRegion{source_target_id}.inputInvariant
      generatedOriginalStaticIndirect0OriginalNormalized
      generatedOriginalStaticIndirect0CandidateNormalized :=
  generatedOriginalStaticIndirect0IndirectExitCertificate
    (by
      simpa [generatedOriginalCarrierContext] using
        {base_namespace}.generatedOriginalCarrierContextStructurallyValid)

theorem generatedIndirectExitCertificateExact :
    generatedIndirectExitCertificate.certificate =
      StageA.Relational.IndirectExitAdapters.fixedRegisterIndirectCertificate
        generatedOriginalStaticIndirect0Claim := rfl

end {namespace}
"""
        path = stage_a / f"{module_name}.lean"
        path.write_text(source, encoding="utf-8")
        results.append(
            OriginalRegisterFiniteOriginCallEntryAuthority(
                source_rva=site.source_rva,
                instruction_rva=site.instruction_rva,
                continuation_rva=site.continuation_rva,
                continuation_target_id=binding.continuation_target_id,
                target_ids=(binding.target_id,),
                module=module,
                namespace=namespace,
                indirect_exit_authority_term=(
                    f"{namespace}.generatedIndirectExitCertificate"
                ),
                indirect_exit_certificate_exact_term=(
                    f"{namespace}.generatedIndirectExitCertificateExact"
                ),
            )
        )
    return tuple(results)


def _machine_import_boundary_site_targets(
    plan: InterpreterMixedOriginalPlan,
) -> tuple[tuple[OriginalMachineImportBoundarySiteProposal, int, int], ...]:
    by_entry_rva: dict[int, int] = {}
    for region in plan.regions:
        for rva in (region.rva, *region.alias_rvas):
            prior = by_entry_rva.get(rva)
            if prior is not None and prior != region.target_id:
                raise InterpreterMixedOriginalGenerationError(
                    f"ambiguous region entry RVA 0x{rva:x}"
                )
            by_entry_rva[rva] = region.target_id

    resolved: list[
        tuple[OriginalMachineImportBoundarySiteProposal, int, int]
    ] = []
    for site in plan.spec.machine_import_boundary_sites:
        source_matches = [
            region.target_id
            for region in plan.regions
            if region.rva <= site.execution_source_rva
            < region.rva + region.size
        ]
        if len(source_matches) != 1:
            raise InterpreterMixedOriginalGenerationError(
                f"machine-import boundary {site.boundary_id} execution RVA "
                f"0x{site.execution_source_rva:x} belongs to "
                f"{len(source_matches)} decoded regions"
            )
        continuation_target_id = by_entry_rva.get(site.continuation_rva)
        if continuation_target_id is None:
            raise InterpreterMixedOriginalGenerationError(
                f"machine-import boundary {site.boundary_id} continuation RVA "
                f"0x{site.continuation_rva:x} is not a checked region entry"
            )
        resolved.append(
            (site, source_matches[0], continuation_target_id)
        )
    return tuple(resolved)


def _lean_machine_import_boundary_projection(
    plan: InterpreterMixedOriginalPlan,
) -> str:
    bindings = plan.spec.bindings.machine_import_boundaries
    if bindings is None:
        return ""
    boundaries = bindings.boundaries.qualified
    inventory = bindings.inventory.qualified
    namespace = "StageA.Relational.StaticMachineImportContracts"
    site_bindings = ", ".join(
        "{ "
        f"boundaryId := {site.boundary_id}, "
        f"sourceTargetId := {source_target_id}, "
        f"continuationTargetId := {continuation_target_id}, "
        "boundaryInvariant := generatedOriginalCarrierInvariantAt "
        f"{source_target_id}, "
        "targetInvariant := generatedOriginalCarrierInvariantAt "
        f"{continuation_target_id} "
        "}"
        for site, source_target_id, continuation_target_id in (
            _machine_import_boundary_site_targets(plan)
        )
    )
    return f"""def generatedOriginalMachineImportBoundarySiteBindings :
    List {namespace}.StaticMachineImportBoundarySiteBinding :=
  [{site_bindings}]

theorem generatedOriginalMachineImportBoundarySiteBindingsIndexedChecked :
    {namespace}.staticMachineImportBoundarySiteBindingsIndexedValid
      generatedOriginalCarrierContext generatedOriginalCarrierRegionIndex
      {boundaries} {inventory}
      generatedOriginalMachineImportBoundarySiteBindings = true := by
  decide +kernel

theorem generatedOriginalMachineImportBoundarySiteBindingsChecked :
    {namespace}.staticMachineImportBoundarySiteBindingsValid
      generatedOriginalCarrierContext generatedOriginalCarrierRegions
      {boundaries} {inventory}
      generatedOriginalMachineImportBoundarySiteBindings = true := by
  exact {namespace}.staticMachineImportBoundarySiteBindingsIndexedValid_sound
    generatedOriginalCarrierContext generatedOriginalCarrierRegionIndex
    {boundaries} {inventory}
    generatedOriginalMachineImportBoundarySiteBindings
    generatedOriginalCarrierRegionIndexSizesSound
    generatedOriginalMachineImportBoundarySiteBindingsIndexedChecked

theorem generatedOriginalMachineImportBoundarySiteRegionsChecked :
    generatedOriginalMachineImportBoundarySiteBindings.all fun binding =>
      (generatedOriginalCarrierRegionIndex.get?
        binding.sourceTargetId).isSome &&
        (generatedOriginalCarrierRegionIndex.get?
          binding.continuationTargetId).isSome := by
  decide +kernel

def generatedOriginalExternalCallSites : List ExternalCallSiteContract :=
  {namespace}.staticMachineImportBoundaryExternalCallSites
    generatedOriginalMachineImportBoundarySiteBindings"""


def _lean_terminal_successor_projection(
    plan: InterpreterMixedOriginalPlan,
) -> str:
    cuts = plan.terminal_successor_cuts
    bindings = plan.spec.bindings.machine_import_boundaries
    if not cuts:
        return ""
    if bindings is None:
        raise InterpreterMixedOriginalGenerationError(
            "terminal successor cuts require exact boundary-indexed bindings"
        )
    branches = "\n".join(
        (
            f"    if boundary.id == {cut.boundary_id} then\n"
            "      some {\n"
            f"        sourceTargetId := {cut.source_target_id}\n"
            f"        continuationTargetId := {cut.continuation_target_id}\n"
            "        binding := { boundary }\n"
            f"        syntheticPadding := {str(cut.synthetic_padding).lower()}\n"
            "      }\n"
            "    else"
        )
        for cut in cuts
    )
    namespace = "StageA.Relational.InterpreterMixedOriginal"
    signatures = bindings.signatures.qualified
    boundaries = bindings.boundaries.qualified
    inventory = bindings.inventory.qualified
    return f"""def generatedOriginalTerminalSuccessorCuts :
    List {namespace}.OriginalTerminalSuccessorCut :=
  {boundaries}.filterMap fun boundary =>
{branches}
      none

theorem generatedOriginalTerminalSuccessorCutsChecked :
    {namespace}.originalTerminalSuccessorCutsValid
      generatedOriginalStaticContext generatedOriginalCarrierContext
      {signatures} {boundaries} {inventory}
      generatedOriginalTerminalSuccessorCuts {len(cuts)} = true := by
  decide +kernel"""


def _lean_state_independent_false_edge_checks(
    plan: InterpreterMixedOriginalPlan,
) -> str:
    namespace = "StageA.Relational.InterpreterMixedOriginal"
    checks: list[str] = []
    for index, cut in enumerate(plan.state_independent_false_edge_cuts):
        name = f"generatedOriginalStateIndependentFalseEdgeCut{index}"
        checks.append(f"""def {name} :
    {namespace}.OriginalStateIndependentFalseEdgeCut := {{
  sourceTargetId := {cut.source_target_id}
  destinationTargetId := {cut.destination_target_id}
  edgeRva := {cut.edge_rva}
}}

theorem {name}Checked :
    {name}.valid generatedOriginalStaticContext = true := by
  decide +kernel

theorem {name}Impossible :
    {name}.Impossible generatedOriginalStaticContext :=
  {namespace}.originalStateIndependentFalseEdgeCut_valid_impossible
    {name}Checked""")
    return "\n\n".join(checks)


def _shard_source(
    plan: InterpreterMixedOriginalPlan,
    shard_index: int,
    regions: Sequence[OriginalRegion],
) -> str:
    namespace = plan.spec.namespace
    target_rows = [_lean_original_target(region) for region in regions]
    address_rows = [
        row
        for region in regions
        for row in _lean_code_addresses(region)
    ]
    region_rows = [_lean_original_region(region) for region in regions]
    static_rows = [_lean_static_target(region) for region in regions]
    carrier_rows = [_lean_carrier_region(plan, region) for region in regions]
    static_indirect_regions = "\n\n".join(
        f"def generatedOriginalStaticIndirectRegion{region.target_id} : "
        f"RegionRelation :=\n  {_lean_carrier_region(plan, region)}"
        for region in regions
        if any(site.static_binding is not None for site in region.indirect_sites)
    )
    return f"""import StageA.RelationalInterpreterMixedOriginal

namespace {namespace}

open StageA.Formal StageA.Relational
open StageA.Relational.InterpreterMixedContext

def generatedOriginalTargetIndexShard{shard_index} :
    FiniteIndex OriginalCodeTarget :=
  {_lean_finite_index(target_rows)}

def generatedOriginalAddressIndexShard{shard_index} :
    FiniteIndex OriginalCodeAddress :=
  {_lean_finite_index(address_rows)}

def generatedOriginalStaticAddressIndexShard{shard_index} :
    FiniteIndex StaticCodeAddress :=
  {_lean_finite_index(address_rows)}

def generatedOriginalRegionIndexShard{shard_index} :
    FiniteIndex OriginalDecodedRegion :=
  {_lean_finite_index(region_rows)}

def generatedOriginalStaticTargetIndexShard{shard_index} :
    FiniteIndex CodeTargetPair :=
  {_lean_finite_index(static_rows)}

def generatedOriginalCarrierRegionIndexShard{shard_index} :
    FiniteIndex RegionRelation :=
  {_lean_finite_index(carrier_rows)}

def generatedOriginalCarrierRegionsShard{shard_index} : List RegionRelation :=
  generatedOriginalCarrierRegionIndexShard{shard_index}.toList

{static_indirect_regions}

end {namespace}
"""


def _final_shard_source(
    plan: InterpreterMixedOriginalPlan,
    shard_index: int,
    regions: Sequence[OriginalRegion],
) -> str:
    namespace = plan.spec.namespace
    target_rows = [_lean_original_target(region) for region in regions]
    address_rows = [
        row for region in regions for row in _lean_code_addresses(region)
    ]
    region_rows = [_lean_original_region(region) for region in regions]
    static_rows = [_lean_static_target(region) for region in regions]
    carrier_rows = [_lean_carrier_region(plan, region) for region in regions]
    static_indirect_regions = "\n\n".join(
        f"def generatedOriginalStaticIndirectRegion{region.target_id} : "
        f"RegionRelation :=\n  {_lean_carrier_region(plan, region)}"
        for region in regions
        if any(site.static_binding is not None for site in region.indirect_sites)
    )
    return f"""import StageA.RelationalInterpreterMixedOriginal
import StageA.{INTERPRETER_MIXED_ORIGINAL_BASE_MODULE}

namespace {namespace}

open StageA.Formal StageA.Relational
open StageA.Relational.InterpreterMixedContext

def generatedOriginalTargetIndexFinalShard{shard_index} :
    FiniteIndex OriginalCodeTarget :=
  {_lean_finite_index(target_rows)}

def generatedOriginalAddressIndexFinalShard{shard_index} :
    FiniteIndex OriginalCodeAddress :=
  {_lean_finite_index(address_rows)}

def generatedOriginalRegionIndexFinalShard{shard_index} :
    FiniteIndex OriginalDecodedRegion :=
  {_lean_finite_index(region_rows)}

def generatedOriginalStaticTargetIndexFinalShard{shard_index} :
    FiniteIndex CodeTargetPair :=
  {_lean_finite_index(static_rows)}

def generatedOriginalCarrierRegionIndexFinalShard{shard_index} :
    FiniteIndex RegionRelation :=
  {_lean_finite_index(carrier_rows)}

def generatedOriginalCarrierRegionsFinalShard{shard_index} :
    List RegionRelation :=
  generatedOriginalCarrierRegionIndexFinalShard{shard_index}.toList

{static_indirect_regions}

end {namespace}
"""


def _final_bundle_source(
    plan: InterpreterMixedOriginalPlan,
    shard_modules: Sequence[str],
    shard_regions: Sequence[Sequence[OriginalRegion]],
) -> str:
    spec = plan.spec
    bindings = spec.bindings
    q = bindings.qualified
    base_namespace = f"{spec.namespace}Base"
    imported_modules = [
        "StageA.RelationalInterpreterMixedOriginal",
        "StageA.RelationalIndirectExitAdapters",
        "StageA.RelationalPEWorldExecution",
        *(
            ["StageA.RelationalInternalDirectCallMixedOriginalIntegration"]
            if any(
                proposal.authorizing_lean_term is not None
                for proposal in spec.register_control_call_contracts
            )
            else []
        ),
        f"StageA.{INTERPRETER_MIXED_ORIGINAL_BASE_MODULE}",
        *(
            [bindings.machine_import_call_contracts.module]
            if bindings.machine_import_call_contracts is not None
            else []
        ),
        *[
            proposal.authorizing_lean_term.module
            for proposal in spec.register_control_call_contracts
            if proposal.authorizing_lean_term is not None
        ],
        *shard_modules,
    ]
    imports = "\n".join(
        f"import {module}" for module in dict.fromkeys(imported_modules)
    )
    carrier_region_refs = [
        (f"generatedOriginalCarrierRegionIndexFinalShard{index}", len(regions))
        for index, regions in enumerate(shard_regions)
    ]
    carrier_region_index = _lean_index_refs(carrier_region_refs)
    boundary_projection = _lean_machine_import_boundary_projection(plan)
    terminal_successor_projection = _lean_terminal_successor_projection(plan)
    false_edge_checks = _lean_state_independent_false_edge_checks(plan)
    static_indirect_checks = _lean_static_indirect_checks(plan)
    blocker_comment = "\n".join(
        f"-- {item.reason_code}: {item.detail}" for item in plan.blockers
    )
    diagnostic_comment = "\n".join(
        f"-- {item.reason_code}: {item.detail}" for item in plan.diagnostics
    )
    alias_compatibility = "\n".join(
        f"-- recovered alias RVA {item.alias_rva}: size := {item.size}"
        for item in plan.recovered_aliases
    )
    static_word_compatibility = (
        "-- base context field: staticWordRelationSlots := ["
        + ", ".join(
            _lean_static_word_slot(binding)
            for binding in _unique_static_word_slot_bindings(plan)
        )
        + "]"
    )
    frame_offsets = ", ".join(
        "ReturnSlotOffsetInventory.zero" for _ in spec.tls_callback_rvas
    )
    machine_contracts = (
        bindings.machine_import_call_contracts.qualified
        if bindings.machine_import_call_contracts is not None
        else "[]"
    )
    reachable = ""
    exact_bindings = ""
    original_combined_reachability = ""
    if plan.complete:
        reachable = f"""
def generatedExactOriginalDecodedReachability :
    ExactOriginalDecodedReachability generatedOriginalStaticContext
      generatedExactOriginalDecodedAuthority generatedOriginalLaunch
      generatedDirectExactOriginalDecodedLaunchRoot := {{
  targetIds := {list(plan.reachable_target_ids)}
  unique := by decide +kernel
  entryReachable := by decide +kernel
  tlsReachable := by decide +kernel
  sourcesExist := by
    intro targetId member
    exact originalReachabilityInventoryValid_sources
      generatedOriginalReachabilityInventoryChecked member
  successorsClosed := by
    intro targetId source member found successor successorMember
    exact originalReachabilityInventoryValid_successors
      generatedOriginalReachabilityInventoryChecked member found successorMember
}}
"""
        exact_bindings = """
def generatedExactDecodedOriginalCarrierBinding
    (environment : WorldExternalEnvironment)
    (protocolEnvironment : WorldExternalProtocolEnvironment)
    (externalCallSites : List ExternalCallSiteContract)
    (finiteBinding : GeneratedOriginalFiniteCarrierBinding
      generatedOriginalStaticContext
      (generatedOriginalDecodedProgram environment protocolEnvironment
        externalCallSites))
    (indexedResolution : forall address,
      (generatedOriginalDecodedProgram environment protocolEnvironment
          externalCallSites).context.codeMap.resolveRawEip false
          generatedOriginalStaticContext.pe.imageBase address =
        generatedOriginalStaticContext.codeMap.resolveRawEip
          generatedOriginalStaticContext.pe.imageBase address)
    (returnResolution : forall address,
      resolveMappedCodeTarget false generatedOriginalStaticContext.pe.imageBase
          (generatedOriginalDecodedProgram environment protocolEnvironment
            externalCallSites).context.codeMap.entries.toList address =
        generatedOriginalStaticContext.codeMap.resolveRawEip
          generatedOriginalStaticContext.pe.imageBase address) :
    ExactDecodedOriginalCarrierBinding generatedOriginalStaticContext
      (generatedOriginalDecodedProgram environment protocolEnvironment
        externalCallSites) :=
  finiteBinding.toExact indexedResolution returnResolution

def generatedExactMixedProgramBinding
    (environment : WorldExternalEnvironment)
    (protocolEnvironment : WorldExternalProtocolEnvironment)
    (externalCallSites : List ExternalCallSiteContract)
    (binding : ExactDecodedOriginalCarrierBinding generatedOriginalStaticContext
      (generatedOriginalDecodedProgram environment protocolEnvironment
        externalCallSites)) :
    ExactMixedProgramBinding generatedOriginalStaticContext
      (generatedOriginalDecodedProgram environment protocolEnvironment
        externalCallSites) := { original := binding }
"""
        original_combined_reachability = f"""
def generatedOriginalCombinedEnvironment : WorldExternalEnvironment := {{
  result := fun _ event => {{ state := event.state, world := event.world }}
}}

def generatedOriginalCombinedProtocolEnvironment :
    WorldExternalProtocolEnvironment := {{
  action := fun request =>
    .returned {{ state := request.state, world := request.world }}
}}

def generatedOriginalCombinedExternalCallSites :
    List ExternalCallSiteContract := []

/-- The concrete original program used by the combined execution inventory.
Its code map is the checked carrier map; environment-family adapters may
retarget the external resolver without changing the raw-EIP facts below. -/
def generatedOriginalCombinedProgram : DecodedWorldProgram :=
  generatedOriginalDecodedProgram generatedOriginalCombinedEnvironment
    generatedOriginalCombinedProtocolEnvironment
    generatedOriginalCombinedExternalCallSites

def generatedOriginalCombinedReachableTargetIds : List Nat :=
  {list(plan.reachable_target_ids)}

theorem generatedOriginalCombinedReachableTargetIdsExact :
    generatedOriginalCombinedReachableTargetIds = generatedReachableTargetIds :=
  rfl

theorem generatedOriginalCombinedReachableTargetIdsUnique :
    generatedOriginalCombinedReachableTargetIds.Nodup := by
  rw [generatedOriginalCombinedReachableTargetIdsExact]
  exact generatedExactOriginalDecodedReachability.unique

theorem generatedOriginalCombinedRegionTargetCountExact :
    generatedOriginalStaticContext.codeMap.entries.size =
      generatedOriginalCarrierContext.codeMap.entries.size := by
  decide +kernel

theorem generatedOriginalCombinedReachableTargetRoundTrips :
    forall targetId,
      targetId ∈ generatedOriginalCombinedReachableTargetIds ->
        exists eip,
          generatedOriginalCombinedProgram.canonicalRawEip? targetId = some eip /\\
            generatedOriginalCombinedProgram.resolveRawEip eip = some targetId := by
  intro targetId member
  rw [generatedOriginalCombinedReachableTargetIdsExact] at member
  obtain ⟨source, sourceFound⟩ :=
    originalReachabilityInventoryValid_sources
      generatedOriginalReachabilityInventoryChecked member
  cases originalTargetFound :
      generatedOriginalStaticContext.codeMap.get? targetId with
  | none =>
      simp [OriginalDecodedStaticContext.source?, originalTargetFound]
        at sourceFound
  | some originalTarget =>
      have originalTargetBefore :=
        FiniteIndex.get?_eq_some_implies_lt_size
          generatedOriginalStaticContext.codeMap.entries targetId
          originalTarget originalTargetFound
      have targetBefore :
          targetId < generatedOriginalCarrierContext.codeMap.entries.size := by
        rw [← generatedOriginalCombinedRegionTargetCountExact]
        exact originalTargetBefore
      have contextValid :
          generatedOriginalCarrierContext.StructurallyValid := by
        simpa [generatedOriginalCarrierContext] using
          {base_namespace}.generatedOriginalCarrierContextStructurallyValid
      have indexed := StaticProofContext.codeMapIndexed_of_structurallyValid
        generatedOriginalCarrierContext contextValid
      rcases indexed with
        ⟨_entriesStructural, _originalAddressesStructural,
          _candidateAddressesStructural, entryValid, _originalAddressCount,
          _candidateAddressCount, _originalAddressesValid,
          _candidateAddressesValid, originalRoundTrips,
          _candidateRoundTrips⟩
      have targetValid := entryValid targetId targetBefore
      cases targetFound : generatedOriginalCarrierContext.codeMap.get? targetId with
      | none =>
          simp [StaticCodeMap.entryAtValid, targetFound] at targetValid
      | some target =>
          have roundTrip := StaticCodeMap.canonicalRawEip_roundTrip false
            generatedOriginalCarrierContext.originalPe.imageBase
            generatedOriginalCarrierContext.codeMap originalRoundTrips
            targetId target targetFound
          simpa [generatedOriginalCombinedProgram,
            generatedOriginalDecodedProgram,
            DecodedWorldProgram.canonicalRawEip?,
            DecodedWorldProgram.resolveRawEip,
            DecodedWorldProgram.sideImageBase] using roundTrip
"""
    return f"""{imports}

namespace {spec.namespace}

open StageA.Formal StageA.Relational
open StageA.Relational.InterpreterMixedContext
open StageA.Relational.InterpreterMixedOriginal
open StageA.Relational.InterpreterMixedWorldBridge
open StageA.Relational.InterpreterNativeLaunch

set_option maxRecDepth 1000000
set_option maxHeartbeats 0

def generatedOriginalStateMachineSha256 : String :=
  {base_namespace}.generatedOriginalStateMachineSha256
def generatedOriginalTargetIndex := {base_namespace}.generatedOriginalTargetIndex
def generatedOriginalAddressIndex := {base_namespace}.generatedOriginalAddressIndex
def generatedOriginalRegionIndex := {base_namespace}.generatedOriginalRegionIndex
def generatedOriginalCodeMap := {base_namespace}.generatedOriginalCodeMap
def generatedOriginalStateMachineImportIdentities :=
  {base_namespace}.generatedOriginalStateMachineImportIdentities
def generatedOriginalMachineImportCallContracts : List MachineImportCallContract :=
  {machine_contracts}
theorem generatedOriginalStateMachineImportsBound :
    originalImportIdentitiesValid {q(spec.bindings.import_certificate)}.imports
      generatedOriginalStateMachineImportIdentities = true := by
  simpa [generatedOriginalStateMachineImportIdentities] using
    {base_namespace}.generatedOriginalStateMachineImportsBound
theorem generatedOriginalMachineContractsCoverImports :
    machineImportContractsCoverIdentities
      generatedOriginalMachineImportCallContracts
      generatedOriginalStateMachineImportIdentities = true := by
  simpa [generatedOriginalMachineImportCallContracts,
    generatedOriginalStateMachineImportIdentities] using
    {base_namespace}.generatedOriginalMachineContractsCoverImports
def generatedOriginalStaticContext : OriginalDecodedStaticContext :=
  {base_namespace}.generatedOriginalStaticContext
def generatedOriginalIATCallSiteBindings :=
  {base_namespace}.generatedOriginalIATCallSiteBindings
theorem generatedOriginalIATCallSiteBindingsChecked :
    originalIATCallSiteBindingsValid generatedOriginalStaticContext
      generatedOriginalIATCallSiteBindings = true := by
  simpa [generatedOriginalStaticContext, generatedOriginalIATCallSiteBindings] using
    {base_namespace}.generatedOriginalIATCallSiteBindingsChecked
def generatedAllChecks := {base_namespace}.generatedAllChecks
def generatedAllAddressChecks := {base_namespace}.generatedAllAddressChecks
def generatedExactOriginalCodeMapCertificate :
    OriginalCodeMapCertificate generatedOriginalStaticContext.pe
      generatedOriginalStaticContext.imports generatedOriginalCodeMap := by
  simpa [generatedOriginalStaticContext, generatedOriginalCodeMap] using
    {base_namespace}.generatedExactOriginalCodeMapCertificate
def generatedExactOriginalDecodedAuthority :
    ExactOriginalDecodedAuthority generatedOriginalStaticContext := by
  simpa [generatedOriginalStaticContext] using
    {base_namespace}.generatedExactOriginalDecodedAuthority
def generatedOriginalStaticTargetIndex :=
  {base_namespace}.generatedOriginalStaticTargetIndex
def generatedOriginalCarrierCodeMap :=
  {base_namespace}.generatedOriginalCarrierCodeMap
def generatedOriginalCarrierContext : StaticProofContext :=
  {base_namespace}.generatedOriginalCarrierContext
{alias_compatibility}
{static_word_compatibility}

def generatedOriginalCarrierRegionIndex : FiniteIndex RegionRelation :=
  {carrier_region_index}

theorem generatedOriginalCarrierRegionIndexSizesSound :
    generatedOriginalCarrierRegionIndex.sizesSound = true := by
  decide +kernel

def generatedOriginalCarrierRegions : List RegionRelation :=
  generatedOriginalCarrierRegionIndex.toList

def generatedOriginalCarrierInvariantAt
    (targetId : Nat) : StateInvariant :=
  match generatedOriginalCarrierRegionIndex.get? targetId with
  | some region => region.inputInvariant
  | none => {{ registerRelations := [] }}

{boundary_projection}

{terminal_successor_projection}

{false_edge_checks}

def generatedOriginalDecodedProgram
    (environment : WorldExternalEnvironment)
    (protocolEnvironment : WorldExternalProtocolEnvironment)
    (externalCallSites : List ExternalCallSiteContract) : DecodedWorldProgram := {{
  candidate := false
  context := generatedOriginalCarrierContext
  regions := generatedOriginalCarrierRegions
  externalCallSites
  environment
  protocolEnvironment
}}

{static_indirect_checks}

def generatedOriginalLaunch : PE32ConsoleLaunchV2 :=
  {base_namespace}.generatedOriginalLaunch
-- base launch field: frameOffsets := [{frame_offsets}]
theorem generatedOriginalLaunchFrameCountChecked :
    generatedOriginalLaunch.frameOffsets.length =
      generatedOriginalLaunch.continuationTargetIds.length := by
  simpa [generatedOriginalLaunch] using
    {base_namespace}.generatedOriginalLaunchFrameCountChecked
def generatedOriginalLaunchRoots : CandidatePELaunchRoots :=
  {base_namespace}.generatedOriginalLaunchRoots
def generatedDirectExactOriginalDecodedLaunchRoot :
    DirectExactOriginalDecodedLaunchRoot generatedOriginalStaticContext
      generatedOriginalLaunch := by
  simpa [generatedOriginalStaticContext, generatedOriginalLaunch] using
    {base_namespace}.generatedDirectExactOriginalDecodedLaunchRoot

def generatedReachableTargetIds : List Nat := {list(plan.reachable_target_ids)}

theorem generatedOriginalReachabilityInventoryChecked :
    originalReachabilityInventoryValid generatedOriginalStaticContext
      generatedReachableTargetIds = true := by
  decide +kernel

{reachable}
{exact_bindings}
{original_combined_reachability}
-- Final authority is absent while any exact frontier remains.
{blocker_comment}
-- Unreachable diagnostics remain non-authoritative.
{diagnostic_comment}

end {spec.namespace}
"""


def _bundle_source(
    plan: InterpreterMixedOriginalPlan,
    shard_modules: Sequence[str],
    shard_regions: Sequence[Sequence[OriginalRegion]],
    *,
    emit_final_authority: bool = True,
) -> str:
    spec = plan.spec
    bindings = spec.bindings
    q = bindings.qualified
    imported_modules = [
        "StageA.RelationalInterpreterMixedOriginal",
        "StageA.RelationalIndirectExitAdapters",
        "StageA.RelationalInterpreterOriginalCarrierBinding",
        bindings.module,
        *(
            [bindings.machine_import_call_contracts.module]
            if bindings.machine_import_call_contracts is not None
            else []
        ),
        *[
            proposal.authorizing_lean_term.module
            for proposal in spec.register_control_call_contracts
            if proposal.authorizing_lean_term is not None
        ],
        *(
            [
                bindings.machine_import_boundaries.signatures.module,
                bindings.machine_import_boundaries.boundaries.module,
                bindings.machine_import_boundaries.inventory.module,
            ]
            if bindings.machine_import_boundaries is not None
            else []
        ),
        *shard_modules,
    ]
    imports = "\n".join(
        f"import {module}" for module in dict.fromkeys(imported_modules)
    )
    target_refs = [
        (f"generatedOriginalTargetIndexShard{index}", len(regions))
        for index, regions in enumerate(shard_regions)
    ]
    address_refs = [
        (
            f"generatedOriginalAddressIndexShard{index}",
            sum(1 + len(region.alias_rvas) for region in regions),
        )
        for index, regions in enumerate(shard_regions)
    ]
    region_refs = [
        (f"generatedOriginalRegionIndexShard{index}", len(regions))
        for index, regions in enumerate(shard_regions)
    ]
    static_refs = [
        (f"generatedOriginalStaticTargetIndexShard{index}", len(regions))
        for index, regions in enumerate(shard_regions)
    ]
    static_address_refs = [
        (
            f"generatedOriginalStaticAddressIndexShard{index}",
            sum(1 + len(region.alias_rvas) for region in regions),
        )
        for index, regions in enumerate(shard_regions)
    ]
    carrier_region_refs = [
        (f"generatedOriginalCarrierRegionIndexShard{index}", len(regions))
        for index, regions in enumerate(shard_regions)
    ]
    carrier_region_index = _lean_index_refs(carrier_region_refs)
    machine_contracts = (
        bindings.machine_import_call_contracts.qualified
        if bindings.machine_import_call_contracts is not None
        else "[]"
    )
    boundary_projection = _lean_machine_import_boundary_projection(plan)
    terminal_successor_projection = _lean_terminal_successor_projection(plan)
    false_edge_checks = _lean_state_independent_false_edge_checks(plan)
    entry_id = _id_for_rva(plan, spec.entry_rva)
    tls_ids = [_id_for_rva(plan, rva) for rva in spec.tls_callback_rvas]
    initial_id = tls_ids[0] if tls_ids else entry_id
    roots = [
        f"{{ targetId := {entry_id}, kind := .entrypoint }}",
        *[
            f"{{ targetId := {target_id}, kind := .tlsInitializer }}"
            for target_id in tls_ids
        ],
    ]
    import_identities = ", ".join(
        _lean_import_identity(identity) for identity in plan.import_identities
    )
    iat_bindings = ", ".join(
        _lean_iat_call_site(plan, site)
        for site in plan.indirect_sites
        if site.iat_import is not None
    )
    data_bindings = _unique_static_data_bindings(plan)
    data_rows = [
        _lean_value_target(target_id, binding)
        for target_id, binding in enumerate(data_bindings)
    ]
    data_entries = "#[" + ", ".join(data_rows) + "]"
    data_ids = list(range(len(data_bindings)))
    static_word_bindings = _unique_static_word_slot_bindings(plan)
    static_word_slots = ", ".join(
        _lean_static_word_slot(binding) for binding in static_word_bindings
    )
    static_indirect_checks = _lean_static_indirect_checks(plan)
    frame_offsets = ", ".join(
        "ReturnSlotOffsetInventory.zero" for _ in spec.tls_callback_rvas
    )
    address_count = len(plan.regions) + len(plan.recovered_aliases)
    reachable_def = ""
    exact_binding_def = ""
    if plan.complete and emit_final_authority:
        reachable_def = f"""
def generatedExactOriginalDecodedReachability :
    ExactOriginalDecodedReachability generatedOriginalStaticContext
      generatedExactOriginalDecodedAuthority generatedOriginalLaunch
      generatedDirectExactOriginalDecodedLaunchRoot := {{
  targetIds := {list(plan.reachable_target_ids)}
  unique := by decide +kernel
  entryReachable := by decide +kernel
  tlsReachable := by decide +kernel
  sourcesExist := by
    intro targetId member
    exact originalReachabilityInventoryValid_sources
      generatedOriginalReachabilityInventoryChecked member
  successorsClosed := by
    intro targetId source member found successor successorMember
    exact originalReachabilityInventoryValid_successors
      generatedOriginalReachabilityInventoryChecked member found successorMember
}}
"""
        exact_binding_def = """
/-- The finite carrier inventory is generated canonically.  The remaining two
resolution equalities compare legacy linear lookup with the checked indexed
lookup and are explicit proof inputs until that generic algorithm bridge is
available. -/
def generatedExactDecodedOriginalCarrierBinding
    (environment : WorldExternalEnvironment)
    (protocolEnvironment : WorldExternalProtocolEnvironment)
    (externalCallSites : List ExternalCallSiteContract)
    (finiteBinding : GeneratedOriginalFiniteCarrierBinding
      generatedOriginalStaticContext
      (generatedOriginalDecodedProgram environment protocolEnvironment
        externalCallSites))
    (indexedResolution : forall address,
      (generatedOriginalDecodedProgram environment protocolEnvironment
          externalCallSites).context.codeMap.resolveRawEip false
          generatedOriginalStaticContext.pe.imageBase address =
        generatedOriginalStaticContext.codeMap.resolveRawEip
          generatedOriginalStaticContext.pe.imageBase address)
    (returnResolution : forall address,
      resolveMappedCodeTarget false generatedOriginalStaticContext.pe.imageBase
          (generatedOriginalDecodedProgram environment protocolEnvironment
            externalCallSites).context.codeMap.entries.toList address =
        generatedOriginalStaticContext.codeMap.resolveRawEip
          generatedOriginalStaticContext.pe.imageBase address) :
    ExactDecodedOriginalCarrierBinding generatedOriginalStaticContext
      (generatedOriginalDecodedProgram environment protocolEnvironment
        externalCallSites) :=
  finiteBinding.toExact indexedResolution returnResolution

def generatedExactMixedProgramBinding
    (environment : WorldExternalEnvironment)
    (protocolEnvironment : WorldExternalProtocolEnvironment)
    (externalCallSites : List ExternalCallSiteContract)
    (binding : ExactDecodedOriginalCarrierBinding generatedOriginalStaticContext
      (generatedOriginalDecodedProgram environment protocolEnvironment
        externalCallSites)) :
    ExactMixedProgramBinding generatedOriginalStaticContext
      (generatedOriginalDecodedProgram environment protocolEnvironment
        externalCallSites) := { original := binding }
"""

    blocker_comment = "\n".join(
        f"-- {item.reason_code}: {item.detail}"
        for item in plan.blockers
    )
    diagnostic_comment = "\n".join(
        f"-- {item.reason_code}: {item.detail}"
        for item in plan.diagnostics
    )
    return f"""{imports}

namespace {spec.namespace}

open StageA.Formal StageA.Relational
open StageA.Relational.InterpreterMixedContext
open StageA.Relational.InterpreterMixedOriginal
open StageA.Relational.InterpreterMixedWorldBridge
open StageA.Relational.InterpreterNativeLaunch

set_option maxRecDepth 1000000
set_option maxHeartbeats 0

def generatedOriginalStateMachineSha256 : String :=
  "{plan.state_machine_sha256}"

def generatedOriginalTargetIndex : FiniteIndex OriginalCodeTarget :=
  {_lean_index_refs(target_refs)}

def generatedOriginalAddressIndex : FiniteIndex OriginalCodeAddress :=
  {_lean_index_refs(address_refs)}

def generatedOriginalRegionIndex : FiniteIndex OriginalDecodedRegion :=
  {_lean_index_refs(region_refs)}

def generatedOriginalCodeMap : OriginalCodeMap := {{
  entries := generatedOriginalTargetIndex
  addresses := generatedOriginalAddressIndex
}}

def generatedOriginalStateMachineImportIdentities :
    List OriginalImportIdentity := [{import_identities}]

theorem generatedOriginalStateMachineImportsBound :
    originalImportIdentitiesValid {q(bindings.import_certificate)}.imports
      generatedOriginalStateMachineImportIdentities = true := by
  decide +kernel

theorem generatedOriginalMachineContractsCoverImports :
    machineImportContractsCoverIdentities {machine_contracts}
      generatedOriginalStateMachineImportIdentities = true := by
  decide +kernel

def generatedOriginalStaticContext : OriginalDecodedStaticContext := {{
  pe := {q(bindings.pe)}
  importCertificate := {q(bindings.import_certificate)}
  relocations := {q(bindings.relocations)}
  codeMap := generatedOriginalCodeMap
  regions := generatedOriginalRegionIndex
  machineImportCallContracts := {machine_contracts}
}}

def generatedOriginalIATCallSiteBindings :
    List OriginalIATCallSiteBinding := [{iat_bindings}]

theorem generatedOriginalIATCallSiteBindingsChecked :
    originalIATCallSiteBindingsValid generatedOriginalStaticContext
      generatedOriginalIATCallSiteBindings = true := by
  decide +kernel

def generatedAllChecks : IndexedBoolCertificate := {{
  ranges := [{{ start := 0, size := {len(plan.regions)} }}]
}}

def generatedAllAddressChecks : IndexedBoolCertificate := {{
  ranges := [{{ start := 0, size := {address_count} }}]
}}

def generatedExactOriginalCodeMapCertificate :
    OriginalCodeMapCertificate generatedOriginalStaticContext.pe
      generatedOriginalStaticContext.imports generatedOriginalCodeMap := {{
  entriesStructurallyValid := by decide +kernel
  addressesStructurallyValid := by decide +kernel
  entryChecks := generatedAllChecks
  entryChecksValid := by decide +kernel
  addressCountExact := by decide +kernel
  addressChecks := generatedAllAddressChecks
  addressChecksValid := by decide +kernel
  roundTripChecks := generatedAllChecks
  roundTripChecksValid := by decide +kernel
  aliasChecks := generatedAllChecks
  aliasChecksValid := by decide +kernel
}}

def generatedExactOriginalDecodedAuthority :
    ExactOriginalDecodedAuthority generatedOriginalStaticContext := {{
  peParsed := by simpa [generatedOriginalStaticContext] using {q(bindings.pe_parsed)}
  importsParsed := by
    simpa [generatedOriginalStaticContext] using {q(bindings.imports_parsed)}
  relocationsParsed := by
    simpa [generatedOriginalStaticContext] using {q(bindings.relocations_parsed)}
  loaderImageValid := by decide +kernel
  codeMap := generatedExactOriginalCodeMapCertificate
  regionsStructurallyValid := by decide +kernel
  sourceChecks := generatedAllChecks
  sourceChecksValid := by decide +kernel
  machineContractsValid := by decide +kernel
}}

def generatedOriginalStaticTargetIndex : FiniteIndex CodeTargetPair :=
  {_lean_index_refs(static_refs)}

def generatedOriginalCarrierCodeMap : StaticCodeMap :=
  StageA.Relational.InterpreterOriginalCarrierBinding.originalCodeMapToStatic
    generatedOriginalCodeMap

def generatedOriginalCarrierContext : StaticProofContext := {{
  originalPe := generatedOriginalStaticContext.pe
  candidatePe := generatedOriginalStaticContext.pe
  originalImportCertificate := generatedOriginalStaticContext.importCertificate
  candidateImportCertificate := generatedOriginalStaticContext.importCertificate
  originalRelocations := generatedOriginalStaticContext.relocations
  candidateRelocations := generatedOriginalStaticContext.relocations
  codeMap := generatedOriginalCarrierCodeMap
  dataMap := {{
    entries := {data_entries}
    originalOrder := {data_ids}
    candidateOrder := {data_ids}
  }}
  roots := [{', '.join(roots)}]
  tlsCallbackTargetIds := {tls_ids}
  observations := {{ tls := {"true" if tls_ids else "false"} }}
  staticWordRelationSlots := [{static_word_slots}]
  machineImportCallContracts :=
    generatedOriginalStaticContext.machineImportCallContracts
}}

theorem generatedOriginalCarrierContextStructurallyValid :
    generatedOriginalCarrierContext.StructurallyValid := by
  apply StaticProofContext.structurallyValid_of_components
  · simpa [generatedOriginalCarrierContext] using
      generatedExactOriginalDecodedAuthority.peParsed
  · simpa [generatedOriginalCarrierContext] using
      generatedExactOriginalDecodedAuthority.peParsed
  · simpa [generatedOriginalCarrierContext] using
      generatedExactOriginalDecodedAuthority.importsParsed
  · simpa [generatedOriginalCarrierContext] using
      generatedExactOriginalDecodedAuthority.importsParsed
  · simpa [generatedOriginalCarrierContext] using
      generatedExactOriginalDecodedAuthority.relocationsParsed
  · simpa [generatedOriginalCarrierContext] using
      generatedExactOriginalDecodedAuthority.relocationsParsed
  · simpa [generatedOriginalCarrierContext, generatedOriginalCarrierCodeMap] using
      StageA.Relational.InterpreterOriginalCarrierBinding.originalCodeMapToStatic_indexedValid
        generatedOriginalCodeMap generatedExactOriginalCodeMapCertificate
  · decide +kernel
  · decide +kernel
  · decide +kernel
  · simpa [generatedOriginalCarrierContext] using
      generatedExactOriginalDecodedAuthority.machineContractsValid
  · simpa [generatedOriginalCarrierContext] using
      generatedExactOriginalDecodedAuthority.machineContractsValid
  · decide +kernel
  · decide +kernel
  · decide +kernel
  · simpa [generatedOriginalCarrierContext] using
      generatedExactOriginalDecodedAuthority.loaderImageValid
  · simpa [generatedOriginalCarrierContext] using
      generatedExactOriginalDecodedAuthority.loaderImageValid

def generatedOriginalCarrierRegionIndex : FiniteIndex RegionRelation :=
  {carrier_region_index}

theorem generatedOriginalCarrierRegionIndexSizesSound :
    generatedOriginalCarrierRegionIndex.sizesSound = true := by
  decide +kernel

def generatedOriginalCarrierRegions : List RegionRelation :=
  generatedOriginalCarrierRegionIndex.toList

def generatedOriginalCarrierInvariantAt
    (targetId : Nat) : StateInvariant :=
  match generatedOriginalCarrierRegionIndex.get? targetId with
  | some region => region.inputInvariant
  | none => {{ registerRelations := [] }}

{boundary_projection}

{terminal_successor_projection}

{false_edge_checks}

def generatedOriginalDecodedProgram
    (environment : WorldExternalEnvironment)
    (protocolEnvironment : WorldExternalProtocolEnvironment)
    (externalCallSites : List ExternalCallSiteContract) : DecodedWorldProgram := {{
  candidate := false
  context := generatedOriginalCarrierContext
  regions := generatedOriginalCarrierRegions
  externalCallSites
  environment
  protocolEnvironment
}}

{static_indirect_checks}

def generatedOriginalLaunch : PE32ConsoleLaunchV2 := {{
  rootNodeId := {initial_id}
  rootTargetId := {initial_id}
  entryNodeId := {entry_id}
  entryTargetId := {entry_id}
  tlsCallbackNodeIds := {tls_ids}
  tlsCallbackTargetIds := {tls_ids}
  rootInvariant := {{ registerRelations := [] }}
  frameOffsets := [{frame_offsets}]
}}

theorem generatedOriginalLaunchFrameCountChecked :
    generatedOriginalLaunch.frameOffsets.length =
      generatedOriginalLaunch.continuationTargetIds.length := by
  decide +kernel

def generatedOriginalLaunchRoots : CandidatePELaunchRoots := {{
  entryRva := {spec.entry_rva}
  tlsCallbackRvas := {list(spec.tls_callback_rvas)}
}}

theorem generatedOriginalLaunchRootsDecodedChecked :
    originalLaunchRootsDecoded generatedOriginalStaticContext
      generatedOriginalLaunch = true := by
  decide +kernel

theorem generatedOriginalEntryMatchesChecked :
    originalTargetIdMatchesRva generatedOriginalStaticContext.codeMap
      generatedOriginalLaunch.entryTargetId generatedOriginalLaunchRoots.entryRva =
      true := by
  decide +kernel

theorem generatedOriginalTlsMatchesChecked :
    originalTargetIdsMatchRvasChecked generatedOriginalStaticContext.codeMap
      generatedOriginalLaunch.tlsCallbackTargetIds
      generatedOriginalLaunchRoots.tlsCallbackRvas = true := by
  decide +kernel

def generatedDirectExactOriginalDecodedLaunchRoot :
    DirectExactOriginalDecodedLaunchRoot generatedOriginalStaticContext
      generatedOriginalLaunch := {{
  roots := generatedOriginalLaunchRoots
  rootsParsed := by decide +kernel
  entryExact := originalTargetIdMatchesRva_sound
    generatedOriginalEntryMatchesChecked
  tlsExact := originalTargetIdsMatchRvasChecked_sound
    generatedOriginalTlsMatchesChecked
  initialExact := by decide +kernel
  rootsDecoded := originalLaunchRootsDecoded_sound
    generatedOriginalLaunchRootsDecodedChecked
}}

def generatedReachableTargetIds : List Nat := {list(plan.reachable_target_ids)}

theorem generatedOriginalReachabilityInventoryChecked :
    originalReachabilityInventoryValid generatedOriginalStaticContext
      generatedReachableTargetIds = true := by
  decide +kernel

{reachable_def}
{exact_binding_def}
-- Generation is fail-closed; these diagnostics prevent a reachability or
-- mixed-program certificate from being emitted.
{blocker_comment}
-- These sources are outside the exact rooted closure.  Their incomplete
-- coverage remains visible but cannot be entered by the emitted reachability.
{diagnostic_comment}

end {spec.namespace}
"""


def _read_rows(raw: bytes, path: Path) -> list[tuple[int, Mapping[str, Any]]]:
    rows: list[tuple[int, Mapping[str, Any]]] = []
    for line_number, line in enumerate(raw.splitlines(), 1):
        if not line.strip():
            continue
        try:
            payload = json.loads(line)
        except json.JSONDecodeError as error:
            raise InterpreterMixedOriginalGenerationError(
                f"{path}:{line_number}: invalid JSON: {error.msg}"
            ) from error
        if not isinstance(payload, Mapping):
            raise InterpreterMixedOriginalGenerationError(
                f"{path}:{line_number}: transfer record must be an object"
            )
        rows.append((line_number, payload))
    return rows


def _mapping(value: Any, line: int, field_name: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise InterpreterMixedOriginalGenerationError(
            f"line {line} {field_name} must be an object"
        )
    return value


def _validated_recovery_binary(
    recovery: OriginalPERecoveryInput | None,
) -> StageABinary | None:
    if recovery is None:
        return None
    try:
        binary = _parse_stage_a_pe(recovery.path)
    except StageAInputError as error:
        raise InterpreterMixedOriginalGenerationError(
            f"unable to parse recovery PE: {error}"
        ) from error
    if binary.sha256 != recovery.sha256:
        binary.pe.close()
        raise InterpreterMixedOriginalGenerationError(
            "recovery PE SHA-256 does not match the declared original hash"
        )
    return binary


_CONDITIONAL_BRANCH_MNEMONICS = frozenset({
    "ja", "jae", "jb", "jbe", "jc", "jcxz", "je", "jecxz", "jg",
    "jge", "jl", "jle", "jna", "jnae", "jnb", "jnbe", "jnc", "jne",
    "jng", "jnge", "jnl", "jnle", "jno", "jnp", "jns", "jnz", "jo",
    "jp", "jpe", "jpo", "js", "jz",
})


def _recover_state_independent_false_edge_cuts(
    binary: StageABinary | None,
    parsed: Sequence[dict[str, Any]],
    resolved_id_by_rva: Mapping[int, int],
) -> tuple[OriginalStateIndependentFalseEdgeCut, ...]:
    """Propose exact-branch cuts; generated Lean remains the authority."""

    if binary is None:
        return ()
    cuts: dict[tuple[int, int], OriginalStateIndependentFalseEdgeCut] = {}
    for source_target_id, item in enumerate(parsed):
        exact_edges = _exact_conditional_branch_rvas(binary, item)
        if exact_edges is None:
            continue
        row_edges = item["row"].get("edge_conditions")
        if not isinstance(row_edges, list):
            continue
        for proposed in row_edges:
            if not isinstance(proposed, Mapping):
                continue
            edge_rva = proposed.get("target_rva")
            if not isinstance(edge_rva, int) or isinstance(edge_rva, bool):
                continue
            if _json_state_independent_bool(proposed.get("condition")) is not False:
                continue
            if edge_rva not in exact_edges or exact_edges[0] == exact_edges[1]:
                continue
            destination_target_id = resolved_id_by_rva.get(edge_rva)
            if destination_target_id is None:
                continue
            key = (item["rva"], edge_rva)
            cuts[key] = OriginalStateIndependentFalseEdgeCut(
                source_target_id=source_target_id,
                destination_target_id=destination_target_id,
                source_rva=item["rva"],
                edge_rva=edge_rva,
            )
    return tuple(
        cuts[key]
        for key in sorted(cuts)
    )


def _exact_conditional_branch_rvas(
    binary: StageABinary,
    item: Mapping[str, Any],
) -> tuple[int, int] | None:
    instructions, failure = _decode_exact_region(binary, item)
    if failure or not instructions:
        return None
    branch = instructions[-1]
    if (
        branch.mnemonic not in _CONDITIONAL_BRANCH_MNEMONICS
        or len(branch.operands) != 1
        or branch.operands[0].type != X86_OP_IMM
    ):
        return None
    branch_end = branch.address + branch.size
    exact_end = binary.image_base + item["rva"] + item["size"]
    if branch_end != exact_end:
        return None
    taken_rva = branch.operands[0].imm - binary.image_base
    fallthrough_rva = branch_end - binary.image_base
    if not 0 <= taken_rva < 2**32 or not 0 <= fallthrough_rva < 2**32:
        return None
    return taken_rva, fallthrough_rva


def _json_state_independent_word(value: Any) -> int | None:
    if not isinstance(value, Mapping):
        return None
    operation = value.get("op")
    if operation == "const":
        constant = value.get("value")
        if isinstance(constant, int) and not isinstance(constant, bool):
            return constant % 2**32
        return None
    args = value.get("args")
    if not isinstance(args, list) or len(args) != 2:
        return None
    left = _json_state_independent_word(args[0])
    right = _json_state_independent_word(args[1])
    if left is None or right is None:
        return None
    if operation == "add32":
        return (left + right) % 2**32
    if operation == "sub32":
        return (left - right) % 2**32
    if operation == "mul32":
        return (left * right) % 2**32
    if operation == "and32":
        return left & right
    if operation == "or32":
        return left | right
    if operation == "xor32":
        return left ^ right
    return None


def _json_state_independent_bool(value: Any) -> bool | None:
    if not isinstance(value, Mapping):
        return None
    operation = value.get("op")
    if operation == "true":
        return True
    if operation == "false":
        return False
    args = value.get("args")
    if not isinstance(args, list):
        return None
    if operation == "not" and len(args) == 1:
        inner = _json_state_independent_bool(args[0])
        return None if inner is None else not inner
    if operation in {"and", "or", "xor"} and len(args) == 2:
        left = _json_state_independent_bool(args[0])
        right = _json_state_independent_bool(args[1])
        if left is None or right is None:
            return None
        if operation == "and":
            return left and right
        if operation == "or":
            return left or right
        return left != right
    if operation in {"eq", "ult32"} and len(args) == 2:
        left = _json_state_independent_word(args[0])
        right = _json_state_independent_word(args[1])
        if left is None or right is None:
            return None
        return left == right if operation == "eq" else left < right
    return None


def _terminal_boundary_edges(
    parsed: list[dict[str, Any]],
    proposals: Sequence[InterpreterMixedTerminalProposal],
    binary: StageABinary | None,
) -> tuple[
    dict[tuple[int, int], InterpreterMixedTerminalProposal],
    set[int],
    dict[int, str],
]:
    """Match terminal proposals and recover omitted end-of-section padding.

    A state-machine inventory commonly omits alignment bytes after its final
    stopping transfer.  A no-return call still needs its concrete continuation
    in the global code map so call-frame normalization can name the return
    address.  We synthesize such a source only from SHA-bound executable bytes
    and only for the conservative one-byte padding subset.  Lean later checks
    the complete reviewed padding grammar and the exact terminating boundary.
    """

    by_rva = {item["rva"]: item for item in parsed}
    matched: dict[tuple[int, int], InterpreterMixedTerminalProposal] = {}
    synthetic_rvas: set[int] = set()
    failures: dict[int, str] = {}
    for proposal in proposals:
        source = by_rva.get(proposal.source_rva)
        if (
            source is None
            or source["size"] != proposal.source_size
            or proposal.continuation_rva not in source["direct_rvas"]
        ):
            continue
        edge = (proposal.source_rva, proposal.continuation_rva)
        matched[edge] = proposal
        if proposal.continuation_rva in by_rva:
            continue
        if binary is None:
            failures[proposal.continuation_rva] = (
                "terminal continuation padding requires a SHA-bound original PE"
            )
            continue
        sections = [
            section
            for section in binary.sections
            if section.executable
            and section.rva_start <= proposal.continuation_rva < section.rva_end
        ]
        if len(sections) != 1:
            failures[proposal.continuation_rva] = (
                "terminal continuation is not within exactly one executable section"
            )
            continue
        section = sections[0]
        following = [
            item["rva"]
            for item in parsed
            if proposal.continuation_rva < item["rva"] <= section.rva_end
        ]
        stop = min(following, default=section.rva_end)
        size = stop - proposal.continuation_rva
        if size <= 0 or size > 4096:
            failures[proposal.continuation_rva] = (
                "terminal continuation padding is empty or exceeds 4096 bytes"
            )
            continue
        data = bytes(binary.pe.get_data(proposal.continuation_rva, size))
        if len(data) != size or any(byte not in {0x00, 0x90, 0xCC} for byte in data):
            failures[proposal.continuation_rva] = (
                "terminal continuation gap is not conservative executable padding"
            )
            continue
        item = {
            "line": 0,
            "rva": proposal.continuation_rva,
            "size": size,
            "row": {},
            "direct_rvas": (),
            "aliases": [],
            "indirect_sites": (),
            "imports": (),
            "synthetic_terminal_padding": True,
        }
        parsed.append(item)
        by_rva[item["rva"]] = item
        synthetic_rvas.add(item["rva"])
    return matched, synthetic_rvas, failures


def _discover_exact_internal_indirect_calls(
    binary: StageABinary,
    item: Mapping[str, Any],
    submitted: Sequence[OriginalIndirectSite],
) -> tuple[OriginalIndirectSite, ...]:
    """Recover memory/register-indirect instructions hidden by resolved events."""

    sites = list(submitted)
    known_instruction_rvas = {site.instruction_rva for site in sites}
    ordered = item["row"].get("ordered_events")
    if not isinstance(ordered, list):
        return tuple(sites)
    for event in ordered:
        if not isinstance(event, Mapping) or event.get("kind") != "internal_call":
            continue
        instruction_rva = event.get("instruction_rva")
        continuation_rva = event.get("return_rva")
        resolved_target_rva = event.get("target_rva")
        if (
            not isinstance(instruction_rva, int)
            or isinstance(instruction_rva, bool)
            or instruction_rva in known_instruction_rvas
            or not isinstance(continuation_rva, int)
            or isinstance(continuation_rva, bool)
            or not isinstance(resolved_target_rva, int)
            or isinstance(resolved_target_rva, bool)
        ):
            continue
        instruction = _decode_exact_instruction_at(binary, item, instruction_rva)
        if instruction is None or instruction.mnemonic not in {"call", "lcall"}:
            continue
        if len(instruction.operands) != 1:
            sites.append(
                OriginalIndirectSite(
                    source_rva=item["rva"],
                    instruction_rva=instruction_rva,
                    category="unknown_indirect_target",
                    detail="exact resolved internal call has an unsupported operand shape",
                    is_call=True,
                    continuation_rva=continuation_rva,
                    resolved_target_rva=resolved_target_rva,
                )
            )
            known_instruction_rvas.add(instruction_rva)
            continue
        operand = instruction.operands[0]
        if operand.type == X86_OP_IMM:
            continue
        if operand.type == X86_OP_REG:
            register = instruction.reg_name(operand.reg)
            sites.append(
                OriginalIndirectSite(
                    source_rva=item["rva"],
                    instruction_rva=instruction_rva,
                    category="register_function_pointer",
                    detail="exact register-indirect internal call lacks recovered provenance",
                    is_call=True,
                    continuation_rva=continuation_rva,
                    resolved_target_rva=resolved_target_rva,
                    target_expression={
                        "op": "reg",
                        "name": register,
                        "width": 32,
                    },
                )
            )
            known_instruction_rvas.add(instruction_rva)
            continue
        if operand.type != X86_OP_MEM or operand.size != 4:
            category = "unknown_indirect_target"
            target_va = None
        else:
            memory = operand.mem
            if memory.base == 0 and memory.index == 0:
                target_va = memory.disp & 0xFFFFFFFF
                category = "static_pointer_slot"
            else:
                target_va = None
                category = "stack_or_dynamic_pointer"
        target_expression: Mapping[str, Any] | None = None
        if target_va is not None:
            target_expression = {
                "op": "load",
                "width": 4,
                "address": {"op": "const", "value": target_va, "width": 32},
            }
        sites.append(
            OriginalIndirectSite(
                source_rva=item["rva"],
                instruction_rva=instruction_rva,
                category=category,
                detail="exact PE instruction refines a resolved internal call",
                target_va=target_va,
                resolved_target_rva=resolved_target_rva,
                is_call=True,
                continuation_rva=continuation_rva,
                target_expression=target_expression,
            )
        )
        known_instruction_rvas.add(instruction_rva)
    return tuple(sites)


def _decode_exact_instruction_at(
    binary: StageABinary, item: Mapping[str, Any], instruction_rva: int
) -> Any | None:
    region_end = item["rva"] + item["size"]
    if not item["rva"] <= instruction_rva < region_end:
        return None
    size = min(15, region_end - instruction_rva)
    data = bytes(binary.pe.get_data(instruction_rva, size))
    if len(data) != size:
        return None
    decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    decoder.detail = True
    instruction = next(
        iter(decoder.disasm(data, binary.image_base + instruction_rva)), None
    )
    if instruction is None or instruction.address != binary.image_base + instruction_rva:
        return None
    return instruction


def _highlow_relocation_counts(
    binary: StageABinary | None,
) -> dict[int, int]:
    if binary is None:
        return {}
    try:
        rows = _raw_base_relocations(binary)
    except StageAInputError as error:
        raise InterpreterMixedOriginalGenerationError(
            f"unable to parse recovery PE relocations: {error}"
        ) from error
    counts: dict[int, int] = {}
    for row in rows:
        if row["type"] == 3:
            rva = row["rva"]
            counts[rva] = counts.get(rva, 0) + 1
    return counts


def _recover_static_indirect_binding(
    binary: StageABinary | None,
    site: OriginalIndirectSite,
    resolved_id_by_rva: Mapping[int, int],
    parsed: Sequence[dict[str, Any]],
    relocation_counts: Mapping[int, int],
    predecessors_by_target_id: Mapping[int, Sequence[dict[str, Any]]],
    iat_by_va: Mapping[int, OriginalIATImport],
    call_contracts_by_edge: Mapping[
        tuple[int, int], OriginalRegisterControlCallContractProposal
    ],
    static_word_call_seeds_by_site: Mapping[
        tuple[int, int], OriginalRegisterStaticWordSeedAuthority
    ],
) -> tuple[OriginalStaticIndirectBinding | None, str]:
    if site.iat_import is not None:
        return None, ""
    if binary is None:
        return None, "no SHA-bound original PE recovery input was supplied"
    if site.category == "constant_internal_target":
        if site.is_call:
            return None, "constant indirect calls require a checked call-frame binding"
        if site.target_va is None:
            return None, "constant target expression has no unsigned PE32 value"
        resolved = _resolve_exact_code_va(
            binary, site.target_va, resolved_id_by_rva, parsed
        )
        if resolved is None:
            return None, "constant target is not a unique indexed executable address"
        target_id, target_rva = resolved
        if site.target_va != binary.image_base + target_rva:
            return None, (
                "constant target resolves through an alias, but the fixed-address "
                "Lean claim requires the canonical indexed address"
            )
        return (
            OriginalFixedTargetBinding(
                target_id=target_id,
                target_rva=target_rva,
                target_va=site.target_va,
            ),
            "",
        )
    if site.category == "static_pointer_slot":
        immutable, immutable_failure = _recover_immutable_slot_binding(
            binary,
            site,
            resolved_id_by_rva,
            parsed,
            relocation_counts,
        )
        if immutable is not None:
            return immutable, ""
        if site.is_call:
            writable, writable_failure = _recover_static_word_slot_binding(
                binary,
                site,
                resolved_id_by_rva,
                parsed,
                relocation_counts,
                iat_by_va,
            )
            if writable is not None:
                return None, (
                    "writable static-word slot has checked normalized internal "
                    "RegionTransition writes, but final authority lacks named Lean "
                    "terms for external-call memory-footprint preservation and "
                    "call-frame argument provenance"
                )
            return None, writable_failure
        return None, immutable_failure
    if site.category == "bounded_table_candidate":
        source_target_id = resolved_id_by_rva.get(site.source_rva)
        if source_target_id is None:
            return None, "table source is not an indexed code target"
        return _recover_bounded_table_binding(
            binary,
            site,
            resolved_id_by_rva,
            parsed,
            relocation_counts,
            predecessors_by_target_id.get(source_target_id, ()),
        )
    if site.category in {"register_function_pointer", "register_tail_target"}:
        return _recover_register_provenance_binding(
            binary,
            site,
            resolved_id_by_rva,
            parsed,
            relocation_counts,
            predecessors_by_target_id,
            iat_by_va,
            call_contracts_by_edge,
            static_word_call_seeds_by_site,
        )
    reasons = {
        "stack_or_dynamic_pointer": (
            "memory-derived target requires a checked stack/dynamic-range provenance "
            "and runtime membership invariant"
        ),
        "unknown_indirect_target": (
            "target expression is outside the static indirect-control profile"
        ),
    }
    return None, reasons.get(site.category, "no sound static recovery rule applies")


def _resolve_exact_code_va(
    binary: StageABinary,
    target_va: int,
    resolved_id_by_rva: Mapping[int, int],
    parsed: Sequence[dict[str, Any]],
) -> tuple[int, int] | None:
    if target_va < binary.image_base:
        return None
    target_rva = target_va - binary.image_base
    target_id = resolved_id_by_rva.get(target_rva)
    if target_id is None:
        return None
    canonical_rva = parsed[target_id]["rva"]
    sections = [
        section
        for section in binary.sections
        if section.executable
        and section.rva_start <= target_rva < section.rva_end
    ]
    if len(sections) != 1:
        return None
    return target_id, canonical_rva


@dataclass(frozen=True)
class _RegisterProvenanceTrace:
    kind: str
    register: str
    target_id: int | None = None
    target_rva: int | None = None
    target_va: int | None = None
    imported: OriginalIATImport | None = None
    seed_target_ids: tuple[int, ...] = ()
    preserve_target_ids: tuple[int, ...] = ()
    edges: tuple[OriginalRegisterProvenanceEdge, ...] = ()
    seed_relocation_rvas: tuple[int, ...] = ()
    static_word_seed_bindings: tuple[
        OriginalRegisterStaticWordSeedBinding, ...
    ] = ()

    @property
    def key(self) -> tuple[object, ...]:
        if self.kind == "fixed_code_pointer":
            return (self.kind, self.target_id, self.target_rva, self.target_va)
        return (self.kind, self.imported)


def _recover_register_provenance_binding(
    binary: StageABinary,
    site: OriginalIndirectSite,
    resolved_id_by_rva: Mapping[int, int],
    parsed: Sequence[dict[str, Any]],
    relocation_counts: Mapping[int, int],
    predecessors_by_target_id: Mapping[int, Sequence[dict[str, Any]]],
    iat_by_va: Mapping[int, OriginalIATImport],
    call_contracts_by_edge: Mapping[
        tuple[int, int], OriginalRegisterControlCallContractProposal
    ],
    static_word_call_seeds_by_site: Mapping[
        tuple[int, int], OriginalRegisterStaticWordSeedAuthority
    ],
) -> tuple[OriginalStaticIndirectBinding | None, str]:
    target = site.target_expression
    if not isinstance(target, Mapping) or target.get("op") != "reg":
        return None, "register provenance requires an exact register target expression"
    register = target.get("name")
    if register not in {"eax", "ebx", "ecx", "edx", "esi", "edi", "ebp"}:
        return None, "register target is outside the supported PE32 register set"
    source_target_id = resolved_id_by_rva.get(site.source_rva)
    if source_target_id is None:
        return None, "register-control source is not an indexed code target"
    source_failure = _register_control_source_checked(
        binary, parsed[source_target_id], site, register
    )
    if source_failure:
        return None, source_failure
    predecessor_rows = tuple(
        dict.fromkeys(
            predecessor["rva"]
            for predecessor in predecessors_by_target_id.get(source_target_id, ())
        )
    )
    if not predecessor_rows:
        return None, "register provenance reaches a root without an exact seed"

    memo: dict[int, tuple[_RegisterProvenanceTrace | None, str]] = {}
    traces: list[_RegisterProvenanceTrace] = []
    for predecessor_rva in predecessor_rows:
        predecessor_target_id = resolved_id_by_rva.get(predecessor_rva)
        if predecessor_target_id is None:
            return None, (
                f"predecessor 0x{predecessor_rva:x} is not an indexed code target"
            )
        trace, failure = _resolve_register_output_provenance(
            binary,
            predecessor_target_id,
            register,
            resolved_id_by_rva,
            parsed,
            relocation_counts,
            predecessors_by_target_id,
            iat_by_va,
            call_contracts_by_edge,
            static_word_call_seeds_by_site,
            memo,
            frozenset(),
        )
        if trace is None:
            return None, (
                f"predecessor 0x{predecessor_rva:x} does not establish {register}: "
                f"{failure}"
            )
        edge_contract = call_contracts_by_edge.get(
            (predecessor_target_id, source_target_id)
        )
        traces.append(
            replace(
                trace,
                edges=_sorted_provenance_edges(
                    (*trace.edges, OriginalRegisterProvenanceEdge(
                        predecessor_target_id,
                        source_target_id,
                        "call_return" if edge_contract is not None else "direct",
                        None if edge_contract is None else edge_contract.contract_id,
                    ))
                ),
            )
        )
    merged, failure = _merge_register_provenance_traces(traces)
    if merged is None:
        return None, failure

    continuation_target_id: int | None = None
    if site.is_call:
        if site.continuation_rva is None:
            return None, "register-indirect call lacks an exact continuation RVA"
        continuation_target_id = resolved_id_by_rva.get(site.continuation_rva)
        if continuation_target_id is None:
            return None, "register-indirect continuation is not an indexed code target"

    if merged.kind == "import":
        if not site.is_call or continuation_target_id is None:
            return None, "register-carried import provenance only supports calls"
        if merged.imported is None:
            raise AssertionError("validated import provenance lost its import")
        seed_bindings, seed_failure = _recover_import_register_seed_bindings(
            binary,
            parsed,
            merged.seed_target_ids,
            register,
            merged.imported,
        )
        if seed_bindings is None:
            return None, seed_failure
        return (
            OriginalRegisterImportBinding(
                register=register,
                imported=merged.imported,
                continuation_target_id=continuation_target_id,
                seed_target_ids=merged.seed_target_ids,
                seed_bindings=seed_bindings,
                preserve_target_ids=merged.preserve_target_ids,
                edges=merged.edges,
                call_contract_ids=tuple(
                    dict.fromkeys(
                        edge.contract_id
                        for edge in merged.edges
                        if (
                            edge.kind == "call_return"
                            and edge.contract_id is not None
                        )
                    )
                ),
            ),
            "",
        )
    if merged.target_id is None or merged.target_rva is None or merged.target_va is None:
        raise AssertionError("validated fixed provenance lost its target")
    if not site.is_call:
        return None, (
            "fixed register tail provenance was recovered, but this profile has no "
            "kernel-checked register-tail closure theorem"
        )
    return (
        OriginalRegisterCodePointerBinding(
            register=register,
            target_id=merged.target_id,
            target_rva=merged.target_rva,
            target_va=merged.target_va,
            continuation_target_id=continuation_target_id,
            seed_target_ids=merged.seed_target_ids,
            preserve_target_ids=merged.preserve_target_ids,
            edges=merged.edges,
            seed_relocation_rvas=merged.seed_relocation_rvas,
            static_word_seed_bindings=merged.static_word_seed_bindings,
        ),
        "",
    )


def _resolve_register_output_provenance(
    binary: StageABinary,
    target_id: int,
    register: str,
    resolved_id_by_rva: Mapping[int, int],
    parsed: Sequence[dict[str, Any]],
    relocation_counts: Mapping[int, int],
    predecessors_by_target_id: Mapping[int, Sequence[dict[str, Any]]],
    iat_by_va: Mapping[int, OriginalIATImport],
    call_contracts_by_edge: Mapping[
        tuple[int, int], OriginalRegisterControlCallContractProposal
    ],
    static_word_call_seeds_by_site: Mapping[
        tuple[int, int], OriginalRegisterStaticWordSeedAuthority
    ],
    memo: dict[int, tuple[_RegisterProvenanceTrace | None, str]],
    active: frozenset[int],
) -> tuple[_RegisterProvenanceTrace | None, str]:
    cached = memo.get(target_id)
    if cached is not None:
        return cached
    if target_id in active:
        return None, "register provenance crosses a cycle without an inductive witness"
    row = parsed[target_id]
    instructions, failure = _decode_exact_region(binary, row)
    if instructions is None:
        result = (None, failure)
        memo[target_id] = result
        return result
    writes = [
        index
        for index, instruction in enumerate(instructions)
        if _instruction_writes_register(instruction, register)
    ]
    if writes:
        seed_index = writes[-1]
        suffix = instructions[seed_index + 1 :]
        suffix_calls = [
            instruction for instruction in suffix
            if _is_call_instruction(instruction)
        ]
        call_contract: OriginalRegisterControlCallContractProposal | None = None
        if suffix_calls:
            call_contract, _continuation_target_id = (
                _exact_preserving_call_contract(
                    binary=binary,
                    source_target_id=target_id,
                    register=register,
                    row=row,
                    instructions=suffix,
                    parsed=parsed,
                    contracts_by_edge=call_contracts_by_edge,
                )
            )
            if call_contract is None:
                result = (
                    None,
                    "an uncontracted call occurs after the last register seed",
                )
                memo[target_id] = result
                return result
        trace, seed_failure = _classify_register_seed(
            binary,
            target_id,
            register,
            instructions[seed_index],
            resolved_id_by_rva,
            parsed,
            relocation_counts,
            iat_by_va,
        )
        if trace is None and call_contract is not None:
            trace, seed_failure = _finite_origin_call_output_trace(
                binary=binary,
                source_target_id=target_id,
                register=register,
                call_instruction=suffix_calls[0],
                contract=call_contract,
                static_word_call_seeds_by_site=static_word_call_seeds_by_site,
                resolved_id_by_rva=resolved_id_by_rva,
                parsed=parsed,
            )
        if trace is not None and call_contract is not None:
            if (
                call_contract.finite_target_ids
                and trace.target_id not in call_contract.finite_target_ids
            ):
                result = (
                    None,
                    "checked finite-origin call target differs from the exact "
                    "register seed",
                )
            else:
                result = (trace, "")
        else:
            result = (trace, seed_failure)
        memo[target_id] = result
        return result
    call_contract: OriginalRegisterControlCallContractProposal | None = None
    call_target_id: int | None = None
    if any(_is_call_instruction(item) for item in instructions):
        call_contract, call_target_id = _exact_preserving_call_contract(
            binary=binary,
            source_target_id=target_id,
            register=register,
            row=row,
            instructions=instructions,
            parsed=parsed,
            contracts_by_edge=call_contracts_by_edge,
        )
        if call_contract is None or call_target_id is None:
            result = (
                None,
                "register provenance crosses an uncontracted call boundary",
            )
            memo[target_id] = result
            return result

    predecessor_ids = tuple(
        dict.fromkeys(
            resolved_id_by_rva[predecessor["rva"]]
            for predecessor in predecessors_by_target_id.get(target_id, ())
            if predecessor["rva"] in resolved_id_by_rva
        )
    )
    if not predecessor_ids:
        result = (None, "register provenance reaches a root without an exact seed")
        memo[target_id] = result
        return result
    traces: list[_RegisterProvenanceTrace] = []
    next_active = active | {target_id}
    for predecessor_id in predecessor_ids:
        trace, predecessor_failure = _resolve_register_output_provenance(
            binary,
            predecessor_id,
            register,
            resolved_id_by_rva,
            parsed,
            relocation_counts,
            predecessors_by_target_id,
            iat_by_va,
            call_contracts_by_edge,
            static_word_call_seeds_by_site,
            memo,
            next_active,
        )
        if trace is None:
            result = (
                None,
                f"predecessor 0x{parsed[predecessor_id]['rva']:x}: "
                f"{predecessor_failure}",
            )
            memo[target_id] = result
            return result
        edge_contract = call_contracts_by_edge.get(
            (predecessor_id, target_id)
        )
        edge = OriginalRegisterProvenanceEdge(
            predecessor_id,
            target_id,
            "call_return" if edge_contract is not None else "direct",
            None if edge_contract is None else edge_contract.contract_id,
        )
        traces.append(replace(
            trace,
            preserve_target_ids=tuple(sorted((
                *trace.preserve_target_ids,
                target_id,
            ))),
            edges=_sorted_provenance_edges((*trace.edges, edge)),
        ))
    result = _merge_register_provenance_traces(traces)
    if result[0] is not None and call_contract is not None:
        result = (
            replace(
                result[0],
                preserve_target_ids=tuple(sorted((
                    *result[0].preserve_target_ids,
                    target_id,
                ))),
            ),
            result[1],
        )
    memo[target_id] = result
    return result


def _register_control_call_contracts_by_edge(
    contracts: Sequence[OriginalRegisterControlCallContractProposal],
    resolved_id_by_rva: Mapping[int, int],
) -> dict[tuple[int, int], OriginalRegisterControlCallContractProposal]:
    by_edge: dict[
        tuple[int, int], OriginalRegisterControlCallContractProposal
    ] = {}
    for contract in contracts:
        source_target_id = resolved_id_by_rva.get(contract.source_rva)
        continuation_target_id = resolved_id_by_rva.get(contract.continuation_rva)
        if source_target_id is None or continuation_target_id is None:
            continue
        edge = (source_target_id, continuation_target_id)
        if edge in by_edge:
            raise InterpreterMixedOriginalGenerationError(
                "register-control call contracts ambiguously authorize one "
                "source/continuation edge"
            )
        by_edge[edge] = contract
    return by_edge


def _exact_preserving_call_contract(
    *,
    binary: StageABinary,
    source_target_id: int,
    register: str,
    row: Mapping[str, Any],
    instructions: Sequence[Any],
    parsed: Sequence[Mapping[str, Any]],
    contracts_by_edge: Mapping[
        tuple[int, int], OriginalRegisterControlCallContractProposal
    ],
) -> tuple[OriginalRegisterControlCallContractProposal | None, int | None]:
    calls = [instruction for instruction in instructions if _is_call_instruction(instruction)]
    if len(calls) != 1:
        return None, None
    call = calls[0]
    instruction_rva = call.address - binary.image_base
    event = _matching_call_event(row, instruction_rva)
    if event is None:
        return None, None
    continuation_rva = event.get("return_rva")
    if not isinstance(continuation_rva, int) or isinstance(continuation_rva, bool):
        return None, None
    matches = [
        (target_target_id, contract)
        for (edge_source_id, target_target_id), contract
        in contracts_by_edge.items()
        if edge_source_id == source_target_id
        and contract.source_rva == row["rva"]
        and contract.instruction_rva == instruction_rva
        and contract.continuation_rva == continuation_rva
        and target_target_id < len(parsed)
        and parsed[target_target_id]["rva"] == continuation_rva
        and (
            _canonical_register(register)
            in {
                _canonical_register(item)
                for item in contract.preserved_registers
            }
            or (
                contract.origin == "checked_finite_origin_call_summary"
                and _canonical_register(register)
                in {
                    _canonical_register(item)
                    for item in contract.target_carried_registers
                }
            )
        )
    ]
    if len(matches) != 1:
        return None, None
    target_target_id, contract = matches[0]
    return contract, target_target_id


def _finite_origin_call_output_trace(
    *,
    binary: StageABinary,
    source_target_id: int,
    register: str,
    call_instruction: Any,
    contract: OriginalRegisterControlCallContractProposal,
    static_word_call_seeds_by_site: Mapping[
        tuple[int, int], OriginalRegisterStaticWordSeedAuthority
    ],
    resolved_id_by_rva: Mapping[int, int],
    parsed: Sequence[Mapping[str, Any]],
) -> tuple[_RegisterProvenanceTrace | None, str]:
    if (
        contract.origin != "checked_finite_origin_call_summary"
        or len(contract.finite_target_ids) != 1
        or _canonical_register(register)
        not in {
            _canonical_register(item)
            for item in contract.target_carried_registers
        }
    ):
        return None, "last register write is not a supported exact seed"
    if len(call_instruction.operands) != 1:
        return None, "finite-origin call has no exact register target"
    operand = call_instruction.operands[0]
    if (
        operand.type != X86_OP_REG
        or call_instruction.reg_name(operand.reg) != register
    ):
        return None, "finite-origin call does not consume the seeded register"
    target_id = contract.finite_target_ids[0]
    if target_id >= len(parsed):
        return None, "finite-origin call target is not an indexed code target"
    target_rva = parsed[target_id].get("rva")
    if (
        not isinstance(target_rva, int)
        or isinstance(target_rva, bool)
        or target_rva < 0
        or target_rva >= 2**32
    ):
        return None, "finite-origin call target has an invalid indexed RVA"
    resolved = _resolve_exact_code_va(
        binary,
        binary.image_base + target_rva,
        resolved_id_by_rva,
        parsed,
    )
    if resolved != (target_id, target_rva):
        return None, "finite-origin call target is not uniquely executable"
    seed_authority = static_word_call_seeds_by_site.get(
        (contract.source_rva, contract.instruction_rva)
    )
    if seed_authority is None:
        return None, "finite-origin call lacks a checked static-word seed"
    if (
        seed_authority.binding.target_id != target_id
        or seed_authority.binding.continuation_target_id
            != resolved_id_by_rva.get(contract.continuation_rva)
    ):
        return None, "finite-origin call static-word seed targets do not match"
    return (
        _RegisterProvenanceTrace(
            kind="fixed_code_pointer",
            register=register,
            target_id=target_id,
            target_rva=target_rva,
            target_va=binary.image_base + target_rva,
            seed_target_ids=(source_target_id,),
            static_word_seed_bindings=(
                OriginalRegisterStaticWordSeedBinding(
                    source_target_id,
                    seed_authority.binding,
                ),
            ),
        ),
        "",
    )


def _build_mixed_original_register_control_provenance(
    *,
    binary: StageABinary,
    parsed: Sequence[dict[str, Any]],
    resolved_id_by_rva: Mapping[int, int],
    relocation_counts: Mapping[int, int],
    iat_by_va: Mapping[int, OriginalIATImport],
    roots: Sequence[int],
    call_contract_proposals: Sequence[
        OriginalRegisterControlCallContractProposal
    ],
) -> Mapping[str, Any]:
    """Adapt exact decoded original facts to proposal-only register analysis."""

    pairs = {
        register: RegisterControlRegisterPair(register, register)
        for register in _REGISTER_CONTROL_REGISTERS
    }
    decoded: dict[int, list[Any]] = {}
    decode_frontiers: list[dict[str, Any]] = []
    exact_edges: list[tuple[int, int, str, int | None]] = []
    internal_direct_call_sites: list[dict[str, Any]] = []
    contract_by_site = {
        (item.instruction_rva, item.continuation_rva): item
        for item in call_contract_proposals
    }
    matched_contract_ids: set[int] = set()
    for source_id, row in enumerate(parsed):
        instructions, failure = _decode_exact_region(binary, row)
        if instructions is None:
            decode_frontiers.append({
                "reason_code": "register_control_exact_decode_incomplete",
                "source_target_id": source_id,
                "source_rva": row["rva"],
                "detail": failure,
            })
            continue
        decoded[source_id] = instructions
        exact_edges.extend(_decoded_register_control_edges(
            binary=binary,
            source_id=source_id,
            row=row,
            instructions=instructions,
            resolved_id_by_rva=resolved_id_by_rva,
            contract_by_site=contract_by_site,
            matched_contract_ids=matched_contract_ids,
        ))
        final = instructions[-1]
        instruction_rva = final.address - binary.image_base
        event = _matching_call_event(row, instruction_rva)
        if (
            final.mnemonic.lower() in {"call", "lcall"}
            and event is not None
            and event.get("kind") == "internal_call"
            and isinstance(event.get("return_rva"), int)
        ):
            continuation_rva = int(event["return_rva"])
            continuation_id = resolved_id_by_rva.get(continuation_rva)
            if continuation_id is not None:
                internal_direct_call_sites.append({
                    "source_target_id": source_id,
                    "continuation_target_id": continuation_id,
                    "source_rva": row["rva"],
                    "callsite_rva": instruction_rva,
                    "continuation_rva": continuation_rva,
                })
        for site in row["indirect_sites"]:
            if site.static_binding is not None:
                exact_edges.extend(
                    (source_id, target_id, "direct", None)
                    for target_id in site.static_binding.target_ids
                )

    exact_edges = sorted(set(exact_edges))
    exact_edge_ids = _stable_register_control_edge_ids(exact_edges)
    exact_edge_indices = {
        (source, target, kind): exact_edge_ids[
            (source, target, kind, contract_id)
        ]
        for source, target, kind, contract_id in exact_edges
    }
    internal_direct_call_sites = [
        {
            **item,
            "edge_index": exact_edge_indices.get((
                int(item["source_target_id"]),
                int(item["continuation_target_id"]),
                "call_return",
            )),
        }
        for item in internal_direct_call_sites
    ]
    successors: dict[int, list[int]] = {}
    for source, target, _kind, _contract_id in exact_edges:
        successors.setdefault(source, []).append(target)
    rooted: set[int] = set()
    queue = deque(
        resolved_id_by_rva[root] for root in roots if root in resolved_id_by_rva
    )
    while queue:
        source = queue.popleft()
        if source in rooted:
            continue
        rooted.add(source)
        queue.extend(successors.get(source, ()))
    # Keep the complete decoded inventory in the proposal.  Rooted closure is
    # reported separately because unresolved indirect targets can make it
    # incomplete; treating non-rooted regions as additional roots would be
    # unsound, while omitting their repair evidence would hide useful work.
    ordered_global_ids = tuple(sorted(decoded))
    local_by_global = {
        global_id: local_id
        for local_id, global_id in enumerate(ordered_global_ids)
    }

    seed_bindings: dict[tuple[int, str], OriginalRegisterCodePointerBinding] = {}
    for row in parsed:
        for site in row["indirect_sites"]:
            binding = site.static_binding
            if isinstance(binding, OriginalRegisterCodePointerBinding):
                for seed_target_id in binding.seed_target_ids:
                    seed_bindings[(seed_target_id, binding.register)] = binding

    transfers: list[RegisterControlRegionTransfer] = []
    transfer_frontiers: list[dict[str, Any]] = []
    import_address_seeds: list[dict[str, Any]] = []
    transfer_by_global: dict[int, RegisterControlRegionTransfer] = {}
    for global_id in ordered_global_ids:
        transfer, frontiers, import_seeds = _decoded_register_control_transfer(
            binary=binary,
            global_id=global_id,
            local_id=local_by_global[global_id],
            row=parsed[global_id],
            instructions=decoded.get(global_id, []),
            pairs=pairs,
            seed_bindings=seed_bindings,
            resolved_id_by_rva=resolved_id_by_rva,
            parsed=parsed,
            relocation_counts=relocation_counts,
            iat_by_va=iat_by_va,
        )
        transfers.append(transfer)
        transfer_by_global[global_id] = transfer
        transfer_frontiers.extend(frontiers)
        import_address_seeds.extend(import_seeds)

    call_contracts = tuple(
        _register_control_call_contract(item, pairs)
        for item in sorted(
            call_contract_proposals, key=lambda proposal: proposal.contract_id
        )
        if item.contract_id in matched_contract_ids
    )
    matched_contracts = {
        item.contract_id: item for item in call_contract_proposals
        if item.contract_id in matched_contract_ids
    }
    edges = tuple(
        RegisterControlEdge(
            local_by_global[source],
            local_by_global[target],
            kind,
            contract_id,
            exact_edge_ids[(source, target, kind, contract_id)],
        )
        for source, target, kind, contract_id in exact_edges
        if source in local_by_global and target in local_by_global
    )

    uses: list[RegisterControlUse] = []
    use_facts: list[dict[str, Any]] = []
    for global_id in ordered_global_ids:
        for site in parsed[global_id]["indirect_sites"]:
            target = site.target_expression
            if (
                site.category not in {
                    "register_function_pointer", "register_tail_target"
                }
                or not isinstance(target, Mapping)
                or target.get("op") != "reg"
                or not isinstance(target.get("name"), str)
            ):
                continue
            register = _canonical_register(target["name"])
            if register not in pairs:
                continue
            use_index = len(uses)
            uses.append(RegisterControlUse(
                local_by_global[global_id], pairs[register], "indirect_control"
            ))
            use_facts.append({
                "use_index": use_index,
                "source_target_id": global_id,
                "source_rva": parsed[global_id]["rva"],
                "instruction_rva": site.instruction_rva,
                "register": register,
                "existing_static_binding": site.static_binding is not None,
                "existing_unresolved_blocker_retained": (
                    site.static_binding is None and site.iat_import is None
                ),
                "use_phase": "region_input_before_pre_control_transfer",
            })

    entry_indices = tuple(sorted(
        local_by_global[resolved_id_by_rva[root]]
        for root in roots
        if root in resolved_id_by_rva
        and resolved_id_by_rva[root] in local_by_global
    ))
    witness = build_register_control_provenance_witness(
        region_count=len(ordered_global_ids),
        register_pairs=tuple(pairs.values()),
        entry_region_indices=entry_indices,
        transfers=tuple(transfers),
        edges=edges,
        call_contracts=call_contracts,
        uses=tuple(uses),
    ).to_payload()
    witness_uses = {
        int(item["use_index"]): item for item in witness["uses"]
    }
    enriched_uses = [
        {**item, "witness": witness_uses.get(item["use_index"])}
        for item in use_facts
    ]
    import_flows = _register_import_address_flows(
        seeds=import_address_seeds,
        uses=enriched_uses,
        exact_edges=exact_edges,
        local_by_global=local_by_global,
        transfer_by_global=transfer_by_global,
        contracts=matched_contracts,
    )
    unmatched_contracts = [
        {
            "reason_code": "register_control_call_contract_not_in_exact_graph",
            "contract_id": item.contract_id,
            "source_rva": item.source_rva,
            "instruction_rva": item.instruction_rva,
            "continuation_rva": item.continuation_rva,
            "origin": item.origin,
        }
        for item in call_contract_proposals
        if item.contract_id not in matched_contract_ids
    ]
    body: dict[str, Any] = {
        "format": INTERPRETER_MIXED_REGISTER_CONTROL_FORMAT,
        "status": (
            "proposal_requires_generated_lean_replay"
            if witness["status"] == "proposal_requires_generated_lean_replay"
            and not decode_frontiers
            and not transfer_frontiers
            and not unmatched_contracts
            else "incomplete"
        ),
        "acceptance_authority": False,
        "checked_static_bindings_added": 0,
        "unresolved_indirect_control_blockers_removed": 0,
        "rooted_global_target_ids": sorted(rooted),
        "global_to_witness_region": [
            {"target_id": global_id, "region_index": local_by_global[global_id]}
            for global_id in ordered_global_ids
        ],
        "exact_graph": {
            "source": "capstone decode of SHA-bound exact PE spans",
            "proposal_only": True,
            "edges": [
                {
                    "edge_index": edge_index,
                    "source_target_id": source,
                    "target_target_id": target,
                    "kind": kind,
                    "machine_contract_id": contract_id,
                }
                for source, target, kind, contract_id in exact_edges
                if source in local_by_global and target in local_by_global
                for edge_index in [
                    exact_edge_ids[(source, target, kind, contract_id)]
                ]
            ],
        },
        "internal_direct_call_sites": sorted(
            internal_direct_call_sites,
            key=lambda item: (
                item["callsite_rva"], item["continuation_rva"]
            ),
        ),
        "import_address_seeds": sorted(
            import_address_seeds,
            key=lambda item: (
                item["source_rva"], item["instruction_rva"], item["register"]
            ),
        ),
        "call_contract_matches": [
            {
                "contract_id": item.contract_id,
                "machine_contract_id": item.machine_authority_id,
                "instruction_rva": item.instruction_rva,
                "continuation_rva": item.continuation_rva,
                "origin": item.origin,
                "import": (
                    None if item.import_identity is None
                    else _import_identity_json(item.import_identity)
                ),
                "preserved_registers": list(item.preserved_registers),
                "callee_preserved_registers": list(
                    item.callee_preserved_registers
                ),
                "target_carried_registers": list(
                    item.target_carried_registers
                ),
                "return_register": item.return_register,
                "arity_kind": item.arity_kind,
                "argument_words": item.argument_words,
                "authorizing_lean_term": (
                    None
                    if item.authorizing_lean_term is None
                    else item.authorizing_lean_term.qualified
                ),
                "finite_target_ids": list(item.finite_target_ids),
            }
            for item in sorted(
                call_contract_proposals, key=lambda proposal: proposal.contract_id
            )
            if item.contract_id in matched_contract_ids
        ],
        "uses": enriched_uses,
        "import_address_flows": import_flows,
        "frontiers": sorted(
            [*decode_frontiers, *transfer_frontiers, *unmatched_contracts],
            key=lambda item: (
                str(item.get("reason_code", "")),
                int(item.get("source_rva", -1)),
                int(item.get("instruction_rva", -1)),
            ),
        ),
        "witness": witness,
        "lean_replay_requirements": [
            "re-decode every transfer and graph edge from exact PE bytes",
            "check each producer against the canonical code or data map",
            "check every call contract and register preservation claim",
            "replay SCC fixed points and finite-disjunction joins",
            "check every indirect-control use before changing reachability",
        ],
    }
    body["adapter_sha256"] = hashlib.sha256(json.dumps(
        body, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode()).hexdigest()
    return body


def interpreter_mixed_original_register_control_lean_adapter(
    plan: InterpreterMixedOriginalPlan,
) -> Mapping[str, Any]:
    """Return deterministic proposal IR for a future generated Lean replay."""

    proposal = plan.register_control_provenance
    if proposal is None:
        raise InterpreterMixedOriginalGenerationError(
            "mixed-original plan has no exact register-control proposal"
        )
    if proposal.get("acceptance_authority") is not False:
        raise InterpreterMixedOriginalGenerationError(
            "register-control proposal unexpectedly claims acceptance authority"
        )
    authorizing_terms = sorted({
        item.authorizing_lean_term.qualified
        for item in plan.spec.register_control_call_contracts
        if item.origin in {
            "checked_direct_call_summary",
            "checked_finite_origin_call_summary",
        }
        and item.authorizing_lean_term is not None
    })
    body: dict[str, Any] = {
        "format": INTERPRETER_MIXED_REGISTER_CONTROL_LEAN_ADAPTER_FORMAT,
        "acceptance_authority": False,
        "state_machine_sha256": plan.state_machine_sha256,
        "proposal_format": proposal.get("format"),
        "proposal_sha256": proposal.get("adapter_sha256"),
        "proposal": json.loads(json.dumps(proposal)),
        "authorizing_term": (
            None if not authorizing_terms
            else authorizing_terms[0] if len(authorizing_terms) == 1
            else authorizing_terms
        ),
    }
    body["adapter_sha256"] = hashlib.sha256(json.dumps(
        body, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode()).hexdigest()
    return body


def derive_mixed_original_direct_call_summary_requests(
    plan: InterpreterMixedOriginalPlan,
) -> MixedOriginalDirectCallSummaryRequestPlan:
    """Find unique unresolved register-flow chains crossing internal calls.

    Calls are traversed speculatively only to discover proposal requests.  The
    returned requests never modify ``plan`` and carry no acceptance authority.
    Cycles, unsupported transfers, and multiple candidate chains fail closed.
    """

    proposal = plan.register_control_provenance
    if not isinstance(proposal, Mapping):
        return MixedOriginalDirectCallSummaryRequestPlan(
            plan.state_machine_sha256, (), (), ({
                "reason_code": "register_control_proposal_missing",
                "detail": "no exact register-control proposal was generated",
            },)
        )
    exact_graph = proposal.get("exact_graph")
    edge_rows = exact_graph.get("edges") if isinstance(exact_graph, Mapping) else None
    seed_rows = proposal.get("import_address_seeds")
    use_rows = proposal.get("uses")
    call_rows = proposal.get("internal_direct_call_sites")
    witness = proposal.get("witness")
    transfer_rows = witness.get("transfers") if isinstance(witness, Mapping) else None
    mapping_rows = proposal.get("global_to_witness_region")
    if not all(isinstance(rows, list) for rows in (
        edge_rows, seed_rows, use_rows, call_rows, transfer_rows, mapping_rows
    )):
        return MixedOriginalDirectCallSummaryRequestPlan(
            plan.state_machine_sha256, (), (), ({
                "reason_code": "register_control_request_inputs_incomplete",
                "detail": "proposal lacks exact graph, seed, use, or transfer rows",
            },)
        )

    global_to_local = {
        int(row["target_id"]): int(row["region_index"])
        for row in mapping_rows
        if isinstance(row, Mapping)
        and isinstance(row.get("target_id"), int)
        and isinstance(row.get("region_index"), int)
    }
    transfers = {
        int(row["region_index"]): row
        for row in transfer_rows
        if isinstance(row, Mapping) and isinstance(row.get("region_index"), int)
    }
    call_sites: dict[tuple[int, int], Mapping[str, Any]] = {}
    ambiguous_call_edges: set[tuple[int, int]] = set()
    for row in call_rows:
        if not isinstance(row, Mapping):
            continue
        source = row.get("source_target_id")
        target = row.get("continuation_target_id")
        if not isinstance(source, int) or not isinstance(target, int):
            continue
        key = (source, target)
        prior = call_sites.get(key)
        if prior is not None and prior != row:
            ambiguous_call_edges.add(key)
            call_sites.pop(key, None)
        elif key not in ambiguous_call_edges:
            call_sites[key] = row

    outgoing: dict[int, list[tuple[int, str, int | None]]] = {}
    for row in edge_rows:
        if not isinstance(row, Mapping):
            continue
        source = row.get("source_target_id")
        target = row.get("target_target_id")
        kind = row.get("kind")
        contract_id = row.get("machine_contract_id")
        if (
            isinstance(source, int)
            and isinstance(target, int)
            and kind in {"direct", "call_return"}
            and (contract_id is None or isinstance(contract_id, int))
        ):
            outgoing.setdefault(source, []).append((target, str(kind), contract_id))
    internal_call_sources = {source for source, _target in call_sites}
    flow_outgoing = {
        source: [
            edge for edge in edges
            if not (edge[1] == "direct" and source in internal_call_sources)
        ]
        for source, edges in outgoing.items()
    }
    matched_contracts = {
        int(row["contract_id"]): row
        for row in proposal.get("call_contract_matches", [])
        if isinstance(row, Mapping) and isinstance(row.get("contract_id"), int)
    }

    seeds_by_register: dict[str, list[Mapping[str, Any]]] = {}
    for row in seed_rows:
        if isinstance(row, Mapping) and row.get("register") in _REGISTER_CONTROL_REGISTERS:
            seeds_by_register.setdefault(str(row["register"]), []).append(row)

    chains: list[Mapping[str, Any]] = []
    frontiers: list[Mapping[str, Any]] = []
    requests_by_site: dict[tuple[int, int], set[str]] = {}
    for use in use_rows:
        if (
            not isinstance(use, Mapping)
            or use.get("existing_unresolved_blocker_retained") is not True
            or use.get("register") not in _REGISTER_CONTROL_REGISTERS
            or not isinstance(use.get("source_target_id"), int)
        ):
            continue
        register = str(use["register"])
        destination = int(use["source_target_id"])
        candidates: list[tuple[tuple[int, ...], tuple[Mapping[str, Any], ...]]] = []
        cycle_seen = False
        unsupported_seen = False
        ancestors = {destination}
        changed = True
        while changed:
            changed = False
            for source, edges in flow_outgoing.items():
                if source in ancestors:
                    continue
                if any(target in ancestors for target, _kind, _contract_id in edges):
                    ancestors.add(source)
                    changed = True

        def visit(
            current: int,
            path: tuple[int, ...],
            required_calls: tuple[Mapping[str, Any], ...],
            start: int,
        ) -> None:
            nonlocal cycle_seen, unsupported_seen
            if len(candidates) > 1:
                return
            if current == destination and current != start:
                candidates.append((path, required_calls))
                return
            if current != start and not _payload_transfer_preserves_register(
                transfers.get(global_to_local.get(current, -1)), register
            ):
                unsupported_seen = True
                return
            for target, kind, contract_id in sorted(flow_outgoing.get(current, ())):
                if target not in ancestors:
                    continue
                if target in path:
                    cycle_seen = True
                    continue
                next_required = required_calls
                if kind == "call_return":
                    contract = matched_contracts.get(contract_id)
                    if contract is not None:
                        preserved = contract.get("preserved_registers")
                        if not isinstance(preserved, list) or register not in preserved:
                            unsupported_seen = True
                            continue
                    else:
                        key = (current, target)
                        site = call_sites.get(key)
                        if site is None or key in ambiguous_call_edges:
                            unsupported_seen = True
                            continue
                        next_required = (*required_calls, site)
                visit(target, (*path, target), next_required, start)

        for seed in sorted(
            seeds_by_register.get(register, ()),
            key=lambda row: (int(row["source_rva"]), int(row["instruction_rva"])),
        ):
            start = seed.get("source_target_id")
            if isinstance(start, int):
                visit(start, (start,), (), start)

        frontier_base = {
            "use_source_rva": use.get("source_rva"),
            "use_instruction_rva": use.get("instruction_rva"),
            "register": register,
        }
        if cycle_seen:
            frontiers.append({
                **frontier_base,
                "reason_code": "direct_call_request_path_has_unsupported_loop",
                "detail": "a candidate register-flow path revisits a region",
            })
            continue
        if len(candidates) != 1:
            frontiers.append({
                **frontier_base,
                "reason_code": (
                    "direct_call_request_path_ambiguous"
                    if len(candidates) > 1
                    else "direct_call_request_path_not_found"
                ),
                "detail": f"found {len(candidates)} exact candidate chains",
            })
            continue
        path, required_calls = candidates[0]
        if unsupported_seen or not required_calls:
            frontiers.append({
                **frontier_base,
                "reason_code": "direct_call_request_path_unsupported",
                "detail": (
                    "the unique chain crosses an unsupported transfer"
                    if unsupported_seen
                    else "the unique chain contains no unresolved internal direct call"
                ),
            })
            continue
        chain = {
            **frontier_base,
            "path_target_ids": list(path),
            "required_internal_calls": [dict(row) for row in required_calls],
        }
        chains.append(chain)
        for call in required_calls:
            callsite_rva = int(call["callsite_rva"])
            source_rva = int(call["source_rva"])
            requests_by_site.setdefault((callsite_rva, source_rva), set()).add(register)

    requests = tuple(
        DirectCallSummaryRequest(
            callsite_rva=callsite_rva,
            caller_rva=source_rva,
            registers=tuple(
                register for register in _REGISTER_CONTROL_REGISTERS
                if register in registers
            ),
        ).checked()
        for (callsite_rva, source_rva), registers in sorted(requests_by_site.items())
    )
    return MixedOriginalDirectCallSummaryRequestPlan(
        state_machine_sha256=plan.state_machine_sha256,
        requests=requests,
        chains=tuple(sorted(
            chains,
            key=lambda row: (
                int(row["use_source_rva"]), int(row["use_instruction_rva"]),
                str(row["register"]),
            ),
        )),
        frontiers=tuple(sorted(
            frontiers,
            key=lambda row: (
                str(row.get("reason_code", "")),
                int(row.get("use_source_rva", -1)),
                int(row.get("use_instruction_rva", -1)),
            ),
        )),
    )


def derive_direct_call_summary_requests_from_register_authority(
    register_authority_report: Mapping[str, Any],
    machine_import_report: Mapping[str, Any],
    *,
    original_sha256: str,
    state_machine_sha256: str,
    machine_import_report_sha256: str,
) -> MixedOriginalDirectCallSummaryRequestPlan:
    """Turn exact register-carry inventory into proof-summary requests.

    This is proposal plumbing only.  The authority report identifies the
    call/return boundaries crossed by each unresolved value-provenance chain;
    generated Lean summaries must still prove every requested preservation
    fact before mixed-original acceptance can consume one.
    """

    if register_authority_report.get("format") != (
        "stage-a-register-indirect-control-authorities-v1"
    ):
        raise InterpreterMixedOriginalGenerationError(
            "register-indirect authority report has the wrong format"
        )
    authority_inputs = register_authority_report.get("inputs")
    if not isinstance(authority_inputs, Mapping):
        raise InterpreterMixedOriginalGenerationError(
            "register-indirect authority report has no hash-bound inputs"
        )
    expected_inputs = {
        "original_sha256": original_sha256,
        "state_machine_sha256": state_machine_sha256,
        "machine_import_report_sha256": machine_import_report_sha256,
    }
    for key, expected in expected_inputs.items():
        if authority_inputs.get(key) != expected:
            raise InterpreterMixedOriginalGenerationError(
                f"register-indirect authority report {key} does not match"
            )

    if machine_import_report.get("format") != (
        STATIC_MACHINE_IMPORT_CONTRACTS_FORMAT
    ):
        raise InterpreterMixedOriginalGenerationError(
            "machine-import report has the wrong format"
        )
    machine_inputs = machine_import_report.get("inputs")
    if not isinstance(machine_inputs, Mapping):
        raise InterpreterMixedOriginalGenerationError(
            "machine-import report has no hash-bound inputs"
        )
    for key, expected in (
        ("original_sha256", original_sha256),
        ("state_machine_sha256", state_machine_sha256),
    ):
        if machine_inputs.get(key) != expected:
            raise InterpreterMixedOriginalGenerationError(
                f"machine-import report {key} does not match"
            )

    boundary_rows = machine_import_report.get("boundaries")
    if not isinstance(boundary_rows, list):
        raise InterpreterMixedOriginalGenerationError(
            "machine-import report has no boundary inventory"
        )
    machine_boundaries: dict[int, list[Mapping[str, Any]]] = {}
    for index, row in enumerate(boundary_rows):
        if not isinstance(row, Mapping):
            raise InterpreterMixedOriginalGenerationError(
                f"machine-import boundary {index} is malformed"
            )
        instruction_rva = _u32(
            row.get("instruction_rva"),
            f"machine-import boundary {index} instruction_rva",
        )
        machine_boundaries.setdefault(instruction_rva, []).append(row)

    site_rows = register_authority_report.get("sites")
    if not isinstance(site_rows, list):
        raise InterpreterMixedOriginalGenerationError(
            "register-indirect authority report has no site inventory"
        )

    requests_by_site: dict[tuple[int, int], set[str]] = {}
    finite_requests_by_site: dict[tuple[int, int], set[str]] = {}
    chains: list[Mapping[str, Any]] = []
    for site_index, site in enumerate(site_rows):
        if not isinstance(site, Mapping):
            raise InterpreterMixedOriginalGenerationError(
                f"register-indirect authority site {site_index} is malformed"
            )
        use_source_rva = _u32(
            site.get("source_rva"), f"register authority site {site_index} source_rva"
        )
        use_instruction_rva = _u32(
            site.get("instruction_rva"),
            f"register authority site {site_index} instruction_rva",
        )
        register = site.get("target_register")
        if register not in _REGISTER_CONTROL_REGISTERS:
            raise InterpreterMixedOriginalGenerationError(
                f"register authority site {site_index} has an unsupported register"
            )
        carry_rows = site.get("carries")
        if not isinstance(carry_rows, list):
            raise InterpreterMixedOriginalGenerationError(
                f"register authority site {site_index} has no carry inventory"
            )

        requested_calls: list[Mapping[str, Any]] = []
        finite_origin_calls: list[Mapping[str, Any]] = []
        covered_imports: list[Mapping[str, Any]] = []
        for carry_index, carry in enumerate(carry_rows):
            if not isinstance(carry, Mapping):
                raise InterpreterMixedOriginalGenerationError(
                    f"register authority site {site_index} carry {carry_index} "
                    "is malformed"
                )
            kind = carry.get("kind")
            if kind not in {"internal_call", "target_call"}:
                continue
            callsite_rva = _u32(
                carry.get("instruction_rva"),
                f"register authority site {site_index} carry {carry_index} "
                "instruction_rva",
            )
            caller_rva = _u32(
                carry.get("source_rva"),
                f"register authority site {site_index} carry {carry_index} source_rva",
            )
            boundaries = machine_boundaries.get(callsite_rva, ())
            if boundaries:
                covered_imports.append({
                    "instruction_rva": callsite_rva,
                    "boundary_ids": sorted(
                        _u32(
                            row.get("id"),
                            f"machine-import boundary at 0x{callsite_rva:x} id",
                        )
                        for row in boundaries
                    ),
                    "routes": sorted({
                        str(row.get("route")) for row in boundaries
                        if isinstance(row.get("route"), str)
                    }),
                })
                continue
            requested = {
                "callsite_rva": callsite_rva,
                "caller_rva": caller_rva,
                "callee_target_id": carry.get("callee_target_id"),
                "source_target_id": carry.get("source_target_id"),
                "continuation_rva": carry.get("continuation_rva"),
                "continuation_target_id": carry.get("continuation_target_id"),
            }
            if kind == "target_call":
                finite_requests_by_site.setdefault(
                    (callsite_rva, caller_rva), set()
                ).add(str(register))
                finite_origin_calls.append(requested)
            else:
                requests_by_site.setdefault(
                    (callsite_rva, caller_rva), set()
                ).add(str(register))
                requested_calls.append(requested)

        chains.append({
            "source": "checked_register_indirect_authority_carry_inventory",
            "site_id": site.get("site_id", site_index),
            "use_source_rva": use_source_rva,
            "use_instruction_rva": use_instruction_rva,
            "register": register,
            "required_internal_calls": requested_calls,
            "required_finite_origin_calls": finite_origin_calls,
            "machine_import_carries": covered_imports,
        })

    requests = tuple(
        DirectCallSummaryRequest(
            callsite_rva=callsite_rva,
            caller_rva=caller_rva,
            registers=tuple(
                register for register in _REGISTER_CONTROL_REGISTERS
                if register in registers
            ),
        ).checked()
        for (callsite_rva, caller_rva), registers in sorted(requests_by_site.items())
    )
    finite_origin_entry_requests = tuple(
        DirectCallSummaryRequest(
            callsite_rva=callsite_rva,
            caller_rva=caller_rva,
            registers=tuple(
                register for register in _REGISTER_CONTROL_REGISTERS
                if register in registers
            ),
        ).checked()
        for (callsite_rva, caller_rva), registers in sorted(
            finite_requests_by_site.items()
        )
    )
    return MixedOriginalDirectCallSummaryRequestPlan(
        state_machine_sha256=state_machine_sha256,
        requests=requests,
        chains=tuple(chains),
        frontiers=(),
        finite_origin_entry_requests=finite_origin_entry_requests,
    )


def _payload_transfer_preserves_register(
    transfer: Mapping[str, Any] | None, register: str
) -> bool:
    if not isinstance(transfer, Mapping):
        return False
    copies = transfer.get("copies")
    if not isinstance(copies, list):
        return False
    for copy in copies:
        if not isinstance(copy, Mapping):
            continue
        output = copy.get("output")
        source = copy.get("source")
        if not isinstance(output, Mapping) or not isinstance(source, Mapping):
            continue
        if (
            output.get("original") == register
            and output.get("candidate") == register
            and source.get("original") == register
            and source.get("candidate") == register
        ):
            return True
    return False


def _apply_register_import_flow_bindings_for_lean_replay(
    *,
    binary: StageABinary,
    parsed: Sequence[dict[str, Any]],
    resolved_id_by_rva: Mapping[int, int],
    iat_by_va: Mapping[int, OriginalIATImport],
    call_contract_proposals: Sequence[
        OriginalRegisterControlCallContractProposal
    ],
    proposal: Mapping[str, Any],
) -> Mapping[str, Any]:
    """Promote unique exact import flows to bindings checked by generated Lean.

    The register-control analysis remains proposal-only.  Promotion merely
    selects the regions and claims emitted by `_lean_register_import_provenance_check`;
    that generated proof re-decodes every region and checks the IAT seed,
    preservation transfers, graph edges, and final indirect-call target.
    """

    exact_graph = proposal.get("exact_graph")
    graph_rows = exact_graph.get("edges") if isinstance(exact_graph, Mapping) else None
    flow_rows = proposal.get("import_address_flows")
    if not isinstance(graph_rows, list) or not isinstance(flow_rows, list):
        return proposal

    graph_edges: dict[tuple[int, int], tuple[str, int | None]] = {}
    for row in graph_rows:
        if not isinstance(row, Mapping):
            continue
        source = row.get("source_target_id")
        target = row.get("target_target_id")
        kind = row.get("kind")
        contract_id = row.get("machine_contract_id")
        if (
            not isinstance(source, int)
            or not isinstance(target, int)
            or kind not in {"direct", "call_return"}
            or (contract_id is not None and not isinstance(contract_id, int))
        ):
            continue
        key = (source, target)
        value = (kind, contract_id)
        prior = graph_edges.get(key)
        if prior is not None and prior != value:
            # A path with two differently justified versions of one edge is
            # ambiguous and must remain an unresolved frontier.
            graph_edges.pop(key, None)
            continue
        graph_edges[key] = value

    contracts = {
        item.contract_id: item for item in call_contract_proposals
    }
    imports = {
        (item.iat_rva, item.identity): item for item in iat_by_va.values()
    }
    candidates: dict[
        tuple[int, int], list[OriginalRegisterImportBinding]
    ] = {}
    for row in flow_rows:
        if not isinstance(row, Mapping) or row.get("status") != (
            "actionable_requires_import_address_atom_and_lean_replay"
        ):
            continue
        register = row.get("register")
        path_value = row.get("path_target_ids")
        crossed_value = row.get("preserving_contract_ids")
        seed_rva = row.get("seed_source_rva")
        use_rva = row.get("use_source_rva")
        use_instruction_rva = row.get("use_instruction_rva")
        iat_rva = row.get("iat_rva")
        if (
            register not in _REGISTER_CONTROL_REGISTERS
            or not isinstance(path_value, list)
            or len(path_value) < 2
            or not all(isinstance(item, int) for item in path_value)
            or not isinstance(crossed_value, list)
            or not all(isinstance(item, int) for item in crossed_value)
            or not isinstance(seed_rva, int)
            or not isinstance(use_rva, int)
            or not isinstance(use_instruction_rva, int)
            or not isinstance(iat_rva, int)
        ):
            continue
        path = tuple(path_value)
        if (
            resolved_id_by_rva.get(seed_rva) != path[0]
            or resolved_id_by_rva.get(use_rva) != path[-1]
            or any(not 0 <= target_id < len(parsed) for target_id in path)
        ):
            continue
        try:
            identity = _original_import_identity_from_json(
                row.get("import"), "register import flow"
            )
        except InterpreterMixedOriginalGenerationError:
            continue
        imported = imports.get((iat_rva, identity))
        if imported is None:
            continue

        path_edges: list[OriginalRegisterProvenanceEdge] = []
        crossed: list[int] = []
        valid_path = True
        for source, target in zip(path, path[1:]):
            edge = graph_edges.get((source, target))
            if edge is None:
                valid_path = False
                break
            kind, contract_id = edge
            if kind == "call_return":
                contract = contracts.get(contract_id) if contract_id is not None else None
                if contract is None or register not in {
                    _canonical_register(item)
                    for item in contract.preserved_registers
                }:
                    valid_path = False
                    break
                crossed.append(contract.contract_id)
            path_edges.append(OriginalRegisterProvenanceEdge(
                source, target, kind, contract_id
            ))
        if not valid_path or tuple(crossed) != tuple(crossed_value):
            continue

        source_item = parsed[path[-1]]
        matching_sites = [
            site for site in source_item["indirect_sites"]
            if site.instruction_rva == use_instruction_rva
            and site.is_call
            and site.static_binding is None
            and site.iat_import is None
            and isinstance(site.target_expression, Mapping)
            and site.target_expression.get("op") == "reg"
            and _canonical_register(str(site.target_expression.get("name")))
                == register
        ]
        if len(matching_sites) != 1 or matching_sites[0].continuation_rva is None:
            continue
        continuation_target_id = resolved_id_by_rva.get(
            matching_sites[0].continuation_rva
        )
        if continuation_target_id is None:
            continue
        seed_bindings, _seed_failure = _recover_import_register_seed_bindings(
            binary, parsed, (path[0],), register, imported
        )
        if seed_bindings is None:
            continue
        binding = OriginalRegisterImportBinding(
            register=register,
            imported=imported,
            continuation_target_id=continuation_target_id,
            seed_target_ids=(path[0],),
            seed_bindings=seed_bindings,
            preserve_target_ids=path[1:-1],
            edges=tuple(path_edges),
            call_contract_ids=tuple(crossed),
        )
        bucket = candidates.setdefault((path[-1], use_instruction_rva), [])
        if binding not in bucket:
            bucket.append(binding)

    added = 0
    selected_sites: set[tuple[int, int]] = set()
    for (source_target_id, instruction_rva), bindings in sorted(candidates.items()):
        if len(bindings) != 1:
            continue
        binding = bindings[0]
        item = parsed[source_target_id]
        sites: list[OriginalIndirectSite] = []
        matched = 0
        for site in item["indirect_sites"]:
            if (
                site.instruction_rva == instruction_rva
                and site.static_binding is None
                and site.iat_import is None
            ):
                sites.append(replace(
                    site,
                    detail=_static_binding_detail(binding),
                    static_binding=binding,
                ))
                matched += 1
            else:
                sites.append(site)
        if matched == 1:
            item["indirect_sites"] = tuple(sites)
            added += 1
            selected_sites.add((item["rva"], instruction_rva))

    body = json.loads(json.dumps(proposal))
    for use in body.get("uses", []):
        if not isinstance(use, dict):
            continue
        key = (use.get("source_rva"), use.get("instruction_rva"))
        if key in selected_sites:
            use["existing_static_binding"] = True
            use["existing_unresolved_blocker_retained"] = False
    for flow in body.get("import_address_flows", []):
        if not isinstance(flow, dict):
            continue
        key = (flow.get("use_source_rva"), flow.get("use_instruction_rva"))
        if key in selected_sites:
            flow["status"] = "selected_for_generated_lean_replay"
    body["checked_static_bindings_added"] = added
    body["unresolved_indirect_control_blockers_removed"] = 0
    body["adapter_sha256"] = hashlib.sha256(json.dumps(
        {key: value for key, value in body.items() if key != "adapter_sha256"},
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode()).hexdigest()
    return body


def _decoded_register_control_edges(
    *,
    binary: StageABinary,
    source_id: int,
    row: Mapping[str, Any],
    instructions: Sequence[Any],
    resolved_id_by_rva: Mapping[int, int],
    contract_by_site: Mapping[
        tuple[int, int], OriginalRegisterControlCallContractProposal
    ],
    matched_contract_ids: set[int],
) -> list[tuple[int, int, str, int | None]]:
    final = instructions[-1]
    mnemonic = final.mnemonic.lower()
    instruction_rva = final.address - binary.image_base
    continuation_rva = instruction_rva + final.size
    result: list[tuple[int, int, str, int | None]] = []
    if mnemonic in {"call", "lcall"}:
        event = _matching_call_event(row, instruction_rva)
        if event is not None and isinstance(event.get("return_rva"), int):
            continuation_rva = int(event["return_rva"])
        continuation_id = resolved_id_by_rva.get(continuation_rva)
        proposal = contract_by_site.get((instruction_rva, continuation_rva))
        contract_id = None
        if proposal is not None:
            matched_contract_ids.add(proposal.contract_id)
            contract_id = proposal.contract_id
        if continuation_id is not None:
            result.append((
                source_id, continuation_id, "call_return", contract_id
            ))
        return result
    if mnemonic in {"ret", "retf", "iret", "iretd"}:
        return result
    if mnemonic in {"jmp", "ljmp"}:
        if len(final.operands) == 1 and final.operands[0].type == X86_OP_IMM:
            target_rva = (final.operands[0].imm - binary.image_base) & 0xFFFFFFFF
            target_id = resolved_id_by_rva.get(target_rva)
            if target_id is not None:
                result.append((source_id, target_id, "direct", None))
        return result
    if final.group(capstone.CS_GRP_JUMP):
        if len(final.operands) == 1 and final.operands[0].type == X86_OP_IMM:
            target_rva = (final.operands[0].imm - binary.image_base) & 0xFFFFFFFF
            target_id = resolved_id_by_rva.get(target_rva)
            if target_id is not None:
                result.append((source_id, target_id, "direct", None))
        continuation_id = resolved_id_by_rva.get(continuation_rva)
        if continuation_id is not None:
            result.append((source_id, continuation_id, "direct", None))
        return result
    continuation_id = resolved_id_by_rva.get(continuation_rva)
    if continuation_id is not None:
        result.append((source_id, continuation_id, "direct", None))
    return result


def _decoded_register_control_transfer(
    *,
    binary: StageABinary,
    global_id: int,
    local_id: int,
    row: Mapping[str, Any],
    instructions: Sequence[Any],
    pairs: Mapping[str, RegisterControlRegisterPair],
    seed_bindings: Mapping[
        tuple[int, str], OriginalRegisterCodePointerBinding
    ],
    resolved_id_by_rva: Mapping[int, int],
    parsed: Sequence[dict[str, Any]],
    relocation_counts: Mapping[int, int],
    iat_by_va: Mapping[int, OriginalIATImport],
) -> tuple[
    RegisterControlRegionTransfer,
    list[dict[str, Any]],
    list[dict[str, Any]],
]:
    pre_control = [
        instruction for instruction in instructions
        if instruction.mnemonic.lower() not in {"call", "lcall"}
    ]
    copies: list[RegisterControlCopy] = []
    producers: list[RegisterControlProvenanceAtom] = []
    blocked: list[RegisterControlBlockedOutput] = []
    frontiers: list[dict[str, Any]] = []
    import_seeds: list[dict[str, Any]] = []
    for register, pair in pairs.items():
        existing = seed_bindings.get((global_id, register))
        if existing is not None:
            producers.append(RegisterControlProvenanceAtom(
                kind="exact_code_pointer",
                producer_region_index=local_id,
                register_pair=pair,
                target_id=existing.target_id,
                claim_kind="existing_exact_register_code_pointer_binding",
            ))
            continue
        writes = [
            instruction for instruction in pre_control
            if _instruction_writes_canonical_register(instruction, register)
        ]
        if not writes:
            copies.append(RegisterControlCopy(pair, pair))
            continue
        instruction = writes[-1]
        decoded_copy = _full_register_copy(instruction)
        if decoded_copy is not None and decoded_copy[0] == register:
            source = pairs.get(decoded_copy[1])
            if source is not None:
                copies.append(RegisterControlCopy(pair, source))
                continue
        trace, _failure = _classify_register_seed(
            binary,
            global_id,
            register,
            instruction,
            resolved_id_by_rva,
            parsed,
            relocation_counts,
            iat_by_va,
        )
        if trace is not None and trace.kind == "fixed_code_pointer":
            immediate = instruction.operands[1].type == X86_OP_IMM
            producers.append(RegisterControlProvenanceAtom(
                kind="exact_code_pointer" if immediate else "static_code_pointer",
                producer_region_index=local_id,
                register_pair=pair,
                target_id=trace.target_id,
                claim_kind=(
                    "relocation_backed_immediate_code_pointer"
                    if immediate else "immutable_static_word_code_pointer"
                ),
            ))
            continue
        absolute = _absolute_mov_load(instruction, register)
        if absolute is not None and absolute in iat_by_va:
            imported = iat_by_va[absolute]
            import_seeds.append({
                "reason_code": "register_control_import_address_atom_required",
                "source_target_id": global_id,
                "source_rva": row["rva"],
                "instruction_rva": instruction.address - binary.image_base,
                "register": register,
                "iat_rva": imported.iat_rva,
                "iat_va": imported.iat_va,
                "import": _import_identity_json(imported.identity),
                "status": "requires_generated_lean_replay",
            })
            continue
        if absolute is not None and _address_is_writable_image_word(
            binary, absolute
        ):
            blocked.append(RegisterControlBlockedOutput(
                pair, REGISTER_CONTROL_AMBIGUOUS_WRITABLE_LOAD
            ))
            frontiers.append({
                "reason_code": REGISTER_CONTROL_AMBIGUOUS_WRITABLE_LOAD,
                "source_target_id": global_id,
                "source_rva": row["rva"],
                "instruction_rva": instruction.address - binary.image_base,
                "register": register,
                "address": absolute,
                "detail": (
                    "writable register seed needs a checked write-provenance frame"
                ),
            })
            continue
        frontiers.append({
            "reason_code": "register_control_output_transfer_unresolved",
            "source_target_id": global_id,
            "source_rva": row["rva"],
            "instruction_rva": instruction.address - binary.image_base,
            "register": register,
            "detail": "exact write is outside the current proposal transfer subset",
        })
    return (
        RegisterControlRegionTransfer(
            region_index=local_id,
            copies=tuple(copies),
            producers=tuple(producers),
            blocked_outputs=tuple(blocked),
            preserve_unmentioned=False,
        ),
        frontiers,
        import_seeds,
    )


def _register_control_call_contract(
    proposal: OriginalRegisterControlCallContractProposal,
    pairs: Mapping[str, RegisterControlRegisterPair],
) -> RegisterControlCallContract:
    results: tuple[RegisterControlImportResult, ...] = ()
    if proposal.return_register is not None:
        assert proposal.import_identity is not None
        results = (RegisterControlImportResult(
            pairs[_canonical_register(proposal.return_register)],
            _import_identity_tuple(proposal.import_identity),
        ),)
    return RegisterControlCallContract(
        proposal.contract_id,
        preserved_registers=tuple(
            pairs[_canonical_register(register)]
            for register in proposal.preserved_registers
        ),
        import_results=results,
    )


def _register_import_address_flows(
    *,
    seeds: Sequence[Mapping[str, Any]],
    uses: Sequence[Mapping[str, Any]],
    exact_edges: Sequence[tuple[int, int, str, int | None]],
    local_by_global: Mapping[int, int],
    transfer_by_global: Mapping[int, RegisterControlRegionTransfer],
    contracts: Mapping[int, OriginalRegisterControlCallContractProposal],
) -> list[dict[str, Any]]:
    outgoing: dict[int, list[tuple[int, str, int | None]]] = {}
    for source, target, kind, contract_id in exact_edges:
        if source in local_by_global and target in local_by_global:
            outgoing.setdefault(source, []).append((target, kind, contract_id))
    uses_by_register: dict[str, list[Mapping[str, Any]]] = {}
    for use in uses:
        uses_by_register.setdefault(str(use["register"]), []).append(use)
    rows: list[dict[str, Any]] = []
    for seed in seeds:
        register = str(seed["register"])
        start = int(seed["source_target_id"])
        queue: deque[tuple[int, tuple[int, ...], tuple[int, ...]]] = deque([
            (start, (start,), ())
        ])
        seen: set[int] = set()
        while queue:
            source, path, crossed = queue.popleft()
            if source in seen:
                continue
            seen.add(source)
            for use in uses_by_register.get(register, ()):
                if int(use["source_target_id"]) == source and source != start:
                    rows.append({
                        "status": (
                            "actionable_requires_import_address_atom_and_lean_replay"
                        ),
                        "register": register,
                        "import": seed["import"],
                        "iat_rva": seed["iat_rva"],
                        "seed_source_rva": seed["source_rva"],
                        "seed_instruction_rva": seed["instruction_rva"],
                        "use_source_rva": use["source_rva"],
                        "use_instruction_rva": use["instruction_rva"],
                        "path_target_ids": list(path),
                        "preserving_contract_ids": list(crossed),
                        "next_action": (
                            "add a checked import-address atom and replay this exact "
                            "preservation path in generated Lean"
                        ),
                    })
            if (
                source != start
                and not _transfer_preserves_register(
                    transfer_by_global[source], register
                )
            ):
                continue
            for target, kind, contract_id in sorted(outgoing.get(source, ())):
                if kind == "call_return":
                    contract = (
                        contracts.get(contract_id)
                        if contract_id is not None else None
                    )
                    if contract is None or register not in {
                        _canonical_register(item)
                        for item in contract.preserved_registers
                    }:
                        continue
                    next_crossed = (*crossed, contract.contract_id)
                else:
                    next_crossed = crossed
                queue.append((target, (*path, target), next_crossed))
    unique = {
        (
            row["seed_instruction_rva"], row["use_instruction_rva"],
            tuple(row["path_target_ids"]),
            tuple(row["preserving_contract_ids"]),
        ): row
        for row in rows
    }
    return [unique[key] for key in sorted(unique)]


def _transfer_preserves_register(
    transfer: RegisterControlRegionTransfer, register: str
) -> bool:
    return any(
        copy.output.original == register
        and copy.source.original == register
        for copy in transfer.copies
    )


def _matching_call_event(
    row: Mapping[str, Any], instruction_rva: int
) -> Mapping[str, Any] | None:
    submitted = row.get("row")
    if isinstance(submitted, Mapping):
        row = submitted
    ordered = row.get("ordered_events")
    if not isinstance(ordered, list):
        return None
    matches = [
        event for event in ordered
        if isinstance(event, Mapping)
        and event.get("kind") in {
            "external_call", "internal_call", "indirect_call"
        }
        and event.get("instruction_rva") == instruction_rva
    ]
    return matches[0] if len(matches) == 1 else None


def _full_register_copy(instruction: Any) -> tuple[str, str] | None:
    if instruction.mnemonic.lower() != "mov" or len(instruction.operands) != 2:
        return None
    destination, source = instruction.operands
    if (
        destination.type != X86_OP_REG or destination.size != 4
        or source.type != X86_OP_REG or source.size != 4
    ):
        return None
    return (
        _canonical_register(instruction.reg_name(destination.reg)),
        _canonical_register(instruction.reg_name(source.reg)),
    )


def _absolute_mov_load(instruction: Any, register: str) -> int | None:
    if instruction.mnemonic.lower() != "mov" or len(instruction.operands) != 2:
        return None
    destination, source = instruction.operands
    if (
        destination.type != X86_OP_REG
        or destination.size != 4
        or _canonical_register(instruction.reg_name(destination.reg)) != register
        or source.type != X86_OP_MEM
        or source.size != 4
        or source.mem.base != 0
        or source.mem.index != 0
    ):
        return None
    return source.mem.disp & 0xFFFFFFFF


def _instruction_writes_canonical_register(
    instruction: Any, register: str
) -> bool:
    try:
        _reads, writes = instruction.regs_access()
    except capstone.CsError:
        return True
    return any(
        _canonical_register(instruction.reg_name(value)) == register
        for value in writes
    )


def _address_is_writable_image_word(binary: StageABinary, address: int) -> bool:
    if address < binary.image_base or address + 4 > 2**32:
        return False
    rva = address - binary.image_base
    return any(
        section.readable and section.writable and not section.executable
        and section.rva_start <= rva and rva + 4 <= section.rva_end
        for section in binary.sections
    )


def _canonical_register(register: str) -> str:
    return _REGISTER_ALIASES.get(str(register).lower(), str(register).lower())


def _import_identity_tuple(
    identity: OriginalImportIdentity,
) -> tuple[str, str, str | int]:
    if identity.symbol is not None:
        return (identity.dll, "symbol", identity.symbol)
    assert identity.ordinal is not None
    return (identity.dll, "ordinal", identity.ordinal)


def _original_import_identity_from_json(
    value: Any, context: str
) -> OriginalImportIdentity:
    if not isinstance(value, Mapping):
        raise InterpreterMixedOriginalGenerationError(
            f"{context} must be an object"
        )
    dll = value.get("dll")
    symbol = value.get("symbol")
    ordinal = value.get("ordinal")
    if not isinstance(dll, str):
        raise InterpreterMixedOriginalGenerationError(
            f"{context}.dll must be a string"
        )
    if symbol is not None and not isinstance(symbol, str):
        raise InterpreterMixedOriginalGenerationError(
            f"{context}.symbol must be a string"
        )
    if ordinal is not None and (
        not isinstance(ordinal, int) or isinstance(ordinal, bool)
    ):
        raise InterpreterMixedOriginalGenerationError(
            f"{context}.ordinal must be an integer"
        )
    return OriginalImportIdentity(dll, symbol, ordinal)


def _decode_exact_region(
    binary: StageABinary, row: Mapping[str, Any]
) -> tuple[list[Any] | None, str]:
    data = bytes(binary.pe.get_data(row["rva"], row["size"]))
    if len(data) != row["size"]:
        return None, "region span is not backed by exact PE bytes"
    decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    decoder.detail = True
    instructions = list(decoder.disasm(data, binary.image_base + row["rva"]))
    if not instructions or sum(item.size for item in instructions) != row["size"]:
        return None, "region does not decode over its complete exact PE span"
    return instructions, ""


def _instruction_writes_register(instruction: Any, register: str) -> bool:
    try:
        _reads, writes = instruction.regs_access()
    except capstone.CsError:
        return True
    return register in {instruction.reg_name(value) for value in writes}


def _is_call_instruction(instruction: Any) -> bool:
    return instruction.mnemonic in {"call", "lcall"}


def _classify_register_seed(
    binary: StageABinary,
    target_id: int,
    register: str,
    instruction: Any,
    resolved_id_by_rva: Mapping[int, int],
    parsed: Sequence[dict[str, Any]],
    relocation_counts: Mapping[int, int],
    iat_by_va: Mapping[int, OriginalIATImport],
) -> tuple[_RegisterProvenanceTrace | None, str]:
    if instruction.mnemonic != "mov" or len(instruction.operands) != 2:
        return None, "last register write is not a supported exact mov seed"
    destination, source = instruction.operands
    if destination.type != X86_OP_REG or instruction.reg_name(destination.reg) != register:
        return None, "last register write does not define the target register exactly"
    if source.type == X86_OP_IMM:
        target_va = source.imm & 0xFFFFFFFF
        resolved = _resolve_exact_code_va(
            binary, target_va, resolved_id_by_rva, parsed
        )
        if resolved is None:
            return None, "immediate register seed is not a unique indexed code address"
        if getattr(instruction, "imm_size", 0) != 4:
            return None, "immediate register seed is not a full PE32 word"
        relocation_rva = (
            instruction.address - binary.image_base + instruction.imm_offset
        )
        if relocation_counts.get(relocation_rva, 0) != 1:
            return None, "immediate code-pointer seed lacks exactly one HIGHLOW relocation"
        resolved_target_id, target_rva = resolved
        if target_va != binary.image_base + target_rva:
            return None, "immediate code-pointer seed resolves through a code alias"
        return (
            _RegisterProvenanceTrace(
                kind="fixed_code_pointer",
                register=register,
                target_id=resolved_target_id,
                target_rva=target_rva,
                target_va=target_va,
                seed_target_ids=(target_id,),
                seed_relocation_rvas=(relocation_rva,),
            ),
            "",
        )
    if source.type != X86_OP_MEM:
        return None, "register seed is neither an immediate nor an absolute memory word"
    memory = source.mem
    if memory.base != 0 or memory.index != 0 or source.size != 4:
        return None, "register seed is not one absolute PE32 memory word"
    address = memory.disp & 0xFFFFFFFF
    imported = iat_by_va.get(address)
    if imported is not None:
        return (
            _RegisterProvenanceTrace(
                kind="import",
                register=register,
                imported=imported,
                seed_target_ids=(target_id,),
            ),
            "",
        )
    seed_site = OriginalIndirectSite(
        source_rva=parsed[target_id]["rva"],
        instruction_rva=instruction.address - binary.image_base,
        category="static_pointer_slot",
        detail="register provenance seed",
        target_va=address,
    )
    slot, failure = _recover_immutable_slot_binding(
        binary,
        seed_site,
        resolved_id_by_rva,
        parsed,
        relocation_counts,
    )
    if slot is None:
        return None, f"absolute register seed is not immutable: {failure}"
    return (
        _RegisterProvenanceTrace(
            kind="fixed_code_pointer",
            register=register,
            target_id=slot.target_id,
            target_rva=slot.target_rva,
            target_va=slot.target_va,
            seed_target_ids=(target_id,),
            seed_relocation_rvas=(slot.slot_rva,),
        ),
        "",
    )


def _register_control_source_checked(
    binary: StageABinary,
    row: Mapping[str, Any],
    site: OriginalIndirectSite,
    register: str,
) -> str:
    instructions, failure = _decode_exact_region(binary, row)
    if instructions is None:
        return failure
    matching = [
        (index, instruction)
        for index, instruction in enumerate(instructions)
        if instruction.address - binary.image_base == site.instruction_rva
    ]
    if len(matching) != 1:
        return "register-control instruction is not unique in the exact decoded span"
    control_index, control = matching[0]
    expected_mnemonic = "call" if site.is_call else "jmp"
    if control.mnemonic != expected_mnemonic or len(control.operands) != 1:
        return "exact control instruction does not match the proposed transfer kind"
    operand = control.operands[0]
    if operand.type != X86_OP_REG or control.reg_name(operand.reg) != register:
        return "exact control instruction does not use the proposed target register"
    if any(
        _instruction_writes_register(instruction, register)
        or _is_call_instruction(instruction)
        for instruction in instructions[:control_index]
    ):
        return "target register is overwritten or crosses a call before indirect control"
    return ""


def _merge_register_provenance_traces(
    traces: Sequence[_RegisterProvenanceTrace],
) -> tuple[_RegisterProvenanceTrace | None, str]:
    if not traces:
        return None, "register provenance has no predecessor evidence"
    keys = {trace.key for trace in traces}
    if len(keys) != 1:
        alternatives = ", ".join(sorted(repr(key) for key in keys))
        return None, f"ambiguous finite register provenance alternatives: {alternatives}"
    first = traces[0]
    static_word_seeds: dict[int, OriginalRegisterStaticWordSeedBinding] = {}
    for trace in traces:
        for seed in trace.static_word_seed_bindings:
            existing = static_word_seeds.get(seed.target_id)
            if existing is not None and existing != seed:
                return None, (
                    "register provenance has conflicting static-word seed "
                    f"authorities for target {seed.target_id}"
                )
            static_word_seeds[seed.target_id] = seed
    return (
        replace(
            first,
            seed_target_ids=tuple(
                sorted({item for trace in traces for item in trace.seed_target_ids})
            ),
            preserve_target_ids=tuple(
                sorted({item for trace in traces for item in trace.preserve_target_ids})
            ),
            edges=_sorted_provenance_edges(
                tuple(edge for trace in traces for edge in trace.edges)
            ),
            seed_relocation_rvas=tuple(
                sorted(
                    {item for trace in traces for item in trace.seed_relocation_rvas}
                )
            ),
            static_word_seed_bindings=tuple(
                static_word_seeds[target_id]
                for target_id in sorted(static_word_seeds)
            ),
        ),
        "",
    )


def _sorted_provenance_edges(
    edges: Sequence[OriginalRegisterProvenanceEdge],
) -> tuple[OriginalRegisterProvenanceEdge, ...]:
    by_endpoints: dict[
        tuple[int, int], OriginalRegisterProvenanceEdge
    ] = {}
    for edge in edges:
        endpoints = (edge.source_target_id, edge.target_target_id)
        existing = by_endpoints.get(endpoints)
        if existing is not None and existing != edge:
            raise InterpreterMixedOriginalGenerationError(
                "register provenance has conflicting authorities for one edge"
            )
        by_endpoints[endpoints] = edge
    return tuple(
        by_endpoints[endpoints] for endpoints in sorted(by_endpoints)
    )


def _recover_immutable_slot_binding(
    binary: StageABinary,
    site: OriginalIndirectSite,
    resolved_id_by_rva: Mapping[int, int],
    parsed: Sequence[dict[str, Any]],
    relocation_counts: Mapping[int, int],
) -> tuple[OriginalImmutableSlotBinding | None, str]:
    if site.target_va is None or site.target_va < binary.image_base:
        return None, "pointer slot is outside the preferred PE image"
    if site.target_va + 4 > 2**32:
        return None, "pointer slot word overflows the PE32 address space"
    slot_rva = site.target_va - binary.image_base
    sections = [
        section
        for section in binary.sections
        if section.rva_start <= slot_rva
        and slot_rva + 4 <= section.rva_end
    ]
    if len(sections) != 1:
        return None, "pointer slot is not contained in exactly one mapped section"
    section = sections[0]
    if not section.readable or section.writable or section.executable:
        return None, (
            "pointer slot is not in a readable, non-writable, non-executable section"
        )
    if relocation_counts.get(slot_rva, 0) != 1:
        return None, "pointer slot lacks exactly one HIGHLOW relocation"
    data = bytes(binary.pe.get_data(slot_rva, 4))
    if len(data) != 4:
        return None, "pointer slot is not backed by four exact PE bytes"
    target_va = int.from_bytes(data, "little")
    resolved = _resolve_exact_code_va(
        binary, target_va, resolved_id_by_rva, parsed
    )
    if resolved is None:
        return None, "preferred pointer-slot value is not an indexed code target"
    if target_va != binary.image_base + resolved[1]:
        return None, (
            "pointer-slot value resolves through a code alias, but the immutable-word "
            "Lean claim requires the canonical indexed address"
        )
    target_id, target_rva = resolved
    if (
        site.resolved_target_rva is not None
        and site.resolved_target_rva != target_rva
    ):
        return None, (
            "resolved internal-control target does not match the exact immutable "
            "pointer-slot value"
        )
    continuation_target_id: int | None = None
    writes: tuple[OriginalRegisterOffsetWrite, ...] = ()
    assembled_read = False
    separations: tuple[OriginalAddressSeparation, ...] = ()
    if site.is_call:
        if site.continuation_rva is None:
            return None, "indirect call lacks an exact continuation RVA"
        continuation_target_id = resolved_id_by_rva.get(site.continuation_rva)
        if continuation_target_id is None:
            return None, "indirect-call continuation is not an indexed code target"
        source_target_id = resolved_id_by_rva.get(site.source_rva)
        if source_target_id is None:
            return None, "immutable-slot indirect-call source is not indexed"
        writes_result, assembled_read, write_failure = (
            _recover_static_word_call_writes(
                parsed[source_target_id]["row"], site, site.target_va, target_rva
            )
        )
        if writes_result is None:
            return None, write_failure
        writes = writes_result
        separations = tuple(
            OriginalAddressSeparation(
                register=write.register,
                offset=write.offset + write_byte,
                address=site.target_va + word_byte,
            )
            for write in writes
            for word_byte in range(4)
            for write_byte in range(4)
        )
    return (
        OriginalImmutableSlotBinding(
            slot_rva=slot_rva,
            slot_va=site.target_va,
            target_id=target_id,
            target_rva=target_rva,
            target_va=target_va,
            continuation_target_id=continuation_target_id,
            assembled_read=assembled_read,
            writes=writes,
            address_separations=separations,
        ),
        "",
    )


def _recover_writable_slot_initial_target(
    binary: StageABinary | None,
    site: OriginalIndirectSite,
    resolved_id_by_rva: Mapping[int, int],
    parsed: Sequence[dict[str, Any]],
    relocation_counts: Mapping[int, int],
    iat_by_va: Mapping[int, OriginalIATImport],
) -> tuple[tuple[int, int] | None, str]:
    """Recover only the exact launch-time target of a mutable static word.

    This is reachability evidence, not an indirect-exit certificate. Later
    writes may replace the word with other related origins and therefore the
    site remains incomplete until its finite-origin invariant is checked.
    """

    if binary is None:
        return None, "no SHA-bound original PE recovery input was supplied"
    if site.target_va is None or site.target_va < binary.image_base:
        return None, "writable pointer slot is outside the preferred PE image"
    if site.target_va + 4 > 2**32:
        return None, "writable pointer slot word overflows the PE32 address space"
    slot_rva = site.target_va - binary.image_base
    sections = [
        section
        for section in binary.sections
        if section.rva_start <= slot_rva
        and slot_rva + 4 <= section.rva_end
    ]
    if len(sections) != 1:
        return None, "writable pointer slot is not contained in exactly one section"
    section = sections[0]
    if not section.readable or not section.writable or section.executable:
        return None, "slot is not readable, writable, non-executable PE data"
    if any(
        site.target_va < imported.iat_va + 4
        and imported.iat_va < site.target_va + 4
        for imported in iat_by_va.values()
    ):
        return None, "writable pointer slot overlaps a proposed import IAT word"
    if relocation_counts.get(slot_rva, 0) != 1:
        return None, "writable pointer slot lacks exactly one HIGHLOW relocation"
    data = bytes(binary.pe.get_data(slot_rva, 4))
    if len(data) != 4:
        return None, "writable pointer slot is not backed by four exact PE bytes"
    target_va = int.from_bytes(data, "little")
    resolved = _resolve_exact_code_va(
        binary, target_va, resolved_id_by_rva, parsed
    )
    if resolved is None:
        return None, "initial writable-slot value is not an indexed code target"
    target_id, target_rva = resolved
    if target_va != binary.image_base + target_rva:
        return None, "initial writable-slot value resolves through a code alias"
    if (
        site.resolved_target_rva is not None
        and site.resolved_target_rva != target_rva
    ):
        return None, (
            "resolved control target differs from the exact initial writable-slot "
            "value"
        )
    return (target_id, target_rva), ""


def _recover_static_word_slot_binding(
    binary: StageABinary,
    site: OriginalIndirectSite,
    resolved_id_by_rva: Mapping[int, int],
    parsed: Sequence[dict[str, Any]],
    relocation_counts: Mapping[int, int],
    iat_by_va: Mapping[int, OriginalIATImport],
) -> tuple[OriginalStaticWordSlotBinding | None, str]:
    if site.target_va is None or site.target_va < binary.image_base:
        return None, "writable pointer slot is outside the preferred PE image"
    if site.target_va + 4 > 2**32:
        return None, "writable pointer slot word overflows the PE32 address space"
    slot_rva = site.target_va - binary.image_base
    sections = [
        section
        for section in binary.sections
        if section.rva_start <= slot_rva
        and slot_rva + 4 <= section.rva_end
    ]
    if len(sections) != 1:
        return None, "writable pointer slot is not contained in exactly one mapped section"
    section = sections[0]
    if not section.readable or not section.writable or section.executable:
        return None, (
            "pointer slot is neither immutable nor in a readable, writable, "
            "non-executable section"
        )
    if any(
        site.target_va < imported.iat_va + 4
        and imported.iat_va < site.target_va + 4
        for imported in iat_by_va.values()
    ):
        return None, "writable pointer slot overlaps a proposed import IAT word"
    if relocation_counts.get(slot_rva, 0) != 1:
        return None, "writable pointer slot does not have exactly one HIGHLOW relocation"
    data = bytes(binary.pe.get_data(slot_rva, 4))
    if len(data) != 4:
        return None, "writable pointer slot is not backed by four exact PE bytes"
    target_va = int.from_bytes(data, "little")
    resolved = _resolve_exact_code_va(
        binary, target_va, resolved_id_by_rva, parsed
    )
    if resolved is None:
        return None, "writable pointer-slot value is not an indexed executable code target"
    target_id, target_rva = resolved
    if target_va != binary.image_base + target_rva:
        return None, "writable pointer-slot value resolves through a code alias"
    if (
        site.resolved_target_rva is not None
        and site.resolved_target_rva != target_rva
    ):
        return None, (
            "resolved internal-call target does not match the exact writable "
            "pointer-slot value"
        )
    if site.continuation_rva is None:
        return None, "writable-slot indirect call lacks an exact continuation RVA"
    continuation_target_id = resolved_id_by_rva.get(site.continuation_rva)
    if continuation_target_id is None:
        return None, "writable-slot indirect-call continuation is not indexed"
    source_target_id = resolved_id_by_rva.get(site.source_rva)
    if source_target_id is None:
        return None, "writable-slot indirect-call source is not indexed"
    writes, assembled_read, write_failure = _recover_static_word_call_writes(
        parsed[source_target_id]["row"], site, site.target_va, target_rva
    )
    if writes is None:
        return None, write_failure
    separations = tuple(
        OriginalAddressSeparation(
            register=write.register,
            offset=write.offset + write_byte,
            address=site.target_va + word_byte,
        )
        for write in writes
        for word_byte in range(4)
        for write_byte in range(4)
    )
    return (
        OriginalStaticWordSlotBinding(
            slot_id=slot_rva,
            slot_rva=slot_rva,
            slot_va=site.target_va,
            slot_bytes=tuple(data),  # type: ignore[arg-type]
            target_id=target_id,
            target_rva=target_rva,
            target_va=target_va,
            continuation_target_id=continuation_target_id,
            assembled_read=assembled_read,
            writes=writes,
            address_separations=separations,
        ),
        "",
    )


def _recover_static_word_call_writes(
    row: Mapping[str, Any],
    site: OriginalIndirectSite,
    slot_va: int,
    target_rva: int,
) -> tuple[tuple[OriginalRegisterOffsetWrite, ...] | None, bool, str]:
    instructions = row.get("instructions")
    if not isinstance(instructions, list) or not all(
        isinstance(instruction, Mapping) for instruction in instructions
    ):
        return None, False, (
            "writable-slot call lacks an exact decoded instruction inventory"
        )
    write_address_forms = {
        int(instruction["rva"]): (
            "raw_modulo" if instruction.get("mnemonic") == "push" else "semantic_ir"
        )
        for instruction in instructions
        if isinstance(instruction.get("rva"), int)
    }
    ordered = row.get("ordered_events")
    if not isinstance(ordered, list):
        return None, False, "writable-slot call lacks an ordered memory framing inventory"
    matching = [
        (index, event)
        for index, event in enumerate(ordered)
        if isinstance(event, Mapping)
        and event.get("kind") in {"internal_call", "indirect_call"}
        and event.get("instruction_rva") == site.instruction_rva
    ]
    if len(matching) != 1:
        return None, False, (
            "writable-slot call does not have exactly one ordered call event"
        )
    event_index, call = matching[0]
    if call.get("return_rva") != site.continuation_rva:
        return None, False, "writable-slot ordered call continuation does not match"
    if call.get("kind") == "internal_call" and call.get("target_rva") != target_rva:
        return None, False, "writable-slot ordered internal-call target does not match"

    return _recover_register_offset_writes_before(
        ordered[:event_index],
        slot_va,
        "writable-slot",
        write_address_forms=write_address_forms,
    )


def _recover_register_offset_writes_before(
    events: Sequence[Any],
    protected_address: int,
    context: str,
    *,
    write_address_forms: Mapping[int, str],
) -> tuple[tuple[OriginalRegisterOffsetWrite, ...] | None, bool, str]:
    """Normalize exact prior word writes and prove they avoid one PE32 word."""

    writes: list[OriginalRegisterOffsetWrite] = []
    for event in events:
        if not isinstance(event, Mapping) or event.get("kind") != "write":
            continue
        if event.get("width") != 4:
            return None, False, (
                f"{context} memory framing contains a non-word write before the read"
            )
        address = event.get("address")
        constant_address = _const_value(address)
        if constant_address is not None:
            if (
                constant_address < protected_address + 4
                and protected_address < constant_address + 4
            ):
                if context == "writable-slot":
                    return None, False, (
                        "pre-call memory write overlaps the writable pointer slot"
                    )
                return None, False, (
                    f"{context} prior memory write overlaps the protected word"
                )
            continue
        register_offset = _register_offset_address(address)
        if register_offset is None:
            return None, False, (
                f"{context} prior memory write lacks register-offset no-alias framing"
            )
        instruction_rva = event.get("instruction_rva")
        if (
            not isinstance(instruction_rva, int)
            or instruction_rva not in write_address_forms
        ):
            return None, False, (
                f"{context} prior register-offset write is not tied to one exact "
                "decoded instruction"
            )
        address_form = write_address_forms[instruction_rva]
        if address_form not in {"raw_modulo", "semantic_ir"}:
            return None, False, (
                f"{context} prior register-offset write has an unsupported exact "
                "address form"
            )
        value = event.get("value")
        if not _static_word_write_value_supported(value):
            return None, False, (
                f"{context} prior register-offset write value is outside the "
                "checked expression subset"
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
    return tuple(writes), bool(writes), ""


def _address_separations_for_writes(
    writes: Sequence[OriginalRegisterOffsetWrite], protected_address: int
) -> tuple[OriginalAddressSeparation, ...]:
    return tuple(
        OriginalAddressSeparation(
            register=write.register,
            offset=write.offset + write_byte,
            address=protected_address + word_byte,
        )
        for write in writes
        for word_byte in range(4)
        for write_byte in range(4)
    )


def _recover_import_register_seed_bindings(
    binary: StageABinary,
    parsed: Sequence[dict[str, Any]],
    target_ids: Sequence[int],
    register: str,
    imported: OriginalIATImport,
) -> tuple[tuple[OriginalImportRegisterSeedBinding, ...] | None, str]:
    bindings: list[OriginalImportRegisterSeedBinding] = []
    for target_id in target_ids:
        if not 0 <= target_id < len(parsed):
            return None, "import-register seed target is outside the exact carrier"
        item = parsed[target_id]
        instructions, failure = _decode_exact_region(binary, item)
        if instructions is None:
            return None, f"import-register seed does not decode exactly: {failure}"
        matches = [
            (index, instruction)
            for index, instruction in enumerate(instructions)
            if _absolute_mov_load(instruction, register) == imported.iat_va
        ]
        if len(matches) != 1:
            return None, (
                "import-register seed lacks exactly one exact mov from the proposed IAT"
            )
        instruction_index, instruction = matches[0]
        instruction_rva = instruction.address - binary.image_base
        row = item.get("row")
        ordered = row.get("ordered_events") if isinstance(row, Mapping) else None
        if not isinstance(ordered, list):
            return None, "import-register seed lacks ordered memory evidence"
        read_matches = [
            (index, event)
            for index, event in enumerate(ordered)
            if isinstance(event, Mapping)
            and event.get("kind") == "read"
            and event.get("instruction_rva") == instruction_rva
            and event.get("width") == 4
            and _const_value(event.get("address")) == imported.iat_va
        ]
        if len(read_matches) == 1:
            event_index, _event = read_matches[0]
            prior_events = ordered[:event_index]
        elif not read_matches and instruction_index == 0:
            # The exact load is the first instruction, so an empty diagnostic
            # event prefix cannot conceal a prior write that changes its read.
            prior_events = ()
        else:
            return None, (
                "import-register seed lacks exactly one matching ordered IAT read"
            )
        writes, assembled_read, write_failure = (
            _recover_register_offset_writes_before(
                prior_events,
                imported.iat_va,
                "import-register seed",
                write_address_forms={
                    instruction.address - binary.image_base: (
                        "raw_modulo"
                        if instruction.mnemonic == "push"
                        else "semantic_ir"
                    )
                    for instruction in instructions
                },
            )
        )
        if writes is None:
            return None, write_failure
        bindings.append(
            OriginalImportRegisterSeedBinding(
                target_id=target_id,
                instruction_rva=instruction_rva,
                assembled_read=assembled_read,
                writes=writes,
                address_separations=_address_separations_for_writes(
                    writes, imported.iat_va
                ),
            )
        )
    return tuple(bindings), ""


def _register_offset_address(value: Any) -> tuple[str, int, bool] | None:
    registers = {"eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp"}

    def affine(expression: Any) -> tuple[dict[str, int], int] | None:
        if not isinstance(expression, Mapping):
            return None
        if expression.get("op") == "reg" and expression.get("name") in registers:
            return {str(expression["name"]): 1}, 0
        if (constant := _const_value(expression)) is not None:
            return {}, constant
        args = expression.get("args")
        operation = expression.get("op")
        if operation not in {"add32", "sub32"} or not isinstance(args, list) or len(args) != 2:
            return None
        left = affine(args[0])
        right = affine(args[1])
        if left is None or right is None:
            return None
        sign = 1 if operation == "add32" else -1
        coefficients = dict(left[0])
        for register, coefficient in right[0].items():
            coefficients[register] = coefficients.get(register, 0) + sign * coefficient
            if coefficients[register] == 0:
                del coefficients[register]
        return coefficients, (left[1] + sign * right[1]) % 2**32

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
        and (-amount) % 2**32 == offset
        and offset != 0
    ):
        subtract = True
    return register, offset, subtract


def _static_word_write_value_supported(value: Any) -> bool:
    if not isinstance(value, Mapping):
        return False
    operation = value.get("op")
    if operation == "const":
        return _const_value(value) is not None
    return operation == "reg" and value.get("name") in {
        "eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp"
    }


def _recover_bounded_table_binding(
    binary: StageABinary,
    site: OriginalIndirectSite,
    resolved_id_by_rva: Mapping[int, int],
    parsed: Sequence[dict[str, Any]],
    relocation_counts: Mapping[int, int],
    predecessors: Sequence[dict[str, Any]],
) -> tuple[OriginalBoundedTableBinding | None, str]:
    shape, failure = _table_shape(site.target_expression)
    if shape is None:
        return None, failure
    table_va, register, mask = shape
    if table_va < binary.image_base:
        return None, "table base is outside the preferred PE image"
    table_rva = table_va - binary.image_base
    sections = [
        section
        for section in binary.sections
        if section.rva_start <= table_rva < section.rva_end
    ]
    if len(sections) != 1:
        return None, "table base is not contained in exactly one mapped section"
    section = sections[0]
    if not section.readable or section.writable or section.executable:
        return None, "bounded table is not in immutable non-executable PE data"
    available_count, scan_failure = _contiguous_relocation_table_entries(
        binary,
        table_rva,
        section.rva_end,
        relocation_counts,
        resolved_id_by_rva,
        parsed,
    )
    if available_count == 0:
        return None, scan_failure
    self_bound = mask + 1 if mask is not None else None
    predecessor_bounds: tuple[OriginalTablePredecessorBound, ...] = ()
    if (
        self_bound is not None
        and self_bound <= 4096
        and self_bound <= available_count
    ):
        upper_exclusive = self_bound
    else:
        upper_exclusive, predecessor_bounds, failure = (
            _recover_predecessor_table_bound(
                binary,
                site,
                register,
                mask,
                predecessors,
                parsed,
                available_count,
            )
        )
        if upper_exclusive is None:
            if self_bound is not None and self_bound > 4096:
                failure = (
                    f"self-contained mask bound {self_bound} exceeds the 4096-entry "
                    f"static proof limit; {failure}"
                )
            return None, failure
    table_size = upper_exclusive * 4
    if table_va + table_size > 2**32:
        return None, "bounded table span overflows the PE32 address space"
    if table_rva + table_size > section.rva_end:
        return None, "bounded table span is not contained in exactly one mapped section"
    table_bytes = bytes(binary.pe.get_data(table_rva, table_size))
    if len(table_bytes) != table_size:
        return None, "bounded table span is not backed by exact PE bytes"
    entry_target_ids: list[int] = []
    for index in range(upper_exclusive):
        entry_rva = table_rva + index * 4
        if relocation_counts.get(entry_rva, 0) != 1:
            return None, (
                f"table entry {index} at RVA 0x{entry_rva:x} lacks exactly one "
                "HIGHLOW relocation"
            )
        target_va = int.from_bytes(
            table_bytes[index * 4 : index * 4 + 4], "little"
        )
        resolved = _resolve_exact_code_va(
            binary, target_va, resolved_id_by_rva, parsed
        )
        if resolved is None:
            return None, (
                f"table entry {index} preferred value 0x{target_va:x} is not an "
                "indexed code target"
            )
        entry_target_ids.append(resolved[0])
    finite_target_ids = tuple(dict.fromkeys(entry_target_ids))
    return (
        OriginalBoundedTableBinding(
            table_rva=table_rva,
            table_va=table_va,
            index_register=register,
            index_mask=mask,
            upper_exclusive=upper_exclusive,
            entry_target_ids=tuple(entry_target_ids),
            finite_target_ids=finite_target_ids,
            bytes_sha256=hashlib.sha256(table_bytes).hexdigest(),
            predecessor_bounds=predecessor_bounds,
        ),
        "",
    )


def _contiguous_relocation_table_entries(
    binary: StageABinary,
    table_rva: int,
    section_end: int,
    relocation_counts: Mapping[int, int],
    resolved_id_by_rva: Mapping[int, int],
    parsed: Sequence[dict[str, Any]],
) -> tuple[int, str]:
    count = 0
    while count < 4096 and table_rva + (count + 1) * 4 <= section_end:
        entry_rva = table_rva + count * 4
        relocation_count = relocation_counts.get(entry_rva, 0)
        if relocation_count == 0:
            break
        if relocation_count != 1:
            return 0, (
                f"table entry {count} at RVA 0x{entry_rva:x} does not have exactly "
                "one HIGHLOW relocation"
            )
        data = bytes(binary.pe.get_data(entry_rva, 4))
        if len(data) != 4:
            return 0, (
                f"table entry {count} at RVA 0x{entry_rva:x} lacks four exact PE bytes"
            )
        target_va = int.from_bytes(data, "little")
        resolved = _resolve_exact_code_va(
            binary, target_va, resolved_id_by_rva, parsed
        )
        if resolved is None or target_va != binary.image_base + resolved[1]:
            return 0, (
                f"table entry {count} preferred value 0x{target_va:x} is not one "
                "canonical indexed code target"
            )
        count += 1
    if count == 0:
        return 0, "table base has no relocation-backed indexed code entries"
    return count, ""


def _recover_predecessor_table_bound(
    binary: StageABinary,
    site: OriginalIndirectSite,
    register: str,
    mask: int | None,
    predecessors: Sequence[dict[str, Any]],
    parsed: Sequence[dict[str, Any]],
    available_count: int,
) -> tuple[
    int | None,
    tuple[OriginalTablePredecessorBound, ...],
    str,
]:
    if not predecessors:
        return None, (), "table source has no indexed direct predecessor"
    bounds: list[OriginalTablePredecessorBound] = []
    for predecessor in predecessors:
        width, failure = _exact_predecessor_upper_bound(
            binary,
            predecessor,
            site.source_rva,
            register,
            mask,
            available_count,
        )
        if width is None:
            return None, (), (
                f"predecessor RVA 0x{predecessor['rva']:x} does not establish "
                f"index < {available_count}: {failure}"
            )
        predecessor_target_id = next(
            (
                index
                for index, item in enumerate(parsed)
                if item["rva"] == predecessor["rva"]
            ),
            None,
        )
        if predecessor_target_id is None:
            raise AssertionError("validated table predecessor disappeared")
        bounds.append(
            OriginalTablePredecessorBound(
                predecessor_target_id=predecessor_target_id,
                predecessor_rva=predecessor["rva"],
                index_width_bits=width,
            )
        )
    return available_count, tuple(bounds), ""


def _exact_predecessor_upper_bound(
    binary: StageABinary,
    predecessor: Mapping[str, Any],
    table_source_rva: int,
    register: str,
    mask: int | None,
    upper_exclusive: int,
) -> tuple[int | None, str]:
    data = bytes(binary.pe.get_data(predecessor["rva"], predecessor["size"]))
    if len(data) != predecessor["size"]:
        return None, "predecessor span is not backed by exact PE bytes"
    decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    decoder.detail = True
    instructions = list(
        decoder.disasm(data, binary.image_base + predecessor["rva"])
    )
    if (
        len(instructions) < 2
        or sum(instruction.size for instruction in instructions) != len(data)
    ):
        return None, "predecessor does not decode over its complete span"
    compare, branch = instructions[-2:]
    if branch.mnemonic != "ja" or len(branch.operands) != 1:
        return None, "selected bound edge is not the fallthrough of an unsigned-above branch"
    if branch.address + branch.size != binary.image_base + table_source_rva:
        return None, "unsigned-above fallthrough does not enter the table source"
    if compare.mnemonic != "cmp" or len(compare.operands) != 2:
        return None, "unsigned-above branch is not immediately preceded by a comparison"
    compared, limit = compare.operands
    if compared.type != X86_OP_REG or limit.type != X86_OP_IMM:
        return None, "table predecessor comparison is not register versus immediate"
    if limit.imm % 2**32 != upper_exclusive - 1:
        return None, "comparison immediate does not match the exact table entry count"
    compared_name = decoder.reg_name(compared.reg)
    aliases = {
        "eax": {8: "al", 16: "ax", 32: "eax"},
        "ebx": {8: "bl", 16: "bx", 32: "ebx"},
        "ecx": {8: "cl", 16: "cx", 32: "ecx"},
        "edx": {8: "dl", 16: "dx", 32: "edx"},
        "esi": {16: "si", 32: "esi"},
        "edi": {16: "di", 32: "edi"},
        "ebp": {16: "bp", 32: "ebp"},
        "esp": {16: "sp", 32: "esp"},
    }
    widths = [
        width
        for width, name in aliases[register].items()
        if name == compared_name
    ]
    if len(widths) != 1:
        return None, "comparison register does not match the table index register"
    width = widths[0]
    expected_mask = 2**width - 1 if width < 32 else None
    if mask != expected_mask:
        return None, "comparison width does not match the table index mask"
    return width, ""


def _table_shape(
    target_expression: Mapping[str, Any] | None,
) -> tuple[tuple[int, str, int | None] | None, str]:
    if not isinstance(target_expression, Mapping) or target_expression.get("op") != "load":
        return None, "target is not a table-word load"
    address = target_expression.get("address")
    add_args = _commutative_args(address, "add32")
    if add_args is None:
        return None, "table address is not base plus scaled index"
    constant = next((item for item in add_args if _const_value(item) is not None), None)
    scaled = next((item for item in add_args if item is not constant), None)
    table_va = _const_value(constant)
    if table_va is None or scaled is None:
        return None, "table address lacks one constant base"
    multiply_args = _commutative_args(scaled, "mul32")
    if multiply_args is None:
        return None, "table index is not scaled by a constant element size"
    scale = next((item for item in multiply_args if _const_value(item) == 4), None)
    index = next((item for item in multiply_args if item is not scale), None)
    if scale is None or index is None:
        return None, "table element scale is not exactly four bytes"
    and_args = _commutative_args(index, "and32")
    if and_args is None:
        if isinstance(index, Mapping) and index.get("op") == "reg":
            register_value = index.get("name")
            mask = None
        else:
            return None, "table index is neither a register nor a masked register"
    else:
        register_value = next(
            (
                item.get("name")
                for item in and_args
                if isinstance(item, Mapping) and item.get("op") == "reg"
            ),
            None,
        )
        mask = next(
            (
                value
                for item in and_args
                if (value := _const_value(item)) is not None
            ),
            None,
        )
    if not isinstance(register_value, str) or register_value not in {
        "eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp"
    }:
        return None, "masked table index is not one IA-32 general register"
    if and_args is not None:
        if mask is None or mask >= 2**32:
            return None, "masked table index lacks one unsigned PE32 mask"
        upper_exclusive = mask + 1
        if upper_exclusive <= 0 or upper_exclusive & (upper_exclusive - 1):
            return None, "table index mask is not a low-bit finite mask"
    return (table_va, register_value, mask), ""


def _commutative_args(value: Any, operation: str) -> tuple[Any, Any] | None:
    if not isinstance(value, Mapping) or value.get("op") != operation:
        return None
    args = value.get("args")
    if not isinstance(args, list) or len(args) != 2:
        return None
    return args[0], args[1]


def _const_value(value: Any) -> int | None:
    if not isinstance(value, Mapping) or value.get("op") != "const":
        return None
    constant = value.get("value")
    if not isinstance(constant, int) or isinstance(constant, bool):
        return None
    if not 0 <= constant < 2**32:
        return None
    return constant


def _recover_direct_target_aliases(
    parsed: Sequence[dict[str, Any]],
    binary: StageABinary | None,
    *,
    recovery_supplied: bool,
) -> tuple[
    tuple[OriginalRecoveredAlias, ...],
    dict[int, int],
    dict[int, str],
]:
    starts = [item["rva"] for item in parsed]
    known = set(starts)
    missing = sorted(
        {
            target
            for item in parsed
            for target in item["direct_rvas"]
            if target not in known
        }
    )
    if not missing:
        return (), {}, {}
    if binary is None:
        return (
            (),
            {},
            {
                target: (
                    "no SHA-bound original PE recovery input was supplied"
                    if not recovery_supplied
                    else "the SHA-bound original PE could not be loaded"
                )
                for target in missing
            },
        )
    aliases: list[OriginalRecoveredAlias] = []
    mapping: dict[int, int] = {}
    failures: dict[int, str] = {}
    for target in missing:
        recovered, failure = _recover_direct_target_alias(
            binary, parsed, starts, target
        )
        if recovered is None:
            failures[target] = failure
            continue
        aliases.append(recovered)
        mapping[target] = recovered.canonical_rva
    return tuple(aliases), mapping, failures


def _recover_direct_target_alias(
    binary: StageABinary,
    parsed: Sequence[dict[str, Any]],
    starts: Sequence[int],
    target: int,
) -> tuple[OriginalRecoveredAlias | None, str]:
    next_index = bisect_right(starts, target)
    if next_index:
        previous = parsed[next_index - 1]
        if previous["rva"] < target < previous["rva"] + previous["size"]:
            return None, "target is inside an existing transfer and requires a split"
    if next_index >= len(starts):
        return None, "there is no following canonical transfer"
    canonical_rva = starts[next_index]
    size = canonical_rva - target
    if size <= 0:
        return None, "canonical target does not follow the alias"
    if size > 4096:
        return None, "candidate alias bridge exceeds the 4096-byte safety bound"
    sections = [
        section
        for section in binary.sections
        if section.executable
        and section.rva_start <= target
        and canonical_rva <= section.rva_end
    ]
    if len(sections) != 1:
        return None, "alias bridge is not within exactly one executable section"
    data = bytes(binary.pe.get_data(target, size))
    if len(data) != size:
        return None, "alias bridge is not backed by the complete mapped PE span"
    decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    decoder.detail = True
    instructions = list(decoder.disasm(data, binary.image_base + target))
    if not instructions or sum(instruction.size for instruction in instructions) != size:
        return None, "alias bridge does not decode over its complete byte span"
    unsupported = [
        instruction
        for instruction in instructions
        if not _is_strict_noop_instruction(instruction)
    ]
    if unsupported:
        first = unsupported[0]
        return None, f"instruction {first.mnemonic} {first.op_str} is not a strict no-op"
    return (
        OriginalRecoveredAlias(
            alias_rva=target,
            canonical_rva=canonical_rva,
            size=size,
            bytes_sha256=hashlib.sha256(data).hexdigest(),
            instructions=tuple(
                f"{instruction.mnemonic} {instruction.op_str}".rstrip()
                for instruction in instructions
            ),
        ),
        "",
    )


def _is_strict_noop_instruction(instruction: Any) -> bool:
    if instruction.mnemonic == "nop":
        return True
    if instruction.mnemonic != "lea" or len(instruction.operands) != 2:
        return False
    destination, source = instruction.operands
    if destination.type != X86_OP_REG or source.type != X86_OP_MEM:
        return False
    memory = source.mem
    return (
        destination.reg == memory.base
        and memory.index == 0
        and memory.disp == 0
    )


def _successor_facts(
    row: Mapping[str, Any],
    line: int,
    source_rva: int,
    iat_by_va: Mapping[int, OriginalIATImport],
) -> tuple[tuple[int, ...], tuple[OriginalIndirectSite, ...]]:
    successors: list[int] = []
    indirect_sites: list[OriginalIndirectSite] = []
    edges = row.get("edge_conditions")
    if not isinstance(edges, list):
        raise InterpreterMixedOriginalGenerationError(
            f"line {line} edge_conditions must be a list"
        )
    for index, edge_value in enumerate(edges):
        edge = _mapping(edge_value, line, f"edge_conditions[{index}]")
        successors.append(
            _u32(edge.get("target_rva"), f"line {line} edge target_rva")
        )

    outcome = _mapping(row.get("outcome"), line, "outcome")
    kind = outcome.get("kind")
    if kind in {"fallthrough", "jump", "direct_call"}:
        successors.append(
            _u32(outcome.get("target_rva"), f"line {line} outcome.target_rva")
        )
    elif kind == "branch":
        successors.extend(
            (
                _u32(outcome.get("true_target_rva"), f"line {line} true target"),
                _u32(outcome.get("false_target_rva"), f"line {line} false target"),
            )
        )
    elif kind == "indirect_jump_table":
        targets = outcome.get("target_rvas")
        if targets is not None:
            if not isinstance(targets, list):
                raise InterpreterMixedOriginalGenerationError(
                    f"line {line} jump-table target inventory must be a list"
                )
            for value in targets:
                _u32(value, f"line {line} jump-table target")
        indirect_sites.append(
            _indirect_site(
                source_rva,
                _control_instruction_rva(row, line, source_rva),
                outcome.get("target"),
                is_call=False,
                continuation_rva=None,
                iat_by_va=iat_by_va,
                detail=(
                    "submitted jump-table targets are untrusted until exact "
                    "PE recovery and Lean checking"
                ),
            )
        )
    elif kind == "indirect_jump":
        indirect_sites.append(
            _indirect_site(
                source_rva,
                _control_instruction_rva(row, line, source_rva),
                outcome.get("target"),
                is_call=False,
                continuation_rva=None,
                iat_by_va=iat_by_va,
                detail="indirect jump has no checked finite target inventory",
            )
        )
    elif kind not in {"return", "external_jump"}:
        raise InterpreterMixedOriginalGenerationError(
            f"line {line} unsupported outcome kind {kind!r}"
        )

    ordered = row.get("ordered_events")
    if not isinstance(ordered, list):
        raise InterpreterMixedOriginalGenerationError(
            f"line {line} ordered_events must be a list"
        )
    for index, event_value in enumerate(ordered):
        event = _mapping(event_value, line, f"ordered_events[{index}]")
        event_kind = event.get("kind")
        if event_kind == "internal_call":
            successors.append(
                _u32(event.get("target_rva"), f"line {line} internal call target")
            )
            successors.append(
                _u32(event.get("return_rva"), f"line {line} internal call return")
            )
        elif event_kind == "indirect_call":
            instruction_rva = _u32(
                event.get("instruction_rva"),
                f"line {line} indirect call instruction_rva",
            )
            indirect_sites.append(
                _indirect_site(
                    source_rva,
                    instruction_rva,
                    event.get("target"),
                    is_call=True,
                    continuation_rva=(
                        _u32(
                            event.get("return_rva"),
                            f"line {line} indirect call return",
                        )
                        if event.get("return_rva") is not None
                        else None
                    ),
                    iat_by_va=iat_by_va,
                    detail="indirect call has no checked finite target inventory",
                )
            )
            if event.get("return_rva") is not None:
                successors.append(
                    _u32(event.get("return_rva"), f"line {line} indirect call return")
                )
    unique_sites = {
        (
            site.source_rva,
            site.instruction_rva,
            site.category,
            site.detail,
            site.target_va,
            site.resolved_target_rva,
            site.iat_import,
            site.is_call,
            site.continuation_rva,
            json.dumps(site.target_expression, sort_keys=True),
        ): site
        for site in indirect_sites
    }
    return tuple(dict.fromkeys(successors)), tuple(unique_sites.values())


def _indirect_site(
    source_rva: int,
    instruction_rva: int,
    target_value: Any,
    *,
    is_call: bool,
    continuation_rva: int | None,
    iat_by_va: Mapping[int, OriginalIATImport],
    detail: str,
) -> OriginalIndirectSite:
    target = target_value if isinstance(target_value, Mapping) else {}
    operation = target.get("op")
    target_va: int | None = None
    iat_import: OriginalIATImport | None = None
    if operation == "load":
        address = target.get("address")
        if isinstance(address, Mapping) and address.get("op") == "const":
            value = address.get("value")
            if isinstance(value, int) and not isinstance(value, bool):
                target_va = _u32(value, "indirect target absolute address")
                iat_import = iat_by_va.get(target_va)
        if iat_import is not None and is_call:
            category = "iat_thunk"
            detail = "IAT-loaded call has exact-PE binding proposal"
        elif target_va is not None:
            category = "static_pointer_slot"
        elif is_call:
            category = "stack_or_dynamic_pointer"
        else:
            category = "bounded_table_candidate"
    elif operation == "reg":
        category = "register_function_pointer" if is_call else "register_tail_target"
    elif operation == "const":
        value = target.get("value")
        if isinstance(value, int) and not isinstance(value, bool):
            target_va = _u32(value, "constant indirect target")
        category = "constant_internal_target"
    else:
        category = "unknown_indirect_target"
    return OriginalIndirectSite(
        source_rva=source_rva,
        instruction_rva=instruction_rva,
        category=category,
        detail=detail,
        target_va=target_va,
        iat_import=iat_import,
        is_call=is_call,
        continuation_rva=continuation_rva,
        target_expression=target,
    )


def _control_instruction_rva(
    row: Mapping[str, Any], line: int, source_rva: int
) -> int:
    instructions = row.get("instructions")
    if isinstance(instructions, list) and instructions:
        final = _mapping(instructions[-1], line, "instructions[-1]")
        return _u32(final.get("rva"), f"line {line} control instruction RVA")
    raise InterpreterMixedOriginalGenerationError(
        f"line {line} indirect control at source 0x{source_rva:x} lacks an "
        "exact instruction RVA"
    )


def _import_identities(
    row: Mapping[str, Any], line: int
) -> set[OriginalImportIdentity]:
    values: list[Mapping[str, Any]] = []
    outcome = _mapping(row.get("outcome"), line, "outcome")
    if outcome.get("kind") == "external_jump":
        values.append(outcome)
    external = row.get("external_events")
    if not isinstance(external, list):
        raise InterpreterMixedOriginalGenerationError(
            f"line {line} external_events must be a list"
        )
    for index, value in enumerate(external):
        event = _mapping(value, line, f"external_events[{index}]")
        if event.get("kind") == "external_call":
            values.append(event)
    result: set[OriginalImportIdentity] = set()
    for value in values:
        dll = value.get("dll")
        symbol = value.get("symbol")
        ordinal = value.get("ordinal")
        if not isinstance(dll, str):
            raise InterpreterMixedOriginalGenerationError(
                f"line {line} external import is missing a DLL identity"
            )
        if symbol is not None and not isinstance(symbol, str):
            raise InterpreterMixedOriginalGenerationError(
                f"line {line} external symbol must be a string"
            )
        if ordinal is not None and not isinstance(ordinal, int):
            raise InterpreterMixedOriginalGenerationError(
                f"line {line} external ordinal must be an integer"
            )
        result.add(OriginalImportIdentity(dll, symbol, ordinal))
    return result


def _reject_alias_fields(row: Mapping[str, Any], line: int) -> None:
    containers = (("record", row), ("original", row.get("original")))
    for label, value in containers:
        if not isinstance(value, Mapping):
            continue
        for key in ("aliases", "original_aliases", "code_aliases"):
            if key in value and value[key] not in (None, [], {}):
                raise InterpreterMixedOriginalGenerationError(
                    f"line {line} contains unsupported alias facts in "
                    f"{label}.{key}"
                )


def _lean_original_target(region: OriginalRegion) -> str:
    return (
        f"{{ id := {region.target_id}, regionIndex := {region.target_id}, "
        f"rva := {region.rva}, aliases := {_lean_code_aliases(region)} }}"
    )


def _lean_static_target(region: OriginalRegion) -> str:
    aliases = _lean_code_aliases(region)
    return (
        f"{{ id := {region.target_id}, regionIndex := {region.target_id}, "
        f"originalRva := {region.rva}, candidateRva := {region.rva}, "
        f"originalAliases := {aliases}, candidateAliases := {aliases} }}"
    )


def _lean_code_aliases(region: OriginalRegion) -> str:
    rows = ", ".join(
        f"{{ rva := {alias_rva}, paddingIndex := 0 }}"
        for alias_rva in region.alias_rvas
    )
    return f"[{rows}]"


def _lean_code_addresses(region: OriginalRegion) -> list[str]:
    return [
        *[
            f"{{ targetId := {region.target_id}, kind := .alias {alias_index} }}"
            for alias_index, _ in enumerate(region.alias_rvas)
        ],
        f"{{ targetId := {region.target_id}, kind := .canonical }}",
    ]


def _lean_original_region(region: OriginalRegion) -> str:
    return (
        f"{{ id := {region.target_id}, span := {{ start := {region.rva}, "
        f"size := {region.size} }}, root := {str(region.root).lower()}, "
        f"targets := {list(region.successor_ids)} }}"
    )


def _lean_carrier_region(
    plan: InterpreterMixedOriginalPlan, region: OriginalRegion
) -> str:
    targets = ", ".join(
        _lean_static_target(plan.regions[target_id])
        for target_id in region.successor_ids
    )
    table_bindings = [
        site.static_binding
        for site in region.indirect_sites
        if isinstance(site.static_binding, OriginalBoundedTableBinding)
    ]
    registers = tuple(
        dict.fromkeys(binding.index_register for binding in table_bindings)
    )
    exact_input_relations = [
        f"{{ original := .{register}, candidate := .{register}, "
        "relation := .exact }"
        for register in registers
    ]
    (
        register_inputs,
        register_outputs,
        import_inputs,
        import_outputs,
    ) = _register_provenance_relations_for_region(plan, region.target_id)
    input_relations = ", ".join(dict.fromkeys((*exact_input_relations, *register_inputs)))
    output_relations = ", ".join(dict.fromkeys(register_outputs))
    input_import_relations = ", ".join(dict.fromkeys(import_inputs))
    output_import_relations = ", ".join(dict.fromkeys(import_outputs))
    bounds = ", ".join(
        _lean_table_bound(binding) for binding in table_bindings
    )
    static_word_bindings = [
        site.static_binding
        for site in region.indirect_sites
        if isinstance(
            site.static_binding,
            (
                OriginalImmutableSlotBinding,
                OriginalStaticWordSlotBinding,
                OriginalStaticWordJumpSlotBinding,
                OriginalFiniteOriginStaticWordJumpBinding,
            ),
        )
    ]
    import_seed_bindings = [
        seed
        for owner in plan.regions
        for site in owner.indirect_sites
        if isinstance(site.static_binding, OriginalRegisterImportBinding)
        for seed in site.static_binding.seed_bindings
        if seed.target_id == region.target_id
    ]
    address_separations = ", ".join(
        _lean_address_separation(separation)
        for separation in dict.fromkeys(
            separation
            for binding in (*static_word_bindings, *import_seed_bindings)
            for separation in binding.address_separations
        )
    )
    optional_relations = "".join(
        (
            f", outputRelations := [{output_relations}]"
            if output_relations
            else "",
            f", inputImportRelations := [{input_import_relations}]"
            if input_import_relations
            else "",
            f", outputImportRelations := [{output_import_relations}]"
            if output_import_relations
            else "",
        )
    )
    return (
        f"{{ id := {region.target_id}, original := {{ start := {region.rva}, "
        f"size := {region.size} }}, candidate := {{ start := {region.rva}, "
        f"size := {region.size} }}, root := {str(region.root).lower()}, "
        f"inputs := [], outputs := [], inputRelations := [{input_relations}]"
        f"{optional_relations}, "
        f"bounds := [{bounds}], addressSeparations := [{address_separations}], "
        f"targets := [{targets}] }}"
    )


def _register_provenance_relations_for_region(
    plan: InterpreterMixedOriginalPlan, target_id: int
) -> tuple[tuple[str, ...], tuple[str, ...], tuple[str, ...], tuple[str, ...]]:
    register_inputs: list[str] = []
    register_outputs: list[str] = []
    import_inputs: list[str] = []
    import_outputs: list[str] = []
    for source_region in plan.regions:
        for site in source_region.indirect_sites:
            binding = site.static_binding
            if isinstance(binding, OriginalRegisterCodePointerBinding):
                relation = (
                    f"{{ original := .{binding.register}, "
                    f"candidate := .{binding.register}, "
                    f"relation := .fixedCodePointer {binding.target_id} }}"
                )
                if target_id in binding.seed_target_ids:
                    register_outputs.append(relation)
                if target_id in binding.preserve_target_ids:
                    register_inputs.append(relation)
                    register_outputs.append(relation)
                if target_id == source_region.target_id:
                    register_inputs.append(relation)
            elif isinstance(binding, OriginalRegisterImportBinding):
                relation = (
                    f"{{ original := .{binding.register}, "
                    f"candidate := .{binding.register}, imported := "
                    f"{_lean_external_target(binding.imported.identity)} }}"
                )
                if target_id in binding.seed_target_ids:
                    import_outputs.append(relation)
                if target_id in binding.preserve_target_ids:
                    import_inputs.append(relation)
                    import_outputs.append(relation)
                if target_id == source_region.target_id:
                    import_inputs.append(relation)
    return (
        tuple(dict.fromkeys(register_inputs)),
        tuple(dict.fromkeys(register_outputs)),
        tuple(dict.fromkeys(import_inputs)),
        tuple(dict.fromkeys(import_outputs)),
    )


def _lean_table_index_expression(binding: OriginalBoundedTableBinding) -> str:
    if binding.index_mask is None:
        return f"Expr.inputReg .{binding.index_register}"
    return (
        f"Expr.bitAnd (Expr.inputReg .{binding.index_register}) "
        f"(Expr.constant {binding.index_mask})"
    )


def _lean_table_index_witness(binding: OriginalBoundedTableBinding) -> str:
    if binding.index_mask is None:
        return (
            f".inputReg .{binding.index_register} .{binding.index_register}"
        )
    return (
        f".binary .bitAnd\n"
        f"    (.inputReg .{binding.index_register} .{binding.index_register})\n"
        f"    (.constant {binding.index_mask})"
    )


def _lean_table_bound(binding: OriginalBoundedTableBinding) -> str:
    expression = _lean_table_index_expression(binding)
    return (
        f"{{ original := .{binding.index_register}, "
        f"candidate := .{binding.index_register}, "
        f"originalExpression := some ({expression}), "
        f"candidateExpression := some ({expression}), "
        f"upperExclusive := {binding.upper_exclusive} }}"
    )


def _unique_static_data_bindings(
    plan: InterpreterMixedOriginalPlan,
) -> tuple[
    OriginalStaticDataBinding
    | OriginalImmutableSlotBinding
    | OriginalBoundedTableBinding,
    ...,
]:
    by_key: dict[
        tuple[int, int],
        OriginalStaticDataBinding
        | OriginalImmutableSlotBinding
        | OriginalBoundedTableBinding,
    ] = {}
    for binding in plan.spec.static_data_bindings:
        by_key[(binding.rva, binding.size)] = binding
    for region in plan.regions:
        for site in region.indirect_sites:
            binding = site.static_binding
            if isinstance(binding, OriginalImmutableSlotBinding):
                key = (binding.slot_rva, 4)
            elif isinstance(binding, OriginalBoundedTableBinding):
                key = (binding.table_rva, binding.upper_exclusive * 4)
            else:
                continue
            prior = by_key.get(key)
            if prior is not None and not _same_static_data_binding(prior, binding):
                raise InterpreterMixedOriginalGenerationError(
                    f"conflicting static data bindings at RVA 0x{key[0]:x}"
                )
            if prior is None:
                by_key[key] = binding
    ordered = sorted(by_key)
    for (prior_rva, prior_size), (current_rva, _current_size) in zip(
        ordered, ordered[1:]
    ):
        if current_rva < prior_rva + prior_size:
            raise InterpreterMixedOriginalGenerationError(
                "overlapping static indirect data bindings at RVAs "
                f"0x{prior_rva:x} and 0x{current_rva:x}"
            )
    return tuple(by_key[key] for key in ordered)


def _unique_static_word_slot_bindings(
    plan: InterpreterMixedOriginalPlan,
) -> tuple[
    OriginalStaticWordSlotBinding
    | OriginalStaticWordJumpSlotBinding
    | OriginalFiniteOriginStaticWordJumpBinding,
    ...,
]:
    by_rva: dict[
        int,
        OriginalStaticWordSlotBinding
        | OriginalStaticWordJumpSlotBinding
        | OriginalFiniteOriginStaticWordJumpBinding,
    ] = {}
    for region in plan.regions:
        for site in region.indirect_sites:
            binding = site.static_binding
            if not isinstance(
                binding,
                (
                    OriginalStaticWordSlotBinding,
                    OriginalStaticWordJumpSlotBinding,
                    OriginalFiniteOriginStaticWordJumpBinding,
                ),
            ):
                continue
            prior = by_rva.get(binding.slot_rva)
            if prior is not None and not _same_static_word_slot(prior, binding):
                raise InterpreterMixedOriginalGenerationError(
                    f"conflicting writable static-word bindings at RVA "
                    f"0x{binding.slot_rva:x}"
                )
            by_rva.setdefault(binding.slot_rva, binding)
    ordered = sorted(by_rva)
    for prior_rva, current_rva in zip(ordered, ordered[1:]):
        if current_rva < prior_rva + 4:
            raise InterpreterMixedOriginalGenerationError(
                "overlapping writable static-word bindings at RVAs "
                f"0x{prior_rva:x} and 0x{current_rva:x}"
            )
    return tuple(by_rva[rva] for rva in ordered)


def _same_static_word_slot(
    left: (
        OriginalStaticWordSlotBinding
        | OriginalStaticWordJumpSlotBinding
        | OriginalFiniteOriginStaticWordJumpBinding
    ),
    right: (
        OriginalStaticWordSlotBinding
        | OriginalStaticWordJumpSlotBinding
        | OriginalFiniteOriginStaticWordJumpBinding
    ),
) -> bool:
    if isinstance(left, OriginalFiniteOriginStaticWordJumpBinding):
        left_shape = (
            left.slot_id,
            left.slot_rva,
            left.slot_va,
            left.slot_bytes,
            left.initial_target_id,
            left.initial_target_rva,
            left.initial_target_va,
            left.internal_target_ids,
            tuple(route.resource_id for route in left.external_routes),
        )
    else:
        left_shape = (
            left.slot_id,
            left.slot_rva,
            left.slot_va,
            left.slot_bytes,
            left.target_id,
            left.target_rva,
            left.target_va,
            (left.target_id,),
            (),
        )
    if isinstance(right, OriginalFiniteOriginStaticWordJumpBinding):
        right_shape = (
            right.slot_id,
            right.slot_rva,
            right.slot_va,
            right.slot_bytes,
            right.initial_target_id,
            right.initial_target_rva,
            right.initial_target_va,
            right.internal_target_ids,
            tuple(route.resource_id for route in right.external_routes),
        )
    else:
        right_shape = (
            right.slot_id,
            right.slot_rva,
            right.slot_va,
            right.slot_bytes,
            right.target_id,
            right.target_rva,
            right.target_va,
            (right.target_id,),
            (),
        )
    return left_shape == right_shape


def _lean_static_word_slot(
    binding: (
        OriginalStaticWordSlotBinding
        | OriginalStaticWordJumpSlotBinding
        | OriginalFiniteOriginStaticWordJumpBinding
    ),
) -> str:
    if isinstance(binding, OriginalFiniteOriginStaticWordJumpBinding):
        origins = [
            *(
                f".staticCodeTarget {target_id} 0"
                for target_id in binding.internal_target_ids
            ),
            *(
                f".opaqueResource {route.resource_id}"
                for route in binding.external_routes
            ),
        ]
        relation = (
            f".finiteOrigins {len(origins)} [{', '.join(origins)}]"
        )
    else:
        relation = f".fixedCodePointer {binding.target_id}"
    return (
        f"{{ id := {binding.slot_id}, "
        f"originalAddress := BitVec.ofNat 32 {binding.slot_va}, "
        f"candidateAddress := BitVec.ofNat 32 {binding.slot_va}, "
        f"relation := {relation} }}"
    )


def _lean_register_offset_write(write: OriginalRegisterOffsetWrite) -> str:
    return (
        f"{{ register := .{write.register}, offset := {write.offset}, "
        f"value := {_lean_static_word_write_value(write.value)}, "
        f"subtract := {str(write.subtract).lower()} }}"
    )


def _lean_static_word_write_value(value: Mapping[str, Any]) -> str:
    if value.get("op") == "const":
        return f".constant {int(value['value'])}"
    if value.get("op") == "reg":
        return f".inputReg .{value['name']}"
    raise AssertionError("validated static-word write expression disappeared")


def _lean_address_separation(separation: OriginalAddressSeparation) -> str:
    return (
        f"{{ originalRegister := .{separation.register}, "
        f"candidateRegister := .{separation.register}, "
        f"originalOffset := {separation.offset}, "
        f"candidateOffset := {separation.offset}, "
        f"originalAddress := {separation.address}, "
        f"candidateAddress := {separation.address} }}"
    )


def _static_data_target_id(
    plan: InterpreterMixedOriginalPlan,
    binding: OriginalImmutableSlotBinding | OriginalBoundedTableBinding,
) -> int:
    inventory = _unique_static_data_bindings(plan)
    for target_id, candidate in enumerate(inventory):
        if _same_static_data_binding(candidate, binding):
            return target_id
    raise AssertionError("validated static data binding disappeared")


def _same_static_data_binding(
    left: OriginalStaticDataBinding
    | OriginalImmutableSlotBinding
    | OriginalBoundedTableBinding,
    right: OriginalStaticDataBinding
    | OriginalImmutableSlotBinding
    | OriginalBoundedTableBinding,
) -> bool:
    if isinstance(left, OriginalStaticDataBinding) and isinstance(
        right, OriginalStaticDataBinding
    ):
        return left == right
    if isinstance(left, OriginalImmutableSlotBinding) and isinstance(
        right, OriginalImmutableSlotBinding
    ):
        return (
            left.slot_rva,
            left.slot_va,
            left.target_id,
            left.target_rva,
            left.target_va,
        ) == (
            right.slot_rva,
            right.slot_va,
            right.target_id,
            right.target_rva,
            right.target_va,
        )
    return left == right


def _lean_value_target(
    target_id: int,
    binding: OriginalStaticDataBinding
    | OriginalImmutableSlotBinding
    | OriginalBoundedTableBinding,
) -> str:
    if isinstance(binding, OriginalStaticDataBinding):
        value = binding.va
        rva = binding.rva
        size = binding.size
        offsets = list(binding.relocation_offsets)
    elif isinstance(binding, OriginalImmutableSlotBinding):
        value = binding.slot_va
        rva = binding.slot_rva
        size = 4
        offsets = [0]
    else:
        value = binding.table_va
        rva = binding.table_rva
        size = binding.upper_exclusive * 4
        offsets = list(range(0, size, 4))
    return (
        f"{{ id := {target_id}, originalValue := {value}, "
        f"candidateValue := {value}, originalRelocationRva := {rva}, "
        f"candidateRelocationRva := {rva}, mappedSize := {size}, "
        f"relocationOffsets := {offsets} }}"
    )


def _lean_static_indirect_checks(plan: InterpreterMixedOriginalPlan) -> str:
    sites = sorted(
        (
            site
            for region in plan.regions
            for site in region.indirect_sites
            if site.static_binding is not None
        ),
        key=lambda site: (site.source_rva, site.instruction_rva),
    )
    return "\n\n".join(
        _lean_static_indirect_check(plan, index, site)
        for index, site in enumerate(sites)
    )


def _lean_static_indirect_check(
    plan: InterpreterMixedOriginalPlan,
    index: int,
    site: OriginalIndirectSite,
) -> str:
    binding = site.static_binding
    if binding is None:
        raise AssertionError("static indirect checker received an unbound site")
    source_id = _id_for_rva(plan, site.source_rva)
    prefix = f"generatedOriginalStaticIndirect{index}"
    region = f"generatedOriginalStaticIndirectRegion{source_id}"
    behavior = f"{prefix}Behavior"
    original_normalized = f"{prefix}OriginalNormalized"
    candidate_normalized = f"{prefix}CandidateNormalized"
    shared = f"""def {behavior} : SymbolicBehavior :=
  (regionBehaviorWithMachineCallContracts
    generatedOriginalCarrierContext.originalPe
    generatedOriginalCarrierContext.originalImports
    generatedOriginalCarrierContext.machineImportCallContracts
    {region}.original).get (by decide +kernel)

theorem {behavior}Decoded :
    regionBehaviorWithMachineCallContracts
      generatedOriginalCarrierContext.originalPe
      generatedOriginalCarrierContext.originalImports
      generatedOriginalCarrierContext.machineImportCallContracts
      {region}.original = some {behavior} := by
  decide +kernel

def {original_normalized} : NormalizedSymbolicBehavior :=
  (normalizeSymbolicBehavior false {region}.targets {behavior}).get
    (by decide +kernel)

def {candidate_normalized} : NormalizedSymbolicBehavior :=
  (normalizeSymbolicBehavior true {region}.targets {behavior}).get
    (by decide +kernel)

theorem {original_normalized}Checked :
    normalizeSymbolicBehavior false {region}.targets {behavior} =
      some {original_normalized} := by
  decide +kernel

theorem {candidate_normalized}Checked :
    normalizeSymbolicBehavior true {region}.targets {behavior} =
      some {candidate_normalized} := by
  decide +kernel"""
    if isinstance(binding, OriginalFixedTargetBinding):
        return shared + f"""

def {prefix}Claim : FixedCodeAddressIndirectJumpTargetClaim := {{
  targetId := {binding.target_id}
  originalTarget := {binding.target_va}
  candidateTarget := {binding.target_va}
}}

theorem {prefix}Checked :
    {prefix}Claim.checked generatedOriginalCarrierContext
      {original_normalized} {candidate_normalized} = true := by
  decide +kernel

theorem {prefix}Closed :
    FixedCodeAddressIndirectJumpTargetsClosed generatedOriginalCarrierContext
      {region}.inputInvariant {original_normalized} {candidate_normalized}
      {prefix}Claim :=
  fixedCodeAddressIndirectJumpTargetsClosed_of_checked
    generatedOriginalCarrierContext {region}.inputInvariant
    {original_normalized} {candidate_normalized} {prefix}Claim
    {prefix}Checked"""
    if isinstance(binding, OriginalStaticWordSlotBinding):
        writes = ", ".join(
            _lean_register_offset_write(write) for write in binding.writes
        )
        slot = _lean_static_word_slot(binding)
        return shared + f"""

def {prefix}Claim : StaticWordSlotIndirectCallTargetClaim := {{
  targetId := {binding.target_id}
  continuationTargetId := {binding.continuation_target_id}
  slot := {slot}
  originalAddress := {binding.slot_va}
  candidateAddress := {binding.slot_va}
  originalAssembledRead := {str(binding.assembled_read).lower()}
  candidateAssembledRead := {str(binding.assembled_read).lower()}
  originalWrites := [{writes}]
  candidateWrites := [{writes}]
}}

def {prefix}Binding : OriginalStaticWordSlotBinding := {{
  sourceTargetId := {source_id}
  instructionRva := {site.instruction_rva}
  slotRva := {binding.slot_rva}
  targetRva := {binding.target_rva}
  slotBytes := {list(binding.slot_bytes)}
  claim := {prefix}Claim
}}

theorem {prefix}BindingChecked :
    {prefix}Binding.valid generatedOriginalStaticContext
      generatedOriginalCarrierContext {region}.inputInvariant
      {original_normalized} {candidate_normalized} = true := by
  decide +kernel

theorem {prefix}Checked :
    {prefix}Claim.checked generatedOriginalCarrierContext
      {region}.inputInvariant {original_normalized} {candidate_normalized} = true :=
  originalStaticWordSlotBinding_claimChecked {prefix}BindingChecked

theorem {prefix}Closed :
    StaticWordSlotIndirectCallTargetsClosed generatedOriginalCarrierContext
      {region}.inputInvariant {original_normalized} {candidate_normalized}
      {prefix}Claim :=
  staticWordSlotIndirectCallTargetsClosed_of_checked
    generatedOriginalCarrierContext {region}.inputInvariant
    {original_normalized} {candidate_normalized} {prefix}Claim
    {prefix}Checked

def {prefix}IndirectExitCertificate :
    StageA.Relational.ValueProvenance.CheckedIndirectExitCertificate
      generatedOriginalCarrierContext {region}.inputInvariant
      {original_normalized} {candidate_normalized} :=
  StageA.Relational.IndirectExitAdapters.checkedStaticWordSlotIndirectCertificate
      generatedOriginalCarrierContext {region}.inputInvariant
      {original_normalized} {candidate_normalized} {prefix}Claim
      {prefix}Checked (by decide +kernel)"""
    if isinstance(binding, OriginalStaticWordJumpSlotBinding):
        writes = ", ".join(
            _lean_register_offset_write(write) for write in binding.writes
        )
        slot = _lean_static_word_slot(binding)
        return shared + f"""

def {prefix}Claim : StaticWordSlotIndirectJumpTargetClaim := {{
  targetId := {binding.target_id}
  slot := {slot}
  originalAddress := {binding.slot_va}
  candidateAddress := {binding.slot_va}
  originalAssembledRead := {str(binding.assembled_read).lower()}
  candidateAssembledRead := {str(binding.assembled_read).lower()}
  originalWrites := [{writes}]
  candidateWrites := [{writes}]
}}

def {prefix}Binding : OriginalStaticWordJumpSlotBinding := {{
  sourceTargetId := {source_id}
  instructionRva := {site.instruction_rva}
  slotRva := {binding.slot_rva}
  targetRva := {binding.target_rva}
  slotBytes := {list(binding.slot_bytes)}
  claim := {prefix}Claim
}}

theorem {prefix}BindingChecked :
    {prefix}Binding.valid generatedOriginalStaticContext
      generatedOriginalCarrierContext {region}.inputInvariant
      {original_normalized} {candidate_normalized} = true := by
  decide +kernel

theorem {prefix}Checked :
    {prefix}Claim.checked generatedOriginalCarrierContext
      {region}.inputInvariant {original_normalized} {candidate_normalized} = true :=
  originalStaticWordJumpSlotBinding_claimChecked {prefix}BindingChecked

theorem {prefix}Closed :
    StaticWordSlotIndirectJumpTargetsClosed generatedOriginalCarrierContext
      {region}.inputInvariant {original_normalized} {candidate_normalized}
      {prefix}Claim :=
  staticWordSlotIndirectJumpTargetsClosed_of_checked
    generatedOriginalCarrierContext {region}.inputInvariant
    {original_normalized} {candidate_normalized} {prefix}Claim
    {prefix}Checked

def {prefix}IndirectExitCertificate :
    StageA.Relational.ValueProvenance.CheckedIndirectExitCertificate
      generatedOriginalCarrierContext {region}.inputInvariant
      {original_normalized} {candidate_normalized} :=
  StageA.Relational.IndirectExitAdapters.checkedStaticWordSlotJumpIndirectCertificate
      generatedOriginalCarrierContext {region}.inputInvariant
      {original_normalized} {candidate_normalized} {prefix}Claim
      {prefix}Checked (by decide +kernel)"""
    if isinstance(binding, OriginalFiniteOriginStaticWordJumpBinding):
        # The named finite-slot authority owns exact bytes and PE seed checks.
        # Its decomposed adapter combines these local normalized behaviors with
        # the callable route and authoritative StateRel slot relation.
        return shared
    if isinstance(binding, OriginalImmutableSlotBinding):
        claim_type = (
            "ImmutableIndirectCallTargetClaim"
            if site.is_call
            else "ImmutableIndirectJumpTargetClaim"
        )
        closed_type = (
            "ImmutableIndirectCallTargetsClosed"
            if site.is_call
            else "ImmutableIndirectJumpTargetsClosed"
        )
        theorem = (
            "immutableIndirectCallTargetsClosed_of_checked"
            if site.is_call
            else "immutableIndirectJumpTargetsClosed_of_checked"
        )
        continuation = (
            f"\n  continuationTargetId := {binding.continuation_target_id}"
            if site.is_call
            else ""
        )
        writes = ", ".join(
            _lean_register_offset_write(write) for write in binding.writes
        )
        return shared + f"""

def {prefix}Claim : {claim_type} := {{
  targetId := {binding.target_id}{continuation}
  originalAddress := {binding.slot_va}
  candidateAddress := {binding.slot_va}
  originalAssembledRead := {str(binding.assembled_read).lower()}
  candidateAssembledRead := {str(binding.assembled_read).lower()}
  originalWrites := [{writes}]
  candidateWrites := [{writes}]
}}

theorem {prefix}Checked :
    {prefix}Claim.checked generatedOriginalCarrierContext
      {region}.inputInvariant {original_normalized} {candidate_normalized} = true := by
  decide +kernel

theorem {prefix}RelocationChecked :
    pe32RelocationWordAt generatedOriginalCarrierContext.originalRelocations
      {binding.slot_rva} = true := by
  decide +kernel

theorem {prefix}BindingChecked :
    {prefix}Claim.checked generatedOriginalCarrierContext
        {region}.inputInvariant {original_normalized} {candidate_normalized} = true ∧
      pe32RelocationWordAt generatedOriginalCarrierContext.originalRelocations
        {binding.slot_rva} = true :=
  ⟨{prefix}Checked, {prefix}RelocationChecked⟩

theorem {prefix}Closed :
    {closed_type} generatedOriginalCarrierContext {region}.inputInvariant
      {original_normalized} {candidate_normalized} {prefix}Claim :=
  {theorem} generatedOriginalCarrierContext {region}.inputInvariant
    {original_normalized} {candidate_normalized} {prefix}Claim
    {prefix}Checked"""
    if isinstance(binding, OriginalRegisterImportBinding):
        return shared + _lean_register_import_provenance_check(
            plan,
            prefix,
            region,
            original_normalized,
            candidate_normalized,
            binding,
        )
    if isinstance(binding, OriginalRegisterCodePointerBinding):
        return shared + _lean_register_code_provenance_check(
            plan,
            prefix,
            region,
            original_normalized,
            candidate_normalized,
            binding,
        )
    if not isinstance(binding, OriginalBoundedTableBinding):
        raise AssertionError("unknown static indirect binding")
    data_target_id = _static_data_target_id(plan, binding)
    expression = _lean_table_index_expression(binding)
    witness = _lean_table_index_witness(binding)
    if binding.predecessor_bounds:
        bound_evidence = "\n\n" + "\n\n".join(
            _lean_table_predecessor_bound_check(
                plan, prefix, expression, binding, predecessor_index, predecessor
            )
            for predecessor_index, predecessor in enumerate(
                binding.predecessor_bounds
            )
        )
    else:
        bound_evidence = f"""

theorem {prefix}IndexUniversallyBounded (state : MachineState) :
    (({expression}).eval state).toNat < {binding.upper_exclusive} := by
  simp only [Expr.eval, BitVec.toNat_and, BitVec.toNat_ofNat]
  exact Nat.lt_succ_of_le Nat.and_le_right"""
    return shared + f"""

def {prefix}Claim : BoundedImmutableRelocationTableJumpControlClaim := {{
  table := {{
    valueTargetId := {data_target_id}
    tableOffset := 0
    originalBase := {binding.table_va}
    candidateBase := {binding.table_va}
    upperExclusive := {binding.upper_exclusive}
    originalIndex := {expression}
    candidateIndex := {expression}
    entryTargetIds := {list(binding.entry_target_ids)}
    finiteTargetIds := {list(binding.finite_target_ids)}
  }}
  indexWitness := {witness}
  indexBound := {_lean_table_bound(binding)}
}}
{bound_evidence}

theorem {prefix}Checked :
    {prefix}Claim.checked generatedOriginalCarrierContext
      {region}.inputInvariant {original_normalized} {candidate_normalized} = true := by
  decide +kernel

theorem {prefix}Closed
    (contextValid : generatedOriginalCarrierContext.StructurallyValid) :
    BoundedImmutableRelocationTableJumpTargetsClosed
      generatedOriginalCarrierContext {region}.inputInvariant
      {original_normalized} {candidate_normalized} {prefix}Claim :=
  boundedImmutableRelocationTableJumpTargetsClosed_of_checked
    generatedOriginalCarrierContext {region}.inputInvariant
    {original_normalized} {candidate_normalized} {prefix}Claim contextValid
    {prefix}Checked"""


def _lean_provenance_region_definitions(
    plan: InterpreterMixedOriginalPlan,
    prefix: str,
    target_ids: Sequence[int],
) -> tuple[str, dict[int, str]]:
    definitions: list[str] = []
    normalized_by_target_id: dict[int, str] = {}
    for target_id in sorted(set(target_ids)):
        region = plan.regions[target_id]
        local = f"{prefix}Provenance{target_id}"
        region_name = f"{local}Region"
        behavior = f"{local}Behavior"
        original_normalized = f"{local}OriginalNormalized"
        candidate_normalized = f"{local}CandidateNormalized"
        normalized_by_target_id[target_id] = original_normalized
        definitions.append(
            f"""def {region_name} : RegionRelation :=
  {_lean_carrier_region(plan, region)}

def {behavior} : SymbolicBehavior :=
  (regionBehaviorWithMachineCallContracts
    generatedOriginalCarrierContext.originalPe
    generatedOriginalCarrierContext.originalImports
    generatedOriginalCarrierContext.machineImportCallContracts
    {region_name}.original).get (by decide +kernel)

theorem {behavior}Decoded :
    regionBehaviorWithMachineCallContracts
      generatedOriginalCarrierContext.originalPe
      generatedOriginalCarrierContext.originalImports
      generatedOriginalCarrierContext.machineImportCallContracts
      {region_name}.original = some {behavior} := by
  decide +kernel

def {original_normalized} : NormalizedSymbolicBehavior :=
  (normalizeSymbolicBehavior false {region_name}.targets {behavior}).get
    (by decide +kernel)

def {candidate_normalized} : NormalizedSymbolicBehavior :=
  (normalizeSymbolicBehavior true {region_name}.targets {behavior}).get
    (by decide +kernel)

theorem {original_normalized}Checked :
    normalizeSymbolicBehavior false {region_name}.targets {behavior} =
      some {original_normalized} := by
  decide +kernel

theorem {candidate_normalized}Checked :
    normalizeSymbolicBehavior true {region_name}.targets {behavior} =
      some {candidate_normalized} := by
  decide +kernel"""
        )
    return "\n\n".join(definitions), normalized_by_target_id


def _lean_register_import_provenance_check(
    plan: InterpreterMixedOriginalPlan,
    prefix: str,
    final_region: str,
    original_normalized: str,
    candidate_normalized: str,
    binding: OriginalRegisterImportBinding,
) -> str:
    witness_ids = (*binding.seed_target_ids, *binding.preserve_target_ids)
    definitions, normalized = _lean_provenance_region_definitions(
        plan, prefix, witness_ids
    )
    imported = _lean_external_target(binding.imported.identity)
    relation = (
        f"{{ original := .{binding.register}, candidate := .{binding.register}, "
        f"imported := {imported} }}"
    )
    checks: list[str] = [definitions]
    if tuple(seed.target_id for seed in binding.seed_bindings) != (
        binding.seed_target_ids
    ):
        raise InterpreterMixedOriginalGenerationError(
            "import-register seed evidence does not match its target inventory"
        )
    for seed_index, seed in enumerate(binding.seed_bindings):
        target_id = seed.target_id
        local = f"{prefix}Seed{seed_index}"
        region = f"{prefix}Provenance{target_id}Region"
        writes = ", ".join(
            _lean_register_offset_write(write) for write in seed.writes
        )
        checks.append(
            f"""def {local}Claim : ImportRegisterSeedClaim := {{
  imported := {imported}
  originalRegister := .{binding.register}
  candidateRegister := .{binding.register}
  originalIatRva := {binding.imported.iat_rva}
  candidateIatRva := {binding.imported.iat_rva}
  assembledRead := {str(seed.assembled_read).lower()}
  originalWrites := [{writes}]
  candidateWrites := [{writes}]
}}

theorem {local}InventoryChecked :
    {region}.outputImportRelations.contains {relation} = true := by
  decide +kernel

theorem {local}Checked :
    {local}Claim.checked generatedOriginalCarrierContext.originalPe
      generatedOriginalCarrierContext.candidatePe
      generatedOriginalCarrierContext.originalImports
      generatedOriginalCarrierContext.candidateImports
      {region}.inputInvariant
      {normalized[target_id]} {normalized[target_id]} = true := by
  decide +kernel

theorem {local}Closed :
    ImportRegisterSeedClosed generatedOriginalCarrierContext.originalPe
      generatedOriginalCarrierContext.candidatePe
      generatedOriginalCarrierContext.originalImports
      generatedOriginalCarrierContext.candidateImports
      {region}.inputInvariant
      {normalized[target_id]} {normalized[target_id]} {local}Claim :=
  importRegisterSeedClosed_of_checked
    generatedOriginalCarrierContext.originalPe
    generatedOriginalCarrierContext.candidatePe
    generatedOriginalCarrierContext.originalImports
    generatedOriginalCarrierContext.candidateImports
    {region}.inputInvariant
    {normalized[target_id]} {normalized[target_id]} {local}Claim {local}Checked"""
        )
    for preserve_index, target_id in enumerate(binding.preserve_target_ids):
        local = f"{prefix}Preserve{preserve_index}"
        region = f"{prefix}Provenance{target_id}Region"
        checks.append(
            f"""def {local}Claim : ImportRegisterPreserveClaim := {{
  imported := {imported}
  sourceOriginalRegister := .{binding.register}
  sourceCandidateRegister := .{binding.register}
  targetOriginalRegister := .{binding.register}
  targetCandidateRegister := .{binding.register}
}}

theorem {local}Checked :
    {local}Claim.checked {region}.inputInvariant {region}.outputInvariant
      {normalized[target_id]} {normalized[target_id]} = true := by
  decide +kernel"""
        )
    checks.extend(
        _lean_register_provenance_edge_checks(
            plan,
            prefix,
            binding.register,
            binding.edges,
            normalized,
            imported=binding.imported.identity,
        )
    )
    checks.append(
        f"""def {prefix}Claim : ImportRegisterIndirectCallClaim := {{
  imported := {imported}
  originalRegister := .{binding.register}
  candidateRegister := .{binding.register}
  continuationTargetId := {binding.continuation_target_id}
}}

theorem {prefix}Checked :
    {prefix}Claim.checked {final_region}.inputInvariant
      {original_normalized} {candidate_normalized} = true := by
  decide +kernel

theorem {prefix}Closed :
    ImportRegisterIndirectCallTargetsClosed generatedOriginalCarrierContext
      {final_region}.inputInvariant {original_normalized} {candidate_normalized}
      {prefix}Claim :=
  importRegisterIndirectCallTargetsClosed_of_checked
    generatedOriginalCarrierContext {final_region}.inputInvariant
    {original_normalized} {candidate_normalized} {prefix}Claim {prefix}Checked

def {prefix}IndirectExitCertificate :
    StageA.Relational.ValueProvenance.CheckedIndirectExitCertificate
      generatedOriginalCarrierContext {final_region}.inputInvariant
      {original_normalized} {candidate_normalized} :=
  StageA.Relational.IndirectExitAdapters.checkedImportRegisterIndirectCertificate
      generatedOriginalCarrierContext {final_region}.inputInvariant
      {original_normalized} {candidate_normalized} {prefix}Claim
      {prefix}Checked (by decide +kernel)"""
    )
    return "\n\n" + "\n\n".join(check for check in checks if check)


def _lean_register_code_provenance_check(
    plan: InterpreterMixedOriginalPlan,
    prefix: str,
    final_region: str,
    original_normalized: str,
    candidate_normalized: str,
    binding: OriginalRegisterCodePointerBinding,
) -> str:
    witness_ids = (*binding.seed_target_ids, *binding.preserve_target_ids)
    definitions, normalized = _lean_provenance_region_definitions(
        plan, prefix, witness_ids
    )
    relation = (
        f"{{ original := .{binding.register}, candidate := .{binding.register}, "
        f"relation := .fixedCodePointer {binding.target_id} }}"
    )
    checks: list[str] = [definitions]
    static_seeds = {
        seed.target_id: seed.slot
        for seed in binding.static_word_seed_bindings
    }
    if len(static_seeds) != len(binding.static_word_seed_bindings):
        raise InterpreterMixedOriginalGenerationError(
            "register provenance has duplicate static-word seed regions"
        )
    immutable_seed_ids = tuple(
        target_id
        for target_id in binding.seed_target_ids
        if target_id not in static_seeds
    )
    if len(immutable_seed_ids) != len(binding.seed_relocation_rvas):
        raise InterpreterMixedOriginalGenerationError(
            "register provenance immutable seeds do not match relocations"
        )
    relocation_by_target_id = dict(
        zip(immutable_seed_ids, binding.seed_relocation_rvas, strict=True)
    )
    for seed_index, target_id in enumerate(binding.seed_target_ids):
        local = f"{prefix}Seed{seed_index}"
        region = f"{prefix}Provenance{target_id}Region"
        static_slot = static_seeds.get(target_id)
        if static_slot is not None:
            if static_slot.target_id != binding.target_id:
                raise InterpreterMixedOriginalGenerationError(
                    "register static-word seed has a different code target"
                )
            writes = ", ".join(
                _lean_register_offset_write(write)
                for write in static_slot.writes
            )
            checks.append(
                f"""def {local}Claim : InvariantWP.StaticWordSlotRegisterOutputClaim := {{
  output := {relation}
  slot := {_lean_static_word_slot(static_slot)}
  originalAddress := {static_slot.slot_va}
  candidateAddress := {static_slot.slot_va}
  originalAssembledRead := {str(static_slot.assembled_read).lower()}
  candidateAssembledRead := {str(static_slot.assembled_read).lower()}
  originalWrites := [{writes}]
  candidateWrites := [{writes}]
}}

theorem {local}InventoryChecked :
    {region}.outputRelations.contains {relation} = true := by
  decide +kernel

theorem {local}Checked :
    {local}Claim.checked generatedOriginalCarrierContext
      {region}.inputInvariant {normalized[target_id]}
      {normalized[target_id]} = true := by
  decide +kernel"""
            )
            continue
        relocation_rva = relocation_by_target_id[target_id]
        checks.append(
            f"""def {local}Claim : InvariantWP.FixedImmutableExprRegisterOutputClaim := {{
  output := {relation}
  originalValue := {binding.target_va}
  candidateValue := {binding.target_va}
}}

theorem {local}InventoryChecked :
    {region}.outputRelations.contains {relation} = true := by
  decide +kernel

theorem {local}RelocationChecked :
    pe32RelocationWordAt generatedOriginalCarrierContext.originalRelocations
      {relocation_rva} = true := by
  decide +kernel

theorem {local}Checked :
    {local}Claim.checked generatedOriginalCarrierContext
      {region}.inputInvariant {normalized[target_id]} {normalized[target_id]} = true := by
  decide +kernel"""
        )
    for preserve_index, target_id in enumerate(binding.preserve_target_ids):
        local = f"{prefix}Preserve{preserve_index}"
        region = f"{prefix}Provenance{target_id}Region"
        checks.append(
            f"""def {local}Claim : InvariantWP.IdentityRegisterOutputClaim := {{
  input := {relation}
  output := {relation}
}}

theorem {local}Checked :
    {local}Claim.checked {region} {normalized[target_id]}
      {normalized[target_id]} = true := by
  decide +kernel"""
        )
    checks.extend(
        _lean_register_provenance_edge_checks(
            plan,
            prefix,
            binding.register,
            binding.edges,
            normalized,
            register_relation=f".fixedCodePointer {binding.target_id}",
        )
    )
    checks.append(
        f"""def {prefix}Claim : FixedCodePointerRegisterIndirectCallClaim := {{
  targetId := {binding.target_id}
  originalRegister := .{binding.register}
  candidateRegister := .{binding.register}
  continuationTargetId := {binding.continuation_target_id}
}}

theorem {prefix}Checked :
    {prefix}Claim.checked {final_region}.inputInvariant
      {original_normalized} {candidate_normalized} = true := by
  decide +kernel

theorem {prefix}Closed :
    FixedCodePointerRegisterIndirectCallTargetsClosed
      generatedOriginalCarrierContext {final_region}.inputInvariant
      {original_normalized} {candidate_normalized} {prefix}Claim :=
  fixedCodePointerRegisterIndirectCallTargetsClosed_of_checked
    generatedOriginalCarrierContext {final_region}.inputInvariant
    {original_normalized} {candidate_normalized} {prefix}Claim {prefix}Checked

def {prefix}IndirectExitCertificate
    (contextValid : generatedOriginalCarrierContext.StructurallyValid) :
    StageA.Relational.ValueProvenance.CheckedIndirectExitCertificate
      generatedOriginalCarrierContext {final_region}.inputInvariant
      {original_normalized} {candidate_normalized} :=
  StageA.Relational.IndirectExitAdapters.checkedFixedRegisterIndirectCertificate
      generatedOriginalCarrierContext {final_region}.inputInvariant
      {original_normalized} {candidate_normalized} {prefix}Claim
      contextValid {prefix}Checked (by decide +kernel)"""
    )
    return "\n\n" + "\n\n".join(check for check in checks if check)


def _lean_register_provenance_edge_checks(
    plan: InterpreterMixedOriginalPlan,
    prefix: str,
    register: str,
    edges: Sequence[OriginalRegisterProvenanceEdge],
    normalized: Mapping[int, str],
    *,
    imported: OriginalImportIdentity | None = None,
    register_relation: str | None = None,
) -> list[str]:
    checks: list[str] = []
    for edge_index, edge in enumerate(edges):
        source = normalized.get(edge.source_target_id)
        if source is None:
            raise AssertionError("provenance edge source has no decoded witness")
        direct_check = f"""theorem {prefix}Edge{edge_index}Checked :
    {source}.outcome.registerRelationDirectTargets.contains
      {edge.target_target_id} = true := by
  decide +kernel"""
        if edge.kind != "call_return":
            checks.append(direct_check)
            continue
        contract = next(
            (
                item for item in plan.spec.register_control_call_contracts
                if item.contract_id == edge.contract_id
            ),
            None,
        )
        if contract is None:
            raise InterpreterMixedOriginalGenerationError(
                f"call-return edge {edge_index} lacks its exact contract"
            )
        if contract.origin in {
            "machine_import_boundary", "propagated_machine_import"
        }:
            if contract.import_identity is None:
                raise InterpreterMixedOriginalGenerationError(
                    f"call-return edge {edge_index} lacks import identity"
                )
            machine_contract_id = contract.machine_authority_id
            if machine_contract_id is None:
                raise InterpreterMixedOriginalGenerationError(
                    f"call-return edge {edge_index} lacks machine authority"
                )
            local = f"{prefix}Edge{edge_index}MachineImportAuthority"
            called_imported_term = f"{local}CalledImported"
            contract_check = f"""
def {called_imported_term} : ExternalTarget :=
  {_lean_external_target(contract.import_identity)}

def {local}Contract : MachineImportCallContract :=
  (machineImportCallContractById? generatedOriginalCarrierContext
    {machine_contract_id}).get (by decide +kernel)

theorem {local}ContractResolved :
    machineImportCallContractById? generatedOriginalCarrierContext
      {machine_contract_id} = some {local}Contract := by
  decide +kernel

theorem {local}ContractMatches :
    {local}Contract.imported = {called_imported_term} /\\
      {local}Contract.preservedRegisters.contains .{register} = true /\\
      {local}Contract.disposition = .returns := by
  decide +kernel"""
            if imported is not None:
                carried_imported_term = f"{local}CarriedImported"
                relation = (
                    f"{{ original := .{register}, candidate := .{register}, "
                    f"imported := {carried_imported_term} }}"
                )
                claim = f"""
def {carried_imported_term} : ExternalTarget :=
  {_lean_external_target(imported)}

def {local}Claim : ExternalImportRegisterPreservationClaim := {{
  source := {relation}
  target := {relation}
}}

theorem {local}Checked :
    {local}Claim.checked {local}Contract = true := by
  decide +kernel"""
            else:
                if register_relation is None:
                    raise InterpreterMixedOriginalGenerationError(
                        f"call-return edge {edge_index} lacks its carried "
                        "register relation"
                    )
                relation = (
                    f"{{ original := .{register}, candidate := .{register}, "
                    f"relation := {register_relation} }}"
                )
                claim = f"""
def {local}Claim : ExternalRegisterRelationPreservationClaim := {{
  source := {relation}
  target := {relation}
}}

theorem {local}Checked :
    {local}Claim.checked generatedOriginalCarrierContext {local}Contract =
      true := by
  decide +kernel"""
            checks.append(
                direct_check
                + contract_check
                + claim
                + f"\n\n#print axioms {local}Checked"
            )
            continue
        authority = contract.authorizing_lean_term
        if authority is None:
            raise InterpreterMixedOriginalGenerationError(
                f"call-return edge {edge_index} lacks semantic Lean authority"
            )
        finite_origin = (
            contract.origin == "checked_finite_origin_call_summary"
        )
        local = (
            f"{prefix}Edge{edge_index}"
            + (
                "FiniteOriginCallAuthority"
                if finite_origin
                else "DirectCallAuthority"
            )
        )
        authority_type = (
            "CheckedFiniteOriginCallRegisterControlContract"
            if finite_origin
            else "CheckedDirectCallRegisterControlContract"
        )
        finite_target_check = (
            f"\n      {local}.entry.calleeTargetId = "
            f"{contract.finite_target_ids[0]} /\\"
            if finite_origin
            else ""
        )
        checks.append(direct_check + f"""

def {local} :
    StageA.Relational.InternalDirectCallMixedOriginalIntegration.{authority_type}
      generatedOriginalCarrierContext :=
  {authority.qualified}

theorem {local}Matches :
    {local}.edge.sourceRegion = {edge.source_target_id} /\\
      {local}.edge.targetRegion = {edge.target_target_id} /\\
      {local}.edge.kind =
        StageA.Relational.RegisterControlProvenance.EdgeKind.callReturn /\\
      {local}.edge.machineContractId = some {contract.contract_id} /\\
      {local}.contract.contractId = {contract.contract_id} /\\
      .{register} ∈ {local}.requestedRegisters /\\{finite_target_check}
      {local}.sourceInvariant =
        ((generatedOriginalCarrierRegionIndex.get?
          {edge.source_target_id}).get
          (by decide +kernel)).inputInvariant := by
  decide +kernel

#print axioms {local}""")
    return checks


def _lean_table_predecessor_bound_check(
    plan: InterpreterMixedOriginalPlan,
    prefix: str,
    table_index_expression: str,
    binding: OriginalBoundedTableBinding,
    predecessor_index: int,
    predecessor: OriginalTablePredecessorBound,
) -> str:
    predecessor_region = plan.regions[predecessor.predecessor_target_id]
    table_target_id = _id_for_rva(
        plan,
        next(
            site.source_rva
            for region in plan.regions
            for site in region.indirect_sites
            if site.static_binding is binding
        ),
    )
    local = f"{prefix}Predecessor{predecessor_index}"
    region = f"{local}Region"
    behavior = f"{local}Behavior"
    normalized = f"{local}Normalized"
    target_predicate = f"{local}TargetPredicate"
    precondition = f"{local}Precondition"
    pulled_index = f"{local}PulledIndex"
    if predecessor.index_width_bits < 32:
        expected_precondition = (
            f"InvariantWP.maskedSuccessorPredicate {pulled_index} "
            f"{predecessor.index_width_bits} {binding.upper_exclusive - 1}"
        )
        precondition_proof = (
            f"InvariantWP.maskedSuccessorPredicate_eval {pulled_index} "
            f"{predecessor.index_width_bits} {binding.upper_exclusive - 1} state "
            "(by decide +kernel) (by decide +kernel)"
        )
    else:
        expected_precondition = (
            f"InvariantWP.successorRangePredicate {pulled_index} "
            f"{binding.upper_exclusive - 1}"
        )
        precondition_proof = (
            f"InvariantWP.successorRangePredicate_eval {pulled_index} "
            f"{binding.upper_exclusive - 1} state (by decide +kernel)"
        )
    return f"""def {region} : RegionRelation :=
  {_lean_carrier_region(plan, predecessor_region)}

def {behavior} : SymbolicBehavior :=
  (regionBehaviorWithMachineCallContracts
    generatedOriginalCarrierContext.originalPe
    generatedOriginalCarrierContext.originalImports
    generatedOriginalCarrierContext.machineImportCallContracts
    {region}.original).get (by decide +kernel)

theorem {behavior}Decoded :
    regionBehaviorWithMachineCallContracts
      generatedOriginalCarrierContext.originalPe
      generatedOriginalCarrierContext.originalImports
      generatedOriginalCarrierContext.machineImportCallContracts
      {region}.original = some {behavior} := by
  decide +kernel

def {normalized} : NormalizedSymbolicBehavior :=
  (normalizeSymbolicBehavior false {region}.targets {behavior}).get
    (by decide +kernel)

theorem {normalized}Checked :
    normalizeSymbolicBehavior false {region}.targets {behavior} =
      some {normalized} := by
  decide +kernel

def {target_predicate} : BoolExpr :=
  .unsignedLess ({table_index_expression})
    (.constant {binding.upper_exclusive})

def {precondition} : BoolExpr :=
  (InvariantWP.edgeWeakestPrecondition {normalized} {table_target_id}
    {target_predicate}).get (by decide +kernel)

theorem {precondition}Computed :
    InvariantWP.edgeWeakestPrecondition {normalized} {table_target_id}
      {target_predicate} = some {precondition} := by
  decide +kernel

def {pulled_index} : Expr :=
  (Expr.inputReg .{binding.index_register}).substituteRegisters
    {normalized}.registers

theorem {precondition}Shape :
    {precondition} = {expected_precondition} := by
  decide +kernel

theorem {precondition}UniversallyValid (state : MachineState) :
    {precondition}.eval state = true := by
  rw [{precondition}Shape]
  exact {precondition_proof}

theorem {local}BoundClosed :
    InvariantWP.NormalizedInvariantPredicateEdgeClosed {normalized} []
      {target_predicate} {table_target_id} := by
  apply InvariantWP.invariantPredicateEdgeClosed_of_wp
    {normalized} [] {target_predicate} {precondition} {table_target_id}
  · decide +kernel
  · exact {precondition}Computed
  · intro state _sourceInvariant
    exact {precondition}UniversallyValid state"""


def _lean_import_identity(identity: OriginalImportIdentity) -> str:
    dll = _lean_bytes(identity.dll.encode("ascii"))
    if identity.symbol is not None:
        name = f"(.symbol {_lean_bytes(identity.symbol.encode('ascii'))})"
    else:
        name = f"(.ordinal {identity.ordinal})"
    return f"{{ dll := {dll}, name := {name} }}"


def _lean_external_target(identity: OriginalImportIdentity) -> str:
    dll = _lean_bytes(identity.dll.lower().encode("ascii"))
    if identity.symbol is not None:
        name = f"(.symbol {_lean_bytes(identity.symbol.encode('ascii'))})"
    else:
        name = f"(.ordinal {identity.ordinal})"
    return f"{{ dll := {dll}, name := {name} }}"


def _lean_iat_call_site(
    plan: InterpreterMixedOriginalPlan, site: OriginalIndirectSite
) -> str:
    imported = site.iat_import
    if imported is None:
        raise AssertionError("IAT call-site encoder received an unbound site")
    source_id = _id_for_rva(plan, site.source_rva)
    return (
        f"{{ sourceTargetId := {source_id}, "
        f"instructionRva := {site.instruction_rva}, "
        f"iatVa := {imported.iat_va}, iatRva := {imported.iat_rva}, "
        f"identity := {_lean_import_identity(imported.identity)} }}"
    )


def _lean_bytes(value: bytes) -> str:
    return "[" + ", ".join(str(byte) for byte in value) + "]"


def _lean_finite_index(rows: Sequence[str], *, leaf_size: int = 16) -> str:
    if not rows:
        return ".empty"
    if len(rows) <= leaf_size:
        return f".leaf [{', '.join(rows)}]"
    middle = len(rows) // 2
    left = _lean_finite_index(rows[:middle], leaf_size=leaf_size)
    right = _lean_finite_index(rows[middle:], leaf_size=leaf_size)
    return f".branch {len(rows)} {middle} ({left}) ({right})"


@dataclass(frozen=True)
class _LeanIndexRefTree:
    expression: str
    size: int
    height: int
    maximum_balance: int = 0


def _lean_finite_index_height(row_count: int, *, leaf_size: int = 16) -> int:
    """Return the checked FiniteIndex height emitted by _lean_finite_index."""

    if row_count < 0:
        raise InterpreterMixedOriginalGenerationError(
            "finite-index reference sizes must be nonnegative"
        )
    if row_count == 0:
        return 0
    if row_count <= leaf_size:
        return 1
    middle = row_count // 2
    return 1 + max(
        _lean_finite_index_height(middle, leaf_size=leaf_size),
        _lean_finite_index_height(row_count - middle, leaf_size=leaf_size),
    )


def _lean_index_ref_tree(
    refs: Sequence[tuple[str, int]], *, leaf_size: int = 16
) -> _LeanIndexRefTree:
    """Compose pre-built indexes without violating their checked AVL shape."""

    if not refs:
        return _LeanIndexRefTree(".empty", 0, 0)
    for name, size in refs:
        if not name:
            raise InterpreterMixedOriginalGenerationError(
                "finite-index reference names must be nonempty"
            )
        if size <= 0:
            raise InterpreterMixedOriginalGenerationError(
                "finite-index reference sizes must be positive"
            )

    count = len(refs)
    table: dict[tuple[int, int], dict[int, _LeanIndexRefTree]] = {}
    for index, (name, size) in enumerate(refs):
        height = _lean_finite_index_height(size, leaf_size=leaf_size)
        table[(index, index + 1)] = {
            height: _LeanIndexRefTree(name, size, height)
        }

    # Keep one deterministic representative for every reachable height. A
    # range can have several valid heights depending on its grouping, and
    # discarding those alternatives can make a valid parent appear impossible.
    for width in range(2, count + 1):
        for start in range(0, count - width + 1):
            stop = start + width
            candidates: dict[int, tuple[tuple[int, int, int], _LeanIndexRefTree]] = {}
            for split in range(start + 1, stop):
                for left in table.get((start, split), {}).values():
                    for right in table.get((split, stop), {}).values():
                        balance = abs(left.height - right.height)
                        if balance > 1:
                            continue
                        height = 1 + max(left.height, right.height)
                        maximum_balance = max(
                            balance, left.maximum_balance, right.maximum_balance
                        )
                        tree = _LeanIndexRefTree(
                            expression=(
                                f".branch {left.size + right.size} {left.size} "
                                f"({left.expression}) ({right.expression})"
                            ),
                            size=left.size + right.size,
                            height=height,
                            maximum_balance=maximum_balance,
                        )
                        score = (
                            maximum_balance,
                            abs(left.size - right.size),
                            split,
                        )
                        previous = candidates.get(height)
                        if previous is None or score < previous[0]:
                            candidates[height] = (score, tree)
            if candidates:
                table[(start, stop)] = {
                    height: scored[1]
                    for height, scored in candidates.items()
                }

    complete = table.get((0, count), {})
    if not complete:
        heights = [
            _lean_finite_index_height(size, leaf_size=leaf_size)
            for _, size in refs
        ]
        raise InterpreterMixedOriginalGenerationError(
            "finite-index shard forest cannot satisfy the checked balance "
            f"invariant (heights={heights})"
        )
    return min(
        complete.values(),
        key=lambda tree: (tree.height, tree.maximum_balance, tree.expression),
    )


def _lean_index_refs(refs: Sequence[tuple[str, int]]) -> str:
    return _lean_index_ref_tree(refs).expression


def _id_for_rva(plan: InterpreterMixedOriginalPlan, rva: int) -> int:
    for region in plan.regions:
        if region.rva == rva:
            return region.target_id
    raise AssertionError(f"validated root 0x{rva:x} disappeared")


def _sorted_imports(
    identities: Sequence[OriginalImportIdentity] | set[OriginalImportIdentity],
) -> list[OriginalImportIdentity]:
    return sorted(
        identities,
        key=lambda item: (
            item.dll.lower(),
            item.symbol or "",
            -1 if item.ordinal is None else item.ordinal,
        ),
    )


def _import_identity_json(identity: OriginalImportIdentity) -> dict[str, Any]:
    return {
        "dll": identity.dll,
        "symbol": identity.symbol,
        "ordinal": identity.ordinal,
    }


def _static_binding_detail(binding: OriginalStaticIndirectBinding) -> str:
    if isinstance(binding, OriginalFixedTargetBinding):
        return (
            f"constant target has exact indexed code binding to RVA "
            f"0x{binding.target_rva:x}"
        )
    if isinstance(binding, OriginalImmutableSlotBinding):
        return (
            f"immutable relocation-backed slot RVA 0x{binding.slot_rva:x} "
            f"contains indexed code target RVA 0x{binding.target_rva:x} with "
            f"{len(binding.address_separations)} checked bytewise no-alias "
            "premise(s)"
        )
    if isinstance(binding, OriginalStaticWordSlotBinding):
        return (
            f"writable static-word slot RVA 0x{binding.slot_rva:x} contains "
            f"indexed code target RVA 0x{binding.target_rva:x} with "
            f"{len(binding.address_separations)} checked bytewise no-alias "
            "premise(s)"
        )
    if isinstance(binding, OriginalStaticWordJumpSlotBinding):
        return (
            f"writable static-word tail slot RVA 0x{binding.slot_rva:x} contains "
            f"indexed code target RVA 0x{binding.target_rva:x} with "
            f"{len(binding.address_separations)} checked bytewise no-alias "
            "premise(s)"
        )
    if isinstance(binding, OriginalFiniteOriginStaticWordJumpBinding):
        return (
            f"writable static-word tail slot RVA 0x{binding.slot_rva:x} has "
            f"{len(binding.internal_target_ids)} internal and "
            f"{len(binding.external_routes)} callable finite origin(s)"
        )
    if isinstance(binding, OriginalRegisterCodePointerBinding):
        return (
            f"register {binding.register} has singleton relocation-backed code "
            f"provenance to RVA 0x{binding.target_rva:x} through "
            f"{len(binding.edges)} checked direct edge(s)"
        )
    if isinstance(binding, OriginalRegisterImportBinding):
        identity = binding.imported.identity
        imported_name = identity.symbol or f"ordinal {identity.ordinal}"
        return (
            f"register {binding.register} has singleton IAT provenance for "
            f"{identity.dll}!{imported_name} through {len(binding.edges)} "
            "checked direct edge(s)"
        )
    if not isinstance(binding, OriginalBoundedTableBinding):
        raise AssertionError("unknown static indirect binding")
    bound_source = (
        "a self-contained mask"
        if not binding.predecessor_bounds
        else f"{len(binding.predecessor_bounds)} checked direct predecessor(s)"
    )
    return (
        f"immutable {binding.upper_exclusive}-entry relocation table at RVA "
        f"0x{binding.table_rva:x} has {len(binding.finite_target_ids)} finite "
        f"indexed targets bounded by {bound_source}"
    )


def _static_indirect_binding_json(site: OriginalIndirectSite) -> dict[str, Any]:
    binding = site.static_binding
    if binding is None:
        raise AssertionError("static binding serializer received an unbound site")
    result: dict[str, Any] = {
        "source_rva": site.source_rva,
        "instruction_rva": site.instruction_rva,
        "is_call": site.is_call,
        "continuation_rva": site.continuation_rva,
    }
    if isinstance(binding, OriginalFixedTargetBinding):
        result.update(
            {
                "kind": "fixed_code_address",
                "target_id": binding.target_id,
                "target_rva": binding.target_rva,
                "target_va": binding.target_va,
            }
        )
    elif isinstance(binding, OriginalImmutableSlotBinding):
        result.update(
            {
                "kind": "immutable_pointer_slot",
                "slot_rva": binding.slot_rva,
                "slot_va": binding.slot_va,
                "target_id": binding.target_id,
                "target_rva": binding.target_rva,
                "target_va": binding.target_va,
                "continuation_target_id": binding.continuation_target_id,
                "assembled_read": binding.assembled_read,
                "writes": [
                    {
                        "register": write.register,
                        "offset": write.offset,
                        "subtract": write.subtract,
                        "value": dict(write.value),
                    }
                    for write in binding.writes
                ],
                "address_separations": [
                    {
                        "register": separation.register,
                        "offset": separation.offset,
                        "address": separation.address,
                    }
                    for separation in binding.address_separations
                ],
            }
        )
    elif isinstance(binding, OriginalStaticWordSlotBinding):
        result.update(
            {
                "kind": "writable_static_word_slot",
                "slot_id": binding.slot_id,
                "slot_rva": binding.slot_rva,
                "slot_va": binding.slot_va,
                "slot_bytes": list(binding.slot_bytes),
                "target_id": binding.target_id,
                "target_rva": binding.target_rva,
                "target_va": binding.target_va,
                "continuation_target_id": binding.continuation_target_id,
                "assembled_read": binding.assembled_read,
                "writes": [
                    {
                        "register": write.register,
                        "offset": write.offset,
                        "subtract": write.subtract,
                        "value": dict(write.value),
                    }
                    for write in binding.writes
                ],
                "address_separations": [
                    {
                        "register": separation.register,
                        "offset": separation.offset,
                        "address": separation.address,
                    }
                    for separation in binding.address_separations
                ],
            }
        )
    elif isinstance(binding, OriginalStaticWordJumpSlotBinding):
        result.update(
            {
                "kind": "writable_static_word_jump_slot",
                "slot_id": binding.slot_id,
                "slot_rva": binding.slot_rva,
                "slot_va": binding.slot_va,
                "slot_bytes": list(binding.slot_bytes),
                "target_id": binding.target_id,
                "target_rva": binding.target_rva,
                "target_va": binding.target_va,
                "assembled_read": binding.assembled_read,
                "writes": [
                    {
                        "register": write.register,
                        "offset": write.offset,
                        "subtract": write.subtract,
                        "value": dict(write.value),
                    }
                    for write in binding.writes
                ],
                "address_separations": [
                    {
                        "register": separation.register,
                        "offset": separation.offset,
                        "address": separation.address,
                    }
                    for separation in binding.address_separations
                ],
            }
        )
    elif isinstance(binding, OriginalFiniteOriginStaticWordJumpBinding):
        result.update(
            {
                "kind": "finite_origin_writable_static_word_jump_slot",
                "slot_id": binding.slot_id,
                "slot_rva": binding.slot_rva,
                "slot_va": binding.slot_va,
                "slot_bytes": list(binding.slot_bytes),
                "initial_target_id": binding.initial_target_id,
                "initial_target_rva": binding.initial_target_rva,
                "initial_target_va": binding.initial_target_va,
                "internal_target_ids": list(binding.internal_target_ids),
                "external_routes": [
                    {
                        "abi_contract_id": route.abi_contract_id,
                        "capability_id": route.capability_id,
                        "resolver_contract_id": route.resolver_contract_id,
                        "resource_id": route.resource_id,
                    }
                    for route in binding.external_routes
                ],
                "assembled_read": binding.assembled_read,
                "writes": [
                    {
                        "register": write.register,
                        "offset": write.offset,
                        "subtract": write.subtract,
                        "value": dict(write.value),
                    }
                    for write in binding.writes
                ],
                "address_separations": [
                    {
                        "register": separation.register,
                        "offset": separation.offset,
                        "address": separation.address,
                    }
                    for separation in binding.address_separations
                ],
            }
        )
    elif isinstance(binding, OriginalRegisterCodePointerBinding):
        result.update(
            {
                "kind": "register_fixed_code_pointer",
                "register": binding.register,
                "target_id": binding.target_id,
                "target_rva": binding.target_rva,
                "target_va": binding.target_va,
                "continuation_target_id": binding.continuation_target_id,
                "seed_target_ids": list(binding.seed_target_ids),
                "preserve_target_ids": list(binding.preserve_target_ids),
                "seed_relocation_rvas": list(binding.seed_relocation_rvas),
                "static_word_seed_bindings": [
                    {
                        "target_id": seed.target_id,
                        "slot_rva": seed.slot.slot_rva,
                        "slot_va": seed.slot.slot_va,
                        "assembled_read": seed.slot.assembled_read,
                    }
                    for seed in binding.static_word_seed_bindings
                ],
                "edges": [
                    {
                        "source_target_id": edge.source_target_id,
                        "target_target_id": edge.target_target_id,
                        "kind": edge.kind,
                        "contract_id": edge.contract_id,
                    }
                    for edge in binding.edges
                ],
            }
        )
    elif isinstance(binding, OriginalRegisterImportBinding):
        result.update(
            {
                "kind": "register_import_pointer",
                "register": binding.register,
                "import": _import_identity_json(binding.imported.identity),
                "iat_rva": binding.imported.iat_rva,
                "iat_va": binding.imported.iat_va,
                "continuation_target_id": binding.continuation_target_id,
                "seed_target_ids": list(binding.seed_target_ids),
                "seed_bindings": [
                    {
                        "target_id": seed.target_id,
                        "instruction_rva": seed.instruction_rva,
                        "assembled_read": seed.assembled_read,
                        "writes": [
                            {
                                "register": write.register,
                                "offset": write.offset,
                                "subtract": write.subtract,
                                "value": dict(write.value),
                            }
                            for write in seed.writes
                        ],
                        "address_separations": [
                            {
                                "register": separation.register,
                                "offset": separation.offset,
                                "address": separation.address,
                            }
                            for separation in seed.address_separations
                        ],
                    }
                    for seed in binding.seed_bindings
                ],
                "preserve_target_ids": list(binding.preserve_target_ids),
                "edges": [
                    {
                        "source_target_id": edge.source_target_id,
                        "target_target_id": edge.target_target_id,
                        "kind": edge.kind,
                        "contract_id": edge.contract_id,
                    }
                    for edge in binding.edges
                ],
                "call_contract_ids": list(binding.call_contract_ids),
            }
        )
    elif isinstance(binding, OriginalBoundedTableBinding):
        result.update(
            {
                "kind": "bounded_immutable_relocation_table",
                "table_rva": binding.table_rva,
                "table_va": binding.table_va,
                "index_register": binding.index_register,
                "index_mask": binding.index_mask,
                "upper_exclusive": binding.upper_exclusive,
                "entry_target_ids": list(binding.entry_target_ids),
                "finite_target_ids": list(binding.finite_target_ids),
                "bytes_sha256": binding.bytes_sha256,
                "predecessor_bounds": [
                    {
                        "predecessor_target_id": predecessor.predecessor_target_id,
                        "predecessor_rva": predecessor.predecessor_rva,
                        "index_width_bits": predecessor.index_width_bits,
                    }
                    for predecessor in binding.predecessor_bounds
                ],
            }
        )
    else:
        raise AssertionError("unknown static indirect binding")
    return result


def _category_counts(sites: Sequence[OriginalIndirectSite]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for site in sites:
        counts[site.category] = counts.get(site.category, 0) + 1
    return dict(sorted(counts.items()))


def _valid_local_identifier(value: str) -> bool:
    return (
        _LOCAL_NAME.fullmatch(value) is not None
        and value != "_"
        and value not in _LEAN_KEYWORDS
    )


def _valid_qualified_identifier(
    value: str, *, pattern: re.Pattern[str] = _LEAN_IDENTIFIER
) -> bool:
    return pattern.fullmatch(value) is not None and all(
        _valid_local_identifier(component) for component in value.split(".")
    )


def _u32(value: Any, context: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or not 0 <= value < 2**32:
        raise InterpreterMixedOriginalGenerationError(
            f"{context} must be an unsigned 32-bit integer"
        )
    return value


def _positive_int(value: Any, context: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
        raise InterpreterMixedOriginalGenerationError(
            f"{context} must be a positive integer"
        )
    return value


__all__ = [
    "CHECKED_STACK_FINITE_ORIGIN_ENTRY_AUTHORITY_FORMAT",
    "INTERPRETER_MIXED_DIRECT_CALL_AUTHORITY_FORMAT",
    "INTERPRETER_MIXED_ORIGINAL_FORMAT",
    "INTERPRETER_MIXED_ORIGINAL_BASE_MODULE",
    "INTERPRETER_MIXED_ORIGINAL_MODULE",
    "INTERPRETER_MIXED_REGISTER_CONTROL_FORMAT",
    "INTERPRETER_MIXED_REGISTER_CONTROL_LEAN_ADAPTER_FORMAT",
    "InterpreterMixedOriginalGenerationError",
    "InterpreterMixedOriginalPlan",
    "InterpreterMixedOriginalSpec",
    "MixedOriginalDirectCallSummaryRequestPlan",
    "OriginalGenerationBlocker",
    "OriginalGenerationDiagnostic",
    "OriginalIATImport",
    "OriginalBoundedTableBinding",
    "OriginalCallableExternalRouteBinding",
    "OriginalFiniteOriginStaticWordJumpBinding",
    "OriginalFixedTargetBinding",
    "OriginalImportIdentity",
    "OriginalIndirectSite",
    "OriginalImmutableSlotBinding",
    "OriginalMachineImportBoundarySiteProposal",
    "OriginalStaticWordJumpSlotBinding",
    "OriginalStaticWordSlotBinding",
    "OriginalStateIndependentFalseEdgeCut",
    "OriginalRegisterCodePointerBinding",
    "OriginalRegisterControlCallContractProposal",
    "OriginalRegisterFiniteOriginCallEntryAuthority",
    "OriginalRegisterStaticWordSeedAuthority",
    "OriginalRegisterStaticWordSeedBinding",
    "OriginalRegisterImportBinding",
    "OriginalRegisterProvenanceEdge",
    "OriginalModuleBindings",
    "OriginalPERecoveryInput",
    "OriginalRecoveredAlias",
    "OriginalRegion",
    "QualifiedLeanSymbol",
    "augment_direct_call_summary_requests_from_runtime_value_carry_hints",
    "derive_direct_call_summary_requests_from_register_authority",
    "derive_mixed_original_direct_call_summary_requests",
    "load_checked_direct_call_summary_contract_proposals",
    "load_checked_stack_finite_origin_call_entry_authorities",
    "load_original_iat_import_proposals",
    "load_original_pe_recovery_input",
    "load_original_register_control_call_contract_proposals",
    "interpreter_mixed_original_register_control_lean_adapter",
    "plan_interpreter_mixed_original",
    "stage_finite_origin_entry_requests",
    "write_relational_interpreter_mixed_original",
    "write_relational_interpreter_mixed_original_base",
    "write_relational_interpreter_mixed_original_final",
    "write_register_finite_origin_call_entry_authorities",
]
