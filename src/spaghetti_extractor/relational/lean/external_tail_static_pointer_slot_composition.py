"""Bind exact external-tail/static-slot macro evidence for Lean.

The generator serializes only stable request metadata and aliases a named Lean
proof object.  The metadata is an index of the requested evidence type, so an
authority for a different source, slot, import, ABI, or outcome does not
elaborate.  No report status or Python analysis result can create authority.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from ...errors import StageAInputError


EXTERNAL_TAIL_STATIC_POINTER_SLOT_COMPOSITION_FORMAT = (
    "stage-a-external-tail-static-pointer-slot-composition-v1"
)
EXTERNAL_TAIL_STATIC_POINTER_SLOT_COMPOSITION_LEAN_FILENAME = (
    "GeneratedRelationalExternalTailStaticPointerSlotComposition.lean"
)

_QUALIFIED = re.compile(
    r"[A-Za-z_][A-Za-z0-9_']*(?:\.[A-Za-z_][A-Za-z0-9_']*)*\Z"
)
_MODULE = re.compile(
    r"[A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z][A-Za-z0-9_]*)*\Z"
)
_REGISTERS = frozenset(("eax", "ebx", "ecx", "edx", "esi", "edi", "ebp"))
_U32_LIMIT = 1 << 32


class ExternalTailStaticPointerSlotCompositionError(StageAInputError):
    """An external-tail/static-slot binding is malformed or ambiguous."""


def _qualified(value: str, field: str) -> str:
    if not isinstance(value, str) or _QUALIFIED.fullmatch(value) is None:
        raise ExternalTailStaticPointerSlotCompositionError(
            f"{field} must be a qualified Lean identifier"
        )
    return value


def _module(value: str, field: str) -> str:
    if not isinstance(value, str) or _MODULE.fullmatch(value) is None:
        raise ExternalTailStaticPointerSlotCompositionError(
            f"{field} must be a Lean module name"
        )
    return value


def _u32(value: int, field: str) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or not 0 <= value < _U32_LIMIT
    ):
        raise ExternalTailStaticPointerSlotCompositionError(
            f"{field} must be an unsigned 32-bit integer"
        )
    return value


def _natural(value: int, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ExternalTailStaticPointerSlotCompositionError(
            f"{field} must be a natural number"
        )
    return value


def _ascii(value: str, field: str) -> bytes:
    if not isinstance(value, str) or not value:
        raise ExternalTailStaticPointerSlotCompositionError(
            f"{field} must be a nonempty ASCII string"
        )
    try:
        return value.encode("ascii")
    except UnicodeEncodeError as error:
        raise ExternalTailStaticPointerSlotCompositionError(
            f"{field} must contain only ASCII characters"
        ) from error


def _bytes(value: bytes) -> str:
    return "[" + ", ".join(str(byte) for byte in value) + "]"


def _naturals(values: tuple[int, ...], field: str) -> str:
    return "[" + ", ".join(
        str(_natural(value, f"{field}[{index}]"))
        for index, value in enumerate(values)
    ) + "]"


def _registers(values: tuple[str, ...], field: str) -> str:
    seen: set[str] = set()
    rendered: list[str] = []
    for index, value in enumerate(values):
        if value not in _REGISTERS:
            raise ExternalTailStaticPointerSlotCompositionError(
                f"{field}[{index}] is not a supported machine-call register"
            )
        if value in seen:
            raise ExternalTailStaticPointerSlotCompositionError(
                f"{field} contains duplicate register {value}"
            )
        seen.add(value)
        rendered.append(f".{value}")
    return "[" + ", ".join(rendered) + "]"


@dataclass(frozen=True)
class ExternalImportIdentity:
    dll: str
    symbol: str | None = None
    ordinal: int | None = None

    def checked(self) -> "ExternalImportIdentity":
        dll = _ascii(self.dll, "import dll")
        if dll != dll.lower():
            raise ExternalTailStaticPointerSlotCompositionError(
                "import dll must already be ASCII-lowercase"
            )
        if (self.symbol is None) == (self.ordinal is None):
            raise ExternalTailStaticPointerSlotCompositionError(
                "import identity requires exactly one of symbol or ordinal"
            )
        if self.symbol is not None:
            _ascii(self.symbol, "import symbol")
        if self.ordinal is not None:
            _u32(self.ordinal, "import ordinal")
        return self

    def lean(self) -> str:
        self.checked()
        if self.symbol is not None:
            name = f".symbol {_bytes(_ascii(self.symbol, 'import symbol'))}"
        else:
            name = f".ordinal {self.ordinal}"
        return (
            "{ dll := "
            + _bytes(_ascii(self.dll, "import dll"))
            + f", name := {name} }}"
        )


@dataclass(frozen=True)
class ExternalTailStaticPointerSlotCompositionBinding:
    context_term: str
    original_context_term: str
    certificate_term: str
    authority_term: str
    source_target_id: int
    wrapper_target_id: int
    continuation_target_id: int
    source_rva: int
    callsite_rva: int
    call_instruction_size: int
    wrapper_rva: int
    continuation_rva: int
    route_kind: Literal["direct_import", "iat_indirect"]
    iat_rva: int | None
    slot_rva: int
    slot_target_id: int
    slot_value: int
    site_id: int
    machine_contract_id: int
    imported: ExternalImportIdentity
    original_frame_argument_offset: int
    candidate_frame_argument_offset: int
    stack_argument_offsets: tuple[int, ...]
    stack_result_delta: int
    preserved_registers: tuple[str, ...]
    clobbered_registers: tuple[str, ...]
    original_decoded_authority_term: str | None = None
    source_region_index: int | None = None
    wrapper_region_index: int | None = None
    continuation_region_index: int | None = None
    source_aliases: tuple[tuple[int, int], ...] = ()
    wrapper_aliases: tuple[tuple[int, int], ...] = ()
    continuation_aliases: tuple[tuple[int, int], ...] = ()
    outcome: Literal["returns", "terminates"] = "returns"
    imports: tuple[str, ...] = ()
    namespace: str = (
        "StageA.Generated.ExternalTailStaticPointerSlotComposition"
    )

    def checked(self) -> "ExternalTailStaticPointerSlotCompositionBinding":
        _qualified(self.context_term, "context_term")
        _qualified(self.original_context_term, "original_context_term")
        _qualified(self.certificate_term, "certificate_term")
        _qualified(self.authority_term, "authority_term")
        if self.original_decoded_authority_term is not None:
            _qualified(
                self.original_decoded_authority_term,
                "original_decoded_authority_term",
            )
        _module(self.namespace, "namespace")
        for field in (
            "source_target_id",
            "wrapper_target_id",
            "continuation_target_id",
            "source_rva",
            "callsite_rva",
            "call_instruction_size",
            "wrapper_rva",
            "continuation_rva",
            "slot_rva",
            "slot_target_id",
            "slot_value",
            "site_id",
            "machine_contract_id",
            "original_frame_argument_offset",
            "candidate_frame_argument_offset",
            "stack_result_delta",
        ):
            _u32(getattr(self, field), field)
        if self.call_instruction_size == 0:
            raise ExternalTailStaticPointerSlotCompositionError(
                "call_instruction_size must be positive"
            )
        if self.callsite_rva + self.call_instruction_size != (
            self.continuation_rva
        ):
            raise ExternalTailStaticPointerSlotCompositionError(
                "callsite plus call_instruction_size must equal continuation_rva"
            )
        for field in (
            "source_region_index",
            "wrapper_region_index",
            "continuation_region_index",
        ):
            value = getattr(self, field)
            if value is not None:
                _natural(value, field)
        for field, aliases in (
            ("source_aliases", self.source_aliases),
            ("wrapper_aliases", self.wrapper_aliases),
            ("continuation_aliases", self.continuation_aliases),
        ):
            if len(set(aliases)) != len(aliases):
                raise ExternalTailStaticPointerSlotCompositionError(
                    f"{field} contains duplicates"
                )
            for index, (rva, padding_index) in enumerate(aliases):
                _u32(rva, f"{field}[{index}].rva")
                _natural(
                    padding_index, f"{field}[{index}].padding_index"
                )
        for field in (
            "original_frame_argument_offset",
            "candidate_frame_argument_offset",
        ):
            offset = getattr(self, field)
            if offset % 4 != 0 or offset + 4 > _U32_LIMIT:
                raise ExternalTailStaticPointerSlotCompositionError(
                    f"{field} must name an aligned 32-bit frame word"
                )
        if self.route_kind == "direct_import":
            if self.iat_rva is not None:
                raise ExternalTailStaticPointerSlotCompositionError(
                    "direct_import must not carry an IAT RVA"
                )
        elif self.route_kind == "iat_indirect":
            if self.iat_rva is None:
                raise ExternalTailStaticPointerSlotCompositionError(
                    "iat_indirect requires an exact IAT RVA"
                )
            _u32(self.iat_rva, "iat_rva")
        else:
            raise ExternalTailStaticPointerSlotCompositionError(
                f"unsupported route_kind: {self.route_kind!r}"
            )
        if self.outcome not in {"returns", "terminates"}:
            raise ExternalTailStaticPointerSlotCompositionError(
                f"unsupported outcome: {self.outcome!r}"
            )
        if self.outcome == "terminates" and self.stack_result_delta != 0:
            raise ExternalTailStaticPointerSlotCompositionError(
                "terminating machine-call ABI requires zero stack_result_delta"
            )
        self.imported.checked()
        _naturals(self.stack_argument_offsets, "stack_argument_offsets")
        if len(set(self.stack_argument_offsets)) != len(
            self.stack_argument_offsets
        ):
            raise ExternalTailStaticPointerSlotCompositionError(
                "stack_argument_offsets contains duplicates"
            )
        if any(
            offset % 4 != 0 or offset + 4 > _U32_LIMIT
            for offset in self.stack_argument_offsets
        ):
            raise ExternalTailStaticPointerSlotCompositionError(
                "stack_argument_offsets must name aligned 32-bit words"
            )
        if self.stack_result_delta % 4 != 0:
            raise ExternalTailStaticPointerSlotCompositionError(
                "stack_result_delta must be word aligned"
            )
        preserved = set(self.preserved_registers)
        clobbered = set(self.clobbered_registers)
        _registers(self.preserved_registers, "preserved_registers")
        _registers(self.clobbered_registers, "clobbered_registers")
        overlap = sorted(preserved & clobbered)
        if overlap:
            raise ExternalTailStaticPointerSlotCompositionError(
                "preserved and clobbered registers overlap: "
                + ", ".join(overlap)
            )
        missing = sorted(_REGISTERS - preserved - clobbered)
        if missing:
            raise ExternalTailStaticPointerSlotCompositionError(
                "machine-call ABI omits registers: " + ", ".join(missing)
            )
        seen: set[str] = set()
        for index, module in enumerate(self.imports):
            checked = _module(module, f"imports[{index}]")
            if checked in seen:
                raise ExternalTailStaticPointerSlotCompositionError(
                    f"imports contains duplicate module {checked}"
                )
            seen.add(checked)
        return self


@dataclass(frozen=True)
class ExternalTailStaticPointerSlotStaticAuthorityBinding:
    context_term: str
    original_context_term: str
    original_decoded_authority_term: str
    source_target_id: int
    wrapper_target_id: int
    continuation_target_id: int
    source_rva: int
    callsite_rva: int
    call_instruction_size: int
    wrapper_rva: int
    continuation_rva: int
    route_kind: Literal["direct_import", "iat_indirect"]
    iat_rva: int | None
    slot_rva: int
    slot_target_id: int
    slot_value: int
    site_id: int
    machine_contract_id: int
    imported: ExternalImportIdentity
    original_frame_argument_offset: int
    candidate_frame_argument_offset: int
    stack_argument_offsets: tuple[int, ...]
    stack_result_delta: int
    preserved_registers: tuple[str, ...]
    clobbered_registers: tuple[str, ...]
    source_region_index: int | None = None
    wrapper_region_index: int | None = None
    continuation_region_index: int | None = None
    source_aliases: tuple[tuple[int, int], ...] = ()
    wrapper_aliases: tuple[tuple[int, int], ...] = ()
    continuation_aliases: tuple[tuple[int, int], ...] = ()
    imports: tuple[str, ...] = ()
    namespace: str = (
        "StageA.Generated.ExternalTailStaticPointerSlotStaticAuthority"
    )

    def checked(
        self,
    ) -> "ExternalTailStaticPointerSlotStaticAuthorityBinding":
        ExternalTailStaticPointerSlotCompositionBinding(
            context_term=self.context_term,
            original_context_term=self.original_context_term,
            certificate_term=self.original_decoded_authority_term,
            authority_term=self.original_decoded_authority_term,
            original_decoded_authority_term=(
                self.original_decoded_authority_term
            ),
            source_target_id=self.source_target_id,
            wrapper_target_id=self.wrapper_target_id,
            continuation_target_id=self.continuation_target_id,
            source_rva=self.source_rva,
            callsite_rva=self.callsite_rva,
            call_instruction_size=self.call_instruction_size,
            wrapper_rva=self.wrapper_rva,
            continuation_rva=self.continuation_rva,
            route_kind=self.route_kind,
            iat_rva=self.iat_rva,
            slot_rva=self.slot_rva,
            slot_target_id=self.slot_target_id,
            slot_value=self.slot_value,
            site_id=self.site_id,
            machine_contract_id=self.machine_contract_id,
            imported=self.imported,
            original_frame_argument_offset=(
                self.original_frame_argument_offset
            ),
            candidate_frame_argument_offset=(
                self.candidate_frame_argument_offset
            ),
            stack_argument_offsets=self.stack_argument_offsets,
            stack_result_delta=self.stack_result_delta,
            preserved_registers=self.preserved_registers,
            clobbered_registers=self.clobbered_registers,
            source_region_index=self.source_region_index,
            wrapper_region_index=self.wrapper_region_index,
            continuation_region_index=self.continuation_region_index,
            source_aliases=self.source_aliases,
            wrapper_aliases=self.wrapper_aliases,
            continuation_aliases=self.continuation_aliases,
            imports=self.imports,
            namespace=self.namespace,
        ).checked()
        return self


def _code_aliases(aliases: tuple[tuple[int, int], ...]) -> str:
    return "[" + ", ".join(
        f"{{ rva := {rva}, paddingIndex := {padding_index} }}"
        for rva, padding_index in aliases
    ) + "]"


def _original_code_target(
    *,
    target_id: int,
    region_index: int | None,
    rva: int,
    aliases: tuple[tuple[int, int], ...],
) -> str:
    region = target_id if region_index is None else region_index
    return (
        f"{{ id := {target_id}, regionIndex := {region}, rva := {rva}, "
        f"aliases := {_code_aliases(aliases)} }}"
    )


def external_tail_static_pointer_slot_static_authority_source(
    binding: ExternalTailStaticPointerSlotStaticAuthorityBinding,
) -> str:
    """Render the exact static authority consumed by mixed-original planning.

    This term deliberately stops before runtime execution.  It kernel-checks
    the original PE/context, code-map locations, initially-zero writable slot,
    and canonical code target.  Concrete frame, event, environment, and
    candidate premises remain inputs to the macro composition theorem.
    """

    binding = binding.checked()
    decoded_authority = binding.original_decoded_authority_term
    imports = tuple(dict.fromkeys((
        "StageA.RelationalExternalTailStaticPointerSlotComposition",
        *binding.imports,
    )))
    source_target = _original_code_target(
        target_id=binding.source_target_id,
        region_index=binding.source_region_index,
        rva=binding.source_rva,
        aliases=binding.source_aliases,
    )
    wrapper_target = _original_code_target(
        target_id=binding.wrapper_target_id,
        region_index=binding.wrapper_region_index,
        rva=binding.wrapper_rva,
        aliases=binding.wrapper_aliases,
    )
    continuation_target = _original_code_target(
        target_id=binding.continuation_target_id,
        region_index=binding.continuation_region_index,
        rva=binding.continuation_rva,
        aliases=binding.continuation_aliases,
    )
    route = {
        "direct_import": ".directImport",
        "iat_indirect": ".iatIndirect",
    }[binding.route_kind]
    iat = "none" if binding.iat_rva is None else f"some {binding.iat_rva}"
    source = f"""{chr(10).join(f'import {module}' for module in imports)}

namespace {binding.namespace}

open StageA.Formal StageA.Relational
open StageA.Relational.ExternalTailStaticPointerSlotComposition
open StageA.Relational.InterpreterMixedContext
open StageA.Relational.ReachableStaticPointerSlot

def generatedContext : StaticProofContext := {binding.context_term}

def generatedOriginalContext : OriginalDecodedStaticContext :=
  {binding.original_context_term}

def generatedExpectedSpec : ExternalTailStaticPointerSlotSpec := {{
  sourceTargetId := {binding.source_target_id}
  wrapperTargetId := {binding.wrapper_target_id}
  continuationTargetId := {binding.continuation_target_id}
  sourceRva := {binding.source_rva}
  callsiteRva := {binding.callsite_rva}
  callInstructionSize := {binding.call_instruction_size}
  wrapperRva := {binding.wrapper_rva}
  continuationRva := {binding.continuation_rva}
  routeKind := {route}
  iatRva := {iat}
  slotRva := {binding.slot_rva}
  slotTargetId := {binding.slot_target_id}
  slotValue := {binding.slot_value}
  siteId := {binding.site_id}
  machineContractId := {binding.machine_contract_id}
  imported := {binding.imported.lean()}
  originalFrameArgumentOffset := {binding.original_frame_argument_offset}
  candidateFrameArgumentOffset := {binding.candidate_frame_argument_offset}
  stackArgumentOffsets := {_naturals(binding.stack_argument_offsets, 'stack_argument_offsets')}
  stackResultDelta := {binding.stack_result_delta}
  preservedRegisters := {_registers(binding.preserved_registers, 'preserved_registers')}
  clobberedRegisters := {_registers(binding.clobbered_registers, 'clobbered_registers')}
}}

def generatedStaticPointerSlotCertificate : Certificate := {{
  slotRva := {binding.slot_rva}
  reachableTargetIds := .unknown
  allowedTargetIds := .exact [{binding.slot_target_id}]
  regions := .unknown
  guardedNonzeroEdges := .unknown
  indirectSlotSites := .unknown
  aliases := .unknown
}}

def generatedExactOriginalDecodedAuthority :
    ExactOriginalDecodedAuthority generatedOriginalContext :=
  {decoded_authority}

theorem generatedInitialSlotChecked :
    initialZeroChecked generatedOriginalContext
      generatedStaticPointerSlotCertificate = true := by
  decide +kernel

theorem generatedAllowedTargetsChecked :
    allowedTargetsChecked generatedOriginalContext
      [{binding.slot_target_id}] = true := by
  decide +kernel

theorem generatedCanonicalSlotTarget :
    targetCanonicalWord? generatedOriginalContext
      {binding.slot_target_id} = some {binding.slot_value} := by
  decide +kernel

def generatedLocalSlotEvidence :
    ExactLocalStaticPointerSlotEvidence generatedOriginalContext
      generatedStaticPointerSlotCertificate [{binding.slot_target_id}]
      {binding.slot_target_id} {binding.slot_value} := {{
  authority := generatedExactOriginalDecodedAuthority
  allowedExact := rfl
  targetMember := by decide
  initialZero := generatedInitialSlotChecked
  targetsChecked := generatedAllowedTargetsChecked
  canonicalWord := {binding.slot_value}
  canonical := generatedCanonicalSlotTarget
  canonicalExact := rfl
}}

def generatedStaticContextBridge :
    ExactOriginalStaticContextBridge generatedContext
      generatedOriginalContext := {{
  pe := rfl
  imports := rfl
  relocations := rfl
  machineContracts := rfl
}}

def generatedCodeBinding :
    ExactOriginalSpecCodeBinding generatedOriginalContext
      generatedExpectedSpec := {{
  source := {source_target}
  wrapper := {wrapper_target}
  continuation := {continuation_target}
  sourceFound := by decide +kernel
  wrapperFound := by decide +kernel
  continuationFound := by decide +kernel
  sourceId := rfl
  wrapperId := rfl
  continuationId := rfl
  sourceRva := rfl
  wrapperRva := rfl
  continuationRva := rfl
}}

def generatedStaticAuthority :
    ExternalTailStaticPointerSlotStaticAuthority generatedContext
      generatedOriginalContext generatedStaticPointerSlotCertificate
      generatedExpectedSpec := {{
  staticContext := generatedStaticContextBridge
  codeBinding := generatedCodeBinding
  targetIds := [{binding.slot_target_id}]
  slotEvidence := generatedLocalSlotEvidence
  certificateSlot := rfl
}}

#print axioms generatedExactOriginalDecodedAuthority
#print axioms generatedInitialSlotChecked
#print axioms generatedAllowedTargetsChecked
#print axioms generatedCanonicalSlotTarget
#print axioms generatedCodeBinding
#print axioms generatedStaticAuthority

end {binding.namespace}
"""
    for forbidden in ("sorry", "native_decide", "axiom ", "unsafe "):
        if forbidden in source:
            raise ExternalTailStaticPointerSlotCompositionError(
                f"generated source unexpectedly contains {forbidden.strip()}"
            )
    return source


def external_tail_static_pointer_slot_composition_source(
    binding: ExternalTailStaticPointerSlotCompositionBinding,
) -> str:
    """Render an exact authority alias and its integration API."""

    binding = binding.checked()
    imports = tuple(dict.fromkeys((
        "StageA.RelationalExternalTailStaticPointerSlotComposition",
        *binding.imports,
    )))
    route = {
        "direct_import": ".directImport",
        "iat_indirect": ".iatIndirect",
    }[binding.route_kind]
    iat = "none" if binding.iat_rva is None else f"some {binding.iat_rva}"
    authority_type = {
        "returns": "CheckedExternalTailStaticPointerSlotReturn",
        "terminates": "CheckedExternalTailStaticPointerSlotTermination",
    }[binding.outcome]
    stack_arguments = _naturals(
        binding.stack_argument_offsets, "stack_argument_offsets"
    )
    returning_slot_audit = (
        "#print axioms generatedStaticPointerSlotAllowedAfterExternal"
        if binding.outcome == "returns"
        else ""
    )
    returning_frame_audit = (
        "#print axioms generatedRuntimeCallFrameAfterExternal"
        if binding.outcome == "returns"
        else ""
    )
    integration = (
        """
def generatedOriginalProgram := generatedAuthority.program

def generatedOriginalCarrier := generatedAuthority.originalCarrier

def generatedOriginalSource := generatedAuthority.source

def generatedOriginalBoundary := generatedAuthority.boundary

def generatedOriginalCallEntry := generatedAuthority.callEntry

def generatedRuntimeCallFrame := generatedAuthority.frame

def generatedCandidateSourceState := generatedAuthority.candidateSourceState

def generatedCandidateEntryState := generatedAuthority.candidateEntryState

def generatedCandidateEvent := generatedAuthority.candidateEvent

def generatedExactWorldExecutionMacroPath :=
  generatedAuthority.worldExecutionPath

theorem generatedStaticPointerSlotAllowedAtBoundary :=
  generatedAuthority.slotAllowedAtBoundary

theorem generatedStaticPointerSlotEqualsExpectedAtBoundary :=
  generatedAuthority.slotEqualsExpectedAtBoundary

theorem generatedRuntimeCallFrameAtBoundary :=
  generatedAuthority.frameAtBoundary

theorem generatedTerminationWorldRelated :=
  generatedAuthority.terminationWorldRelated
"""
        if binding.outcome == "terminates"
        else """
def generatedOriginalProgram := generatedAuthority.program

def generatedOriginalCarrier := generatedAuthority.originalCarrier

def generatedOriginalSource := generatedAuthority.source

def generatedOriginalBoundary := generatedAuthority.boundary

def generatedOriginalCallEntry := generatedAuthority.callEntry

def generatedRuntimeCallFrame := generatedAuthority.frame

def generatedCandidateSourceState := generatedAuthority.candidateSourceState

def generatedCandidateEntryState := generatedAuthority.candidateEntryState

def generatedCandidateEvent := generatedAuthority.candidateEvent

def generatedOriginalResult := generatedAuthority.originalResult

def generatedCandidateResult := generatedAuthority.candidateResult

def generatedExternalTailStaticPointerSlotResult :=
  generatedAuthority.result

def generatedExactWorldExecutionMacroPath :=
  generatedAuthority.worldExecutionPath

theorem generatedStaticPointerSlotAllowedAtBoundary :=
  generatedAuthority.slotAllowedAtBoundary

theorem generatedStaticPointerSlotEqualsExpectedAtBoundary :=
  generatedAuthority.slotEqualsExpectedAtBoundary

theorem generatedRuntimeCallFrameAtBoundary :=
  generatedAuthority.frameAtBoundary

theorem generatedStaticPointerSlotAllowedAfterExternal :=
  generatedAuthority.slotAllowedAfterExternal

theorem generatedExternalResultsRelated :=
  generatedAuthority.resultsRelated

theorem generatedRuntimeCallFrameAfterExternal :=
  generatedAuthority.callFrameAfterExternal
"""
    )
    source = f"""{chr(10).join(f'import {module}' for module in imports)}

namespace {binding.namespace}

open StageA.Formal StageA.Relational
open StageA.Relational.ExternalTailStaticPointerSlotComposition
open StageA.Relational.InterpreterMixedContext
open StageA.Relational.ReachableStaticPointerSlot

def generatedContext : StaticProofContext := {binding.context_term}

def generatedOriginalContext : OriginalDecodedStaticContext :=
  {binding.original_context_term}

def generatedStaticPointerSlotCertificate : Certificate :=
  {binding.certificate_term}

def generatedExpectedSpec : ExternalTailStaticPointerSlotSpec := {{
  sourceTargetId := {binding.source_target_id}
  wrapperTargetId := {binding.wrapper_target_id}
  continuationTargetId := {binding.continuation_target_id}
  sourceRva := {binding.source_rva}
  callsiteRva := {binding.callsite_rva}
  callInstructionSize := {binding.call_instruction_size}
  wrapperRva := {binding.wrapper_rva}
  continuationRva := {binding.continuation_rva}
  routeKind := {route}
  iatRva := {iat}
  slotRva := {binding.slot_rva}
  slotTargetId := {binding.slot_target_id}
  slotValue := {binding.slot_value}
  siteId := {binding.site_id}
  machineContractId := {binding.machine_contract_id}
  imported := {binding.imported.lean()}
  originalFrameArgumentOffset := {binding.original_frame_argument_offset}
  candidateFrameArgumentOffset := {binding.candidate_frame_argument_offset}
  stackArgumentOffsets := {stack_arguments}
  stackResultDelta := {binding.stack_result_delta}
  preservedRegisters := {_registers(binding.preserved_registers, 'preserved_registers')}
  clobberedRegisters := {_registers(binding.clobbered_registers, 'clobbered_registers')}
}}

def generatedAuthority : {authority_type} generatedContext
    generatedOriginalContext generatedStaticPointerSlotCertificate
    generatedExpectedSpec :=
  {binding.authority_term}
{integration}
#print axioms generatedAuthority
#print axioms generatedExactWorldExecutionMacroPath
#print axioms generatedStaticPointerSlotAllowedAtBoundary
#print axioms generatedStaticPointerSlotEqualsExpectedAtBoundary
{returning_slot_audit}
{returning_frame_audit}

end {binding.namespace}
"""
    for forbidden in ("sorry", "native_decide", "axiom ", "unsafe "):
        if forbidden in source:
            raise ExternalTailStaticPointerSlotCompositionError(
                f"generated source unexpectedly contains {forbidden.strip()}"
            )
    return source


def write_external_tail_static_pointer_slot_composition(
    output: Path | str,
    binding: ExternalTailStaticPointerSlotCompositionBinding,
) -> Path:
    path = Path(output)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        external_tail_static_pointer_slot_composition_source(binding),
        encoding="utf-8",
    )
    return path


__all__ = [
    "EXTERNAL_TAIL_STATIC_POINTER_SLOT_COMPOSITION_FORMAT",
    "EXTERNAL_TAIL_STATIC_POINTER_SLOT_COMPOSITION_LEAN_FILENAME",
    "ExternalImportIdentity",
    "ExternalTailStaticPointerSlotCompositionBinding",
    "ExternalTailStaticPointerSlotStaticAuthorityBinding",
    "ExternalTailStaticPointerSlotCompositionError",
    "external_tail_static_pointer_slot_composition_source",
    "external_tail_static_pointer_slot_static_authority_source",
    "write_external_tail_static_pointer_slot_composition",
]
