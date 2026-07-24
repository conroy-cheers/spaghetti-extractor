"""Bind semantic direct-call authority to one mixed-original call-return edge.

The generated module never constructs semantic premises from JSON.  It aliases
an already named ``CheckedDirectCallRegisterControlContract`` term and asks Lean
to check that term against the exact edge and request selected by the Python
planner.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from ...errors import StageAInputError


INTERNAL_DIRECT_CALL_MIXED_ORIGINAL_INTEGRATION_FORMAT = (
    "stage-a-internal-direct-call-mixed-original-integration-v1"
)
INTERNAL_DIRECT_CALL_MIXED_ORIGINAL_INTEGRATION_MODULE_PREFIX = (
    "GeneratedRelationalInternalDirectCallMixedOriginalIntegration"
)

_QUALIFIED = re.compile(r"[A-Za-z_][A-Za-z0-9_']*(?:\.[A-Za-z_][A-Za-z0-9_']*)*\Z")
_MODULE = re.compile(r"[A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z][A-Za-z0-9_]*)*\Z")
_REGISTERS = frozenset(("eax", "ebx", "ecx", "edx", "esi", "edi", "ebp"))


class InternalDirectCallMixedOriginalIntegrationError(StageAInputError):
    """A semantic authority binding is malformed or ambiguous."""


def _qualified(value: str, context: str) -> str:
    if not isinstance(value, str) or _QUALIFIED.fullmatch(value) is None:
        raise InternalDirectCallMixedOriginalIntegrationError(
            f"{context} must be a qualified Lean identifier"
        )
    return value


def _module(value: str, context: str) -> str:
    if not isinstance(value, str) or _MODULE.fullmatch(value) is None:
        raise InternalDirectCallMixedOriginalIntegrationError(
            f"{context} must be a Lean module name"
        )
    return value


def _u32(value: int, context: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value < 2**32:
        raise InternalDirectCallMixedOriginalIntegrationError(
            f"{context} must be an unsigned 32-bit integer"
        )
    return value


@dataclass(frozen=True)
class DirectCallMixedOriginalAuthorityBinding:
    context: str
    authority_term: str
    source_target_id: int
    continuation_target_id: int
    edge_index: int
    contract_id: int
    source_rva: int
    callsite_rva: int
    continuation_rva: int
    registers: tuple[str, ...]
    imports: tuple[str, ...]
    namespace: str

    def checked(self) -> "DirectCallMixedOriginalAuthorityBinding":
        _qualified(self.context, "context")
        _qualified(self.authority_term, "authority_term")
        _module(self.namespace, "namespace")
        for field_name in (
            "source_target_id",
            "continuation_target_id",
            "edge_index",
            "contract_id",
            "source_rva",
            "callsite_rva",
            "continuation_rva",
        ):
            _u32(getattr(self, field_name), field_name)
        if not self.registers or len(set(self.registers)) != len(self.registers):
            raise InternalDirectCallMixedOriginalIntegrationError(
                "registers must be a nonempty unique list"
            )
        if any(register not in _REGISTERS for register in self.registers):
            raise InternalDirectCallMixedOriginalIntegrationError(
                "registers contains an unsupported mixed-original register"
            )
        seen: set[str] = set()
        for index, module in enumerate(self.imports):
            checked = _module(module, f"imports[{index}]")
            if checked in seen:
                raise InternalDirectCallMixedOriginalIntegrationError(
                    f"imports contains duplicate module {checked}"
                )
            seen.add(checked)
        return self


@dataclass(frozen=True)
class DirectCallMixedOriginalFiniteEvidenceBinding:
    """Bind one complete Lean operational package to exact request metadata.

    ``evidence_term`` must already inhabit
    ``CheckedDirectCallFiniteEvidence``.  Python cannot construct the semantic
    fields of that structure; this emitter only selects the term and asks Lean
    to check that its exact decoded spans, graph edge, frame argument, and
    static slot are the requested ones.
    """

    context: str
    evidence_term: str
    source_target_id: int
    callee_target_id: int
    continuation_target_id: int
    edge_index: int
    contract_id: int
    source_rva: int
    callsite_rva: int
    call_instruction_size: int
    callee_rva: int
    continuation_rva: int
    argument_original_offset: int
    argument_candidate_offset: int
    argument_code_target_id: int
    static_slot_original_address: int
    static_slot_candidate_address: int
    static_slot_code_target_id: int
    registers: tuple[str, ...]
    imports: tuple[str, ...]
    namespace: str

    def checked(self) -> "DirectCallMixedOriginalFiniteEvidenceBinding":
        _qualified(self.context, "context")
        _qualified(self.evidence_term, "evidence_term")
        _module(self.namespace, "namespace")
        for field_name in (
            "source_target_id",
            "callee_target_id",
            "continuation_target_id",
            "edge_index",
            "contract_id",
            "source_rva",
            "callsite_rva",
            "call_instruction_size",
            "callee_rva",
            "continuation_rva",
            "argument_original_offset",
            "argument_candidate_offset",
            "argument_code_target_id",
            "static_slot_original_address",
            "static_slot_candidate_address",
            "static_slot_code_target_id",
        ):
            _u32(getattr(self, field_name), field_name)
        if self.call_instruction_size == 0:
            raise InternalDirectCallMixedOriginalIntegrationError(
                "call_instruction_size must be positive"
            )
        if self.argument_code_target_id != self.static_slot_code_target_id:
            raise InternalDirectCallMixedOriginalIntegrationError(
                "frame argument and static slot must name the same code target"
            )
        if not self.registers or len(set(self.registers)) != len(self.registers):
            raise InternalDirectCallMixedOriginalIntegrationError(
                "registers must be a nonempty unique list"
            )
        if any(register not in _REGISTERS for register in self.registers):
            raise InternalDirectCallMixedOriginalIntegrationError(
                "registers contains an unsupported mixed-original register"
            )
        seen: set[str] = set()
        for index, module in enumerate(self.imports):
            checked = _module(module, f"imports[{index}]")
            if checked in seen:
                raise InternalDirectCallMixedOriginalIntegrationError(
                    f"imports contains duplicate module {checked}"
                )
            seen.add(checked)
        return self


def direct_call_mixed_original_finite_evidence_source(
    binding: DirectCallMixedOriginalFiniteEvidenceBinding,
) -> str:
    """Expose all checked operational terms from one non-vacuous package."""

    binding = binding.checked()
    imports = [
        "StageA.RelationalInternalDirectCallMixedOriginalIntegration",
        *binding.imports,
    ]
    register_rows = ", ".join(f".{register}" for register in binding.registers)
    source = f"""{chr(10).join(f"import {module}" for module in dict.fromkeys(imports))}

namespace {binding.namespace}

open StageA.Formal StageA.Relational
open StageA.Relational.InternalDirectCallComposition
open StageA.Relational.InternalDirectCallMixedOriginalIntegration

def generatedContext : StaticProofContext := {binding.context}

def generatedCheckedDirectCallFiniteEvidence :
    CheckedDirectCallFiniteEvidence generatedContext :=
  {binding.evidence_term}

def generatedCheckedDirectCallRegisterControlContract :
    CheckedDirectCallRegisterControlContract generatedContext :=
  generatedCheckedDirectCallFiniteEvidence.authority

def generatedIntegratedSummaryPremises :=
  generatedCheckedDirectCallRegisterControlContract.provenance.premises

def generatedExactDirectCallEntry :=
  generatedCheckedDirectCallFiniteEvidence.entry

def generatedOperationalCallReturnCompleteness :=
  generatedCheckedDirectCallFiniteEvidence.operational

def generatedCheckedFiniteCallRegionExecutionForSource
    (source : RelatedDirectCallSource generatedContext
      generatedCheckedDirectCallRegisterControlContract.provenance.tree
      generatedExactDirectCallEntry) :=
  generatedCheckedDirectCallFiniteEvidence.executionForSource source

noncomputable def generatedFiniteReturningExecutionForSource
    (source : RelatedDirectCallSource generatedContext
      generatedCheckedDirectCallRegisterControlContract.provenance.tree
      generatedExactDirectCallEntry) :=
  generatedCheckedDirectCallFiniteEvidence.finiteReturningExecutionForSource source

def generatedRuntimeFrameArgumentWord :=
  generatedCheckedDirectCallFiniteEvidence.argumentWord

def generatedStaticWordRelationSlot :=
  generatedCheckedDirectCallFiniteEvidence.staticSlot

def generatedRuntimeFrameArgumentStaticWrite
    (actual : ActualDirectCallReturnExecution generatedContext
      generatedCheckedDirectCallRegisterControlContract.provenance.tree
      generatedExactDirectCallEntry
      generatedOperationalCallReturnCompleteness.originalProgram
      generatedOperationalCallReturnCompleteness.candidateProgram) :=
  generatedCheckedDirectCallFiniteEvidence.staticWrite actual

theorem generatedArgumentToStaticSlot
    (actual : ActualDirectCallReturnExecution generatedContext
      generatedCheckedDirectCallRegisterControlContract.provenance.tree
      generatedExactDirectCallEntry
      generatedOperationalCallReturnCompleteness.originalProgram
      generatedOperationalCallReturnCompleteness.candidateProgram) :=
  generatedCheckedDirectCallFiniteEvidence.argumentToStaticSlot actual

theorem generatedFiniteEvidenceMatchesExactRequest :
    generatedCheckedDirectCallRegisterControlContract.edge.edgeIndex =
        {binding.edge_index} /\
      generatedCheckedDirectCallRegisterControlContract.edge.sourceRegion =
        {binding.source_target_id} /\
      generatedCheckedDirectCallRegisterControlContract.edge.targetRegion =
        {binding.continuation_target_id} /\
      generatedCheckedDirectCallRegisterControlContract.edge.kind = .callReturn /\
      generatedCheckedDirectCallRegisterControlContract.edge.machineContractId =
        some {binding.contract_id} /\
      generatedCheckedDirectCallRegisterControlContract.contract.contractId =
        {binding.contract_id} /\
      generatedCheckedDirectCallRegisterControlContract.requestedRegisters =
        [{register_rows}] /\
      generatedIntegratedSummaryPremises.callEntry.sourceTargetId =
        {binding.source_target_id} /\
      generatedIntegratedSummaryPremises.callEntry.calleeTargetId =
        {binding.callee_target_id} /\
      generatedIntegratedSummaryPremises.callEntry.continuationTargetId =
        {binding.continuation_target_id} /\
      generatedCheckedDirectCallRegisterControlContract.provenance.tree.certificate.callsite.original.start =
        {binding.source_rva} /\
      generatedCheckedDirectCallRegisterControlContract.provenance.tree.certificate.callsite.original.start +
          generatedCheckedDirectCallRegisterControlContract.provenance.tree.certificate.callsite.original.size =
        {binding.callsite_rva + binding.call_instruction_size} /\
      generatedCheckedDirectCallRegisterControlContract.provenance.tree.certificate.calleeEntry.original.start =
        {binding.callee_rva} /\
      generatedCheckedDirectCallRegisterControlContract.provenance.tree.certificate.continuation.original.start =
        {binding.continuation_rva} /\
      generatedRuntimeFrameArgumentWord.originalOffset =
        {binding.argument_original_offset} /\
      generatedRuntimeFrameArgumentWord.candidateOffset =
        {binding.argument_candidate_offset} /\
      generatedRuntimeFrameArgumentWord.relation =
        .fixedCodePointer {binding.argument_code_target_id} /\
      generatedStaticWordRelationSlot.originalAddress =
        {binding.static_slot_original_address} /\
      generatedStaticWordRelationSlot.candidateAddress =
        {binding.static_slot_candidate_address} /\
      generatedStaticWordRelationSlot.relation =
        .fixedCodePointer {binding.static_slot_code_target_id} := by
  decide +kernel

#print axioms generatedCheckedDirectCallFiniteEvidence
#print axioms generatedCheckedDirectCallRegisterControlContract
#print axioms generatedIntegratedSummaryPremises
#print axioms generatedOperationalCallReturnCompleteness
#print axioms generatedFiniteReturningExecutionForSource
#print axioms generatedRuntimeFrameArgumentStaticWrite
#print axioms generatedArgumentToStaticSlot
#print axioms generatedFiniteEvidenceMatchesExactRequest

end {binding.namespace}
"""
    for forbidden in ("sorry", "native_decide", "axiom ", "unsafe "):
        if forbidden in source:
            raise InternalDirectCallMixedOriginalIntegrationError(
                f"generated source unexpectedly contains {forbidden.strip()}"
            )
    return source


def direct_call_mixed_original_integration_source(
    binding: DirectCallMixedOriginalAuthorityBinding,
) -> str:
    """Emit an exact term alias and closed metadata equalities checked by Lean."""

    binding = binding.checked()
    imports = [
        "StageA.RelationalInternalDirectCallMixedOriginalIntegration",
        *binding.imports,
    ]
    register_rows = ", ".join(f".{register}" for register in binding.registers)
    source = f"""{chr(10).join(f"import {module}" for module in dict.fromkeys(imports))}

namespace {binding.namespace}

open StageA.Formal StageA.Relational
open StageA.Relational.InternalDirectCallMixedOriginalIntegration

def generatedContext : StaticProofContext := {binding.context}

def generatedCheckedDirectCallRegisterControlContract :
    CheckedDirectCallRegisterControlContract generatedContext :=
  {binding.authority_term}

theorem generatedAuthorityMatchesExactRequest :
    generatedCheckedDirectCallRegisterControlContract.edge.edgeIndex =
        {binding.edge_index} /\
      generatedCheckedDirectCallRegisterControlContract.edge.sourceRegion =
        {binding.source_target_id} /\
      generatedCheckedDirectCallRegisterControlContract.edge.targetRegion =
        {binding.continuation_target_id} /\
      generatedCheckedDirectCallRegisterControlContract.edge.kind = .callReturn /\
      generatedCheckedDirectCallRegisterControlContract.edge.machineContractId =
        some {binding.contract_id} /\
      generatedCheckedDirectCallRegisterControlContract.contract.contractId =
        {binding.contract_id} /\
      generatedCheckedDirectCallRegisterControlContract.requestedRegisters =
        [{register_rows}] /\
      generatedCheckedDirectCallRegisterControlContract.provenance.tree.certificate.callsite.original.start =
        {binding.source_rva} /\
      generatedCheckedDirectCallRegisterControlContract.provenance.tree.certificate.continuation.original.start =
        {binding.continuation_rva} := by
  decide +kernel

#print axioms generatedCheckedDirectCallRegisterControlContract
#print axioms generatedAuthorityMatchesExactRequest

end {binding.namespace}
"""
    for forbidden in ("sorry", "native_decide", "axiom ", "unsafe "):
        if forbidden in source:
            raise InternalDirectCallMixedOriginalIntegrationError(
                f"generated source unexpectedly contains {forbidden.strip()}"
            )
    return source


__all__ = [
    "INTERNAL_DIRECT_CALL_MIXED_ORIGINAL_INTEGRATION_FORMAT",
    "INTERNAL_DIRECT_CALL_MIXED_ORIGINAL_INTEGRATION_MODULE_PREFIX",
    "DirectCallMixedOriginalAuthorityBinding",
    "DirectCallMixedOriginalFiniteEvidenceBinding",
    "InternalDirectCallMixedOriginalIntegrationError",
    "direct_call_mixed_original_finite_evidence_source",
    "direct_call_mixed_original_integration_source",
]
