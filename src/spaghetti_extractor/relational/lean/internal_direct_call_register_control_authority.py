"""Plan and emit exact register-control authority for internal direct calls.

The mixed-original register analysis deliberately treats call boundaries as
unknown until a named Lean term proves preservation.  This module is the
small integration layer between that proposal and the operational direct-call
proof.  Python may locate a crossing and serialize exact metadata, but the
only emitted authority is a ``CheckedDirectCallRegisterControlContract`` built
from an already checked ``CheckedDirectCallSummaryProvenance`` term.

One batch may contain many indirect-control uses.  Each unique
``(callsite, register)`` crossing gets its own Lean module so changing one
callee proof does not invalidate unrelated crossings.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Sequence

import capstone
import pefile

from ...errors import StageAInputError
from .internal_direct_call_summary_proposal import (
    DirectCallSummaryRequest,
    InternalDirectCallSummaryProposalPlan,
    construct_internal_direct_call_summary_proposals,
)


REGISTER_CONTROL_AUTHORITY_FORMAT = (
    "stage-a-internal-direct-call-register-control-authority-v1"
)
REGISTER_CONTROL_AUTHORITY_MODULE_PREFIX = (
    "GeneratedRelationalInternalDirectCallRegisterControlAuthority"
)

_QUALIFIED = re.compile(r"[A-Za-z_][A-Za-z0-9_']*(?:\.[A-Za-z_][A-Za-z0-9_']*)*\Z")
_MODULE = re.compile(r"[A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z][A-Za-z0-9_]*)*\Z")
_REGISTERS = frozenset(("eax", "ebx", "ecx", "edx", "esi", "edi", "ebp"))
_U32_LIMIT = 1 << 32


class DirectCallRegisterControlAuthorityError(StageAInputError):
    """Exact register-control authority cannot be planned or serialized."""


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _u32(value: object, context: str) -> int:
    if (
        not isinstance(value, int)
        or isinstance(value, bool)
        or not 0 <= value < _U32_LIMIT
    ):
        raise DirectCallRegisterControlAuthorityError(
            f"{context} must be an unsigned 32-bit integer"
        )
    return value


def _qualified(value: str, context: str) -> str:
    if not isinstance(value, str) or _QUALIFIED.fullmatch(value) is None:
        raise DirectCallRegisterControlAuthorityError(
            f"{context} must be a qualified Lean identifier"
        )
    return value


def _module(value: str, context: str) -> str:
    if not isinstance(value, str) or _MODULE.fullmatch(value) is None:
        raise DirectCallRegisterControlAuthorityError(
            f"{context} must be a Lean module name"
        )
    return value


def _register(value: object, context: str) -> str:
    if not isinstance(value, str) or value not in _REGISTERS:
        raise DirectCallRegisterControlAuthorityError(
            f"{context} is not a supported IA-32 register"
        )
    return value


def _mapping(value: object, context: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise DirectCallRegisterControlAuthorityError(
            f"{context} must be a JSON object"
        )
    return value


def _rows(value: object, context: str) -> list[Any]:
    if not isinstance(value, list):
        raise DirectCallRegisterControlAuthorityError(
            f"{context} must be a JSON array"
        )
    return value


def _load_machine_import_report(
    path: Path, *, original_pe_sha256: str, state_machine_sha256: str
) -> Mapping[str, Any]:
    try:
        report = _mapping(
            json.loads(path.read_text(encoding="utf-8")), "machine-import report"
        )
    except (OSError, json.JSONDecodeError) as error:
        raise DirectCallRegisterControlAuthorityError(
            f"cannot read machine-import report {path}: {error}"
        ) from error
    if report.get("format") != "stage-a-static-machine-import-contracts-v1":
        raise DirectCallRegisterControlAuthorityError(
            "machine-import report has an unsupported format"
        )
    inputs = _mapping(report.get("inputs"), "machine-import report inputs")
    if inputs.get("original_sha256") != original_pe_sha256:
        raise DirectCallRegisterControlAuthorityError(
            "machine-import report original PE hash does not match"
        )
    if inputs.get("state_machine_sha256") != state_machine_sha256:
        raise DirectCallRegisterControlAuthorityError(
            "machine-import report state-machine hash does not match"
        )
    if report.get("exact_inventory_matches") is not True:
        raise DirectCallRegisterControlAuthorityError(
            "machine-import report does not certify an exact import inventory"
        )
    _rows(report.get("signatures"), "machine-import report signatures")
    _rows(report.get("boundaries"), "machine-import report boundaries")
    return report


def _validate_exact_graph_inventory(
    *,
    exact_edges: Sequence[Mapping[str, Any]],
    internal_sites: Sequence[Mapping[str, Any]],
    global_rvas: Mapping[int, int],
    alias_to_canonical: Mapping[int, int],
    state_rows: Mapping[int, "_StateRow"],
    call_contracts: Mapping[int, Mapping[str, Any]],
) -> None:
    if len(set(global_rvas.values())) != len(global_rvas):
        raise DirectCallRegisterControlAuthorityError(
            "canonical target inventory maps multiple IDs to one RVA"
        )
    edge_indexes: set[int] = set()
    call_edges: dict[tuple[int, int], Mapping[str, Any]] = {}
    for index, edge in enumerate(exact_edges):
        edge_index = _u32(edge.get("edge_index"), f"edge[{index}].edge_index")
        source_id = _u32(
            edge.get("source_target_id"), f"edge[{index}].source_target_id"
        )
        target_id = _u32(
            edge.get("target_target_id"), f"edge[{index}].target_target_id"
        )
        if edge_index in edge_indexes:
            raise DirectCallRegisterControlAuthorityError(
                f"duplicate exact edge index {edge_index}"
            )
        edge_indexes.add(edge_index)
        if source_id not in global_rvas or target_id not in global_rvas:
            raise DirectCallRegisterControlAuthorityError(
                f"exact edge {edge_index} names a target outside the canonical inventory"
            )
        if edge.get("kind") == "call_return":
            call_edges[(source_id, target_id)] = edge
            contract_id = edge.get("machine_contract_id")
            if isinstance(contract_id, int) and contract_id not in call_contracts:
                raise DirectCallRegisterControlAuthorityError(
                    f"exact edge {edge_index} names absent call contract {contract_id}"
                )
    seen_sites: set[tuple[int, int]] = set()
    for index, site in enumerate(internal_sites):
        source_id = _u32(
            site.get("source_target_id"),
            f"internal_direct_call_sites[{index}].source_target_id",
        )
        target_id = _u32(
            site.get("continuation_target_id"),
            f"internal_direct_call_sites[{index}].continuation_target_id",
        )
        pair = (source_id, target_id)
        if pair in seen_sites:
            raise DirectCallRegisterControlAuthorityError(
                "duplicate internal direct-call source/continuation inventory"
            )
        seen_sites.add(pair)
        edge = call_edges.get(pair)
        if edge is None:
            raise DirectCallRegisterControlAuthorityError(
                "internal direct-call site has no matching call-return edge"
            )
        if site.get("edge_index") != edge.get("edge_index"):
            raise DirectCallRegisterControlAuthorityError(
                "internal direct-call site edge index disagrees with the exact graph"
            )
        source_rva = _u32(
            site.get("source_rva"), f"internal_direct_call_sites[{index}].source_rva"
        )
        continuation_rva = _u32(
            site.get("continuation_rva"),
            f"internal_direct_call_sites[{index}].continuation_rva",
        )
        canonical_continuation = alias_to_canonical.get(
            continuation_rva, continuation_rva
        )
        if (
            global_rvas.get(source_id) != source_rva
            or global_rvas.get(target_id) != canonical_continuation
        ):
            raise DirectCallRegisterControlAuthorityError(
                "internal direct-call site disagrees with the canonical target inventory"
            )
        if source_rva not in state_rows:
            raise DirectCallRegisterControlAuthorityError(
                "internal direct-call site has no exact state-machine source row"
            )


@dataclass(frozen=True)
class RegisterControlFrontierRequest:
    use_instruction_rva: int

    def checked(self) -> "RegisterControlFrontierRequest":
        _u32(self.use_instruction_rva, "request.use_instruction_rva")
        return self


@dataclass(frozen=True)
class DirectCallSemanticProvenanceBinding:
    """Named semantic provenance for one exact direct call.

    The target inventory is repeated outside the Lean term so stale or
    accidentally selected bindings fail before source generation.  Lean checks
    the same values against the term again.
    """

    callsite_rva: int
    callee_rva: int
    continuation_rva: int
    module: str
    term: str

    def checked(self) -> "DirectCallSemanticProvenanceBinding":
        _u32(self.callsite_rva, "binding.callsite_rva")
        _u32(self.callee_rva, "binding.callee_rva")
        _u32(self.continuation_rva, "binding.continuation_rva")
        _module(self.module, "binding.module")
        _qualified(self.term, "binding.term")
        return self


@dataclass(frozen=True)
class DirectCallCrossing:
    register: str
    callsite_rva: int
    source_rva: int
    continuation_rva: int
    callee_rva: int
    source_target_id: int
    continuation_target_id: int
    callee_target_id: int
    edge_index: int

    def key(self) -> tuple[int, str]:
        return self.callsite_rva, self.register

    def to_json(self) -> dict[str, Any]:
        return {
            "callee_rva": self.callee_rva,
            "callee_target_id": self.callee_target_id,
            "callsite_rva": self.callsite_rva,
            "continuation_rva": self.continuation_rva,
            "continuation_target_id": self.continuation_target_id,
            "edge_index": self.edge_index,
            "register": self.register,
            "source_rva": self.source_rva,
            "source_target_id": self.source_target_id,
        }


@dataclass(frozen=True)
class RegisterControlAuthorityBlocker:
    category: str
    location_rva: int
    detail: str
    next_action: str
    use_instruction_rva: int

    def to_json(self) -> dict[str, Any]:
        return {
            "category": self.category,
            "detail": self.detail,
            "location_rva": self.location_rva,
            "next_action": self.next_action,
            "use_instruction_rva": self.use_instruction_rva,
        }


@dataclass(frozen=True)
class RegisterControlAuthoritySite:
    use_instruction_rva: int
    use_source_rva: int
    use_source_target_id: int
    register: str
    crossing_keys: tuple[tuple[int, str], ...]
    residual_source_class: str

    def to_json(self) -> dict[str, Any]:
        return {
            "crossing_keys": [
                {"callsite_rva": callsite, "register": register}
                for callsite, register in self.crossing_keys
            ],
            "register": self.register,
            "residual_source_class": self.residual_source_class,
            "use_instruction_rva": self.use_instruction_rva,
            "use_source_rva": self.use_source_rva,
            "use_source_target_id": self.use_source_target_id,
        }


@dataclass(frozen=True)
class RegisterControlAuthorityModule:
    crossing: DirectCallCrossing
    contract_id: int
    module: str
    namespace: str
    authority_term: str
    source: str

    def to_json(self) -> dict[str, Any]:
        return {
            "authority_term": {
                "module": self.module,
                "namespace": self.namespace,
                "symbol": self.authority_term.rsplit(".", 1)[-1],
            },
            "contract_id": self.contract_id,
            "crossing": self.crossing.to_json(),
        }


@dataclass(frozen=True)
class DirectCallRegisterControlAuthorityPlan:
    original_pe_sha256: str
    state_machine_sha256: str
    mixed_original_plan_sha256: str
    machine_import_report_sha256: str
    sites: tuple[RegisterControlAuthoritySite, ...]
    crossings: tuple[DirectCallCrossing, ...]
    summaries: tuple[InternalDirectCallSummaryProposalPlan, ...]
    modules: tuple[RegisterControlAuthorityModule, ...]
    blockers: tuple[RegisterControlAuthorityBlocker, ...]

    def to_json(self) -> dict[str, Any]:
        return {
            "authority": {
                "named_lean_terms_only": True,
                "python_status_is_authority": False,
                "report_is_acceptance_authority": False,
            },
            "blockers": [blocker.to_json() for blocker in self.blockers],
            "crossings": [crossing.to_json() for crossing in self.crossings],
            "format": REGISTER_CONTROL_AUTHORITY_FORMAT,
            "inputs": {
                "machine_import_report_sha256": self.machine_import_report_sha256,
                "mixed_original_plan_sha256": self.mixed_original_plan_sha256,
                "original_pe_sha256": self.original_pe_sha256,
                "state_machine_sha256": self.state_machine_sha256,
            },
            "modules": [module.to_json() for module in self.modules],
            "sites": [site.to_json() for site in self.sites],
            "summaries": [summary.to_json() for summary in self.summaries],
        }

    def semantic_input_json(self) -> dict[str, Any]:
        """Return the existing GNU driver semantic-input shape.

        This is an adapter containing names only.  The driver still emits its
        own exact request binding, and Lean type-checks every selected term.
        """

        return {
            "bindings": [
                {
                    "authority_term": module.to_json()["authority_term"],
                    "callsite_rva": module.crossing.callsite_rva,
                }
                for module in self.modules
            ],
            "format": "stage-a-mixed-original-direct-call-semantic-inputs-v1",
        }


@dataclass(frozen=True)
class DirectCallRegisterControlLeanBindings:
    context: str
    source_invariant: str
    semantic_provenance: str
    semantic_provenance_module: str
    context_module: str
    namespace: str

    def checked(self) -> "DirectCallRegisterControlLeanBindings":
        _qualified(self.context, "bindings.context")
        _qualified(self.source_invariant, "bindings.source_invariant")
        _qualified(self.semantic_provenance, "bindings.semantic_provenance")
        _module(
            self.semantic_provenance_module,
            "bindings.semantic_provenance_module",
        )
        _module(self.context_module, "bindings.context_module")
        _module(self.namespace, "bindings.namespace")
        return self


def direct_call_register_control_authority_source(
    crossing: DirectCallCrossing,
    *,
    contract_id: int,
    bindings: DirectCallRegisterControlLeanBindings,
) -> str:
    """Emit one exact, independently cacheable authority module."""

    bindings = bindings.checked()
    contract_id = _u32(contract_id, "contract_id")
    register = _register(crossing.register, "crossing.register")
    pair = f"registerControlPair .{register}"
    source = f"""import StageA.RelationalInternalDirectCallMixedOriginalIntegration
import {bindings.context_module}
import {bindings.semantic_provenance_module}

namespace {bindings.namespace}

open StageA.Formal StageA.Relational
open StageA.Relational.InternalDirectCallComposition
open StageA.Relational.InternalDirectCallMixedOriginalIntegration
open StageA.Relational.RegisterControlProvenance

def generatedContext : StaticProofContext :=
  {bindings.context}

def generatedSemanticProvenance :
    CheckedDirectCallSummaryProvenance generatedContext :=
  {bindings.semantic_provenance}

def generatedRegisterControlEdge : RegionEdge := {{
  edgeIndex := {crossing.edge_index}
  sourceRegion := {crossing.source_target_id}
  targetRegion := {crossing.continuation_target_id}
  kind := .callReturn
  machineContractId := some {contract_id}
}}

def generatedRegisterControlCallContract : CallContract := {{
  contractId := {contract_id}
  preservedRegisters := [{pair}]
  importResults := []
}}

def generatedRequestedRegisters : List Reg := [.{register}]

def generatedSourceInvariant : StateInvariant :=
  {bindings.source_invariant} {crossing.source_target_id}

theorem evalBehaviorPreservesIdentityRegister
    (candidate : Bool) (targets : List CodeTargetPair)
    (state : MachineState) (behavior : SymbolicBehavior)
    (result : RelationalBehavior) (register : Reg)
    (identity : behavior.registers.get register = .inputReg register)
    (evaluated : evalBehavior candidate targets state behavior = some result) :
    (result.nextMachineState state).registers.get register =
      state.registers.get register := by
  cases normalizedEquation :
      normalizeSymbolicBehavior candidate targets behavior with
  | none => simp [evalBehavior, normalizedEquation] at evaluated
  | some normalized =>
    have fields := normalizeSymbolicBehavior_fields candidate targets behavior
      normalized normalizedEquation
    simp [evalBehavior, normalizedEquation] at evaluated
    subst result
    simp [NormalizedSymbolicBehavior.eval, fields.1, identity,
      RelationalBehavior.nextMachineState, Expr.eval]

theorem generatedCallEntryRegistersPreserved :
    CallEntryRegistersPreserved generatedSemanticProvenance
      generatedRequestedRegisters := by
  intro register member world sourceOriginal sourceCandidate entryOriginal
    entryCandidate frame execution
  have requested : register = .{register} := by
    simpa [generatedRequestedRegisters] using member
  subst register
  have originalIdentity :
      execution.originalBehavior.registers.get .{register} = .inputReg .{register} := by
    have decoded := execution.originalDecoded
    have exact :
        (regionBehaviorWithMachineCallContracts generatedContext.originalPe
          generatedContext.originalImports generatedContext.machineImportCallContracts
          generatedSemanticProvenance.tree.certificate.callsite.original).map
            (fun behavior => behavior.registers.get .{register}) =
          some (.inputReg .{register}) := by
      decide +kernel
    rw [decoded] at exact
    exact Option.some.inj exact
  have candidateIdentity :
      execution.candidateBehavior.registers.get .{register} = .inputReg .{register} := by
    have decoded := execution.candidateDecoded
    have exact :
        (regionBehaviorWithMachineCallContracts generatedContext.candidatePe
          generatedContext.candidateImports generatedContext.machineImportCallContracts
          generatedSemanticProvenance.tree.certificate.callsite.candidate).map
            (fun behavior => behavior.registers.get .{register}) =
          some (.inputReg .{register}) := by
      decide +kernel
    rw [decoded] at exact
    exact Option.some.inj exact
  constructor
  · rw [execution.originalEntry]
    exact evalBehaviorPreservesIdentityRegister false
      generatedContext.codeMap.entries.toList sourceOriginal
      execution.originalBehavior execution.originalResult .{register}
      originalIdentity execution.originalEvaluated
  · rw [execution.candidateEntry]
    exact evalBehaviorPreservesIdentityRegister true
      generatedContext.codeMap.entries.toList sourceCandidate
      execution.candidateBehavior execution.candidateResult .{register}
      candidateIdentity execution.candidateEvaluated

def generatedCheckedDirectCallRegisterControlContract :
    CheckedDirectCallRegisterControlContract generatedContext := {{
  provenance := generatedSemanticProvenance
  edge := generatedRegisterControlEdge
  contract := generatedRegisterControlCallContract
  requestedRegisters := generatedRequestedRegisters
  sourceInvariant := generatedSourceInvariant
  sourceInvariantExact := by decide +kernel
  edgeKind := rfl
  edgeSource := by decide +kernel
  edgeTarget := by decide +kernel
  edgeContract := rfl
  noImportResults := rfl
  preservedRegistersExact := rfl
  requestedRegistersUnique := by decide
  requestedRegistersExcludeStackPointer := by decide
  requestedBySummary := by decide +kernel
  callEntryPreserved := generatedCallEntryRegistersPreserved
}}

theorem generatedAuthorityMatchesExactPERequest :
    generatedSemanticProvenance.tree.checked generatedContext.originalPe
        generatedContext.candidatePe generatedContext.originalImports
        generatedContext.candidateImports = true /\
      generatedSemanticProvenance.tree.certificate.callsite.original.start =
        {crossing.source_rva} /\
      generatedSemanticProvenance.tree.certificate.callsite.original.start +
          generatedSemanticProvenance.tree.certificate.callsite.original.size =
        {crossing.continuation_rva} /\
      generatedSemanticProvenance.tree.certificate.calleeEntry.original.start =
        {crossing.callee_rva} /\
      generatedSemanticProvenance.tree.certificate.continuation.original.start =
        {crossing.continuation_rva} /\
      generatedSemanticProvenance.premises.callEntry.sourceTargetId =
        {crossing.source_target_id} /\
      generatedSemanticProvenance.premises.callEntry.calleeTargetId =
        {crossing.callee_target_id} /\
      generatedSemanticProvenance.premises.callEntry.continuationTargetId =
        {crossing.continuation_target_id} /\
      generatedCheckedDirectCallRegisterControlContract.sourceInvariant =
        {bindings.source_invariant} {crossing.source_target_id} /\
      generatedSemanticProvenance.tree.certificate.graphClosed = true /\
      generatedSemanticProvenance.tree.certificate.returns.isEmpty = false := by
  refine And.intro generatedSemanticProvenance.premises.structuralChecked ?_
  decide +kernel

#print axioms generatedCallEntryRegistersPreserved
#print axioms generatedCheckedDirectCallRegisterControlContract
#print axioms generatedAuthorityMatchesExactPERequest

end {bindings.namespace}
"""
    for forbidden in ("sorry", "native_decide", "axiom ", "unsafe "):
        if forbidden in source:
            raise DirectCallRegisterControlAuthorityError(
                f"generated source unexpectedly contains {forbidden.strip()}"
            )
    return source


@dataclass(frozen=True)
class _StateRow:
    rva: int
    end: int
    instructions: tuple[Mapping[str, Any], ...]
    events: tuple[Mapping[str, Any], ...]


def _load_state_rows(path: Path, pe: pefile.PE) -> dict[int, _StateRow]:
    rows: dict[int, _StateRow] = {}
    image_base = int(pe.OPTIONAL_HEADER.ImageBase)
    decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    decoder.detail = True
    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        try:
            payload = json.loads(line)
        except json.JSONDecodeError as error:
            raise DirectCallRegisterControlAuthorityError(
                f"state-machine line {line_number} is invalid JSON: {error}"
            ) from error
        row = _mapping(payload, f"state-machine line {line_number}")
        original = _mapping(row.get("original"), f"line {line_number}.original")
        rva = _u32(original.get("rva_start"), f"line {line_number}.rva_start")
        end = _u32(original.get("rva_end"), f"line {line_number}.rva_end")
        if rva in rows or end <= rva:
            raise DirectCallRegisterControlAuthorityError(
                f"state-machine line {line_number} has a duplicate or empty span"
            )
        instruction_rows = tuple(
            _mapping(value, f"line {line_number}.instructions[{index}]")
            for index, value in enumerate(
                _rows(row.get("instructions"), f"line {line_number}.instructions")
            )
        )
        cursor = rva
        for index, instruction in enumerate(instruction_rows):
            instruction_rva = _u32(
                instruction.get("rva"),
                f"line {line_number}.instructions[{index}].rva",
            )
            size = _u32(
                instruction.get("size"),
                f"line {line_number}.instructions[{index}].size",
            )
            if size == 0 or instruction_rva != cursor:
                raise DirectCallRegisterControlAuthorityError(
                    f"state-machine line {line_number} instruction inventory is not contiguous"
                )
            raw_hex = instruction.get("bytes")
            if not isinstance(raw_hex, str):
                raise DirectCallRegisterControlAuthorityError(
                    f"line {line_number} instruction {index} has no exact bytes"
                )
            try:
                raw = bytes.fromhex(raw_hex)
            except ValueError as error:
                raise DirectCallRegisterControlAuthorityError(
                    f"line {line_number} instruction {index} bytes are invalid"
                ) from error
            exact = bytes(pe.get_data(instruction_rva, size))
            decoded = tuple(decoder.disasm(exact, image_base + instruction_rva))
            if raw != exact or len(decoded) != 1 or decoded[0].size != size:
                raise DirectCallRegisterControlAuthorityError(
                    "state-machine instruction bytes do not match the exact PE at "
                    f"RVA 0x{instruction_rva:x}"
                )
            cursor += size
        if cursor != end:
            raise DirectCallRegisterControlAuthorityError(
                f"state-machine line {line_number} instructions do not cover its span"
            )
        events = tuple(
            _mapping(value, f"line {line_number}.ordered_events[{index}]")
            for index, value in enumerate(row.get("ordered_events", ()))
        )
        rows[rva] = _StateRow(rva, end, instruction_rows, events)
    return rows


def _event_at(row: _StateRow, instruction_rva: int) -> Mapping[str, Any] | None:
    matches = [
        event
        for event in row.events
        if event.get("instruction_rva") == instruction_rva
        and event.get("kind") in {"internal_call", "external_call", "indirect_call"}
    ]
    if len(matches) > 1:
        raise DirectCallRegisterControlAuthorityError(
            f"multiple call events exist at RVA 0x{instruction_rva:x}"
        )
    return matches[0] if matches else None


def _last_register_write_before(
    row: _StateRow, register: str, before_rva: int
) -> tuple[int, str] | None:
    decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    decoder.detail = True
    result: tuple[int, str] | None = None
    for instruction in row.instructions:
        rva = _u32(instruction.get("rva"), "instruction.rva")
        if rva >= before_rva:
            break
        raw = bytes.fromhex(str(instruction.get("bytes", "")))
        decoded = next(iter(decoder.disasm(raw, rva)), None)
        if decoded is None or decoded.size != len(raw):
            raise DirectCallRegisterControlAuthorityError(
                f"unable to replay exact register writes at RVA 0x{rva:x}"
            )
        _reads, writes = decoded.regs_access()
        written = {decoded.reg_name(value).lower() for value in writes}
        if register in written:
            result = (rva, f"{decoded.mnemonic.lower()} {decoded.op_str.lower()}".strip())
    return result


def _register_seed_class(instruction: str) -> str:
    if instruction.startswith("pop "):
        return "stack_restore"
    if "[esp" in instruction or "[ebp" in instruction:
        return "stack_or_frame_load"
    if "ptr [0x" in instruction:
        return "static_memory_load"
    if instruction.startswith("mov ") and ", 0x" in instruction:
        return "immediate_value"
    if instruction.startswith(("mov ", "lea ")):
        return "local_register_expression"
    return "local_register_seed"


def _stable_contract_id(crossing: DirectCallCrossing) -> int:
    key = f"{crossing.callsite_rva:08x}:{crossing.register}".encode("ascii")
    suffix = int.from_bytes(hashlib.sha256(key).digest()[:4], "big")
    return 0x90000000 | (suffix & 0x0FFFFFFF)


def _binding_matches_exact_crossing(
    binding: DirectCallSemanticProvenanceBinding,
    crossing: DirectCallCrossing,
) -> bool:
    return (
        binding.callsite_rva == crossing.callsite_rva
        and binding.callee_rva == crossing.callee_rva
        and binding.continuation_rva == crossing.continuation_rva
    )


def _callee_from_event(event: Mapping[str, Any], context: str) -> int:
    if event.get("kind") != "internal_call":
        raise DirectCallRegisterControlAuthorityError(
            f"{context} is not an internal direct call"
        )
    return _u32(event.get("target_rva"), f"{context}.target_rva")


def _crossings_for_site(
    *,
    use: Mapping[str, Any],
    exact_edges: Sequence[Mapping[str, Any]],
    internal_sites: Sequence[Mapping[str, Any]],
    state_rows: Mapping[int, _StateRow],
    global_rvas: Mapping[int, int],
    call_contracts: Mapping[int, Mapping[str, Any]],
) -> tuple[tuple[DirectCallCrossing, ...], str, list[RegisterControlAuthorityBlocker]]:
    """Recover the exact unknown-call frontier immediately feeding one use.

    This deliberately does not invent whole-memory provenance.  It walks
    identity register transfers and call-return edges only.  A non-call seed,
    writable/stack load, external result, cycle, or ambiguous predecessor is
    returned as a residual source class for the appropriate Stage A layer.
    """

    use_rva = _u32(use.get("instruction_rva"), "use.instruction_rva")
    source_id = _u32(use.get("source_target_id"), "use.source_target_id")
    register = _register(use.get("register"), "use.register")
    incoming: dict[int, list[Mapping[str, Any]]] = {}
    for edge in exact_edges:
        target = edge.get("target_target_id")
        if isinstance(target, int):
            incoming.setdefault(target, []).append(edge)
    site_by_edge = {
        (int(site["source_target_id"]), int(site["continuation_target_id"])): site
        for site in internal_sites
        if isinstance(site.get("source_target_id"), int)
        and isinstance(site.get("continuation_target_id"), int)
    }
    blockers: list[RegisterControlAuthorityBlocker] = []
    found: dict[tuple[int, str], DirectCallCrossing] = {}
    active: set[int] = set()

    def block(category: str, location: int, detail: str, action: str) -> None:
        blockers.append(
            RegisterControlAuthorityBlocker(
                category,
                location,
                detail,
                action,
                use_rva,
            )
        )

    def visit(target_id: int, depth: int) -> str:
        if depth > len(global_rvas):
            block(
                "unranked_register_provenance_cycle",
                global_rvas.get(target_id, use_rva),
                "register provenance exceeded the finite exact graph inventory",
                "supply a checked SCC invariant/ranking",
            )
            return "unranked_cycle"
        if target_id in active:
            block(
                "unranked_register_provenance_cycle",
                global_rvas.get(target_id, use_rva),
                "register provenance revisits a target without a checked ranking",
                "supply a checked SCC invariant/ranking",
            )
            return "unranked_cycle"
        edges = incoming.get(target_id, ())
        if not edges:
            return "root_or_local_seed"
        signatures: set[str] = set()
        active.add(target_id)
        try:
            for edge in edges:
                source_id = _u32(edge.get("source_target_id"), "edge.source_target_id")
                source_rva = global_rvas.get(source_id)
                row = None if source_rva is None else state_rows.get(source_rva)
                kind = edge.get("kind")
                if kind == "direct":
                    if row is not None:
                        writer = _last_register_write_before(
                            row, register, row.end
                        )
                        if writer is not None:
                            signatures.add(_register_seed_class(writer[1]))
                            continue
                    signatures.add(visit(source_id, depth + 1))
                    continue
                if kind != "call_return":
                    signatures.add("unsupported_edge")
                    continue
                contract_id = edge.get("machine_contract_id")
                if isinstance(contract_id, int):
                    contract = call_contracts.get(contract_id)
                    if contract is None:
                        block(
                            "missing_call_contract_inventory",
                            source_rva if source_rva is not None else use_rva,
                            f"call-return edge names absent contract {contract_id}",
                            "regenerate the exact register-control contract inventory",
                        )
                        signatures.add("missing_call_contract")
                        continue
                    if contract.get("return_register") == register:
                        block(
                            "external_return_target_inventory_required",
                            source_rva if source_rva is not None else use_rva,
                            "control target is produced by an external call result",
                            "provide an exact 1:1 external result and finite "
                            "callable-target contract",
                        )
                        signatures.add("external_return_target")
                        continue
                    preserved = contract.get("preserved_registers")
                    if not isinstance(preserved, list) or register not in preserved:
                        block(
                            "call_contract_clobbers_register",
                            source_rva if source_rva is not None else use_rva,
                            f"call contract {contract_id} does not preserve {register}",
                            "recover a post-call source or reject this control path",
                        )
                        signatures.add("clobbered_by_call")
                        continue
                    if row is not None:
                        call_rva = _u32(
                            next(
                                (
                                    event.get("instruction_rva")
                                    for event in reversed(row.events)
                                    if event.get("kind")
                                    in {"internal_call", "external_call", "indirect_call"}
                                ),
                                row.end,
                            ),
                            "call instruction RVA",
                        )
                        writer = _last_register_write_before(row, register, call_rva)
                        if writer is not None:
                            signatures.add(_register_seed_class(writer[1]))
                            continue
                    signatures.add(visit(source_id, depth + 1))
                    continue
                site = site_by_edge.get((source_id, target_id))
                continuation_rva = global_rvas.get(target_id)
                if site is None or source_rva is None or continuation_rva is None:
                    call_event = None
                    if row is not None:
                        call_events = [
                            event
                            for event in row.events
                            if event.get("kind")
                            in {"internal_call", "external_call", "indirect_call"}
                        ]
                        if len(call_events) == 1:
                            call_event = call_events[0]
                    if call_event is not None and call_event.get("kind") != "internal_call":
                        call_rva = _u32(
                            call_event.get("instruction_rva"),
                            "call_event.instruction_rva",
                        )
                        block(
                            "unsupported_external_effect",
                            call_rva,
                            "register provenance crosses an uncontracted external or indirect call",
                            "supply a checked machine-level call contract with exact "
                            "preserved registers",
                        )
                        signatures.add("external_call")
                    else:
                        block(
                            "missing_internal_direct_call_edge",
                            source_rva if source_rva is not None else use_rva,
                            "an uncontracted call-return edge has no unique exact "
                            "internal-call site",
                            "regenerate exact call-event and graph inventories",
                        )
                        signatures.add("missing_call_edge")
                    continue
                callsite_rva = _u32(site.get("callsite_rva"), "site.callsite_rva")
                row = state_rows.get(source_rva)
                event = None if row is None else _event_at(row, callsite_rva)
                if event is None or event.get("kind") != "internal_call":
                    block(
                        "unsupported_external_effect",
                        callsite_rva,
                        "the uncontracted call is not an exact internal direct call",
                        "use a checked machine-level external/callable contract",
                    )
                    signatures.add("external_call")
                    continue
                callee_rva = _callee_from_event(event, "internal call event")
                callee_ids = [
                    target
                    for target, rva in global_rvas.items()
                    if rva == callee_rva
                ]
                if len(callee_ids) != 1:
                    block(
                        "wrong_or_ambiguous_target_inventory",
                        callsite_rva,
                        f"direct-call target RVA 0x{callee_rva:x} has "
                        f"{len(callee_ids)} canonical IDs",
                        "repair the exact code-target inventory",
                    )
                    signatures.add("ambiguous_target")
                    continue
                crossing = DirectCallCrossing(
                    register=register,
                    callsite_rva=callsite_rva,
                    source_rva=source_rva,
                    continuation_rva=continuation_rva,
                    callee_rva=callee_rva,
                    source_target_id=source_id,
                    continuation_target_id=target_id,
                    callee_target_id=callee_ids[0],
                    edge_index=_u32(edge.get("edge_index"), "edge.edge_index"),
                )
                found[crossing.key()] = crossing
                assert row is not None
                writer = _last_register_write_before(row, register, callsite_rva)
                if writer is not None:
                    signatures.add(_register_seed_class(writer[1]))
                else:
                    signatures.add(visit(source_id, depth + 1))
        finally:
            active.remove(target_id)
        if len(signatures) > 1:
            block(
                "ambiguous_register_source",
                global_rvas.get(target_id, use_rva),
                f"predecessors imply incompatible register source classes {sorted(signatures)}",
                "split the cutpoint or provide a bounded finite source disjunction",
            )
            return "ambiguous"
        return next(iter(signatures), "root_or_local_seed")

    residual = visit(source_id, 0)
    return (
        tuple(sorted(found.values(), key=lambda value: value.key())),
        residual,
        blockers,
    )


def plan_direct_call_register_control_authorities(
    *,
    original_pe: Path | str,
    state_machine: Path | str,
    mixed_original_plan: Path | str,
    machine_import_report: Path | str,
    requests: Sequence[RegisterControlFrontierRequest],
    semantic_bindings: Sequence[DirectCallSemanticProvenanceBinding] = (),
    lean_context: str,
    lean_source_invariant: str,
    lean_context_module: str,
) -> DirectCallRegisterControlAuthorityPlan:
    """Plan a batch and emit source only where named semantic evidence exists."""

    pe_path = Path(original_pe)
    state_path = Path(state_machine)
    plan_path = Path(mixed_original_plan)
    report_path = Path(machine_import_report)
    checked_requests = tuple(request.checked() for request in requests)
    if not checked_requests or len({item.use_instruction_rva for item in checked_requests}) != len(
        checked_requests
    ):
        raise DirectCallRegisterControlAuthorityError(
            "requests must be a nonempty unique use-instruction inventory"
        )
    bindings_by_callsite: dict[int, DirectCallSemanticProvenanceBinding] = {}
    for binding in semantic_bindings:
        binding = binding.checked()
        if binding.callsite_rva in bindings_by_callsite:
            raise DirectCallRegisterControlAuthorityError(
                f"duplicate semantic binding for callsite 0x{binding.callsite_rva:x}"
            )
        bindings_by_callsite[binding.callsite_rva] = binding

    payload = _mapping(
        json.loads(plan_path.read_text(encoding="utf-8")), "mixed-original plan"
    )
    if payload.get("format") != "stage-a-interpreter-mixed-original-v1":
        raise DirectCallRegisterControlAuthorityError(
            "mixed-original plan has an unsupported format"
        )
    state_hash = _sha256(state_path)
    if payload.get("state_machine_sha256") != state_hash:
        raise DirectCallRegisterControlAuthorityError(
            "mixed-original plan state-machine hash does not match"
        )
    original_hash = _sha256(pe_path)
    _load_machine_import_report(
        report_path,
        original_pe_sha256=original_hash,
        state_machine_sha256=state_hash,
    )
    proposal = _mapping(
        payload.get("register_control_provenance"),
        "mixed-original register-control provenance",
    )
    exact_graph = _mapping(proposal.get("exact_graph"), "exact_graph")
    exact_edges = [
        _mapping(value, f"exact_graph.edges[{index}]")
        for index, value in enumerate(_rows(exact_graph.get("edges"), "exact_graph.edges"))
    ]
    internal_sites = [
        _mapping(value, f"internal_direct_call_sites[{index}]")
        for index, value in enumerate(
            _rows(
                proposal.get("internal_direct_call_sites"),
                "internal_direct_call_sites",
            )
        )
    ]
    uses = [
        _mapping(value, f"uses[{index}]")
        for index, value in enumerate(_rows(proposal.get("uses"), "uses"))
    ]
    call_contracts: dict[int, Mapping[str, Any]] = {}
    for index, raw in enumerate(
        _rows(proposal.get("call_contract_matches"), "call_contract_matches")
    ):
        value = _mapping(raw, f"call_contract_matches[{index}]")
        contract_id = _u32(
            value.get("contract_id"),
            f"call_contract_matches[{index}].contract_id",
        )
        if contract_id in call_contracts:
            raise DirectCallRegisterControlAuthorityError(
                f"duplicate call contract ID {contract_id}"
            )
        preserved = _rows(
            value.get("preserved_registers"),
            f"call_contract_matches[{index}].preserved_registers",
        )
        if len(set(preserved)) != len(preserved):
            raise DirectCallRegisterControlAuthorityError(
                f"call contract {contract_id} has duplicate preserved registers"
            )
        for register_index, register in enumerate(preserved):
            _register(
                register,
                f"call_contract_matches[{index}].preserved_registers[{register_index}]",
            )
        return_register = value.get("return_register")
        if return_register is not None:
            _register(
                return_register,
                f"call_contract_matches[{index}].return_register",
            )
        call_contracts[contract_id] = value
    recovered_targets = _rows(
        payload.get("recovered_direct_targets"), "recovered_direct_targets"
    )
    alias_to_canonical: dict[int, int] = {}
    for index, raw in enumerate(recovered_targets):
        row = _mapping(raw, f"recovered_direct_targets[{index}]")
        alias = _u32(row.get("alias_rva"), f"recovered_direct_targets[{index}].alias_rva")
        canonical = _u32(
            row.get("canonical_rva"),
            f"recovered_direct_targets[{index}].canonical_rva",
        )
        prior = alias_to_canonical.get(alias)
        if prior is not None and prior != canonical:
            raise DirectCallRegisterControlAuthorityError(
                f"direct-target alias RVA 0x{alias:x} has ambiguous canonical targets"
            )
        alias_to_canonical[alias] = canonical
    global_rvas = {
        _u32(row.get("target_id"), f"mapping[{index}].target_id"): _u32(
            row.get("rva", row.get("source_rva")), f"mapping[{index}].rva"
        )
        for index, row in enumerate(recovered_targets)
        if isinstance(row, Mapping)
        and isinstance(row.get("target_id"), int)
        and isinstance(row.get("rva", row.get("source_rva")), int)
    }
    # Older reports do not repeat target IDs in recovered_direct_targets.  The
    # canonical state-machine inventory is sorted by RVA and is exactly the
    # inventory used by the mixed-original generator.
    pe = pefile.PE(str(pe_path), fast_load=False)
    try:
        state_rows = _load_state_rows(state_path, pe)
    finally:
        pe.close()
    if not global_rvas:
        synthetic_rvas = {
            _u32(cut.get("continuation_rva"), f"terminal_successor_cuts[{index}]")
            for index, cut in enumerate(
                _rows(payload.get("terminal_successor_cuts"), "terminal_successor_cuts")
            )
            if isinstance(cut, Mapping) and cut.get("synthetic_padding") is True
        }
        global_rvas = {
            index: rva
            for index, rva in enumerate(sorted({*state_rows, *synthetic_rvas}))
        }
    _validate_exact_graph_inventory(
        exact_edges=exact_edges,
        internal_sites=internal_sites,
        global_rvas=global_rvas,
        alias_to_canonical=alias_to_canonical,
        state_rows=state_rows,
        call_contracts=call_contracts,
    )

    blockers: list[RegisterControlAuthorityBlocker] = []
    sites: list[RegisterControlAuthoritySite] = []
    crossings: dict[tuple[int, str], DirectCallCrossing] = {}
    uses_by_instruction: dict[int, list[Mapping[str, Any]]] = {}
    for use in uses:
        value = use.get("instruction_rva")
        if isinstance(value, int):
            uses_by_instruction.setdefault(value, []).append(use)
    for request in checked_requests:
        matches = uses_by_instruction.get(request.use_instruction_rva, ())
        if len(matches) != 1:
            blockers.append(RegisterControlAuthorityBlocker(
                "missing_or_ambiguous_register_use",
                request.use_instruction_rva,
                f"expected one register-control use, found {len(matches)}",
                "regenerate the exact register-control proposal",
                request.use_instruction_rva,
            ))
            continue
        use = matches[0]
        use_source_id = _u32(use.get("source_target_id"), "use.source_target_id")
        use_source_rva = _u32(use.get("source_rva"), "use.source_rva")
        if global_rvas.get(use_source_id) != use_source_rva:
            raise DirectCallRegisterControlAuthorityError(
                "register-control use disagrees with the canonical target inventory at "
                f"RVA 0x{request.use_instruction_rva:x}"
            )
        row = state_rows.get(use_source_rva)
        if row is None or not any(
            instruction.get("rva") == request.use_instruction_rva
            for instruction in row.instructions
        ):
            raise DirectCallRegisterControlAuthorityError(
                "register-control use does not name an exact instruction in its source row at "
                f"RVA 0x{request.use_instruction_rva:x}"
            )
        recovered, residual, site_blockers = _crossings_for_site(
            use=use,
            exact_edges=exact_edges,
            internal_sites=internal_sites,
            state_rows=state_rows,
            global_rvas=global_rvas,
            call_contracts=call_contracts,
        )
        blockers.extend(site_blockers)
        for crossing in recovered:
            prior = crossings.get(crossing.key())
            if prior is not None and prior != crossing:
                blockers.append(RegisterControlAuthorityBlocker(
                    "ambiguous_direct_call_crossing",
                    crossing.callsite_rva,
                    "one callsite/register pair has inconsistent exact metadata",
                    "repair the canonical graph inventory",
                    request.use_instruction_rva,
                ))
            else:
                crossings[crossing.key()] = crossing
        sites.append(RegisterControlAuthoritySite(
            use_instruction_rva=request.use_instruction_rva,
            use_source_rva=use_source_rva,
            use_source_target_id=use_source_id,
            register=_register(use.get("register"), "use.register"),
            crossing_keys=tuple(item.key() for item in recovered),
            residual_source_class=residual,
        ))

    summary_plans: list[InternalDirectCallSummaryProposalPlan] = []
    summary_by_crossing: dict[tuple[int, str], InternalDirectCallSummaryProposalPlan] = {}
    for crossing in sorted(crossings.values(), key=lambda item: item.key()):
        summary = construct_internal_direct_call_summary_proposals(
            pe_path,
            state_path,
            report_path,
            [DirectCallSummaryRequest(
                crossing.callsite_rva,
                (crossing.register,),
                crossing.source_rva,
            )],
        )
        summary_plans.append(summary)
        summary_by_crossing[crossing.key()] = summary
        for summary_blocker in summary.blockers:
            blockers.append(RegisterControlAuthorityBlocker(
                summary_blocker.category,
                summary_blocker.location_rva,
                summary_blocker.detail,
                summary_blocker.next_action,
                next(
                    (
                        site.use_instruction_rva
                        for site in sites
                        if crossing.key() in site.crossing_keys
                    ),
                    crossing.callsite_rva,
                ),
            ))

    modules: list[RegisterControlAuthorityModule] = []
    used_contract_ids: dict[int, tuple[int, str]] = {}
    for crossing in sorted(crossings.values(), key=lambda item: item.key()):
        binding = bindings_by_callsite.get(crossing.callsite_rva)
        summary = summary_by_crossing[crossing.key()]
        if binding is None:
            blockers.append(RegisterControlAuthorityBlocker(
                "semantic_direct_call_provenance_missing",
                crossing.callsite_rva,
                "the exact crossing has no named CheckedDirectCallSummaryProvenance term",
                "complete the operational finite-call/external macro-step proof "
                "and provide its Lean term",
                next(
                    (
                        site.use_instruction_rva
                        for site in sites
                        if crossing.key() in site.crossing_keys
                    ),
                    crossing.callsite_rva,
                ),
            ))
            continue
        if not _binding_matches_exact_crossing(binding, crossing):
            blockers.append(RegisterControlAuthorityBlocker(
                "wrong_target_inventory",
                crossing.callsite_rva,
                "semantic provenance target inventory does not match the exact call event",
                "select the provenance term for the exact callee and continuation",
                crossing.callsite_rva,
            ))
            continue
        # If the standalone summary succeeded, it must describe the same target
        # inventory.  A failed standalone summary does not override a stronger
        # named operational provenance term, but its blockers remain visible.
        if summary.proposals:
            proposal_row = summary.proposals[0].tree.certificate
            if (
                proposal_row.callee_entry.original.start != crossing.callee_rva
                or proposal_row.continuation.original.start
                != crossing.continuation_rva
            ):
                blockers.append(RegisterControlAuthorityBlocker(
                    "wrong_target_inventory",
                    crossing.callsite_rva,
                    "standalone summary target inventory disagrees with the exact call event",
                    "regenerate the direct-call summary proposal",
                    crossing.callsite_rva,
                ))
                continue
        contract_id = _stable_contract_id(crossing)
        prior_key = used_contract_ids.get(contract_id)
        if prior_key is not None and prior_key != crossing.key():
            raise DirectCallRegisterControlAuthorityError(
                "stable generated call-contract ID collision between "
                f"{prior_key!r} and {crossing.key()!r}"
            )
        used_contract_ids[contract_id] = crossing.key()
        module_name = (
            f"{REGISTER_CONTROL_AUTHORITY_MODULE_PREFIX}"
            f"{crossing.callsite_rva:08X}{crossing.register.upper()}"
        )
        module = f"StageA.{module_name}"
        namespace = f"StageA.Generated.{module_name}"
        source = direct_call_register_control_authority_source(
            crossing,
            contract_id=contract_id,
            bindings=DirectCallRegisterControlLeanBindings(
                context=lean_context,
                source_invariant=lean_source_invariant,
                semantic_provenance=binding.term,
                semantic_provenance_module=binding.module,
                context_module=lean_context_module,
                namespace=namespace,
            ),
        )
        modules.append(RegisterControlAuthorityModule(
            crossing=crossing,
            contract_id=contract_id,
            module=module,
            namespace=namespace,
            authority_term=(
                f"{namespace}.generatedCheckedDirectCallRegisterControlContract"
            ),
            source=source,
        ))

    for callsite_rva in sorted(set(bindings_by_callsite) - {
        crossing.callsite_rva for crossing in crossings.values()
    }):
        blockers.append(RegisterControlAuthorityBlocker(
            "wrong_target_inventory",
            callsite_rva,
            "semantic provenance binding does not correspond to a recovered crossing",
            "select a binding for an exact internal call crossed by a requested register use",
            callsite_rva,
        ))

    blockers.sort(key=lambda item: (
        item.use_instruction_rva,
        item.location_rva,
        item.category,
        item.detail,
    ))
    return DirectCallRegisterControlAuthorityPlan(
        original_pe_sha256=original_hash,
        state_machine_sha256=state_hash,
        mixed_original_plan_sha256=_sha256(plan_path),
        machine_import_report_sha256=_sha256(report_path),
        sites=tuple(sorted(sites, key=lambda item: item.use_instruction_rva)),
        crossings=tuple(sorted(crossings.values(), key=lambda item: item.key())),
        summaries=tuple(summary_plans),
        modules=tuple(modules),
        blockers=tuple(blockers),
    )


def write_direct_call_register_control_authority_bundle(
    plan: DirectCallRegisterControlAuthorityPlan,
    out: Path | str,
) -> tuple[Path, ...]:
    output = Path(out)
    stage_a = output / "StageA"
    stage_a.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []
    for module in plan.modules:
        filename = module.module.removeprefix("StageA.") + ".lean"
        destination = stage_a / filename
        destination.write_text(module.source, encoding="utf-8")
        written.append(destination)
    (output / "register-control-authority-plan.json").write_text(
        json.dumps(plan.to_json(), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    (output / "direct-call-semantic-inputs.json").write_text(
        json.dumps(plan.semantic_input_json(), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return tuple(written)


__all__ = [
    "REGISTER_CONTROL_AUTHORITY_FORMAT",
    "REGISTER_CONTROL_AUTHORITY_MODULE_PREFIX",
    "DirectCallCrossing",
    "DirectCallRegisterControlAuthorityError",
    "DirectCallRegisterControlAuthorityPlan",
    "DirectCallRegisterControlLeanBindings",
    "DirectCallSemanticProvenanceBinding",
    "RegisterControlAuthorityBlocker",
    "RegisterControlAuthorityModule",
    "RegisterControlAuthoritySite",
    "RegisterControlFrontierRequest",
    "direct_call_register_control_authority_source",
    "plan_direct_call_register_control_authorities",
    "write_direct_call_register_control_authority_bundle",
]
