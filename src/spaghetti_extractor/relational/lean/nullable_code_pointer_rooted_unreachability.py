"""Emit checked scanner-execution and rooted-SCC certificates.

The generator serializes names and finite graph rows only. Lean rechecks the
decoded-original binding, roots, exact root path, maximal source SCC, and
complete SCC incoming-edge inventory. It also replays the exact constructor
scanner blocks and proves that the only outside SCC edge is disabled.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from ...errors import StageAInputError
from .scanner import OriginalScannerExecutionProposal


NULLABLE_CODE_POINTER_ROOTED_UNREACHABILITY_FORMAT = (
    "stage-a-relational-nullable-code-pointer-rooted-scc-v4"
)
NULLABLE_CODE_POINTER_ROOTED_UNREACHABILITY_LEAN_FILENAME = (
    "GeneratedRelationalNullableCodePointerRootedUnreachability.lean"
)

_IDENTIFIER = re.compile(r"[A-Za-z_][A-Za-z0-9_']*\Z")
_QUALIFIED = re.compile(
    r"[A-Za-z_][A-Za-z0-9_']*(?:\.[A-Za-z_][A-Za-z0-9_']*)*\Z"
)


class NullableCodePointerRootedUnreachabilityGenerationError(StageAInputError):
    """A rooted-unreachability proposal cannot be represented in Lean."""


def _natural(value: int, field: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise NullableCodePointerRootedUnreachabilityGenerationError(
            f"{field} must be a natural number"
        )
    return value


def _name(value: str, field: str, *, identifier: bool = False) -> str:
    pattern = _IDENTIFIER if identifier else _QUALIFIED
    if not isinstance(value, str) or pattern.fullmatch(value) is None:
        raise NullableCodePointerRootedUnreachabilityGenerationError(
            f"{field} is not a valid Lean name"
        )
    return value


def _nat_list(values: tuple[int, ...], field: str) -> str:
    return "[" + ", ".join(str(_natural(value, field)) for value in values) + "]"


@dataclass(frozen=True)
class OriginalIncomingEdgeProposal:
    source_target_id: int
    target_target_id: int

    def lean(self) -> str:
        source = _natural(self.source_target_id, "incoming-edge source target id")
        target = _natural(self.target_target_id, "incoming-edge target target id")
        return (
            "{ sourceTargetId := "
            f"{source}, targetTargetId := {target} }}"
        )


@dataclass(frozen=True)
class NullableCodePointerRootedUnreachabilitySpec:
    definition_name: str
    original_context_name: str
    empty_indexed_authority_name: str
    root_target_ids: tuple[int, ...]
    root_path_target_ids: tuple[int, ...]
    forward_target_ids: tuple[int, ...]
    scc_target_ids: tuple[int, ...]
    incoming_edges: tuple[OriginalIncomingEdgeProposal, ...]
    scanner_execution: OriginalScannerExecutionProposal
    namespace: str = (
        "StageA.Generated.RelationalNullableCodePointerRootedUnreachability"
    )
    imports: tuple[str, ...] = ()

    def validate(self) -> None:
        _name(self.definition_name, "definition name", identifier=True)
        _name(self.namespace, "namespace")
        for field, value in (
            ("original context name", self.original_context_name),
            (
                "empty indexed authority name",
                self.empty_indexed_authority_name,
            ),
        ):
            _name(value, field)
        for module in self.imports:
            _name(module, "import module")
        for target_id in self.root_target_ids:
            _natural(target_id, "root target id")
        for target_id in self.root_path_target_ids:
            _natural(target_id, "root path target id")
        for target_id in self.forward_target_ids:
            _natural(target_id, "forward target id")
        for target_id in self.scc_target_ids:
            _natural(target_id, "SCC target id")
        for edge in self.incoming_edges:
            if not isinstance(edge, OriginalIncomingEdgeProposal):
                raise NullableCodePointerRootedUnreachabilityGenerationError(
                    "incoming edges must be OriginalIncomingEdgeProposal values"
                )
            edge.lean()
        if not isinstance(
            self.scanner_execution, OriginalScannerExecutionProposal
        ):
            raise NullableCodePointerRootedUnreachabilityGenerationError(
                "scanner execution has the wrong proposal type"
            )
        self.scanner_execution.validate()

    def lean(self) -> str:
        self.validate()
        roots = _nat_list(self.root_target_ids, "root target id")
        root_path = _nat_list(
            self.root_path_target_ids, "root path target id"
        )
        forward = _nat_list(
            self.forward_target_ids, "forward target id"
        )
        scc = _nat_list(self.scc_target_ids, "SCC target id")
        edges = "[" + ", ".join(edge.lean() for edge in self.incoming_edges) + "]"
        return f"""def {self.definition_name} : RootedSccCertificate := {{
  rootTargetIds := {roots}
  rootPathTargetIds := {root_path}
  forwardTargetIds := {forward}
  sccTargetIds := {scc}
  incomingEdges := {edges}
}}"""


def nullable_code_pointer_rooted_unreachability_source(
    spec: NullableCodePointerRootedUnreachabilitySpec,
    *,
    expectation: Literal["accepted", "rejected"] = "accepted",
) -> str:
    """Render one kernel-rechecked rooted-SCC module."""

    spec.validate()
    if expectation not in {"accepted", "rejected"}:
        raise NullableCodePointerRootedUnreachabilityGenerationError(
            f"unsupported rooted-unreachability expectation: {expectation!r}"
        )

    checked_value = "true" if expectation == "accepted" else "false"
    checked_name = f"{spec.definition_name}Checked"
    authority_name = f"{spec.definition_name}Authority"
    scanner_claim_name = f"{spec.definition_name}ScannerClaim"
    scanner_checked_name = f"{spec.definition_name}ScannerChecked"
    scanner_authority_name = f"{spec.definition_name}ScannerAuthority"
    source_exact_name = f"{spec.definition_name}ScannerSourceExact"
    boundary_checked_name = f"{spec.definition_name}ScannerBoundaryChecked"
    execution_authority_name = f"{spec.definition_name}ExecutionAuthority"
    scanner_execution_name = f"{spec.definition_name}ScannerExecution"
    scanner_bypass_name = f"{spec.definition_name}ScannerBypassReachable"
    scc_exclusion_name = f"{spec.definition_name}SccExclusion"
    source_name = f"{spec.definition_name}SourceExcluded"
    imports = "\n".join(
        [
            "import "
            "StageA.RelationalNullableCodePointerRootedUnreachability"
        ]
        + [f"import {module}" for module in spec.imports]
    )
    authority = ""
    if expectation == "accepted":
        authority = f"""
def {authority_name} : CheckedRootedSccCertificate
    {spec.original_context_name} {spec.empty_indexed_authority_name}.site := {{
  decodedAuthority := {spec.empty_indexed_authority_name}.decodedAuthority
  certificate := {spec.definition_name}
  checked := {checked_name}
}}

def {scanner_claim_name} : OriginalScannerExecutionClaim :=
  {spec.scanner_execution.lean()}

theorem {scanner_checked_name} :
    {scanner_claim_name}.checked {spec.original_context_name} = true := by
  decide +kernel

def {scanner_authority_name} : CheckedOriginalScannerExecution
    {spec.original_context_name} := {{
  decodedAuthority := {spec.empty_indexed_authority_name}.decodedAuthority
  claim := {scanner_claim_name}
  checked := {scanner_checked_name}
}}

theorem {source_exact_name} :
    {scanner_claim_name}.dispatchSourceTargetId =
      {spec.empty_indexed_authority_name}.site.sourceTargetId := by
  decide +kernel

theorem {boundary_checked_name} :
    rootedSccScannerBoundaryChecked {spec.definition_name}
      {scanner_claim_name} = true := by
  decide +kernel

def {execution_authority_name} : CheckedRootedScannerSccExecution
    {spec.original_context_name} {spec.empty_indexed_authority_name}.site := {{
  graph := {authority_name}
  scanner := {scanner_authority_name}
  sourceExact := {source_exact_name}
  boundaryChecked := {boundary_checked_name}
}}

theorem {scanner_execution_name}
    (selectorState scannerEntryState : MachineState)
    (selectorImmutable : ImmutableImageWordMemory
      {spec.original_context_name}.pe selectorState.memory)
    (scannerImmutable : ImmutableImageWordMemory
      {spec.original_context_name}.pe scannerEntryState.memory)
    (selectorWritesAvoid : forall decoded,
      {scanner_claim_name}.decode? {spec.original_context_name} =
          some decoded ->
        WritesAvoidWord (BitVec.ofNat 32 {scanner_claim_name}.tableBase)
          (evalNormalizedWrites selectorState decoded.selector.writes)) :
    exists decoded,
      {scanner_claim_name}.decode? {spec.original_context_name} =
        some decoded /\\
      OriginalScannerExecutionResult {scanner_claim_name} decoded
        selectorState scannerEntryState :=
  {scanner_authority_name}.executes selectorState scannerEntryState
    selectorImmutable scannerImmutable selectorWritesAvoid

theorem {scanner_bypass_name}
    (selectorReachable : RootedScannerOperationalReachable
      {execution_authority_name} {scanner_claim_name}.selectorRegion.targetId)
    (selectorState scannerEntryState : MachineState)
    (selectorImmutable : ImmutableImageWordMemory
      {spec.original_context_name}.pe selectorState.memory)
    (scannerImmutable : ImmutableImageWordMemory
      {spec.original_context_name}.pe scannerEntryState.memory)
    (selectorWritesAvoid : forall decoded,
      {scanner_claim_name}.decode? {spec.original_context_name} =
          some decoded ->
        WritesAvoidWord (BitVec.ofNat 32 {scanner_claim_name}.tableBase)
          (evalNormalizedWrites selectorState decoded.selector.writes)) :
    RootedScannerOperationalReachable {execution_authority_name}
      {scanner_claim_name}.dispatchBypassTargetId :=
  {execution_authority_name}.scannerBypassReachable selectorReachable
    selectorState scannerEntryState selectorImmutable scannerImmutable
    selectorWritesAvoid

theorem {scc_exclusion_name} {{targetId : Nat}}
    (reachable : RootedScannerOperationalReachable
      {execution_authority_name} targetId) :
    targetId ∉ {spec.definition_name}.sccTargetIds :=
  {execution_authority_name}.sccUnreachable reachable

theorem {source_name}
    (reachable : RootedScannerOperationalReachable
      {execution_authority_name}
      {spec.empty_indexed_authority_name}.site.sourceTargetId) :
    False :=
  {execution_authority_name}.sourceUnreachable reachable

#print axioms {scanner_execution_name}
#print axioms {scanner_bypass_name}
#print axioms {scc_exclusion_name}
#print axioms {source_name}
"""

    return f"""{imports}

namespace {spec.namespace}

open StageA.Formal StageA.Relational
open StageA.Relational.InterpreterMixedContext
open StageA.Relational.NullableCodePointerDispatch
open StageA.Relational.NullableCodePointerRootedUnreachability
open StageA.Relational.OriginalStackDynamicControlClosure

set_option maxRecDepth 1000000
set_option maxHeartbeats 0

{spec.lean()}

theorem {checked_name} :
    {spec.definition_name}.checked {spec.original_context_name}
      {spec.empty_indexed_authority_name}.decodedAuthority
      {spec.empty_indexed_authority_name}.site = {checked_value} := by
  decide +kernel

#print axioms {checked_name}
{authority}
end {spec.namespace}
"""


def write_nullable_code_pointer_rooted_unreachability_module(
    output: Path | str,
    spec: NullableCodePointerRootedUnreachabilitySpec,
    *,
    expectation: Literal["accepted", "rejected"] = "accepted",
) -> Path:
    path = Path(output)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        nullable_code_pointer_rooted_unreachability_source(
            spec, expectation=expectation
        ),
        encoding="utf-8",
    )
    return path
