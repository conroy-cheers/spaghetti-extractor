"""Serialize checked nullable code-pointer dispatch bindings for Lean.

Python names exact context objects and finite region metadata.  It never
decides acceptance: generated Lean re-decodes every region and proves either a
finite target closure or, with an explicit composition premise, that an empty
dispatch source is unreachable.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from ...errors import StageAInputError


NULLABLE_CODE_POINTER_DISPATCH_FORMAT = (
    "stage-a-relational-nullable-code-pointer-dispatch-v1"
)
NULLABLE_CODE_POINTER_DISPATCH_LEAN_FILENAME = (
    "GeneratedRelationalNullableCodePointerDispatch.lean"
)

_IDENTIFIER = re.compile(r"[A-Za-z_][A-Za-z0-9_']*\Z")
_QUALIFIED = re.compile(
    r"[A-Za-z_][A-Za-z0-9_']*(?:\.[A-Za-z_][A-Za-z0-9_']*)*\Z"
)
_U32_LIMIT = 1 << 32


class NullableCodePointerDispatchGenerationError(StageAInputError):
    """A dispatch binding cannot be represented unambiguously in Lean."""


def _natural(value: int, field: str, *, word: bool = False) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise NullableCodePointerDispatchGenerationError(
            f"{field} must be a natural number"
        )
    if word and value >= _U32_LIMIT:
        raise NullableCodePointerDispatchGenerationError(
            f"{field} must fit in an unsigned 32-bit word"
        )
    return value


def _name(value: str, field: str, *, identifier: bool = False) -> str:
    pattern = _IDENTIFIER if identifier else _QUALIFIED
    if not isinstance(value, str) or pattern.fullmatch(value) is None:
        raise NullableCodePointerDispatchGenerationError(
            f"{field} is not a valid Lean name"
        )
    return value


def _nat_list(values: tuple[int, ...], field: str) -> str:
    checked = [str(_natural(value, field)) for value in values]
    return "[" + ", ".join(checked) + "]"


@dataclass(frozen=True)
class PairedDecodedRegionProposal:
    target_id: int
    original_rva: int
    original_size: int
    candidate_rva: int
    candidate_size: int

    def lean(self, field: str) -> str:
        target = _natural(self.target_id, f"{field} target id")
        original_rva = _natural(
            self.original_rva, f"{field} original RVA", word=True
        )
        candidate_rva = _natural(
            self.candidate_rva, f"{field} candidate RVA", word=True
        )
        original_size = _natural(
            self.original_size, f"{field} original size", word=True
        )
        candidate_size = _natural(
            self.candidate_size, f"{field} candidate size", word=True
        )
        if original_size == 0 or candidate_size == 0:
            raise NullableCodePointerDispatchGenerationError(
                f"{field} spans must be nonempty"
            )
        if original_rva + original_size > _U32_LIMIT:
            raise NullableCodePointerDispatchGenerationError(
                f"{field} original span exceeds the IA-32 address space"
            )
        if candidate_rva + candidate_size > _U32_LIMIT:
            raise NullableCodePointerDispatchGenerationError(
                f"{field} candidate span exceeds the IA-32 address space"
            )
        return (
            "{ targetId := "
            f"{target}, originalSpan := {{ start := {original_rva}, "
            f"size := {original_size} }}, candidateSpan := {{ start := "
            f"{candidate_rva}, size := {candidate_size} }} }}"
        )


@dataclass(frozen=True)
class NullableCodePointerDispatchSpec:
    definition_name: str
    context_name: str
    table_certificate_name: str
    table_call_name: str
    scanner_name: str
    scanner_source_invariant_name: str
    scanner_post_invariant_name: str
    scanner_finished_invariant_name: str
    dispatch_invariant_name: str
    scanner_region: PairedDecodedRegionProposal
    test_region: PairedDecodedRegionProposal
    bridge_region: PairedDecodedRegionProposal
    guard_region: PairedDecodedRegionProposal
    dispatch_region: PairedDecodedRegionProposal
    dispatch_bypass_target_id: int
    dispatch_predecessor_ids: tuple[int, ...]
    original_dispatch_base: int
    candidate_dispatch_base: int
    dispatch_scale: int = 4
    dispatch_index_offset: int = 0
    namespace: str = (
        "StageA.Generated.RelationalNullableCodePointerDispatch"
    )
    imports: tuple[str, ...] = ()

    def validate(self) -> None:
        _name(self.definition_name, "definition name", identifier=True)
        _name(self.namespace, "namespace")
        for field, value in (
            ("context name", self.context_name),
            ("table certificate name", self.table_certificate_name),
            ("table call name", self.table_call_name),
            ("scanner name", self.scanner_name),
            ("scanner source invariant name", self.scanner_source_invariant_name),
            ("scanner post invariant name", self.scanner_post_invariant_name),
            (
                "scanner finished invariant name",
                self.scanner_finished_invariant_name,
            ),
            ("dispatch invariant name", self.dispatch_invariant_name),
        ):
            _name(value, field)
        for module in self.imports:
            _name(module, "import module")
        _natural(
            self.dispatch_bypass_target_id, "dispatch bypass target id"
        )
        for value in self.dispatch_predecessor_ids:
            _natural(value, "dispatch predecessor id")
        _natural(
            self.original_dispatch_base,
            "original dispatch base",
            word=True,
        )
        _natural(
            self.candidate_dispatch_base,
            "candidate dispatch base",
            word=True,
        )
        _natural(self.dispatch_scale, "dispatch scale")
        _natural(self.dispatch_index_offset, "dispatch index offset")
        for field, region in (
            ("scanner region", self.scanner_region),
            ("test region", self.test_region),
            ("bridge region", self.bridge_region),
            ("guard region", self.guard_region),
            ("dispatch region", self.dispatch_region),
        ):
            region.lean(field)

    def lean(self) -> str:
        self.validate()
        predecessors = _nat_list(
            self.dispatch_predecessor_ids, "dispatch predecessor id"
        )
        return f"""def {self.definition_name} : Claim := {{
  tableCertificate := {self.table_certificate_name}
  tableCall := {self.table_call_name}
  scanner := {self.scanner_name}
  scannerSourceInvariant := {self.scanner_source_invariant_name}
  scannerPostInvariant := {self.scanner_post_invariant_name}
  scannerFinishedInvariant := {self.scanner_finished_invariant_name}
  dispatchInvariant := {self.dispatch_invariant_name}
  scannerRegion := {self.scanner_region.lean("scanner region")}
  testRegion := {self.test_region.lean("test region")}
  bridgeRegion := {self.bridge_region.lean("bridge region")}
  guardRegion := {self.guard_region.lean("guard region")}
  dispatchRegion := {self.dispatch_region.lean("dispatch region")}
  dispatchBypassTargetId := {self.dispatch_bypass_target_id}
  dispatchPredecessorIds := {predecessors}
  originalDispatchBase := {self.original_dispatch_base}
  candidateDispatchBase := {self.candidate_dispatch_base}
  dispatchScale := {self.dispatch_scale}
  dispatchIndexOffset := {self.dispatch_index_offset}
}}"""


def nullable_code_pointer_dispatch_source(
    spec: NullableCodePointerDispatchSpec,
    *,
    expectation: Literal["accepted", "rejected"] = "accepted",
) -> str:
    """Render a binding and its kernel obligations.

    The accepted theorem still requires the product graph's typed predecessor
    premise before it can conclude global empty-source unreachability.
    """

    spec.validate()
    if expectation not in {"accepted", "rejected"}:
        raise NullableCodePointerDispatchGenerationError(
            f"unsupported dispatch expectation: {expectation!r}"
        )
    imports = "\n".join(
        ["import StageA.RelationalNullableCodePointerDispatch"]
        + [f"import {module}" for module in spec.imports]
    )
    checked = "true" if expectation == "accepted" else "false"
    theorem_name = f"{spec.definition_name}Checked"
    authority = ""
    if expectation == "accepted":
        authority = f"""
theorem {spec.definition_name}Closure
    (cluster : DecodedDispatchCluster)
    (decoded : {spec.definition_name}.cluster? {spec.context_name} = some cluster)
    (actualReachable : RelationalWorld → MachineState → MachineState → Prop)
    (structurallyValid : {spec.context_name}.StructurallyValid)
    (complete : {spec.definition_name}.tableCall.entryCount = 0 →
      CompleteDispatchPredecessorPremise {spec.context_name}
        {spec.definition_name} cluster actualReachable) :
    ActualDecodedMixedDispatchClosure {spec.context_name}
      {spec.definition_name} cluster actualReachable := by
  have accepted := {theorem_name}
  exact actualDecodedMixedDispatchClosure_of_checked {spec.context_name}
    {spec.definition_name} cluster actualReachable structurallyValid
    decoded accepted complete

#print axioms {spec.definition_name}Closure
"""
    return f"""{imports}

namespace {spec.namespace}

open StageA.Formal StageA.Relational
open StageA.Relational.NullableCodePointerDispatch

set_option maxRecDepth 1000000
set_option maxHeartbeats 0

{spec.lean()}

theorem {theorem_name} :
    {spec.definition_name}.checked {spec.context_name} = {checked} := by
  decide +kernel

#print axioms {theorem_name}
{authority}
end {spec.namespace}
"""


def write_nullable_code_pointer_dispatch_module(
    output: Path | str,
    spec: NullableCodePointerDispatchSpec,
    *,
    expectation: Literal["accepted", "rejected"] = "accepted",
) -> Path:
    path = Path(output)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        nullable_code_pointer_dispatch_source(spec, expectation=expectation),
        encoding="utf-8",
    )
    return path
