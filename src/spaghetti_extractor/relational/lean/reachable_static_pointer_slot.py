"""Emit finite reachable static pointer-slot proposals for Lean replay.

The emitter performs representation checks only.  It does not parse the PE,
classify a proposal as accepted, or turn Python status into proof authority.
The generated module binds an existing exact decoded-original authority and
asks Lean to recompute rooted closure, decode every reachable region, normalize
its behavior, and validate every write classification.

Region bindings are sparse: omitted rows ask Lean to prove all writes in that
reachable region statically disjoint. This removes per-slot boilerplate but not
the current per-slot normalized re-decode; the decoded authority does not yet
publish a reusable checked behavior inventory.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from ...errors import StageAInputError


REACHABLE_STATIC_POINTER_SLOT_FORMAT = (
    "stage-a-relational-reachable-static-pointer-slot-v1"
)
REACHABLE_STATIC_POINTER_SLOT_LEAN_FILENAME = (
    "GeneratedRelationalReachableStaticPointerSlot.lean"
)

_IDENTIFIER = re.compile(r"[A-Za-z_][A-Za-z0-9_']*\Z")
_NAMESPACE = re.compile(
    r"[A-Za-z_][A-Za-z0-9_']*(?:\.[A-Za-z_][A-Za-z0-9_']*)*\Z"
)
_U32_LIMIT = 1 << 32


class ReachableStaticPointerSlotGenerationError(StageAInputError):
    """A proposal cannot be serialized to an unambiguous Lean term."""


def _natural(value: int, field: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise ReachableStaticPointerSlotGenerationError(
            f"{field} must be a natural number"
        )
    return value


def _word(value: int, field: str) -> int:
    result = _natural(value, field)
    if result >= _U32_LIMIT:
        raise ReachableStaticPointerSlotGenerationError(
            f"{field} must fit in an unsigned 32-bit word"
        )
    return result


def _identifier(value: str, field: str) -> str:
    if not isinstance(value, str) or _IDENTIFIER.fullmatch(value) is None:
        raise ReachableStaticPointerSlotGenerationError(
            f"{field} is not a Lean identifier"
        )
    return value


def _namespace(value: str, field: str) -> str:
    if not isinstance(value, str) or _NAMESPACE.fullmatch(value) is None:
        raise ReachableStaticPointerSlotGenerationError(
            f"{field} is not a Lean namespace"
        )
    return value


def _list(values: tuple[object, ...], render) -> str:
    return "[" + ", ".join(render(value) for value in values) + "]"


@dataclass(frozen=True)
class LeanAuthorityBinding:
    module: str
    namespace: str
    context_name: str
    authority_name: str

    def validate(self) -> None:
        _namespace(self.module, "authority module")
        _namespace(self.namespace, "authority namespace")
        _identifier(self.context_name, "context name")
        _identifier(self.authority_name, "authority name")

    @property
    def context(self) -> str:
        return f"{self.namespace}.{self.context_name}"

    @property
    def authority(self) -> str:
        return f"{self.namespace}.{self.authority_name}"


@dataclass(frozen=True)
class WriteClassificationProposal:
    kind: Literal[
        "absolute_disjoint",
        "slot_zero",
        "slot_code_target",
        "runtime_separated",
    ]
    target_id: int | None = None
    width: Literal[1, 2, 4] = 4

    def lean(self) -> str:
        widths = {1: ".byte", 2: ".word", 4: ".dword"}
        try:
            width = widths[self.width]
        except KeyError as error:
            raise ReachableStaticPointerSlotGenerationError(
                f"unsupported write width: {self.width!r}"
            ) from error
        if self.kind == "slot_code_target":
            if self.target_id is None:
                raise ReachableStaticPointerSlotGenerationError(
                    "slot_code_target requires target_id"
                )
            if self.width != 4:
                raise ReachableStaticPointerSlotGenerationError(
                    "slot_code_target requires a four-byte write"
                )
            return f".slotCodeTarget {_natural(self.target_id, 'write target id')}"
        if self.target_id is not None:
            raise ReachableStaticPointerSlotGenerationError(
                f"{self.kind} must not carry target_id"
            )
        if self.kind == "slot_zero" and self.width != 4:
            raise ReachableStaticPointerSlotGenerationError(
                "slot_zero requires a four-byte write"
            )
        names = {
            "absolute_disjoint": f".absoluteDisjoint {width}",
            "slot_zero": ".slotZero",
            "runtime_separated": f".runtimeSeparated {width}",
        }
        try:
            return names[self.kind]
        except KeyError as error:
            raise ReachableStaticPointerSlotGenerationError(
                f"unsupported write classification: {self.kind!r}"
            ) from error


@dataclass(frozen=True)
class RegionBindingProposal:
    target_id: int
    writes: tuple[WriteClassificationProposal, ...] | None

    def lean(self) -> str:
        target_id = _natural(self.target_id, "region target id")
        writes = (
            ".unknown"
            if self.writes is None
            else ".exact " + _list(self.writes, lambda value: value.lean())
        )
        return f"{{ targetId := {target_id}, writes := {writes} }}"


@dataclass(frozen=True)
class GuardedNonzeroEdgeProposal:
    source_target_id: int
    nonzero_target_id: int

    def lean(self) -> str:
        source = _natural(self.source_target_id, "guard source target id")
        target = _natural(self.nonzero_target_id, "guard nonzero target id")
        return f"{{ sourceTargetId := {source}, nonzeroTargetId := {target} }}"


@dataclass(frozen=True)
class IndirectSlotSiteProposal:
    source_target_id: int

    def lean(self) -> str:
        source = _natural(self.source_target_id, "indirect source target id")
        return f"{{ sourceTargetId := {source} }}"


@dataclass(frozen=True)
class ReachableStaticPointerSlotCertificateSpec:
    definition_name: str
    authority: LeanAuthorityBinding
    slot_rva: int
    reachable_target_ids: tuple[int, ...] | None
    allowed_target_ids: tuple[int, ...] | None
    regions: tuple[RegionBindingProposal, ...] | None
    guarded_nonzero_edges: tuple[GuardedNonzeroEdgeProposal, ...] | None = ()
    indirect_slot_sites: tuple[IndirectSlotSiteProposal, ...] | None = ()
    aliases: tuple[int, ...] | None = ()
    namespace: str = (
        "StageA.Generated.RelationalReachableStaticPointerSlot"
    )

    def validate(self) -> None:
        _identifier(self.definition_name, "certificate definition name")
        _namespace(self.namespace, "certificate namespace")
        self.authority.validate()
        _word(self.slot_rva, "slot RVA")

    @staticmethod
    def _knowledge(values, render) -> str:
        return ".unknown" if values is None else f".exact {render(values)}"

    def lean(self) -> str:
        self.validate()
        naturals = lambda values: _list(
            values, lambda value: str(_natural(value, "inventory target id"))
        )
        return f"""def {self.definition_name} : Certificate := {{
  slotRva := {_word(self.slot_rva, 'slot RVA')}
  reachableTargetIds := {self._knowledge(self.reachable_target_ids, naturals)}
  allowedTargetIds := {self._knowledge(self.allowed_target_ids, naturals)}
  regions := {self._knowledge(
      self.regions, lambda values: _list(values, lambda value: value.lean()))}
  guardedNonzeroEdges := {self._knowledge(
      self.guarded_nonzero_edges,
      lambda values: _list(values, lambda value: value.lean()))}
  indirectSlotSites := {self._knowledge(
      self.indirect_slot_sites,
      lambda values: _list(values, lambda value: value.lean()))}
  aliases := {self._knowledge(self.aliases, naturals)}
}}"""


def reachable_static_pointer_slot_source(
    spec: ReachableStaticPointerSlotCertificateSpec,
    *,
    expectation: Literal["accepted", "rejected"] = "accepted",
) -> str:
    """Render one kernel replay module.

    ``expectation`` selects the equality Lean must prove.  Python does not
    evaluate the checker.
    """

    spec.validate()
    if expectation not in {"accepted", "rejected"}:
        raise ReachableStaticPointerSlotGenerationError(
            f"unsupported expectation: {expectation!r}"
        )
    checked_value = "true" if expectation == "accepted" else "false"
    checked_name = f"{spec.definition_name}Checked"
    authority_name = f"{spec.definition_name}ExactAuthority"
    evidence_name = f"{spec.definition_name}Evidence"
    evidence = ""
    if expectation == "accepted":
        evidence = f"""
def {authority_name} :
    ExactOriginalDecodedAuthority {spec.authority.context} :=
  {spec.authority.authority}

def {evidence_name} :
    KernelEvidence {spec.authority.context} {spec.definition_name} := {{
  authority := {authority_name}
  checked := {checked_name}
}}

#print axioms {authority_name}
"""
    return f"""import StageA.RelationalReachableStaticPointerSlot
import {spec.authority.module}

namespace {spec.namespace}

open StageA.Formal StageA.Relational
open StageA.Relational.InterpreterMixedContext
open StageA.Relational.ReachableStaticPointerSlot

set_option maxRecDepth 1000000
set_option maxHeartbeats 0

{spec.lean()}

theorem {checked_name} :
    {spec.definition_name}.checked {spec.authority.context} = {checked_value} := by
  decide +kernel

{evidence}
#print axioms {checked_name}
#print axioms Certificate.transition_preserves
#print axioms Certificate.trace_preserves
#print axioms GuardedNonzeroEdge.not_selected_when_zero
#print axioms IndirectSlotSite.target_is_finite

end {spec.namespace}
"""


def write_reachable_static_pointer_slot_module(
    output: Path | str,
    spec: ReachableStaticPointerSlotCertificateSpec,
    *,
    expectation: Literal["accepted", "rejected"] = "accepted",
) -> Path:
    path = Path(output)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        reachable_static_pointer_slot_source(spec, expectation=expectation),
        encoding="utf-8",
    )
    return path
