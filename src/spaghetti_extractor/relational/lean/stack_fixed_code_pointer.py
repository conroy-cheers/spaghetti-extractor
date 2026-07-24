"""Emit kernel-checked stack fixed-code-pointer indirect-call facts.

The emitter only serializes finite evidence.  Its generated theorem is proved
by Lean reduction; Python never supplies an acceptance status or proposition.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from ...errors import StageAInputError


_LEAN_NAME = re.compile(r"[A-Za-z][A-Za-z0-9_]*\Z")
_LEAN_QUALIFIED_NAME = re.compile(
    r"[A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z][A-Za-z0-9_]*)*\Z"
)
_U32_LIMIT = 1 << 32


class StackFixedCodePointerGenerationError(StageAInputError):
    """The finite claim cannot be represented without ambiguity."""


@dataclass(frozen=True)
class LeanStackAdjustment:
    kind: Literal["identity", "add", "subtract"]
    amount: int = 0

    def lean(self) -> str:
        _validate_u32(self.amount, "stack adjustment amount")
        if self.kind == "identity":
            if self.amount != 0:
                raise StackFixedCodePointerGenerationError(
                    "identity stack adjustment must have amount zero"
                )
            return ".identity"
        if self.kind == "add":
            return f".add {self.amount}"
        if self.kind == "subtract":
            return f".subtract {self.amount}"
        raise StackFixedCodePointerGenerationError(
            f"unsupported stack adjustment kind: {self.kind!r}"
        )


@dataclass(frozen=True)
class LeanStackWindow:
    range_id: int
    original_register: str
    candidate_register: str
    bytes_below: int
    bytes_above: int

    def lean(self) -> str:
        _validate_u32(self.range_id, "stack range id")
        _validate_register(self.original_register, "original stack register")
        _validate_register(self.candidate_register, "candidate stack register")
        _validate_u32(self.bytes_below, "stack bytes below")
        _validate_u32(self.bytes_above, "stack bytes above")
        return (
            "{ rangeId := "
            f"{self.range_id}, originalRegister := .{self.original_register}, "
            f"candidateRegister := .{self.candidate_register}, "
            f"bytesBelow := {self.bytes_below}, bytesAbove := {self.bytes_above} }}"
        )


@dataclass(frozen=True)
class StackFixedCodePointerClaimSpec:
    definition_name: str
    window: LeanStackWindow
    read_adjustment: LeanStackAdjustment
    target_id: int
    original_target_address: int
    candidate_target_address: int
    continuation_target_id: int
    original_writes: tuple[LeanStackAdjustment, ...] = ()
    candidate_writes: tuple[LeanStackAdjustment, ...] = ()

    def lean(self) -> str:
        _validate_name(self.definition_name, "claim definition")
        _validate_u32(self.target_id, "target id")
        _validate_u32(self.original_target_address, "original target address")
        _validate_u32(self.candidate_target_address, "candidate target address")
        _validate_u32(self.continuation_target_id, "continuation target id")
        original_writes = ", ".join(item.lean() for item in self.original_writes)
        candidate_writes = ", ".join(item.lean() for item in self.candidate_writes)
        header = (
            f"def {self.definition_name} : "
            "StackSlotFixedCodePointerIndirectCallClaim := {"
        )
        return f"""{header}
  stackRead := {{
    window := {self.window.lean()}
    adjustment := {self.read_adjustment.lean()}
  }}
  targetId := {self.target_id}
  originalTargetAddress := {self.original_target_address}
  candidateTargetAddress := {self.candidate_target_address}
  continuationTargetId := {self.continuation_target_id}
  writes := {{
    original := [{original_writes}]
    candidate := [{candidate_writes}]
  }}
}}"""


@dataclass(frozen=True)
class StackFixedCodePointerLeanBinding:
    dependency_module: str
    namespace: str
    context_name: str
    source_invariant_name: str
    original_behavior_name: str
    candidate_behavior_name: str

    def validate(self) -> None:
        for value, label in (
            (self.dependency_module, "dependency module"),
            (self.namespace, "namespace"),
            (self.context_name, "context name"),
            (self.source_invariant_name, "source invariant name"),
            (self.original_behavior_name, "original behavior name"),
            (self.candidate_behavior_name, "candidate behavior name"),
        ):
            _validate_qualified_name(value, label)


def stack_fixed_code_pointer_source(
    spec: StackFixedCodePointerClaimSpec,
    binding: StackFixedCodePointerLeanBinding,
) -> str:
    """Emit one finite claim and its kernel-reduced checked fact."""

    binding.validate()
    claim = spec.lean()
    theorem_name = f"{spec.definition_name}Checked"
    return f"""import StageA.RelationalStackFixedCodePointer
import {binding.dependency_module}

namespace {binding.namespace}

open StageA.Formal StageA.Relational

{claim}

theorem {theorem_name} :
    {spec.definition_name}.checked {binding.context_name}
      {binding.source_invariant_name} {binding.original_behavior_name}
      {binding.candidate_behavior_name} = true := by
  decide +kernel

#print axioms {theorem_name}

end {binding.namespace}
"""


def write_stack_fixed_code_pointer_module(
    output: Path | str,
    spec: StackFixedCodePointerClaimSpec,
    binding: StackFixedCodePointerLeanBinding,
) -> Path:
    path = Path(output)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(stack_fixed_code_pointer_source(spec, binding), encoding="utf-8")
    return path


def _validate_u32(value: int, label: str) -> None:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or not 0 <= value < _U32_LIMIT
    ):
        raise StackFixedCodePointerGenerationError(
            f"{label} must be an unsigned PE32 integer"
        )


def _validate_name(value: str, label: str) -> None:
    if not isinstance(value, str) or _LEAN_NAME.fullmatch(value) is None:
        raise StackFixedCodePointerGenerationError(
            f"{label} must be a simple Lean identifier"
        )


def _validate_qualified_name(value: str, label: str) -> None:
    if not isinstance(value, str) or _LEAN_QUALIFIED_NAME.fullmatch(value) is None:
        raise StackFixedCodePointerGenerationError(
            f"{label} must be a qualified Lean identifier"
        )


def _validate_register(value: str, label: str) -> None:
    if value not in {"eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp"}:
        raise StackFixedCodePointerGenerationError(
            f"{label} is not an IA-32 general-purpose register"
        )


__all__ = [
    "LeanStackAdjustment",
    "LeanStackWindow",
    "StackFixedCodePointerClaimSpec",
    "StackFixedCodePointerGenerationError",
    "StackFixedCodePointerLeanBinding",
    "stack_fixed_code_pointer_source",
    "write_stack_fixed_code_pointer_module",
]
