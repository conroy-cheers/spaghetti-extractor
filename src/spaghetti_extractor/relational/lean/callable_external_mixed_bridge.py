"""Generate typed bindings for the callable-external mixed bridge.

The artifact names Lean terms and finite inventories. It contains no proof
status, verdict, trace, observation, successor state, or native-transition
claim; Lean remains responsible for checking every referenced term.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from ...errors import StageAInputError


CALLABLE_EXTERNAL_MIXED_BRIDGE_FORMAT = (
    "stage-a-callable-external-mixed-bridge-v1"
)
CALLABLE_EXTERNAL_MIXED_BRIDGE_MODULE_PREFIX = (
    "GeneratedRelationalCallableExternalMixedBridge"
)

_ROOT_FIELDS = frozenset({
    "format",
    "namespace",
    "imports",
    "context_term",
    "callable_program_term",
    "candidate_program_term",
    "candidate_program_binding_term",
    "capability_inventory_term",
    "resolved_abi_inventory_term",
})
_QUALIFIED = re.compile(
    r"[A-Za-z_][A-Za-z0-9_']*(?:\.[A-Za-z_][A-Za-z0-9_']*)*\Z"
)
_MODULE = re.compile(r"[A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z][A-Za-z0-9_]*)*\Z")


class CallableExternalMixedBridgeError(StageAInputError):
    """A callable-external mixed binding is malformed or ambiguous."""


def _object(value: object, context: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise CallableExternalMixedBridgeError(f"{context} must be a JSON object")
    if any(not isinstance(key, str) for key in value):
        raise CallableExternalMixedBridgeError(
            f"{context} field names must be strings"
        )
    return value


def _exact_fields(
    value: Mapping[str, Any], expected: frozenset[str], context: str
) -> None:
    missing = sorted(expected - set(value))
    unexpected = sorted(set(value) - expected)
    if missing:
        raise CallableExternalMixedBridgeError(
            f"{context} is missing required fields: {', '.join(missing)}"
        )
    if unexpected:
        raise CallableExternalMixedBridgeError(
            f"{context} has unexpected fields: {', '.join(unexpected)}"
        )


def _qualified(value: object, context: str) -> str:
    if not isinstance(value, str) or _QUALIFIED.fullmatch(value) is None:
        raise CallableExternalMixedBridgeError(
            f"{context} must be a qualified Lean identifier"
        )
    return value


def _module(value: object, context: str) -> str:
    if not isinstance(value, str) or _MODULE.fullmatch(value) is None:
        raise CallableExternalMixedBridgeError(
            f"{context} must be a Lean module name"
        )
    return value


@dataclass(frozen=True)
class CallableExternalMixedBridgeBinding:
    namespace: str
    imports: tuple[str, ...]
    context_term: str
    callable_program_term: str
    candidate_program_term: str
    candidate_program_binding_term: str
    capability_inventory_term: str
    resolved_abi_inventory_term: str


def parse_callable_external_mixed_bridge_binding(
    payload: object,
) -> CallableExternalMixedBridgeBinding:
    context = "callable external mixed bridge artifact"
    root = _object(payload, context)
    _exact_fields(root, _ROOT_FIELDS, context)
    if root["format"] != CALLABLE_EXTERNAL_MIXED_BRIDGE_FORMAT:
        raise CallableExternalMixedBridgeError(
            "unsupported callable external mixed bridge format"
        )

    raw_imports = root["imports"]
    if not isinstance(raw_imports, list):
        raise CallableExternalMixedBridgeError("imports must be an array")
    imports = tuple(
        _module(value, f"imports[{index}]")
        for index, value in enumerate(raw_imports)
    )
    if len(set(imports)) != len(imports):
        raise CallableExternalMixedBridgeError("imports contains duplicate modules")

    return CallableExternalMixedBridgeBinding(
        namespace=_module(root["namespace"], "namespace"),
        imports=imports,
        context_term=_qualified(root["context_term"], "context_term"),
        callable_program_term=_qualified(
            root["callable_program_term"], "callable_program_term"
        ),
        candidate_program_term=_qualified(
            root["candidate_program_term"], "candidate_program_term"
        ),
        candidate_program_binding_term=_qualified(
            root["candidate_program_binding_term"],
            "candidate_program_binding_term",
        ),
        capability_inventory_term=_qualified(
            root["capability_inventory_term"], "capability_inventory_term"
        ),
        resolved_abi_inventory_term=_qualified(
            root["resolved_abi_inventory_term"], "resolved_abi_inventory_term"
        ),
    )


def relational_callable_external_mixed_bridge_source(payload: object) -> str:
    """Render typed aliases and the canonical candidate classifier frontier."""
    binding = parse_callable_external_mixed_bridge_binding(payload)
    imports = tuple(dict.fromkeys((
        "StageA.RelationalCallableExternalMixedBridge",
        *binding.imports,
    )))
    source = f"""{chr(10).join(f'import {module}' for module in imports)}

namespace {binding.namespace}

open StageA.Formal StageA.Relational
open StageA.Relational.CallableExternalCapability
open StageA.Relational.CallableExternalExecution
open StageA.Relational.CallableExternalMixedBridge
open StageA.Relational.InterpreterNativeWorld

def generatedContext : StaticProofContext := {binding.context_term}

def generatedCallableProgram : OriginalCallableProgram :=
  {binding.callable_program_term}

def generatedCandidateProgram : ExactNativeWorldProgram :=
  {binding.candidate_program_term}

def generatedCandidateProgramBinding :
    ExactCandidateCallableProgramBinding generatedContext
      generatedCandidateProgram :=
  {binding.candidate_program_binding_term}

def generatedCallableCapabilities : List CallableExternalCapability :=
  {binding.capability_inventory_term}

def generatedResolvedABIContracts : List ResolvedExternalABIContract :=
  {binding.resolved_abi_inventory_term}

def generatedCandidateKernelCallableFrontier :
    CandidateKernelCallableFrontier :=
  canonicalCandidateKernelCallableFrontier generatedCallableCapabilities
    generatedResolvedABIContracts

def generatedCandidateNativeCallableFrontier :
    CandidateNativeCallableFrontier :=
  candidateNativeCallableFrontier generatedCandidateProgram generatedContext
    generatedCandidateProgramBinding generatedCandidateKernelCallableFrontier

end {binding.namespace}
"""
    for forbidden in ("sorry", "native_decide", "axiom ", "unsafe "):
        if forbidden in source:
            raise CallableExternalMixedBridgeError(
                f"generated source unexpectedly contains {forbidden.strip()}"
            )
    return source


__all__ = [
    "CALLABLE_EXTERNAL_MIXED_BRIDGE_FORMAT",
    "CALLABLE_EXTERNAL_MIXED_BRIDGE_MODULE_PREFIX",
    "CallableExternalMixedBridgeBinding",
    "CallableExternalMixedBridgeError",
    "parse_callable_external_mixed_bridge_binding",
    "relational_callable_external_mixed_bridge_source",
]
