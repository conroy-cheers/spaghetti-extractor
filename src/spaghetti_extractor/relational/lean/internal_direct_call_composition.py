"""Bind exact direct-call summaries to their Lean semantic composition proof.

The serializer deliberately does not reproduce CFG, register, frame, import,
operational execution, or loop facts.  Those facts live in the structural
summary and in an ``IntegratedSummaryPremises`` term checked by Lean.  That
term includes total exact-PE call-return coverage and the checked lift from
``WorldExecution`` into relational segment composition.  The lift is derived
by Lean from a complete, rank-decreasing operational classifier and is carried
by each invocation; it is not a free-standing premise.  With no such term the
only representable result is explicit non-authority.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from ...errors import StageAInputError


INTERNAL_DIRECT_CALL_COMPOSITION_LEAN_FILENAME = (
    "GeneratedRelationalInternalDirectCallComposition.lean"
)

_LEAN_QUALIFIED_NAME = re.compile(
    r"[A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z][A-Za-z0-9_]*)*\Z"
)


class InternalDirectCallCompositionGenerationError(StageAInputError):
    """The semantic witness binding is ambiguous or internally inconsistent."""


def _qualified(value: str, context: str) -> str:
    if not isinstance(value, str) or _LEAN_QUALIFIED_NAME.fullmatch(value) is None:
        raise InternalDirectCallCompositionGenerationError(
            f"{context} must be a qualified Lean identifier"
        )
    return value


def _module(value: str, context: str) -> str:
    if not isinstance(value, str) or _LEAN_QUALIFIED_NAME.fullmatch(value) is None:
        raise InternalDirectCallCompositionGenerationError(
            f"{context} must be a Lean module name"
        )
    return value


@dataclass(frozen=True)
class InternalDirectCallCompositionLeanBindings:
    context: str
    summary_tree: str
    premises: str | None = None
    imports: tuple[str, ...] = ()
    namespace: str = "StageA.Generated.InternalDirectCallComposition"

    def checked(self) -> "InternalDirectCallCompositionLeanBindings":
        _qualified(self.context, "context")
        _qualified(self.summary_tree, "summary_tree")
        if self.premises is not None:
            _qualified(self.premises, "premises")
        _module(self.namespace, "namespace")
        seen: set[str] = set()
        for index, module in enumerate(self.imports):
            checked = _module(module, f"imports[{index}]")
            if checked in seen:
                raise InternalDirectCallCompositionGenerationError(
                    f"imports contains duplicate module {checked}"
                )
            seen.add(checked)
        return self


CompositionExpectation = Literal["complete", "incomplete"]


def internal_direct_call_composition_source(
    bindings: InternalDirectCallCompositionLeanBindings,
    *,
    expectation: CompositionExpectation,
) -> str:
    """Emit an operationally complete proof-object binding, never a verdict."""

    bindings = bindings.checked()
    if expectation not in {"complete", "incomplete"}:
        raise InternalDirectCallCompositionGenerationError(
            "expectation must be complete or incomplete"
        )
    if expectation == "complete" and bindings.premises is None:
        raise InternalDirectCallCompositionGenerationError(
            "complete composition requires an operationally complete "
            "IntegratedSummaryPremises term"
        )
    if expectation == "incomplete" and bindings.premises is not None:
        raise InternalDirectCallCompositionGenerationError(
            "incomplete composition must not carry semantic premises"
        )

    imports = ["import StageA.RelationalInternalDirectCallComposition"]
    imports.extend(f"import {module}" for module in bindings.imports)
    context = bindings.context
    tree = bindings.summary_tree
    lines = [
        *imports,
        "",
        f"namespace {bindings.namespace}",
        "",
        "open StageA.Relational",
        "open StageA.Relational.InternalDirectCallComposition",
        "",
        f"def generatedContext : StaticProofContext := {context}",
        f"def generatedSummaryTree : SummaryTree := {tree}",
    ]

    if bindings.premises is None:
        lines.extend(
            [
                "",
                "def generatedIntegratedSummaryPremises :",
                "    Option (IntegratedSummaryPremises generatedContext",
                "      generatedSummaryTree) := none",
                "",
                "def generatedStandaloneAcceptanceAuthority : Bool :=",
                "  StandaloneAcceptanceAuthority generatedIntegratedSummaryPremises",
                "",
                "theorem generatedStandaloneAcceptanceAuthorityFalse :",
                "    generatedStandaloneAcceptanceAuthority = false := rfl",
                "",
                "#print axioms generatedStandaloneAcceptanceAuthorityFalse",
            ]
        )
    else:
        premises = bindings.premises
        lines.extend(
            [
                "",
                "def generatedCompletePremises : IntegratedSummaryPremises",
                f"    generatedContext generatedSummaryTree := {premises}",
                "",
                "def generatedIntegratedSummaryPremises :",
                "    Option (IntegratedSummaryPremises generatedContext",
                "      generatedSummaryTree) := some generatedCompletePremises",
                "",
                "def generatedSemanticContract : DirectCallSemanticContract",
                "    generatedContext generatedSummaryTree :=",
                "  generatedCompletePremises.toSemanticContract",
                "",
                "def generatedCheckedDirectCallSummaryProvenance :",
                "    CheckedDirectCallSummaryProvenance generatedContext :=",
                "  generatedCompletePremises.provenance",
                "",
                "def generatedStandaloneAcceptanceAuthority : Bool :=",
                "  StandaloneAcceptanceAuthority generatedIntegratedSummaryPremises",
                "",
                "theorem generatedStandaloneAcceptanceAuthorityTrue :",
                "    generatedStandaloneAcceptanceAuthority = true := rfl",
                "",
                "#print axioms generatedSemanticContract",
                "#print axioms generatedCheckedDirectCallSummaryProvenance",
                "#print axioms generatedStandaloneAcceptanceAuthorityTrue",
            ]
        )

    lines.extend(["", f"end {bindings.namespace}", ""])
    source = "\n".join(lines)
    for forbidden in ("sorry", "native_decide", "axiom ", "unsafe "):
        if forbidden in source:
            raise InternalDirectCallCompositionGenerationError(
                f"generated source unexpectedly contains {forbidden.strip()}"
            )
    return source


def write_internal_direct_call_composition(
    destination: Path,
    bindings: InternalDirectCallCompositionLeanBindings,
    *,
    expectation: CompositionExpectation,
) -> Path:
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(
        internal_direct_call_composition_source(bindings, expectation=expectation),
        encoding="utf-8",
    )
    return destination
