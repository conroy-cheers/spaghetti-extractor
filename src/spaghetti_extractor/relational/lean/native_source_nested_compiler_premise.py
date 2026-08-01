"""Generate the sole callback-capable compiler-correctness premise.

The checked response-family module supplies the exact
``PinnedNestedCompilerStackPremise`` type.  This generator adds only the one
explicit trust-boundary axiom accepted by native-source whole-program
equivalence.  It deliberately emits no report, status, or other declaration
that could carry acceptance authority.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from ...errors import StageAInputError


NATIVE_SOURCE_NESTED_COMPILER_PREMISE_MODULE = (
    "GeneratedNativeSourceNestedCompilerPremise"
)
NATIVE_SOURCE_NESTED_COMPILER_PREMISE_AUDIT_MODULE = (
    "GeneratedNativeSourceNestedCompilerPremiseAudit"
)

_LEAN_IDENTIFIER = re.compile(
    r"[A-Za-z_][A-Za-z0-9_']*(?:\.[A-Za-z_][A-Za-z0-9_']*)*\Z"
)
_LOCAL_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_']*\Z")
_STAGE_A_MODULE = re.compile(
    r"StageA\.[A-Za-z_][A-Za-z0-9_']*(?:\.[A-Za-z_][A-Za-z0-9_']*)*\Z"
)
_FORBIDDEN_NAME_PARTS = frozenset(
    {
        "admit",
        "axiom",
        "by",
        "def",
        "else",
        "end",
        "import",
        "in",
        "inductive",
        "instance",
        "let",
        "match",
        "namespace",
        "native_decide",
        "opaque",
        "partial",
        "protected",
        "sorry",
        "structure",
        "theorem",
        "then",
        "unsafe",
        "variable",
        "where",
        "with",
    }
)


class NativeSourceNestedCompilerPremiseGenerationError(StageAInputError):
    """The nested compiler-premise request is malformed or ambiguous."""


@dataclass(frozen=True)
class NativeSourceNestedCompilerPremiseSpec:
    """Canonical checked declaration used by the sole approved axiom."""

    response_family_module: str
    premise_type: str
    namespace: str = (
        "StageA.GeneratedRelational.NativeSourceNestedCompilerPremise"
    )
    output_module: str = NATIVE_SOURCE_NESTED_COMPILER_PREMISE_MODULE
    audit_output_module: str = (
        NATIVE_SOURCE_NESTED_COMPILER_PREMISE_AUDIT_MODULE
    )
    axiom_name: str = "pinnedCompilerLoweringCorrect"

    def validate(self) -> None:
        if not _valid_stage_a_module(self.response_family_module):
            raise NativeSourceNestedCompilerPremiseGenerationError(
                "response_family_module must be a canonical StageA module"
            )
        if not _valid_identifier(self.premise_type):
            raise NativeSourceNestedCompilerPremiseGenerationError(
                "premise_type must be a canonical Lean declaration"
            )
        if "." not in self.premise_type:
            raise NativeSourceNestedCompilerPremiseGenerationError(
                "premise_type must be fully qualified"
            )
        if not _valid_identifier(self.namespace):
            raise NativeSourceNestedCompilerPremiseGenerationError(
                "namespace must be a canonical Lean declaration"
            )
        for label, value in (
            ("output_module", self.output_module),
            ("audit_output_module", self.audit_output_module),
            ("axiom_name", self.axiom_name),
        ):
            if not _valid_local_name(value):
                raise NativeSourceNestedCompilerPremiseGenerationError(
                    f"{label} must be a canonical local Lean identifier"
                )
        if self.output_module == self.audit_output_module:
            raise NativeSourceNestedCompilerPremiseGenerationError(
                "premise and audit output modules must be distinct"
            )
        if self.axiom_name != "pinnedCompilerLoweringCorrect":
            raise NativeSourceNestedCompilerPremiseGenerationError(
                "the sole compiler axiom must be named "
                "pinnedCompilerLoweringCorrect"
            )


def _valid_identifier(value: object) -> bool:
    return (
        isinstance(value, str)
        and _LEAN_IDENTIFIER.fullmatch(value) is not None
        and all(
            part.casefold() not in _FORBIDDEN_NAME_PARTS
            for part in value.split(".")
        )
    )


def _valid_local_name(value: object) -> bool:
    return (
        isinstance(value, str)
        and _LOCAL_NAME.fullmatch(value) is not None
        and value.casefold() not in _FORBIDDEN_NAME_PARTS
    )


def _valid_stage_a_module(value: object) -> bool:
    return (
        isinstance(value, str)
        and _STAGE_A_MODULE.fullmatch(value) is not None
        and all(
            part.casefold() not in _FORBIDDEN_NAME_PARTS
            for part in value.split(".")
        )
    )


def native_source_nested_compiler_premise_source(
    spec: NativeSourceNestedCompilerPremiseSpec,
) -> str:
    """Emit the one explicit nested compiler-stack trust premise."""

    spec.validate()
    return f"""import {spec.response_family_module}

namespace {spec.namespace}

/-- Sole approved semantic assumption: the pinned compiler and lowering stack
implements the checked source program for every admitted callback-capable
response-environment pair. -/
axiom {spec.axiom_name} :
  {spec.premise_type}

end {spec.namespace}
"""


def native_source_nested_compiler_premise_audit_source(
    spec: NativeSourceNestedCompilerPremiseSpec,
) -> str:
    """Emit a detached audit naming only the compiler premise."""

    spec.validate()
    declaration = f"{spec.namespace}.{spec.axiom_name}"
    return (
        f"import StageA.{spec.output_module}\n\n"
        f"#print axioms {declaration}\n"
    )


def write_native_source_nested_compiler_premise(
    out: Path | str, spec: NativeSourceNestedCompilerPremiseSpec
) -> tuple[Path, Path]:
    """Write the premise and detached audit below ``out/StageA``."""

    spec.validate()
    stage_a = Path(out) / "StageA"
    stage_a.mkdir(parents=True, exist_ok=True)
    premise = stage_a / f"{spec.output_module}.lean"
    audit = stage_a / f"{spec.audit_output_module}.lean"
    premise.write_text(
        native_source_nested_compiler_premise_source(spec), encoding="ascii"
    )
    audit.write_text(
        native_source_nested_compiler_premise_audit_source(spec),
        encoding="ascii",
    )
    return premise, audit


__all__ = [
    "NATIVE_SOURCE_NESTED_COMPILER_PREMISE_AUDIT_MODULE",
    "NATIVE_SOURCE_NESTED_COMPILER_PREMISE_MODULE",
    "NativeSourceNestedCompilerPremiseGenerationError",
    "NativeSourceNestedCompilerPremiseSpec",
    "native_source_nested_compiler_premise_audit_source",
    "native_source_nested_compiler_premise_source",
    "write_native_source_nested_compiler_premise",
]
