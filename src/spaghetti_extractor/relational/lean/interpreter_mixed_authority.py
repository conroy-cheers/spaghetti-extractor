"""Generate the exact native authority for a compiled interpreter candidate.

The generated module is intentionally small.  It references the authoritative
candidate PE and semantic table exported by an interpreter-kernel-data bundle;
it never serializes candidate bytes or accepts a generated status as evidence.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, fields
from pathlib import Path

from ...errors import StageAInputError


INTERPRETER_MIXED_AUTHORITY_MODULE = (
    "GeneratedRelationalInterpreterMixedAuthority"
)

_LEAN_IDENTIFIER = re.compile(
    r"[A-Za-z_][A-Za-z0-9_']*(?:\.[A-Za-z_][A-Za-z0-9_']*)*\Z"
)
_STAGE_A_MODULE = re.compile(
    r"StageA\.[A-Za-z_][A-Za-z0-9_']*(?:\.[A-Za-z_][A-Za-z0-9_']*)*\Z"
)
_LOCAL_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_']*\Z")
_LEAN_KEYWORDS = {
    "abbrev",
    "axiom",
    "by",
    "class",
    "def",
    "deriving",
    "do",
    "else",
    "end",
    "example",
    "export",
    "if",
    "import",
    "in",
    "inductive",
    "instance",
    "let",
    "match",
    "namespace",
    "open",
    "opaque",
    "partial",
    "private",
    "protected",
    "structure",
    "syntax",
    "theorem",
    "then",
    "unsafe",
    "variable",
    "where",
    "with",
}


class InterpreterMixedAuthorityGenerationError(StageAInputError):
    """A requested Lean module, namespace, or binding name is invalid."""


@dataclass(frozen=True)
class InterpreterMixedAuthoritySpec:
    """Lean names exported by one exact interpreter-kernel-data bundle."""

    kernel_data_module: str = "StageA.GeneratedInterpreterKernelDataBundle"
    kernel_data_namespace: str = (
        "StageA.GeneratedRelational.InterpreterKernelData"
    )
    output_module: str = INTERPRETER_MIXED_AUTHORITY_MODULE
    namespace: str = "StageA.GeneratedRelational.InterpreterMixedAuthority"
    candidate_pe: str = "generatedInterpreterKernelCandidatePe"
    import_certificate: str = "generatedInterpreterKernelImportCertificate"
    imports: str = "generatedInterpreterKernelImports"
    relocations: str = "generatedInterpreterKernelRelocations"
    table_rva: str = "generatedInterpreterKernelTableRva"
    count_rva: str = "generatedInterpreterKernelCountRva"
    semantic_records: str = "semanticInterpreterProgramRecords"
    pe_parsed: str = "generatedInterpreterKernelCandidateParsed"
    imports_parsed: str = "generatedInterpreterKernelImportsChecked"
    relocations_parsed: str = "generatedInterpreterKernelRelocationsParsed"
    table_certificate: str = "generatedInterpreterKernelDataCertificate"

    def validate(self) -> None:
        if not _valid_qualified_identifier(
            self.kernel_data_module, pattern=_STAGE_A_MODULE
        ):
            raise InterpreterMixedAuthorityGenerationError(
                "kernel_data_module must be a canonical StageA module"
            )
        if not _valid_local_identifier(self.output_module):
            raise InterpreterMixedAuthorityGenerationError(
                "output_module must be a local Lean identifier"
            )
        for name, value in (
            ("kernel_data_namespace", self.kernel_data_namespace),
            ("namespace", self.namespace),
        ):
            if not _valid_qualified_identifier(value):
                raise InterpreterMixedAuthorityGenerationError(
                    f"{name} must be a canonical Lean identifier"
                )
        structural = {
            "kernel_data_module",
            "kernel_data_namespace",
            "output_module",
            "namespace",
        }
        for field in fields(self):
            if field.name in structural:
                continue
            value = getattr(self, field.name)
            if not _valid_local_identifier(value):
                raise InterpreterMixedAuthorityGenerationError(
                    f"{field.name} must be a local Lean identifier"
                )

    def qualified(self, name: str) -> str:
        return f"{self.kernel_data_namespace}.{name}"


def _valid_local_identifier(value: str) -> bool:
    return (
        _LOCAL_NAME.fullmatch(value) is not None
        and value != "_"
        and value not in _LEAN_KEYWORDS
    )


def _valid_qualified_identifier(
    value: str, *, pattern: re.Pattern[str] = _LEAN_IDENTIFIER
) -> bool:
    return pattern.fullmatch(value) is not None and all(
        _valid_local_identifier(component) for component in value.split(".")
    )


def relational_interpreter_mixed_authority_source(
    spec: InterpreterMixedAuthoritySpec,
) -> str:
    """Emit a compact exact candidate-world/static-authority binding."""

    spec.validate()
    qualified = spec.qualified
    candidate_pe = qualified(spec.candidate_pe)
    import_certificate = qualified(spec.import_certificate)
    imports = qualified(spec.imports)
    relocations = qualified(spec.relocations)
    table_rva = qualified(spec.table_rva)
    count_rva = qualified(spec.count_rva)
    semantic_records = qualified(spec.semantic_records)
    pe_parsed = qualified(spec.pe_parsed)
    imports_parsed = qualified(spec.imports_parsed)
    relocations_parsed = qualified(spec.relocations_parsed)
    table_certificate = qualified(spec.table_certificate)

    return f"""import StageA.RelationalInterpreterMixedContext
import {spec.kernel_data_module}

namespace {spec.namespace}

open StageA.Relational
open StageA.Relational.InterpreterMixedContext
open StageA.Relational.InterpreterNativeWorld

/-- The native candidate uses the exact PE and import inventory already checked
by the interpreter-kernel-data bundle. -/
def generatedCandidateNativeWorldProgram
    (environment : NativeWorldEnvironment) : ExactNativeWorldProgram := {{
  pe := {candidate_pe}
  imports := {imports}
  environment
}}

/-- Loader qualification is computed from the authoritative PE definition.
No PE bytes are duplicated in this binding module. -/
theorem generatedCandidateNativeWorldLoaderImageValid :
    preferredBaseLoaderImageValid {candidate_pe} = true := by
  decide +kernel

/-- Exact static authority for the generated native candidate.  Every field is
bound to checked kernel-data evidence rather than a manifest verdict. -/
def generatedExactNativeCandidateAuthority
    (environment : NativeWorldEnvironment) :
    ExactNativeCandidateAuthority
      (generatedCandidateNativeWorldProgram environment) := {{
  importCertificate := {import_certificate}
  relocations := {relocations}
  tableRva := {table_rva}
  countRva := {count_rva}
  semanticRecords := {semantic_records}
  peParsed := by
    simpa [generatedCandidateNativeWorldProgram] using {pe_parsed}
  importsBound := by
    rfl
  importsParsed := by
    simpa [generatedCandidateNativeWorldProgram] using {imports_parsed}
  relocationsParsed := by
    simpa [generatedCandidateNativeWorldProgram] using {relocations_parsed}
  loaderImageValid := by
    simpa [generatedCandidateNativeWorldProgram] using
      generatedCandidateNativeWorldLoaderImageValid
  table := by
    simpa [generatedCandidateNativeWorldProgram] using {table_certificate}
}}

end {spec.namespace}
"""


def write_relational_interpreter_mixed_authority(
    out: Path | str, spec: InterpreterMixedAuthoritySpec
) -> Path:
    """Write the generated authority module below ``out/StageA``."""

    spec.validate()
    stage_a = Path(out) / "StageA"
    stage_a.mkdir(parents=True, exist_ok=True)
    destination = stage_a / f"{spec.output_module}.lean"
    destination.write_text(
        relational_interpreter_mixed_authority_source(spec), encoding="utf-8"
    )
    return destination


__all__ = [
    "INTERPRETER_MIXED_AUTHORITY_MODULE",
    "InterpreterMixedAuthorityGenerationError",
    "InterpreterMixedAuthoritySpec",
    "relational_interpreter_mixed_authority_source",
    "write_relational_interpreter_mixed_authority",
]
