"""Assemble a checked one-sided source execution domain in Lean.

The generator does not infer reachability or manufacture invariant facts.  It
only packages explicitly named Lean declarations into the stable
``OriginalInvariantDomainCertificate`` interface and exports its derived
domain, decoded-step admissibility, and raw-EIP closure.  A separate generated
module owns the axiom audit so consumers can cache the proof module without
embedding diagnostic commands in it.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, fields
from pathlib import Path

from ...errors import StageAInputError


SOURCE_EXECUTION_DOMAIN_MODULE = "GeneratedSourceExecutionDomain"
SOURCE_EXECUTION_DOMAIN_AUDIT_MODULE = "GeneratedSourceExecutionDomainAudit"

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
        "where",
        "with",
    }
)


class SourceExecutionDomainGenerationError(StageAInputError):
    """A requested source-domain declaration or module is malformed."""


@dataclass(frozen=True)
class SourceExecutionDomainSpec:
    """Checked declarations used to assemble one original execution domain."""

    imports: tuple[str, ...]
    program: str
    root: str
    invariant: str
    root_holds: str
    blocks_excluded: str
    raw_concretizable: str
    instruction_semantics_adequate: str
    namespace: str = "StageA.GeneratedRelational.SourceExecutionDomain"
    output_module: str = SOURCE_EXECUTION_DOMAIN_MODULE
    audit_module: str = SOURCE_EXECUTION_DOMAIN_AUDIT_MODULE
    certificate_name: str = "generatedOriginalInvariantDomainCertificate"
    domain_name: str = "generatedSourceExecutionDomain"
    decoded_admissibility_name: str = (
        "generatedDecodedSemanticStepsAdmissible"
    )
    raw_eip_closure_name: str = "generatedRawEipLeftStepClosed"

    def validate(self) -> None:
        if not self.imports:
            raise SourceExecutionDomainGenerationError(
                "imports must contain at least one StageA module"
            )
        if len(set(self.imports)) != len(self.imports):
            raise SourceExecutionDomainGenerationError(
                "imports must not contain duplicates"
            )
        for module in self.imports:
            if not _valid_stage_a_module(module):
                raise SourceExecutionDomainGenerationError(
                    "imports must contain canonical StageA modules"
                )

        local_fields = {
            "output_module",
            "audit_module",
            "certificate_name",
            "domain_name",
            "decoded_admissibility_name",
            "raw_eip_closure_name",
        }
        for field in fields(self):
            if field.name == "imports":
                continue
            value = getattr(self, field.name)
            if field.name in local_fields:
                valid = _valid_local_name(value)
                expected = "a canonical local Lean identifier"
            else:
                valid = _valid_identifier(value)
                expected = "a canonical Lean identifier"
            if not valid:
                raise SourceExecutionDomainGenerationError(
                    f"{field.name} must be {expected}"
                )

        if self.output_module == self.audit_module:
            raise SourceExecutionDomainGenerationError(
                "output_module and audit_module must be distinct"
            )
        generated_names = (
            self.certificate_name,
            self.domain_name,
            self.decoded_admissibility_name,
            self.raw_eip_closure_name,
        )
        if len(set(generated_names)) != len(generated_names):
            raise SourceExecutionDomainGenerationError(
                "generated declaration names must be distinct"
            )


@dataclass(frozen=True)
class SourceExecutionDomainModules:
    """Paths of the generated proof and detached audit modules."""

    proof: Path
    audit: Path


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


def _ordered_imports(spec: SourceExecutionDomainSpec) -> tuple[str, ...]:
    modules = (
        *spec.imports,
        "StageA.RelationalSourceExecutionDomain",
        "StageA.RelationalSourceRawEIP",
    )
    return tuple(dict.fromkeys(modules))


def source_execution_domain_source(spec: SourceExecutionDomainSpec) -> str:
    """Emit the deterministic checked-domain assembly module."""

    spec.validate()
    imports = "\n".join(
        f"import {module}" for module in _ordered_imports(spec)
    )
    return f"""{imports}

namespace {spec.namespace}

open StageA.Relational
open StageA.Relational.OriginalExecutionInvariant
open StageA.Relational.SourceWorld
open StageA.Relational.SourceWorld.InterpreterKernel

noncomputable section

/-- This value only assembles its four explicitly checked evidence inputs. -/
def {spec.certificate_name} :
    OriginalInvariantDomainCertificate {spec.program} {spec.root} := {{
  invariant := {spec.invariant}
  rootHolds := {spec.root_holds}
  blocksExcluded := {spec.blocks_excluded}
  rawConcretizable := {spec.raw_concretizable}
}}

def {spec.domain_name} :
    CheckedExecutionDomain {spec.program} {spec.root} :=
  {spec.certificate_name}.domain

theorem {spec.decoded_admissibility_name} :
    DecodedSemanticStepsAdmissible {spec.program} {spec.domain_name} :=
  {spec.certificate_name}.decodedSemanticStepsAdmissible
    {spec.instruction_semantics_adequate}

theorem {spec.raw_eip_closure_name} :
    RawEipLeftStepClosed {spec.program} {spec.root} {spec.domain_name} :=
  {spec.certificate_name}.rawEipSuccessorConcretizable

end
end {spec.namespace}
"""


def source_execution_domain_audit_source(
    spec: SourceExecutionDomainSpec,
) -> str:
    """Emit a detached axiom audit for every exported proof artifact."""

    spec.validate()
    qualified = (
        f"{spec.namespace}.{spec.certificate_name}",
        f"{spec.namespace}.{spec.domain_name}",
        f"{spec.namespace}.{spec.decoded_admissibility_name}",
        f"{spec.namespace}.{spec.raw_eip_closure_name}",
    )
    audits = "\n".join(f"#print axioms {name}" for name in qualified)
    return f"""import StageA.{spec.output_module}

{audits}
"""


def write_source_execution_domain(
    out: Path | str, spec: SourceExecutionDomainSpec
) -> SourceExecutionDomainModules:
    """Write the checked-domain proof and audit modules below ``out/StageA``."""

    spec.validate()
    stage_a = Path(out) / "StageA"
    stage_a.mkdir(parents=True, exist_ok=True)
    proof = stage_a / f"{spec.output_module}.lean"
    audit = stage_a / f"{spec.audit_module}.lean"
    proof.write_text(source_execution_domain_source(spec), encoding="ascii")
    audit.write_text(
        source_execution_domain_audit_source(spec), encoding="ascii"
    )
    return SourceExecutionDomainModules(proof=proof, audit=audit)


__all__ = [
    "SOURCE_EXECUTION_DOMAIN_AUDIT_MODULE",
    "SOURCE_EXECUTION_DOMAIN_MODULE",
    "SourceExecutionDomainGenerationError",
    "SourceExecutionDomainModules",
    "SourceExecutionDomainSpec",
    "source_execution_domain_audit_source",
    "source_execution_domain_source",
    "write_source_execution_domain",
]
