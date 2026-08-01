"""Generate checked source target-routing component assemblies.

The generator emits data assembly only.  Every named source step and decoded
behavior is bound to the actual Lean evaluator by a universal equality, and a
separate universal theorem equates their canonical local effects.  The stable
Lean kernel composes those facts into full world routing.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, fields
from pathlib import Path

from ...errors import StageAInputError


SOURCE_TARGET_ROUTING_MODULE = "GeneratedSourceTargetRouting"
SOURCE_TARGET_ROUTING_AUDIT_MODULE = "GeneratedSourceTargetRoutingAudit"

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


class SourceTargetRoutingGenerationError(StageAInputError):
    """A target-routing component request is malformed or incomplete."""


@dataclass(frozen=True)
class TargetRoutingComponentSpec:
    """Lean declarations proving the compact effect equality for one target."""

    target_id: int
    source_step: str
    decoded_behavior: str
    source_step_exact: str
    decoded_behavior_exact: str
    effects_exact: str

    def validate(self) -> None:
        if not isinstance(self.target_id, int) or isinstance(self.target_id, bool):
            raise SourceTargetRoutingGenerationError(
                "target_id must be a non-negative integer"
            )
        if self.target_id < 0:
            raise SourceTargetRoutingGenerationError(
                "target_id must be a non-negative integer"
            )
        for field in fields(self):
            if field.name == "target_id":
                continue
            if not _valid_identifier(getattr(self, field.name)):
                raise SourceTargetRoutingGenerationError(
                    f"{field.name} must be a canonical Lean declaration"
                )


@dataclass(frozen=True)
class SourceTargetRoutingSpec:
    """A deterministic finite inventory of target-routing components."""

    imports: tuple[str, ...]
    program: str
    targets: tuple[TargetRoutingComponentSpec, ...]
    namespace: str = "StageA.GeneratedRelational.SourceTargetRouting"
    output_module: str = SOURCE_TARGET_ROUTING_MODULE
    audit_module: str = SOURCE_TARGET_ROUTING_AUDIT_MODULE
    component_prefix: str = "generatedTargetEffectComponents"
    local_effect_prefix: str = "generatedTargetLocalEffectExact"

    def validate(self) -> None:
        if not self.imports:
            raise SourceTargetRoutingGenerationError(
                "imports must contain at least one StageA module"
            )
        if len(set(self.imports)) != len(self.imports):
            raise SourceTargetRoutingGenerationError(
                "imports must not contain duplicates"
            )
        for module in self.imports:
            if not _valid_stage_a_module(module):
                raise SourceTargetRoutingGenerationError(
                    "imports must contain canonical StageA modules"
                )
        if not _valid_identifier(self.program):
            raise SourceTargetRoutingGenerationError(
                "program must be a canonical Lean declaration"
            )
        for name in (
            "namespace",
            "output_module",
            "audit_module",
            "component_prefix",
            "local_effect_prefix",
        ):
            value = getattr(self, name)
            valid = _valid_identifier(value) if name == "namespace" else _valid_local_name(value)
            if not valid:
                raise SourceTargetRoutingGenerationError(
                    f"{name} must be a canonical Lean identifier"
                )
        if self.output_module == self.audit_module:
            raise SourceTargetRoutingGenerationError(
                "output_module and audit_module must be distinct"
            )
        if self.component_prefix == self.local_effect_prefix:
            raise SourceTargetRoutingGenerationError(
                "generated declaration prefixes must be distinct"
            )
        if not self.targets:
            raise SourceTargetRoutingGenerationError(
                "targets must contain at least one checked component"
            )
        for target in self.targets:
            if not isinstance(target, TargetRoutingComponentSpec):
                raise SourceTargetRoutingGenerationError(
                    "targets must contain TargetRoutingComponentSpec values"
                )
            target.validate()
        target_ids = tuple(target.target_id for target in self.targets)
        if target_ids != tuple(sorted(target_ids)):
            raise SourceTargetRoutingGenerationError(
                "targets must be in deterministic target-id order"
            )
        if len(set(target_ids)) != len(target_ids):
            raise SourceTargetRoutingGenerationError(
                "targets must not contain duplicate target identifiers"
            )


@dataclass(frozen=True)
class SourceTargetRoutingModules:
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


def component_name(spec: SourceTargetRoutingSpec, target_id: int) -> str:
    return f"{spec.component_prefix}_{target_id}"


def local_effect_name(spec: SourceTargetRoutingSpec, target_id: int) -> str:
    return f"{spec.local_effect_prefix}_{target_id}"


def source_target_routing_source(spec: SourceTargetRoutingSpec) -> str:
    """Emit deterministic checked component and local-effect declarations."""

    spec.validate()
    imports = "\n".join(
        [
            *(f"import {module}" for module in spec.imports),
            "import StageA.RelationalSourceInterpreterKernel",
        ]
    )
    declarations: list[str] = []
    for target in spec.targets:
        component = component_name(spec, target.target_id)
        local_effect = local_effect_name(spec, target.target_id)
        declarations.append(
            f"""def {component} :
    SuccessfulTargetEffectComponents {spec.program} {target.target_id} := {{
  sourceStep := {target.source_step}
  decodedBehavior := {target.decoded_behavior}
  sourceStepExact := {target.source_step_exact}
  decodedBehaviorExact := {target.decoded_behavior_exact}
  effectsExact := {target.effects_exact}
}}

def {local_effect} : TargetLocalEffectExact {spec.program} {target.target_id} :=
  {component}.toLocalEffectExact"""
        )
    body = "\n\n".join(declarations)
    return f"""{imports}

namespace {spec.namespace}

open StageA.Relational
open StageA.Relational.SourceWorld
open StageA.Relational.SourceWorld.InterpreterKernel

noncomputable section

{body}

end
end {spec.namespace}
"""


def source_target_routing_audit_source(spec: SourceTargetRoutingSpec) -> str:
    """Emit the detached axiom audit for generated local-effect certificates."""

    spec.validate()
    audits = "\n".join(
        f"#print axioms {spec.namespace}.{local_effect_name(spec, target.target_id)}"
        for target in spec.targets
    )
    return f"""import StageA.{spec.output_module}

{audits}
"""


def write_source_target_routing(
    out: Path | str, spec: SourceTargetRoutingSpec
) -> SourceTargetRoutingModules:
    """Write checked routing and detached audit modules below ``out/StageA``."""

    spec.validate()
    stage_a = Path(out) / "StageA"
    stage_a.mkdir(parents=True, exist_ok=True)
    proof = stage_a / f"{spec.output_module}.lean"
    audit = stage_a / f"{spec.audit_module}.lean"
    proof.write_text(source_target_routing_source(spec), encoding="ascii")
    audit.write_text(source_target_routing_audit_source(spec), encoding="ascii")
    return SourceTargetRoutingModules(proof=proof, audit=audit)


__all__ = [
    "SOURCE_TARGET_ROUTING_AUDIT_MODULE",
    "SOURCE_TARGET_ROUTING_MODULE",
    "SourceTargetRoutingGenerationError",
    "SourceTargetRoutingModules",
    "SourceTargetRoutingSpec",
    "TargetRoutingComponentSpec",
    "component_name",
    "local_effect_name",
    "source_target_routing_audit_source",
    "source_target_routing_source",
    "write_source_target_routing",
]
