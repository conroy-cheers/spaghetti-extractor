"""Emit compact checked bindings for the one-sided original carrier.

The generated module contains only two indexed range certificates.  Exact PE,
code-map, decoded-region, and legacy-carrier data stay in their independently
cached modules; Lean rechecks those values and derives both universal lookup
equalities through ``RelationalInterpreterOriginalCarrierBinding``.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from ...errors import StageAInputError


ORIGINAL_CARRIER_BINDING_MODULE = (
    "GeneratedRelationalInterpreterOriginalCarrierBinding"
)
ORIGINAL_CARRIER_BINDING_NAMESPACE = (
    "StageA.GeneratedRelational.InterpreterOriginalCarrierBinding"
)

_LOCAL_IDENTIFIER = re.compile(r"[A-Za-z_][A-Za-z0-9_']*\Z")
_QUALIFIED_IDENTIFIER = re.compile(
    r"[A-Za-z_][A-Za-z0-9_']*(?:\.[A-Za-z_][A-Za-z0-9_']*)*\Z"
)
_STAGE_A_MODULE = re.compile(
    r"StageA\.[A-Za-z_][A-Za-z0-9_']*(?:\.[A-Za-z_][A-Za-z0-9_']*)*\Z"
)
_LEAN_KEYWORDS = {
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
    "opaque",
    "partial",
    "protected",
    "structure",
    "theorem",
    "then",
    "unsafe",
    "where",
    "with",
}


class OriginalCarrierBindingGenerationError(StageAInputError):
    """The requested generated carrier binding is not well formed."""


@dataclass(frozen=True)
class OriginalCarrierBindingSpec:
    """Symbols and finite inventory sizes checked by the generated module."""

    original_module: str
    original_namespace: str
    target_count: int
    address_count: int
    context_symbol: str = "generatedOriginalStaticContext"
    program_symbol: str = "generatedOriginalDecodedProgram"
    authority_symbol: str = "generatedExactOriginalDecodedAuthority"
    output_module: str = ORIGINAL_CARRIER_BINDING_MODULE
    namespace: str = ORIGINAL_CARRIER_BINDING_NAMESPACE
    term_prefix: str = "generatedOriginal"

    def validate(self) -> None:
        if not _STAGE_A_MODULE.fullmatch(self.original_module):
            raise OriginalCarrierBindingGenerationError(
                "original_module must be a canonical StageA module"
            )
        _require_qualified_identifier(
            self.original_namespace, "original_namespace"
        )
        for label, value in (
            ("context_symbol", self.context_symbol),
            ("program_symbol", self.program_symbol),
            ("authority_symbol", self.authority_symbol),
            ("output_module", self.output_module),
            ("term_prefix", self.term_prefix),
        ):
            _require_local_identifier(value, label)
        _require_qualified_identifier(self.namespace, "namespace")
        _require_count(self.target_count, "target_count")
        _require_count(self.address_count, "address_count")

    def original(self, symbol: str) -> str:
        return f"{self.original_namespace}.{symbol}"


@dataclass(frozen=True)
class OriginalCarrierBindingTerms:
    """Stable exported terms consumed by the final one-sided mixed profile."""

    proposal: str
    checked: str
    certificate: str
    indexed_resolution: str
    return_resolution: str
    finite_binding: str
    exact_binding: str
    mixed_binding: str

    @classmethod
    def from_spec(
        cls, spec: OriginalCarrierBindingSpec
    ) -> "OriginalCarrierBindingTerms":
        prefix = spec.term_prefix
        return cls(
            proposal=f"{prefix}CarrierBindingProposal",
            checked=f"{prefix}CarrierBindingChecked",
            certificate=f"{prefix}CarrierBindingCertificate",
            indexed_resolution=f"{prefix}IndexedResolution",
            return_resolution=f"{prefix}ReturnResolution",
            finite_binding=f"{prefix}FiniteCarrierBinding",
            exact_binding=f"{prefix}ExactCarrierBinding",
            mixed_binding=f"{prefix}ExactMixedProgramBinding",
        )

    def qualified(self, namespace: str, term: str) -> str:
        return f"{namespace}.{term}"


@dataclass(frozen=True)
class GeneratedOriginalCarrierBinding:
    module: str
    namespace: str
    source: str
    terms: OriginalCarrierBindingTerms


def generate_original_carrier_binding(
    spec: OriginalCarrierBindingSpec,
) -> GeneratedOriginalCarrierBinding:
    """Generate a kernel-checkable exact original carrier binding module."""

    spec.validate()
    terms = OriginalCarrierBindingTerms.from_spec(spec)
    context = spec.original(spec.context_symbol)
    program = spec.original(spec.program_symbol)
    authority = spec.original(spec.authority_symbol)
    target_ranges = _lean_ranges(spec.target_count)
    address_ranges = _lean_ranges(spec.address_count)
    source = f"""import StageA.RelationalInterpreterOriginalCarrierBinding
import {spec.original_module}

namespace {spec.namespace}

open StageA.Formal StageA.Relational
open StageA.Relational.InterpreterMixedOriginal
open StageA.Relational.InterpreterMixedWorldBridge
open StageA.Relational.InterpreterOriginalCarrierBinding

def {terms.proposal} : Proposal := {{
  entryChecks := {{ ranges := {target_ranges} }}
  addressChecks := {{ ranges := {address_ranges} }}
}}

theorem {terms.checked} :
    forall (environment : WorldExternalEnvironment)
      (protocolEnvironment : WorldExternalProtocolEnvironment)
      (externalCallSites : List ExternalCallSiteContract),
      {terms.proposal}.checked {context}
        ({program} environment protocolEnvironment externalCallSites) = true := by
  intro environment protocolEnvironment externalCallSites
  change {terms.proposal}.checked {context}
    ({program}
      {{ result := fun _ event => {{ state := event.state, world := event.world }} }}
      {{ action := fun request =>
          .returned {{ state := request.state, world := request.world }} }}
      []) = true
  decide +kernel

def {terms.certificate}
    (environment : WorldExternalEnvironment)
    (protocolEnvironment : WorldExternalProtocolEnvironment)
    (externalCallSites : List ExternalCallSiteContract) :
    Certificate {context}
      ({program} environment protocolEnvironment externalCallSites) := {{
  authority := {authority}
  proposal := {terms.proposal}
  checked := {terms.checked} environment protocolEnvironment externalCallSites
}}

theorem {terms.indexed_resolution}
    (environment : WorldExternalEnvironment)
    (protocolEnvironment : WorldExternalProtocolEnvironment)
    (externalCallSites : List ExternalCallSiteContract) (address : Word) :
    ({program} environment protocolEnvironment
      externalCallSites).context.codeMap.resolveRawEip false
        {context}.pe.imageBase address =
      {context}.codeMap.resolveRawEip {context}.pe.imageBase address :=
  ({terms.certificate} environment protocolEnvironment
    externalCallSites).indexedResolution address

theorem {terms.return_resolution}
    (environment : WorldExternalEnvironment)
    (protocolEnvironment : WorldExternalProtocolEnvironment)
    (externalCallSites : List ExternalCallSiteContract) (address : Word) :
    resolveMappedCodeTarget false {context}.pe.imageBase
        ({program} environment protocolEnvironment
          externalCallSites).context.codeMap.entries.toList address =
      {context}.codeMap.resolveRawEip {context}.pe.imageBase address :=
  ({terms.certificate} environment protocolEnvironment
    externalCallSites).returnResolution address

def {terms.finite_binding}
    (environment : WorldExternalEnvironment)
    (protocolEnvironment : WorldExternalProtocolEnvironment)
    (externalCallSites : List ExternalCallSiteContract) :
    GeneratedOriginalFiniteCarrierBinding {context}
      ({program} environment protocolEnvironment externalCallSites) :=
  ({terms.certificate} environment protocolEnvironment
    externalCallSites).toFiniteBinding

def {terms.exact_binding}
    (environment : WorldExternalEnvironment)
    (protocolEnvironment : WorldExternalProtocolEnvironment)
    (externalCallSites : List ExternalCallSiteContract) :
    ExactDecodedOriginalCarrierBinding {context}
      ({program} environment protocolEnvironment externalCallSites) :=
  ({terms.certificate} environment protocolEnvironment
    externalCallSites).toExactBinding

def {terms.mixed_binding}
    (environment : WorldExternalEnvironment)
    (protocolEnvironment : WorldExternalProtocolEnvironment)
    (externalCallSites : List ExternalCallSiteContract) :
    ExactMixedProgramBinding {context}
      ({program} environment protocolEnvironment externalCallSites) :=
  ({terms.certificate} environment protocolEnvironment
    externalCallSites).toMixedBinding

#print axioms {terms.indexed_resolution}
#print axioms {terms.return_resolution}
#print axioms {terms.exact_binding}
#print axioms {terms.mixed_binding}

end {spec.namespace}
"""
    return GeneratedOriginalCarrierBinding(
        module=spec.output_module,
        namespace=spec.namespace,
        source=source,
        terms=terms,
    )


def write_original_carrier_binding(
    lean_root: Path, spec: OriginalCarrierBindingSpec
) -> Path:
    """Write the generated module beneath ``lean_root/StageA``."""

    generated = generate_original_carrier_binding(spec)
    stage_a = lean_root / "StageA"
    stage_a.mkdir(parents=True, exist_ok=True)
    path = stage_a / f"{generated.module}.lean"
    path.write_text(generated.source, encoding="utf-8")
    return path


def _lean_ranges(count: int) -> str:
    if count == 0:
        return "[]"
    return f"[{{ start := 0, size := {count} }}]"


def _require_count(value: int, label: str) -> None:
    if isinstance(value, bool) or not isinstance(value, int):
        raise OriginalCarrierBindingGenerationError(f"{label} must be an integer")
    if not 0 <= value < 2**32:
        raise OriginalCarrierBindingGenerationError(
            f"{label} must fit an unsigned 32-bit value"
        )


def _require_local_identifier(value: str, label: str) -> None:
    if not _LOCAL_IDENTIFIER.fullmatch(value) or value in _LEAN_KEYWORDS:
        raise OriginalCarrierBindingGenerationError(
            f"{label} must be a canonical local Lean identifier"
        )


def _require_qualified_identifier(value: str, label: str) -> None:
    if not _QUALIFIED_IDENTIFIER.fullmatch(value) or any(
        component in _LEAN_KEYWORDS for component in value.split(".")
    ):
        raise OriginalCarrierBindingGenerationError(
            f"{label} must be a canonical qualified Lean identifier"
        )
