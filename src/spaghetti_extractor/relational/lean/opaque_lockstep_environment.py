"""Generate checked data for prototype-free exact-lockstep environments.

The artifact describes machine-level call sites only.  It never asserts that
an external environment satisfies the generated proposition and therefore has
no Stage A acceptance authority on its own.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from ...errors import StageAInputError
from ..full_machine_lockstep import FullMachineLockstepImportIdentity
from .expressions import _lean_external_target
from .lockstep_environment import _lean_exact_state_invariant


OPAQUE_LOCKSTEP_ENVIRONMENT_FORMAT = (
    "stage-a-relational-opaque-lockstep-environment-v2"
)

_ROOT_FIELDS = frozenset({"format", "call_sites"})
_SITE_FIELDS = frozenset({
    "id",
    "source_target_id",
    "continuation_target_id",
    "disposition",
    "import",
    "original_iat_rva",
    "candidate_iat_rva",
    "argument_sources",
    "memory_observations",
    "boundary_invariant",
    "target_invariant",
})
_PAIR_FIELDS = frozenset({"original", "candidate"})
_MEMORY_FIELDS = frozenset({
    "argument_index",
    "original_offset",
    "candidate_offset",
    "bytes",
    "relation",
})
_REGISTERS = frozenset({"eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp"})
_MEMORY_RELATIONS = frozenset({"exact_bytes", "related_words"})
_DISPOSITIONS = frozenset({"returns", "terminates"})


def _object(value: object, context: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise StageAInputError(f"{context} must be a JSON object")
    if any(not isinstance(key, str) for key in value):
        raise StageAInputError(f"{context} field names must be strings")
    return value


def _exact_fields(
    value: Mapping[str, Any], expected: frozenset[str], context: str
) -> None:
    missing = sorted(expected - set(value))
    unexpected = sorted(set(value) - expected)
    if missing:
        raise StageAInputError(
            f"{context} is missing required fields: {', '.join(missing)}"
        )
    if unexpected:
        raise StageAInputError(
            f"{context} has unexpected fields: {', '.join(unexpected)}"
        )


def _natural(value: object, context: str, *, positive: bool = False) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise StageAInputError(f"{context} must be a natural number")
    if positive and value == 0:
        raise StageAInputError(f"{context} must be positive")
    if value >= 2**32:
        raise StageAInputError(f"{context} must fit in an unsigned 32-bit word")
    return value


@dataclass(frozen=True)
class OpaqueArgumentSourceSpec:
    kind: str
    register: str | None = None
    offset: int | None = None
    value: int | None = None

    @classmethod
    def parse(cls, value: object, context: str) -> "OpaqueArgumentSourceSpec":
        source = _object(value, context)
        kind = source.get("kind")
        if kind == "register":
            _exact_fields(source, frozenset({"kind", "register"}), context)
            register = source["register"]
            if not isinstance(register, str) or register not in _REGISTERS:
                raise StageAInputError(f"{context} register is unsupported")
            return cls(kind=kind, register=register)
        if kind == "stack_word":
            _exact_fields(source, frozenset({"kind", "offset"}), context)
            return cls(
                kind=kind,
                offset=_natural(source["offset"], f"{context} offset"),
            )
        if kind == "constant":
            _exact_fields(source, frozenset({"kind", "value"}), context)
            return cls(
                kind=kind,
                value=_natural(source["value"], f"{context} value"),
            )
        raise StageAInputError(
            f"{context} kind must be register, stack_word, or constant"
        )

    def lean(self) -> str:
        if self.kind == "register":
            return f".register .{self.register}"
        if self.kind == "constant":
            return f".constant (BitVec.ofNat 32 {self.value})"
        return f".stackWord {self.offset}"


@dataclass(frozen=True)
class OpaqueArgumentSourcePairSpec:
    original: OpaqueArgumentSourceSpec
    candidate: OpaqueArgumentSourceSpec

    @classmethod
    def parse(
        cls, value: object, context: str
    ) -> "OpaqueArgumentSourcePairSpec":
        pair = _object(value, context)
        _exact_fields(pair, _PAIR_FIELDS, context)
        return cls(
            original=OpaqueArgumentSourceSpec.parse(
                pair["original"], f"{context} original"
            ),
            candidate=OpaqueArgumentSourceSpec.parse(
                pair["candidate"], f"{context} candidate"
            ),
        )

    def lean(self) -> str:
        return (
            "{ original := "
            + self.original.lean()
            + ", candidate := "
            + self.candidate.lean()
            + " }"
        )


@dataclass(frozen=True)
class OpaqueMemoryObservationSpec:
    argument_index: int
    original_offset: int
    candidate_offset: int
    bytes: int
    relation: str

    @classmethod
    def parse(
        cls, value: object, context: str, *, argument_count: int
    ) -> "OpaqueMemoryObservationSpec":
        observation = _object(value, context)
        _exact_fields(observation, _MEMORY_FIELDS, context)
        argument_index = _natural(
            observation["argument_index"], f"{context} argument_index"
        )
        if argument_index >= argument_count:
            raise StageAInputError(
                f"{context} argument_index is outside argument_sources"
            )
        relation = observation["relation"]
        if not isinstance(relation, str) or relation not in _MEMORY_RELATIONS:
            raise StageAInputError(f"{context} relation is unsupported")
        byte_count = _natural(
            observation["bytes"], f"{context} bytes", positive=True
        )
        if relation == "related_words" and byte_count % 4:
            raise StageAInputError(
                f"{context} related_words byte count must be divisible by four"
            )
        return cls(
            argument_index=argument_index,
            original_offset=_natural(
                observation["original_offset"], f"{context} original_offset"
            ),
            candidate_offset=_natural(
                observation["candidate_offset"], f"{context} candidate_offset"
            ),
            bytes=byte_count,
            relation=relation,
        )

    def lean(self) -> str:
        relation = "exactBytes" if self.relation == "exact_bytes" else "relatedWords"
        return (
            "{ argumentIndex := "
            f"{self.argument_index}, originalOffset := {self.original_offset}, "
            f"candidateOffset := {self.candidate_offset}, bytes := {self.bytes}, "
            f"relation := .{relation} }}"
        )


@dataclass(frozen=True)
class OpaqueLockstepCallSiteSpec:
    id: int
    source_target_id: int
    continuation_target_id: int
    disposition: str
    imported: dict[str, str | int]
    original_iat_rva: int
    candidate_iat_rva: int
    argument_sources: tuple[OpaqueArgumentSourcePairSpec, ...]
    memory_observations: tuple[OpaqueMemoryObservationSpec, ...]
    boundary_invariant: str
    target_invariant: str


@dataclass(frozen=True)
class OpaqueLockstepEnvironmentArtifact:
    call_sites: tuple[OpaqueLockstepCallSiteSpec, ...]


def parse_opaque_lockstep_environment_artifact(
    payload: object,
) -> OpaqueLockstepEnvironmentArtifact:
    root = _object(payload, "opaque lockstep environment artifact")
    _exact_fields(root, _ROOT_FIELDS, "opaque lockstep environment artifact")
    if root["format"] != OPAQUE_LOCKSTEP_ENVIRONMENT_FORMAT:
        raise StageAInputError("unsupported opaque lockstep environment format")
    raw_sites = root["call_sites"]
    if not isinstance(raw_sites, list) or not raw_sites:
        raise StageAInputError("opaque lockstep call_sites must be a non-empty array")

    sites: list[OpaqueLockstepCallSiteSpec] = []
    for index, raw_site in enumerate(raw_sites):
        context = f"opaque lockstep call site {index}"
        site = _object(raw_site, context)
        _exact_fields(site, _SITE_FIELDS, context)
        imported = FullMachineLockstepImportIdentity.parse(
            site["import"], context=f"{context} import"
        ).to_payload()
        disposition = site["disposition"]
        if not isinstance(disposition, str) or disposition not in _DISPOSITIONS:
            raise StageAInputError(f"{context} disposition is unsupported")
        raw_sources = site["argument_sources"]
        if not isinstance(raw_sources, list):
            raise StageAInputError(f"{context} argument_sources must be an array")
        sources = tuple(
            OpaqueArgumentSourcePairSpec.parse(source, f"{context} argument {item_index}")
            for item_index, source in enumerate(raw_sources)
        )
        raw_observations = site["memory_observations"]
        if not isinstance(raw_observations, list):
            raise StageAInputError(f"{context} memory_observations must be an array")
        observations = tuple(
            OpaqueMemoryObservationSpec.parse(
                observation,
                f"{context} memory observation {item_index}",
                argument_count=len(sources),
            )
            for item_index, observation in enumerate(raw_observations)
        )
        if len(set(observations)) != len(observations):
            raise StageAInputError(f"{context} has duplicate memory observations")
        sites.append(OpaqueLockstepCallSiteSpec(
            id=_natural(site["id"], f"{context} id"),
            source_target_id=_natural(
                site["source_target_id"], f"{context} source_target_id"
            ),
            continuation_target_id=_natural(
                site["continuation_target_id"],
                f"{context} continuation_target_id",
            ),
            disposition=disposition,
            imported=dict(imported),
            original_iat_rva=_natural(
                site["original_iat_rva"], f"{context} original_iat_rva",
                positive=True,
            ),
            candidate_iat_rva=_natural(
                site["candidate_iat_rva"], f"{context} candidate_iat_rva",
                positive=True,
            ),
            argument_sources=sources,
            memory_observations=observations,
            boundary_invariant=_lean_exact_state_invariant(
                site["boundary_invariant"], f"{context} boundary_invariant"
            ),
            target_invariant=_lean_exact_state_invariant(
                site["target_invariant"], f"{context} target_invariant"
            ),
        ))

    ids = [site.id for site in sites]
    if len(set(ids)) != len(ids):
        raise StageAInputError("opaque lockstep call site ids are ambiguous")
    if ids != sorted(ids):
        raise StageAInputError(
            "opaque lockstep call sites must be in canonical site-id order"
        )
    return OpaqueLockstepEnvironmentArtifact(tuple(sites))


def relational_opaque_lockstep_environment_source(payload: object) -> str:
    """Render checked static call-site data for later acceptance integration."""
    artifact = parse_opaque_lockstep_environment_artifact(payload)
    definitions: list[str] = []
    for site in artifact.call_sites:
        sources = ", ".join(source.lean() for source in site.argument_sources)
        observations = ", ".join(
            observation.lean() for observation in site.memory_observations
        )
        definitions.append(
            f"def opaqueLockstepCallSite{site.id} : OpaqueLockstepCallSite := {{\n"
            f"  id := {site.id}\n"
            f"  sourceTargetId := {site.source_target_id}\n"
            f"  continuationTargetId := {site.continuation_target_id}\n"
            f"  disposition := .{site.disposition}\n"
            f"  imported := {_lean_external_target(site.imported)}\n"
            f"  originalIatRva := {site.original_iat_rva}\n"
            f"  candidateIatRva := {site.candidate_iat_rva}\n"
            f"  argumentSources := [{sources}]\n"
            f"  memoryObservations := [{observations}]\n"
            f"  boundaryInvariant := {site.boundary_invariant}\n"
            f"  targetInvariant := {site.target_invariant}\n"
            "}"
        )
    names = ", ".join(
        f"opaqueLockstepCallSite{site.id}" for site in artifact.call_sites
    )
    return (
        "import StageA.RelationalOpaqueLockstepEnvironment\n\n"
        "namespace StageA.GeneratedRelational\n\n"
        "open StageA.Formal StageA.Relational\n\n"
        + "\n\n".join(definitions)
        + "\n\n"
        "def opaqueLockstepCallSites : List OpaqueLockstepCallSite :=\n"
        f"  [{names}]\n\n"
        "theorem opaqueLockstepCallSiteIdsUniqueChecked :\n"
        "    opaqueLockstepCallSiteIdsUnique opaqueLockstepCallSites = true := by\n"
        "  decide\n\n"
        "theorem opaqueLockstepCallSiteShapesChecked :\n"
        "    opaqueLockstepCallSites.all OpaqueLockstepCallSite.shapeValid = true := by\n"
        "  decide\n\n"
        "end StageA.GeneratedRelational\n"
    )


def relational_opaque_lockstep_acceptance_source() -> str:
    """Render the acceptance premise without manufacturing proof evidence."""
    return """import StageA.RelationalOpaqueLockstepEnvironment

namespace StageA.Relational

/-- Whole-program premise for the prototype-free exact-lockstep profile.
`externalRefines` retains the current decoded-world operational interface.  The
opaque certificate, coverage check, and boundary theorem are separate so no
generated Python status can establish an external result relation. -/
structure OpaqueLockstepExternalEnvironmentsRefine
    (context : StaticProofContext) (sites : List ExternalCallSiteContract)
    (opaqueSites : List OpaqueLockstepCallSite)
    (requiredSiteIds : List Nat)
    (original candidate : WorldExternalEnvironment) : Prop where
  externalRefines : ExternalEnvironmentRefines context sites original candidate
  checked : CheckedOpaqueLockstepEnvironment context opaqueSites original candidate
  sitesCovered :
    opaqueLockstepCallSitesCoverExternalSiteIds context sites opaqueSites
      requiredSiteIds = true
  boundaryEstablished : forall site contract opaqueSite,
    site \u2208 sites -> opaqueSite \u2208 opaqueSites ->
    machineImportCallContractById? context site.machineContractId = some contract ->
    opaqueSite.matchesExternalCallSite context site = true ->
    forall originalEvent candidateEvent,
      ExternalCallBoundaryRelated context site contract originalEvent candidateEvent ->
      OpaqueLockstepBoundaryRelated context opaqueSite originalEvent candidateEvent

/-- Use the same event index on both environments and obtain the opaque
successor relation, including nested runtime-frame preservation. -/
theorem OpaqueLockstepExternalEnvironmentsRefine.atReturning
    (context : StaticProofContext) (sites : List ExternalCallSiteContract)
    (opaqueSites : List OpaqueLockstepCallSite)
    (requiredSiteIds : List Nat)
    (original candidate : WorldExternalEnvironment)
    (refines : OpaqueLockstepExternalEnvironmentsRefine context sites opaqueSites
      requiredSiteIds original candidate)
    (site : ExternalCallSiteContract) (contract : MachineImportCallContract)
    (opaqueSite : OpaqueLockstepCallSite)
    (siteMember : site \u2208 sites) (opaqueMember : opaqueSite \u2208 opaqueSites)
    (resolved : machineImportCallContractById? context site.machineContractId =
      some contract)
    (contractReturns : contract.disposition = .returns)
    (siteMatches : opaqueSite.matchesExternalCallSite context site = true)
    (eventIndex : Nat) (originalEvent candidateEvent : WorldExternalEvent)
    (boundary : ExternalCallBoundaryRelated context site contract
      originalEvent candidateEvent) :
    OpaqueLockstepResultRelated context opaqueSite originalEvent candidateEvent
      (original.result eventIndex originalEvent)
      (candidate.result eventIndex candidateEvent) := by
  have opaqueBoundary := refines.boundaryEstablished site contract opaqueSite
    siteMember opaqueMember resolved siteMatches originalEvent candidateEvent boundary
  have opaqueAt := CheckedOpaqueLockstepEnvironment.at context opaqueSites
    original candidate refines.checked opaqueSite opaqueMember (by
      have matched := siteMatches
      simp only [OpaqueLockstepCallSite.matchesExternalCallSite,
        resolved, Bool.and_eq_true] at matched
      exact opaqueLockstepDispositionsMatch_returns opaqueSite.disposition
        contract.disposition matched.2.2 contractReturns)
  exact opaqueAt eventIndex originalEvent candidateEvent opaqueBoundary

/-- A terminating event is checked at the same event index, but deliberately
does not ask either total environment function for a result that execution
will never consume. -/
theorem OpaqueLockstepExternalEnvironmentsRefine.atTerminating
    (context : StaticProofContext) (sites : List ExternalCallSiteContract)
    (opaqueSites : List OpaqueLockstepCallSite)
    (requiredSiteIds : List Nat)
    (original candidate : WorldExternalEnvironment)
    (refines : OpaqueLockstepExternalEnvironmentsRefine context sites opaqueSites
      requiredSiteIds original candidate)
    (site : ExternalCallSiteContract) (contract : MachineImportCallContract)
    (opaqueSite : OpaqueLockstepCallSite)
    (siteMember : site ∈ sites) (opaqueMember : opaqueSite ∈ opaqueSites)
    (resolved : machineImportCallContractById? context site.machineContractId =
      some contract)
    (contractTerminates : contract.disposition = .terminates)
    (siteMatches : opaqueSite.matchesExternalCallSite context site = true)
    (eventIndex : Nat) (originalEvent candidateEvent : WorldExternalEvent)
    (boundary : ExternalCallBoundaryRelated context site contract
      originalEvent candidateEvent) :
    OpaqueLockstepTerminalEventRelated context opaqueSite eventIndex
      originalEvent candidateEvent := by
  refine ⟨?_, refines.boundaryEstablished site contract opaqueSite
    siteMember opaqueMember resolved siteMatches originalEvent candidateEvent boundary⟩
  have matched := siteMatches
  simp only [OpaqueLockstepCallSite.matchesExternalCallSite,
    resolved, Bool.and_eq_true] at matched
  exact opaqueLockstepDispositionsMatch_terminates opaqueSite.disposition
    contract.disposition matched.2.2 contractTerminates

end StageA.Relational
"""


__all__ = [
    "OPAQUE_LOCKSTEP_ENVIRONMENT_FORMAT",
    "OpaqueLockstepEnvironmentArtifact",
    "parse_opaque_lockstep_environment_artifact",
    "relational_opaque_lockstep_acceptance_source",
    "relational_opaque_lockstep_environment_source",
]
