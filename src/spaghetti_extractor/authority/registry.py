"""Fail-closed registry for the authority-family v3 phases."""

from __future__ import annotations

from collections.abc import Iterable, Iterator, Mapping
from dataclasses import dataclass
from types import MappingProxyType

from ..phase_framework_v3 import PhaseDefinitionV3
from ._schema import fail
from .callbacks import CALLBACK_AUTHORITY_PHASE_V3
from .exact_units import EXACT_UNITS_PHASE_V3
from .exceptional_transitions import EXCEPTIONAL_TRANSITIONS_PHASE_V3
from .external_site_checker import CANONICAL_EXTERNAL_SITES_PHASE_V3
from .fallback_coverage import FALLBACK_COVERAGE_PHASE_V3
from .final_authority import FINAL_AUTHORITY_PHASE_V3
from .inductive import (
    INDUCTIVE_AUTHORITY_PHASE_V3,
)
from .isa_qualification import ISA_QUALIFICATION_PHASE_V3
from .memory_versions import MEMORY_VERSIONS_PHASE_V3
from .root_closure import LAUNCH_ROOT_CLOSURE_PHASE_V3
from .semantic_index import SEMANTIC_INDEX_PHASE_V3
from .structural_targets import STRUCTURAL_TARGETS_PHASE_V3
from .target_certificate_checker import INDIRECT_TARGET_CERTIFICATES_PHASE_V3
from .transition_summaries import TRANSITION_SUMMARIES_PHASE_V3


REQUIRED_AUTHORITY_PHASE_NAMES_V3 = frozenset(
    {
        "exact-units-v3",
        "semantic-index-v3",
        "canonical-external-sites-v3",
        "callback-authority-v3",
        "exceptional-transitions-v3",
        "fallback-coverage-v3",
        "final-authority-v3",
        "inductive-authority-v3",
        "indirect-target-certificates-v3",
        "memory-versions-v3",
        "launch-root-closure-v3",
        "isa-qualification-v3",
        "structural-target-proposals-v3",
        "transition-summaries-v3",
    }
)


@dataclass(frozen=True)
class AuthorityPhaseRegistryV3:
    """Immutable phase inventory checked for uniqueness and total coverage."""

    _by_name: Mapping[str, PhaseDefinitionV3]

    @classmethod
    def create(
        cls, phases: Iterable[PhaseDefinitionV3]
    ) -> "AuthorityPhaseRegistryV3":
        rows = tuple(phases)
        if any(not isinstance(row, PhaseDefinitionV3) for row in rows):
            fail(
                "invalid_phase_registry",
                "authority registry contains a non-PhaseDefinitionV3 value",
                "register only typed v3 phase definitions",
            )
        by_name = {row.name: row for row in rows}
        if len(by_name) != len(rows):
            fail(
                "duplicate_phase_registration",
                "authority registry repeats a phase name",
                "register each stable phase name exactly once",
            )
        output_kinds = [row.output_artifact_kind for row in rows]
        if len(set(output_kinds)) != len(output_kinds):
            fail(
                "duplicate_artifact_producer",
                "authority registry has multiple producers for one artifact kind",
                "give each registered artifact kind one phase owner",
            )
        missing_checks = sorted(
            row.name for row in rows if row.completeness is None
        )
        if missing_checks:
            fail(
                "missing_completeness_hook",
                f"authority phases lack completeness checks {missing_checks!r}",
                "attach an independent fail-closed completeness hook to every phase",
            )
        return cls(MappingProxyType(dict(sorted(by_name.items()))))

    def require_complete_family(self) -> None:
        actual = frozenset(self._by_name)
        if actual != REQUIRED_AUTHORITY_PHASE_NAMES_V3:
            fail(
                "incomplete_phase_registry",
                "authority registry differs: "
                f"missing={sorted(REQUIRED_AUTHORITY_PHASE_NAMES_V3-actual)!r}, "
                f"unexpected={sorted(actual-REQUIRED_AUTHORITY_PHASE_NAMES_V3)!r}",
                "register exactly the complete authority-family v3 inventory",
            )

    def get(self, name: str) -> PhaseDefinitionV3:
        try:
            return self._by_name[name]
        except KeyError:
            fail(
                "unregistered_phase",
                f"authority phase {name!r} is not registered",
                "select a name from AUTHORITY_PHASE_REGISTRY_V3.names",
            )

    @property
    def names(self) -> tuple[str, ...]:
        return tuple(self._by_name)

    def __iter__(self) -> Iterator[PhaseDefinitionV3]:
        return iter(self._by_name.values())


AUTHORITY_PHASE_REGISTRY_V3 = AuthorityPhaseRegistryV3.create(
    (
        EXACT_UNITS_PHASE_V3,
        SEMANTIC_INDEX_PHASE_V3,
        TRANSITION_SUMMARIES_PHASE_V3,
        MEMORY_VERSIONS_PHASE_V3,
        STRUCTURAL_TARGETS_PHASE_V3,
        INDIRECT_TARGET_CERTIFICATES_PHASE_V3,
        INDUCTIVE_AUTHORITY_PHASE_V3,
        CANONICAL_EXTERNAL_SITES_PHASE_V3,
        CALLBACK_AUTHORITY_PHASE_V3,
        LAUNCH_ROOT_CLOSURE_PHASE_V3,
        EXCEPTIONAL_TRANSITIONS_PHASE_V3,
        ISA_QUALIFICATION_PHASE_V3,
        FALLBACK_COVERAGE_PHASE_V3,
        FINAL_AUTHORITY_PHASE_V3,
    )
)
AUTHORITY_PHASE_REGISTRY_V3.require_complete_family()


__all__ = [
    "AUTHORITY_PHASE_REGISTRY_V3",
    "AuthorityPhaseRegistryV3",
    "REQUIRED_AUTHORITY_PHASE_NAMES_V3",
]
