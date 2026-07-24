"""Generate static site bindings for callable external execution.

The generated data contains no event order, arguments, result values, or
observations. Those are derived by the Lean runtime transition relation.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from ...errors import StageAInputError
from .callable_external_capability import CallableArgumentSourceSpec


CALLABLE_EXTERNAL_EXECUTION_FORMAT = "stage-a-callable-external-execution-v1"
CALLABLE_EXTERNAL_PROGRAM_MODULE = "GeneratedCallableExternalProgram"

_ROOT_FIELDS = frozenset({"format", "sites"})
_ORDINARY_SITE_FIELDS = frozenset({
    "kind",
    "id",
    "source_target_id",
    "machine_contract_id",
    "argument_sources",
})
_RESOLVER_SITE_FIELDS = _ORDINARY_SITE_FIELDS | frozenset({
    "resolver_contract_id",
    "capability_id",
})


def _object(value: object, context: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise StageAInputError(f"{context} must be a JSON object")
    if any(not isinstance(key, str) for key in value):
        raise StageAInputError(f"{context} field names must be strings")
    return value


def _array(value: object, context: str) -> list[object]:
    if not isinstance(value, list):
        raise StageAInputError(f"{context} must be an array")
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


def _natural(value: object, context: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise StageAInputError(f"{context} must be a natural number")
    return value


@dataclass(frozen=True)
class OriginalExternalSiteSpec:
    kind: str
    id: int
    source_target_id: int
    machine_contract_id: int
    argument_sources: tuple[CallableArgumentSourceSpec, ...]
    resolver_contract_id: int | None = None
    capability_id: int | None = None

    def lean(self) -> str:
        sources = ", ".join(source.lean() for source in self.argument_sources)
        resolver = (
            "none"
            if self.resolver_contract_id is None
            else f"some {self.resolver_contract_id}"
        )
        capability = (
            "none" if self.capability_id is None else f"some {self.capability_id}"
        )
        return (
            f"{{ id := {self.id}, sourceTargetId := {self.source_target_id}, "
            f"machineContractId := {self.machine_contract_id}, "
            f"argumentSources := [{sources}], resolverContractId := {resolver}, "
            f"capabilityId := {capability} }}"
        )


@dataclass(frozen=True)
class CallableExternalExecutionArtifact:
    sites: tuple[OriginalExternalSiteSpec, ...]


def parse_callable_external_execution_artifact(
    payload: object,
) -> CallableExternalExecutionArtifact:
    root = _object(payload, "callable external execution artifact")
    _exact_fields(root, _ROOT_FIELDS, "callable external execution artifact")
    if root["format"] != CALLABLE_EXTERNAL_EXECUTION_FORMAT:
        raise StageAInputError("unsupported callable external execution format")

    result: list[OriginalExternalSiteSpec] = []
    for index, raw in enumerate(_array(root["sites"], "sites")):
        context = f"sites[{index}]"
        site = _object(raw, context)
        kind = site.get("kind")
        if kind == "ordinary":
            _exact_fields(site, _ORDINARY_SITE_FIELDS, context)
        elif kind == "resolver":
            _exact_fields(site, _RESOLVER_SITE_FIELDS, context)
        else:
            raise StageAInputError(f"{context}.kind must be ordinary or resolver")
        sources = tuple(
            CallableArgumentSourceSpec.parse(source, f"{context}.argument_sources[{i}]")
            for i, source in enumerate(
                _array(site["argument_sources"], f"{context}.argument_sources")
            )
        )
        if any(source.kind != "stack_word" for source in sources):
            raise StageAInputError(
                f"{context}.argument_sources must use exact stack_word sources"
            )
        result.append(OriginalExternalSiteSpec(
            kind=kind,
            id=_natural(site["id"], f"{context}.id"),
            source_target_id=_natural(
                site["source_target_id"], f"{context}.source_target_id"
            ),
            machine_contract_id=_natural(
                site["machine_contract_id"], f"{context}.machine_contract_id"
            ),
            argument_sources=sources,
            resolver_contract_id=(
                _natural(
                    site["resolver_contract_id"],
                    f"{context}.resolver_contract_id",
                )
                if kind == "resolver"
                else None
            ),
            capability_id=(
                _natural(site["capability_id"], f"{context}.capability_id")
                if kind == "resolver"
                else None
            ),
        ))
    if not result:
        raise StageAInputError("sites must not be empty")
    ids = [site.id for site in result]
    if len(set(ids)) != len(ids):
        raise StageAInputError("site ids are ambiguous")
    if ids != sorted(ids):
        raise StageAInputError("sites must be in canonical id order")
    routes = [(site.source_target_id, site.machine_contract_id) for site in result]
    if len(set(routes)) != len(routes):
        raise StageAInputError("source/machine site routes are ambiguous")
    return CallableExternalExecutionArtifact(tuple(result))


def classify_original_indirect_matches(
    *,
    internal_matches: list[int],
    import_matches: list[int],
    resource_matches: list[int],
    capability_resources: list[tuple[int, int]],
    abi_routes: list[tuple[int, str]],
    transfer: str,
) -> str:
    """Reference the Lean fail-closed category classifier for fixture tests."""
    if transfer not in {"call", "jump"}:
        raise StageAInputError("transfer must be call or jump")
    categories = (
        bool(internal_matches),
        bool(import_matches),
        bool(resource_matches),
    )
    if sum(categories) > 1:
        return "ambiguous"
    if internal_matches:
        return "internal" if len(internal_matches) == 1 else "ambiguous"
    if import_matches:
        return "imported" if len(import_matches) == 1 else "ambiguous"
    if not resource_matches:
        return "unmapped"
    if len(resource_matches) != 1:
        return "ambiguous"
    resource_id = resource_matches[0]
    capabilities = [
        capability_id
        for capability_id, candidate_resource_id in capability_resources
        if candidate_resource_id == resource_id
    ]
    if len(capabilities) != 1:
        return "invalid_callable"
    capability_id = capabilities[0]
    matching_abis = [
        route for route in abi_routes if route == (capability_id, transfer)
    ]
    return "callable" if len(matching_abis) == 1 else "invalid_callable"


def relational_callable_external_execution_source(payload: object) -> str:
    """Render static original-side site bindings without runtime claims."""
    artifact = parse_callable_external_execution_artifact(payload)
    definitions: list[str] = []
    names: list[str] = []
    for site in artifact.sites:
        name = f"originalExternalSite{site.id}"
        names.append(name)
        definitions.append(f"def {name} : OriginalExternalSite := {site.lean()}")
    rendered_names = ", ".join(names)
    return (
        "import StageA.RelationalCallableExternalExecution\n\n"
        "namespace StageA.GeneratedRelational.CallableExternalExecution\n\n"
        "open StageA.Relational.CallableExternalCapability\n"
        "open StageA.Relational.CallableExternalExecution\n\n"
        + "\n\n".join(definitions)
        + "\n\n"
        "def originalExternalSites : List OriginalExternalSite :=\n"
        f"  [{rendered_names}]\n\n"
        "theorem originalExternalSiteIdsUniqueChecked :\n"
        "    originalExternalSiteIdsUnique originalExternalSites = true := by\n"
        "  decide\n\n"
        "end StageA.GeneratedRelational.CallableExternalExecution\n"
    )


def relational_callable_external_program_source() -> str:
    """Bind generated callable inventories to the checked original context."""
    return """import StageA.GeneratedCallableExternalCapability
import StageA.GeneratedCallableExternalExecution
import StageA.GeneratedRelationalInterpreterMixedOriginalBaseCarrierData

namespace StageA.GeneratedRelational.CallableExternalProgram

open StageA.Relational.CallableExternalExecution

set_option maxRecDepth 1000000
set_option maxHeartbeats 0

def originalCallableProgram : OriginalCallableProgram := {
  context :=
    StageA.GeneratedRelational.InterpreterMixedOriginalBase.generatedOriginalCarrierContext
  resolverContracts :=
    StageA.GeneratedRelational.CallableExternalCapability.resolverCallContracts
  capabilities :=
    StageA.GeneratedRelational.CallableExternalCapability.callableExternalCapabilities
  resolvedABIContracts :=
    StageA.GeneratedRelational.CallableExternalCapability.resolvedExternalABIContracts
  externalSites :=
    StageA.GeneratedRelational.CallableExternalExecution.originalExternalSites
}

theorem originalCallableProgramValid :
    originalCallableProgram.Valid := {
  contextValid :=
    StageA.GeneratedRelational.InterpreterMixedOriginalBase.generatedOriginalCarrierContextStructurallyValid
  resolverIds :=
    StageA.GeneratedRelational.CallableExternalCapability.resolverCallContractIdsUniqueChecked
  capabilityIds :=
    StageA.GeneratedRelational.CallableExternalCapability.callableCapabilityIdsUniqueChecked
  capabilityResourceIds :=
    StageA.GeneratedRelational.CallableExternalCapability.callableCapabilityResourceIdsUniqueChecked
  capabilityShapes := by decide +kernel
  abiIds :=
    StageA.GeneratedRelational.CallableExternalCapability.resolvedExternalABIContractIdsUniqueChecked
  abiRoutes :=
    StageA.GeneratedRelational.CallableExternalCapability.resolvedExternalABIRoutesUniqueChecked
  abiShapes :=
    StageA.GeneratedRelational.CallableExternalCapability.resolvedExternalABIContractShapesChecked
  siteIds :=
    StageA.GeneratedRelational.CallableExternalExecution.originalExternalSiteIdsUniqueChecked
  sites := by decide +kernel
}

end StageA.GeneratedRelational.CallableExternalProgram
"""


__all__ = [
    "CALLABLE_EXTERNAL_EXECUTION_FORMAT",
    "CALLABLE_EXTERNAL_PROGRAM_MODULE",
    "CallableExternalExecutionArtifact",
    "classify_original_indirect_matches",
    "parse_callable_external_execution_artifact",
    "relational_callable_external_execution_source",
    "relational_callable_external_program_source",
]
