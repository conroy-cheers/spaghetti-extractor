from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from ...stage_binary import StageAInputError
from ..full_machine_lockstep import FullMachineLockstepImportIdentity
from ..schema import RegionStatePredicate, SchemaError
from .expressions import (
    _lean_external_target,
    _lean_semantic_bool_expr,
    _lean_semantic_expr,
    _lean_state_invariant,
)


FULL_MACHINE_LOCKSTEP_ENVIRONMENT_FORMAT = (
    "stage-a-relational-full-machine-lockstep-environment-v1"
)

_ROOT_FIELDS = frozenset({"format", "exact_import_identities", "call_sites"})
_SITE_FIELDS = frozenset({
    "id",
    "import",
    "boundary_invariant",
    "target_invariant",
})
_INVARIANT_FIELDS = frozenset({
    "register_relations",
    "import_register_relations",
    "dynamic_register_range_relations",
    "dynamic_stack_range_relations",
    "flag_bits",
    "bounds",
    "address_separations",
    "stack_windows",
    "predicates",
})


def _object(value: object, context: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise StageAInputError(f"{context} must be a JSON object")
    if any(not isinstance(key, str) for key in value):
        raise StageAInputError(f"{context} field names must be strings")
    return value


def _require_exact_fields(
    value: Mapping[str, Any], expected: frozenset[str], context: str
) -> None:
    fields = set(value)
    missing = sorted(expected - fields)
    unexpected = sorted(fields - expected)
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


def _exact_import(value: object, context: str) -> dict[str, str | int]:
    return FullMachineLockstepImportIdentity.parse(
        value, context=context
    ).to_payload()


def _import_key(
    imported: Mapping[str, str | int],
) -> tuple[str, int, str, int]:
    if "symbol" in imported:
        return (str(imported["dll"]), 0, str(imported["symbol"]), -1)
    return (str(imported["dll"]), 1, "", int(imported["ordinal"]))


def _lean_paired_state_predicate(
    value: object, context: str
) -> str:
    predicate_payload = _object(value, context)
    try:
        predicate = RegionStatePredicate.parse(predicate_payload)
        exact_reads = ", ".join(
            "{ originalAddress := "
            + _lean_semantic_expr(read["original_address"])
            + ", candidateAddress := "
            + _lean_semantic_expr(read["candidate_address"])
            + ", bytes := "
            + str(int(read["bytes"]))
            + " }"
            for read in predicate.exact_memory_reads
        )
        return (
            "{ original := "
            + _lean_semantic_bool_expr(predicate.original)
            + ", candidate := "
            + _lean_semantic_bool_expr(predicate.candidate)
            + ", exactMemoryReads := ["
            + exact_reads
            + "] }"
        )
    except (KeyError, SchemaError, TypeError, ValueError, StageAInputError) as exc:
        raise StageAInputError(f"{context} is malformed: {exc}") from exc


def _lean_exact_state_invariant(value: object, context: str) -> str:
    invariant = _object(value, context)
    unexpected = sorted(set(invariant) - _INVARIANT_FIELDS)
    if unexpected:
        raise StageAInputError(
            f"{context} has unexpected fields: {', '.join(unexpected)}"
        )
    for field, field_value in invariant.items():
        if not isinstance(field_value, list):
            raise StageAInputError(f"{context} {field} must be a JSON array")

    predicates = [
        _lean_paired_state_predicate(predicate, f"{context} predicates[{index}]")
        for index, predicate in enumerate(invariant.get("predicates", []))
    ]
    try:
        literal = _lean_state_invariant(dict(invariant))
    except (KeyError, TypeError, ValueError, StageAInputError) as exc:
        raise StageAInputError(f"{context} is malformed: {exc}") from exc
    if not predicates:
        return literal
    if not literal.endswith(" }"):
        raise StageAInputError(f"{context} has an unsupported literal shape")
    return literal[:-2] + ", predicates := [" + ", ".join(predicates) + "] }"


def _validated_artifact(
    payload: object,
) -> tuple[tuple[dict[str, Any], ...], tuple[dict[str, Any], ...]]:
    artifact = _object(payload, "full-machine lockstep environment artifact")
    _require_exact_fields(
        artifact, _ROOT_FIELDS, "full-machine lockstep environment artifact"
    )
    if artifact["format"] != FULL_MACHINE_LOCKSTEP_ENVIRONMENT_FORMAT:
        raise StageAInputError(
            "unsupported full-machine lockstep environment artifact format"
        )

    raw_identities = artifact["exact_import_identities"]
    if not isinstance(raw_identities, list):
        raise StageAInputError("exact_import_identities must be a JSON array")
    identities: list[dict[str, Any]] = []
    for index, raw_identity in enumerate(raw_identities):
        context = f"exact import identity {index}"
        identities.append({
            "id": index,
            "import": _exact_import(raw_identity, context),
        })
    identity_keys = [_import_key(identity["import"]) for identity in identities]
    if len(set(identity_keys)) != len(identity_keys):
        raise StageAInputError("exact import identities are ambiguous")
    if identity_keys != sorted(identity_keys):
        raise StageAInputError(
            "exact import identities must be in canonical order"
        )

    raw_sites = artifact["call_sites"]
    if not isinstance(raw_sites, list):
        raise StageAInputError("call_sites must be a JSON array")
    if not raw_sites:
        raise StageAInputError(
            "full-machine lockstep artifact must contain at least one call site"
        )
    sites: list[dict[str, Any]] = []
    for index, raw_site in enumerate(raw_sites):
        context = f"full-machine lockstep call site {index}"
        site = _object(raw_site, context)
        _require_exact_fields(site, _SITE_FIELDS, context)
        site_id = _natural(site["id"], f"{context} id")
        imported = _exact_import(site["import"], f"{context} import")
        matching_identity_ids = [
            identity["id"]
            for identity in identities
            if identity["import"] == imported
        ]
        if len(matching_identity_ids) != 1:
            raise StageAInputError(
                f"{context} does not match exactly one exact import identity"
            )
        sites.append({
            "id": site_id,
            "import_identity_id": matching_identity_ids[0],
            "boundary_invariant": _lean_exact_state_invariant(
                site["boundary_invariant"], f"{context} boundary_invariant"
            ),
            "target_invariant": _lean_exact_state_invariant(
                site["target_invariant"], f"{context} target_invariant"
            ),
        })

    site_ids = [site["id"] for site in sites]
    if len(set(site_ids)) != len(site_ids):
        raise StageAInputError("full-machine lockstep call site ids are ambiguous")
    if site_ids != sorted(site_ids):
        raise StageAInputError(
            "full-machine lockstep call sites must be in canonical site-id order"
        )
    referenced_identity_ids = {
        site["import_identity_id"] for site in sites
    }
    missing_site_identity_ids = sorted(
        set(range(len(identities))) - referenced_identity_ids
    )
    if missing_site_identity_ids:
        rendered = ", ".join(
            str(identity_id) for identity_id in missing_site_identity_ids
        )
        raise StageAInputError(
            "exact import identities lack full-machine lockstep call sites: "
            + rendered
        )
    return tuple(identities), tuple(sites)


def relational_lockstep_environment_source(payload: object) -> str:
    """Render checked lockstep-site data without claiming environment refinement."""
    identities, sites = _validated_artifact(payload)
    identity_definitions = "\n\n".join(
        f"def fullMachineLockstepImportIdentity{identity['id']} : ExternalTarget :=\n"
        f"  {_lean_external_target(identity['import'])}"
        for identity in identities
    )
    site_definitions = "\n\n".join(
        f"def fullMachineLockstepCallSite{site['id']} : "
        "FullMachineLockstepCallSite := {\n"
        f"  id := {site['id']}\n"
        "  imported := "
        f"fullMachineLockstepImportIdentity{site['import_identity_id']}\n"
        f"  boundaryInvariant := {site['boundary_invariant']}\n"
        f"  targetInvariant := {site['target_invariant']}\n"
        "}"
        for site in sites
    )
    site_names = ", ".join(
        f"fullMachineLockstepCallSite{site['id']}" for site in sites
    )
    static_identities = ", ".join(
        f"({site['id']}, "
        f"fullMachineLockstepImportIdentity{site['import_identity_id']})"
        for site in sites
    )
    definitions = "\n\n".join(
        block for block in (identity_definitions, site_definitions) if block
    )
    return (
        "import StageA.RelationalLockstepEnvironment\n\n"
        "namespace StageA.GeneratedRelational\n\n"
        "open StageA.Formal StageA.Relational\n\n"
        + definitions
        + "\n\n"
        "def fullMachineLockstepCallSites : "
        "List FullMachineLockstepCallSite :=\n"
        f"  [{site_names}]\n\n"
        "def fullMachineLockstepCallSiteStaticIdentities : "
        "List (Prod Nat ExternalTarget) :=\n"
        f"  [{static_identities}]\n\n"
        "theorem fullMachineLockstepCallSiteIdsUniqueChecked :\n"
        "    fullMachineLockstepCallSiteIdsUnique "
        "fullMachineLockstepCallSites = true := by\n"
        "  decide\n\n"
        "theorem fullMachineLockstepCallSiteStaticIdentitiesChecked :\n"
        "    fullMachineLockstepCallSites.map "
        "(fun site => (site.id, site.imported)) =\n"
        "      fullMachineLockstepCallSiteStaticIdentities := by\n"
        "  decide\n\n"
        "end StageA.GeneratedRelational\n"
    )


def relational_exact_lockstep_acceptance_source() -> str:
    """Render the generic exact-lockstep acceptance bridge.

    The generated proposition strengthens the ordinary environment refinement
    with one kernel-checked exact-lockstep return certificate per returning
    call site.  It deliberately does not manufacture any ABI, memory, result,
    or runtime-frame evidence.
    """
    return """import StageA.RelationalLockstepEnvironment

namespace StageA.Relational

/-- Acceptance-facing external-environment contract.  The ordinary refinement
continues to cover terminal and protocol dispositions.  Every returning site
additionally carries the stronger exact-lockstep evidence checked by
`externalEnvironmentRefinesAt_of_checkedExactLockstep`. -/
structure ExactLockstepExternalEnvironmentsRefine
    (context : StaticProofContext) (sites : List ExternalCallSiteContract)
    (original candidate : WorldExternalEnvironment) : Prop where
  externalRefines : ExternalEnvironmentRefines context sites original candidate
  checkedReturns : forall site contract,
    site \u2208 sites ->
    machineImportCallContractById? context site.machineContractId = some contract ->
    contract.disposition = .returns ->
    CheckedExactLockstepExternalReturn context site contract original candidate

/-- Project a returning call site through the checked exact-lockstep bridge.
The resulting theorem includes the static site/import checks, weak-to-full
boundary implication, exact event synchronization, machine-result conformance,
successor `StateRel`, and nested runtime-frame preservation. -/
theorem ExactLockstepExternalEnvironmentsRefine.atReturning
    (context : StaticProofContext) (sites : List ExternalCallSiteContract)
    (original candidate : WorldExternalEnvironment)
    (refines : ExactLockstepExternalEnvironmentsRefine context sites
      original candidate)
    (site : ExternalCallSiteContract) (contract : MachineImportCallContract)
    (member : site \u2208 sites)
    (resolved : machineImportCallContractById? context site.machineContractId =
      some contract)
    (returns : contract.disposition = .returns) :
    ExternalEnvironmentRefinesAt context site contract original candidate :=
  externalEnvironmentRefinesAt_of_checkedExactLockstep context site contract
    original candidate
    (refines.checkedReturns site contract member resolved returns)

end StageA.Relational
"""
