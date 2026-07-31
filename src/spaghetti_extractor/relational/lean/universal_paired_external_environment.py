"""Emit exact PE/import evidence for universal paired external environments.

The emitted Lean source can prove exact import/profile facts and, when concrete
route/context/site bindings are supplied, all non-behavioral certificate
premises.  It never constructs a favorable external environment.  Concrete
acceptance consumers must still provide a universally sound response relation
and prove that the selected environment pair implements it.

For native-interpreter candidates, route and call-site closure belongs to the
mixed component proof: those candidates intentionally do not have a synthetic
paired ``StaticProofContext``.  The optional static-authority adapter remains
available for structurally paired binary-to-binary proofs.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

from ...artifact_formats import STATIC_MACHINE_IMPORT_CONTRACTS_FORMAT
from ...stage_binary import StageAInputError
from ...util import sha256_file, write_json


UNIVERSAL_PAIRED_EXTERNAL_ENVIRONMENT_FORMAT = (
    "stage-a-universal-paired-external-environment-v1"
)
UNIVERSAL_PAIRED_EXTERNAL_ENVIRONMENT_STATIC_AUTHORITY_MODULE = (
    "StageA.RelationalUniversalPairedExternalEnvironmentStaticAuthority"
)
_LEAN_NAME = re.compile(r"^[A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z][A-Za-z0-9_]*)*$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")


@dataclass(frozen=True)
class UniversalPairedExternalEnvironmentBindings:
    original_module: str
    candidate_module: str
    static_import_module: str
    original_namespace: str
    candidate_namespace: str
    static_import_namespace: str
    original_bytes: str
    candidate_bytes: str
    original_pe: str
    candidate_pe: str
    original_imports: str
    candidate_imports: str
    original_pe_parsed: str
    candidate_pe_parsed: str
    required_imports: str = "generatedRequiredImports"
    signatures: str = "generatedMachineImportSignatures"
    contracts: str = "generatedMachineImportBoundaryContracts"
    original_profile_certificate: str = (
        "generatedStaticMachineImportProfileCertificate"
    )

    def __post_init__(self) -> None:
        for field, value in self.__dict__.items():
            if not isinstance(value, str) or not _LEAN_NAME.fullmatch(value):
                raise StageAInputError(
                    f"universal paired external environment binding {field} "
                    "must be a Lean name"
                )

    def original(self, name: str) -> str:
        return f"{self.original_namespace}.{name}"

    def candidate(self, name: str) -> str:
        return f"{self.candidate_namespace}.{name}"

    def static(self, name: str) -> str:
        return f"{self.static_import_namespace}.{name}"


@dataclass(frozen=True)
class UniversalPairedExternalEnvironmentStaticAuthorityBindings:
    """Concrete generated terms used to compute all non-behavioral authority."""

    dependency_modules: tuple[str, ...]
    context: str
    sites: str
    candidate_regions: str
    candidate_boundaries: str

    def __post_init__(self) -> None:
        if not self.dependency_modules:
            raise StageAInputError(
                "universal paired external environment static authority "
                "requires dependency modules"
            )
        values = {
            "context": self.context,
            "sites": self.sites,
            "candidate_regions": self.candidate_regions,
            "candidate_boundaries": self.candidate_boundaries,
        }
        for index, module in enumerate(self.dependency_modules):
            values[f"dependency_modules[{index}]"] = module
        for field, value in values.items():
            if not isinstance(value, str) or not _LEAN_NAME.fullmatch(value):
                raise StageAInputError(
                    "universal paired external environment static authority "
                    f"binding {field} must be a Lean name"
                )
        if len(set(self.dependency_modules)) != len(self.dependency_modules):
            raise StageAInputError(
                "universal paired external environment static authority "
                "dependency modules must be unique"
            )


def _mapping(value: object, context: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise StageAInputError(f"{context} must be a JSON object")
    if any(not isinstance(key, str) for key in value):
        raise StageAInputError(f"{context} field names must be strings")
    return value


def _load_machine_import_report(
    path: Path, *, original_sha256: str
) -> Mapping[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise StageAInputError(
            f"cannot read machine-import report {path}: {exc}"
        ) from exc
    report = _mapping(payload, "machine-import report")
    if report.get("format") != STATIC_MACHINE_IMPORT_CONTRACTS_FORMAT:
        raise StageAInputError("unsupported machine-import report format")
    if report.get("status") != "ready":
        raise StageAInputError("machine-import report is not ready")
    blockers = report.get("blockers")
    if not isinstance(blockers, list) or blockers:
        raise StageAInputError("machine-import report contains blockers")
    inputs = _mapping(report.get("inputs"), "machine-import report inputs")
    if inputs.get("original_sha256") != original_sha256:
        raise StageAInputError(
            "machine-import report does not match the exact original PE"
        )
    counts = _mapping(report.get("counts"), "machine-import report counts")
    for field in (
        "required_reachable_imports",
        "lean_profile_signatures",
        "checked_boundary_proposals",
    ):
        value = counts.get(field)
        if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
            raise StageAInputError(
                f"machine-import report {field} must be positive"
            )
    if counts["required_reachable_imports"] != counts["lean_profile_signatures"]:
        raise StageAInputError(
            "machine-import report does not provide one signature per "
            "required import"
        )
    return report


def universal_paired_external_environment_source(
    *,
    original_sha256: str,
    candidate_sha256: str,
    machine_import_report_sha256: str,
    bindings: UniversalPairedExternalEnvironmentBindings,
    static_authority: (
        UniversalPairedExternalEnvironmentStaticAuthorityBindings | None
    ) = None,
    namespace: str = "StageA.GeneratedRelational.UniversalPairedExternal",
) -> str:
    for field, value in (
        ("original_sha256", original_sha256),
        ("candidate_sha256", candidate_sha256),
        ("machine_import_report_sha256", machine_import_report_sha256),
    ):
        if not _SHA256.fullmatch(value):
            raise StageAInputError(f"{field} must be a lowercase SHA-256")
    if not _LEAN_NAME.fullmatch(namespace):
        raise StageAInputError("generated namespace must be a Lean name")

    original_bytes = bindings.original(bindings.original_bytes)
    candidate_bytes = bindings.candidate(bindings.candidate_bytes)
    original_pe = bindings.original(bindings.original_pe)
    candidate_pe = bindings.candidate(bindings.candidate_pe)
    original_imports = bindings.original(bindings.original_imports)
    candidate_imports = bindings.candidate(bindings.candidate_imports)
    required = bindings.static(bindings.required_imports)
    signatures = bindings.static(bindings.signatures)
    contracts = bindings.static(bindings.contracts)
    original_profile = bindings.static(bindings.original_profile_certificate)
    static_authority_imports = ""
    static_authority_open = ""
    static_authority_source = ""
    if static_authority is not None:
        dependency_modules = tuple(
            dict.fromkeys(
                (
                    UNIVERSAL_PAIRED_EXTERNAL_ENVIRONMENT_STATIC_AUTHORITY_MODULE,
                    *static_authority.dependency_modules,
                )
            )
        )
        static_authority_imports = "".join(
            f"import {module}\n" for module in dependency_modules
        )
        static_authority_open = (
            "open StageA.Relational."
            "UniversalPairedExternalEnvironmentStaticAuthority\n"
        )
        context = static_authority.context
        sites = static_authority.sites
        candidate_regions = static_authority.candidate_regions
        candidate_boundaries = static_authority.candidate_boundaries
        static_authority_source = f"""
theorem exactCandidateMachineImportCallRoutesPinned :
    candidateStaticMachineImportCallRoutesPinned {context}
      {candidate_regions} {signatures} {candidate_boundaries}
      {sites} = true := by
  decide

theorem exactPinnedStaticMachineImportPairBoundToContext :
    exactPinnedStaticMachineImportPair.BoundToContext {context} := {{
  originalPeExact := by decide
  candidatePeExact := by decide
  originalImportsExact := by decide
  candidateImportsExact := by decide
  machineContractsExact := by decide
}}

theorem exactExternalCallSiteIdsUnique :
    externalCallSiteIdsUnique {sites} = true := by
  decide

theorem exactExternalCallSitesStaticValid :
    {sites}.all
      (ExternalCallSiteContract.staticValid {context}) = true := by
  decide

def exactUniversalPairedExternalEnvironmentStaticAuthority :
    UniversalPairedExternalEnvironmentStaticAuthority
      exactPinnedStaticMachineImportPair {context} {candidate_regions}
      {candidate_boundaries} {sites} := {{
  candidateRoutesPinned := exactCandidateMachineImportCallRoutesPinned
  contextBound := exactPinnedStaticMachineImportPairBoundToContext
  siteIdsUnique := exactExternalCallSiteIdsUnique
  sitesStaticValid := exactExternalCallSitesStaticValid
}}

/-- All static premises are computed above.  The selected environments and
their universally sound returning-response evidence remain explicit inputs. -/
def exactPinnedUniversalPairedExternalEnvironmentCertificateOfResponses
    (original candidate : WorldExternalEnvironment)
    (returningResponses : forall site contract,
      site ∈ {sites} ->
      machineImportCallContractById? {context} site.machineContractId =
        some contract ->
      contract.disposition = .returns ->
      CheckedUniversalPairedMachineResponse {context} site contract
        original candidate) :
    UniversalPairedExternalEnvironmentCertificate
      exactPinnedStaticMachineImportPair {context} {sites}
      original candidate :=
  UniversalPairedExternalEnvironmentStaticAuthority.certificate
    exactPinnedStaticMachineImportPair {context} {candidate_regions}
    {candidate_boundaries} {sites} original candidate
    exactUniversalPairedExternalEnvironmentStaticAuthority returningResponses

#print axioms exactCandidateMachineImportCallRoutesPinned
#print axioms exactPinnedStaticMachineImportPairBoundToContext
#print axioms exactExternalCallSiteIdsUnique
#print axioms exactExternalCallSitesStaticValid
#print axioms exactPinnedUniversalPairedExternalEnvironmentCertificateOfResponses
"""
    return f"""import StageA.RelationalUniversalPairedExternalEnvironment
import {bindings.original_module}
import {bindings.candidate_module}
import {bindings.static_import_module}
{static_authority_imports}

namespace {namespace}

open StageA.Formal StageA.Relational
open StageA.Relational.StaticMachineImportContracts
open StageA.Relational.UniversalPairedExternalEnvironment
{static_authority_open}

set_option maxRecDepth 1000000
set_option maxHeartbeats 0

/- SHA-256 labels are audited build metadata.  Exact proof authority comes
from the parsed byte-tree equations below, not from trusting these strings. -/
def exactOriginalPESha256 : String := {json.dumps(original_sha256)}
def exactCandidatePESha256 : String := {json.dumps(candidate_sha256)}
def exactMachineImportReportSha256 : String :=
  {json.dumps(machine_import_report_sha256)}

theorem exactNormalizedImportInventoryChecked :
    {original_imports}.map normalizeImport =
      {candidate_imports}.map normalizeImport := by
  decide

theorem candidateStaticMachineImportProfileChecked :
    staticMachineImportProfilesValid {candidate_pe} {candidate_imports}
      {required} {signatures} = true := by
  decide

def candidateStaticMachineImportProfileCertificate :
    StaticMachineImportProfileCertificate {candidate_pe} {candidate_imports}
      {required} {signatures} := {{
  checked := candidateStaticMachineImportProfileChecked
}}

theorem sharedBoundaryMachineContractsChecked :
    pinnedMachineImportContractsValid {required} {signatures}
      {contracts} = true := by
  decide

def exactPinnedStaticMachineImportPair :
    PinnedStaticMachineImportPair
      {original_bytes} {candidate_bytes}
      {original_pe} {candidate_pe}
      {original_imports} {candidate_imports}
      {required} {signatures} {contracts} := {{
  originalPeParsed := {bindings.original(bindings.original_pe_parsed)}
  candidatePeParsed := {bindings.candidate(bindings.candidate_pe_parsed)}
  importIdentitiesExact := exactNormalizedImportInventoryChecked
  originalProfile := {original_profile}
  candidateProfile := candidateStaticMachineImportProfileCertificate
  contractsPinned := sharedBoundaryMachineContractsChecked
}}

/-- Acceptance-facing exact-hash-selected type.  A consumer must still inhabit
`BoundToContext`, site resolution, and one universal response certificate for
every returning site; no concrete environment is selected here. -/
abbrev ExactPinnedUniversalPairedExternalEnvironmentCertificate
    (context : StaticProofContext)
    (sites : List ExternalCallSiteContract)
    (original candidate : WorldExternalEnvironment) : Type :=
  UniversalPairedExternalEnvironmentCertificate
    exactPinnedStaticMachineImportPair context sites original candidate

{static_authority_source}
#print axioms exactNormalizedImportInventoryChecked
#print axioms candidateStaticMachineImportProfileChecked
#print axioms sharedBoundaryMachineContractsChecked

end {namespace}
"""


def write_universal_paired_external_environment_source(
    *,
    original_pe: Path,
    candidate_pe: Path,
    machine_import_report: Path,
    out_dir: Path,
    bindings: UniversalPairedExternalEnvironmentBindings,
    static_authority: (
        UniversalPairedExternalEnvironmentStaticAuthorityBindings | None
    ) = None,
    module: str = "GeneratedUniversalPairedExternalEnvironment",
    namespace: str = "StageA.GeneratedRelational.UniversalPairedExternal",
) -> tuple[Path, Path]:
    if not _LEAN_NAME.fullmatch(module) or "." in module:
        raise StageAInputError("generated module must be an unqualified Lean name")
    original_sha256 = sha256_file(original_pe)
    candidate_sha256 = sha256_file(candidate_pe)
    report = _load_machine_import_report(
        machine_import_report, original_sha256=original_sha256
    )
    report_sha256 = sha256_file(machine_import_report)
    stage_a = out_dir / "StageA"
    stage_a.mkdir(parents=True, exist_ok=True)
    lean_path = stage_a / f"{module}.lean"
    lean_path.write_text(
        universal_paired_external_environment_source(
            original_sha256=original_sha256,
            candidate_sha256=candidate_sha256,
            machine_import_report_sha256=report_sha256,
            bindings=bindings,
            static_authority=static_authority,
            namespace=namespace,
        ),
        encoding="utf-8",
    )
    counts = _mapping(report["counts"], "machine-import report counts")
    manifest_path = out_dir / "universal-paired-external-environment.json"
    write_json(
        manifest_path,
        {
            "format": UNIVERSAL_PAIRED_EXTERNAL_ENVIRONMENT_FORMAT,
            "status": "source-ready",
            "proof_authority": False,
            "executes_original_binary": False,
            "executes_candidate_binary": False,
            "inputs": {
                "original_sha256": original_sha256,
                "candidate_sha256": candidate_sha256,
                "machine_import_report_sha256": report_sha256,
            },
            "counts": {
                "required_imports": counts["required_reachable_imports"],
                "machine_contracts": counts["checked_boundary_proposals"],
            },
            "proved_by_generated_terms": [
                "exact_original_pe_byte_tree_parses",
                "exact_candidate_pe_byte_tree_parses",
                "normalized_import_inventories_equal",
                "shared_static_machine_import_profiles_valid",
                "shared_boundary_machine_contracts_shape_valid",
                *(
                    [
                        (
                            "candidate_exact_call_routes_pinned_to_checked_"
                            "sites_and_contracts"
                        ),
                        "static_proof_context_bound_to_the_exact_pe_pair",
                        "external_call_site_ids_unique",
                        "external_call_sites_static_valid",
                        "external_call_site_contracts_resolved",
                    ]
                    if static_authority is not None
                    else []
                ),
            ],
            # This phase attests only the exact PE/import/profile pair.
            # Structurally paired call routes can be checked by the optional
            # adapter above.  Native-interpreter route closure is checked by
            # mixed component composition and is not a premise of this phase.
            "remaining_premises": [],
            "route_authority": (
                "paired_static_context"
                if static_authority is not None
                else "mixed_component_composition"
            ),
            "conditional_environment_parameters": [
                "each_returning_site_has_a_universally_sound_response_relation",
                "both_selected_environments_implement_each_response_relation",
                "protocol_and_callback_actions_have_separate_nested_frame_refinement",
            ],
            "lean_module": f"StageA/{lean_path.name}",
            "authorizing_term": (
                f"{namespace}."
                + (
                    "exactUniversalPairedExternalEnvironmentStaticAuthority"
                    if static_authority is not None
                    else (
                        "ExactPinnedUniversalPairedExternalEnvironmentCertificate"
                    )
                )
            ),
        },
    )
    return lean_path, manifest_path


__all__ = [
    "UNIVERSAL_PAIRED_EXTERNAL_ENVIRONMENT_FORMAT",
    "UNIVERSAL_PAIRED_EXTERNAL_ENVIRONMENT_STATIC_AUTHORITY_MODULE",
    "UniversalPairedExternalEnvironmentBindings",
    "UniversalPairedExternalEnvironmentStaticAuthorityBindings",
    "universal_paired_external_environment_source",
    "write_universal_paired_external_environment_source",
]
